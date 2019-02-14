/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "checks.h"
#include "db.h"
#include "list.h"
#include "pkcs11.h"
#include "session.h"
#include "session_table.h"
#include "slot.h"
#include "tpm.h"
#include "token.h"
#include "utils.h"

void token_free_list(token *t, size_t len) {

    size_t i;
    for (i=0; i < len; i++) {
        token_free(&t[i]);
    }
    free(t);
}

void token_free(token *t) {

    session_table_free(t->s_table);

    twist_free(t->sopobjauth);
    twist_free(t->sopobjauthkeysalt);

    twist_free(t->userpobjauth);
    twist_free(t->userpobjauthkeysalt);

    sobject_free(&t->sobject);
    sealobject_free(&t->sealobject);
    wrappingobject_free(&t->wrappingobject);

    if (t->tobjects) {
        list *cur = &t->tobjects->l;
        while(cur) {
            tobject *tobj = list_entry(cur, tobject, l);
            cur = cur->next;
            tobject_free(tobj);
        }
    }

    tpm_ctx_free(t->tctx);

    mutex_destroy(t->mutex);
}

CK_RV token_get_info (token *t, CK_TOKEN_INFO *info) {

    check_pointer(info);

    const CK_BYTE token_sn[]   = TPM2_TOKEN_SERIAL_NUMBER;
    const CK_BYTE token_manuf[]  = TPM2_TOKEN_MANUFACTURER;
    const CK_BYTE token_model[]  = TPM2_TOKEN_MODEL;
    const CK_BYTE token_hwver[2] = TPM2_SLOT_HW_VERSION;
    const CK_BYTE token_fwver[2] = TPM2_SLOT_FW_VERSION;
    time_t rawtime;
    struct tm * tminfo;

    memset(info, 0, sizeof(*info));

    /*
     * TODO Set these to better values
     * and get valid VERSION info. Likely
     * need to make version match what is in general.c
     * for the CK_INFO structure, not sure.
     *
     * Below is ALL the fields grouped.
     */

    // Version info
    memcpy(&info->firmwareVersion, &token_fwver, sizeof(token_fwver));
    memcpy(&info->hardwareVersion, &token_hwver, sizeof(token_hwver));

    // Support Flags
    info->flags = CKF_RNG
        | CKF_LOGIN_REQUIRED;

    if (t->config.is_initialized) {
        info->flags |= CKF_TOKEN_INITIALIZED;
    }

    // Identification
    str_padded_copy(info->label, t->label, sizeof(info->label));
    str_padded_copy(info->manufacturerID, token_manuf, sizeof(info->manufacturerID));
    str_padded_copy(info->model, token_model, sizeof(info->model));
    str_padded_copy(info->serialNumber, token_sn, sizeof(info->serialNumber));

    // Memory: TODO not sure what memory values should go here, the platform?
    info->ulFreePrivateMemory = ~0;
    info->ulFreePublicMemory = ~0;
    info->ulTotalPrivateMemory = ~0;
    info->ulTotalPublicMemory = ~0;

    // Maximums and Minimums
    info->ulMaxPinLen = 128;
    info->ulMinPinLen = 5;
    info->ulMaxSessionCount = MAX_NUM_OF_SESSIONS;
    info->ulMaxRwSessionCount = MAX_NUM_OF_SESSIONS;

    // Session
    session_table_get_cnt(t->s_table, &info->ulSessionCount, &info->ulRwSessionCount, NULL);

    // Time
    time (&rawtime);
    tminfo = gmtime(&rawtime);
    strftime ((char *)info->utcTime, sizeof(info->utcTime), "%Y%m%d%H%M%S", tminfo);

    return CKR_OK;
}

static bool token_is_any_user_logged_in(token *tok) {

    return tok->login_state != token_no_one_logged_in;
}

CK_RV token_logout(token *tok) {

    bool is_anyone_logged_in = token_is_any_user_logged_in(tok);
    if (!is_anyone_logged_in) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    /*
     * Ok now start evicting TPM objects from the right
     * context
     */
    tpm_ctx *tpm = tok->tctx;

    // Evict the keys
    sobject *sobj = &tok->sobject;

    if (tok->tobjects) {

        list *cur = &tok->tobjects->l;
        while(cur) {
            tobject *tobj = list_entry(cur, tobject, l);
            cur = cur->next;
            if (tobj->handle) {
                bool result = tpm_flushcontext(tpm, tobj->handle);
                assert(result);
                UNUSED(result);
                tobj->handle = 0;

                /* Clear the unwrapped auth value for tertiary objects */
                twist_free(tobj->unsealed_auth);
                tobj->unsealed_auth = NULL;
            }
        }
    }

    // Evict the wrapping object
    wrappingobject *wobj = &tok->wrappingobject;
    if (tok->config.sym_support) {
        bool result = tpm_flushcontext(tpm, wobj->handle);
        assert(result);
        UNUSED(result);
    }
    twist_free(wobj->objauth);
    wobj->objauth = NULL;
    wobj->handle = 0;

    // Evict the secondary object
    bool result = tpm_flushcontext(tpm, sobj->handle);
    assert(result);
    UNUSED(result);
    sobj->handle = 0;

    // Kill primary object auth data
    pobject *pobj = &tok->pobject;
    twist_free(pobj->objauth);
    pobj->objauth = NULL;

    /*
     * State transition all sessions in the table
     */
    token_logout_all_sessions(tok);

    /*
     * mark no one logged in
     */
    tok->login_state = token_no_one_logged_in;

    tpm_session_stop(tok->tctx);

    return CKR_OK;
}

CK_RV token_login(token *tok, twist pin, CK_USER_TYPE user) {

    bool on_error_flush_session = false;

    twist sealobjauth = NULL;
    twist dpobjauth = NULL;

    CK_RV rv = CKR_GENERAL_ERROR;

    bool is_anyone_logged_in = token_is_any_user_logged_in(tok);
    if (is_anyone_logged_in) {
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    CK_ULONG ro;
    session_table_get_cnt(tok->s_table, NULL, NULL, &ro);

    if (user == CKU_SO && ro) {
        return CKR_SESSION_READ_ONLY_EXISTS;
    }


    /*
     * To login, we need to use PIN against the correct seal object.
     * Load that seal object, and use tpm2_unseal to extract the
     * wrapping key auth. Also, load the wrapping key and secondary object.
     * Then on actual key operation, we can load the tertiary object.
     */

    /* derive the primary object auth for loading the sealed and wrapping key up */
    unsigned pobjiters = user == CKU_USER ? tok->userpobjauthkeyiters : tok->sopobjauthkeyiters;
    twist pobjsalt = user == CKU_USER ? tok->userpobjauthkeysalt : tok->sopobjauthkeysalt;
    twist pobjauth = user == CKU_USER ? tok->userpobjauth : tok->sopobjauth;

    dpobjauth = decrypt(pin, pobjsalt, pobjiters, pobjauth);
    if (!dpobjauth) {
        return CKR_PIN_INCORRECT;
    }

    tok->pobject.objauth = dpobjauth;

    CK_RV tmp = tpm_sesion_start(tok->tctx, tok->pobject.objauth, tok->pobject.handle);
    if (tmp != CKR_OK) {
        return tmp;
    }

    on_error_flush_session = true;

    tpm_ctx *tpm = tok->tctx;

    /* load seal object */
    sealobject *sealobj = &tok->sealobject;
    twist sealpub = user == CKU_USER ? sealobj->userpub : sealobj->sopub;
    twist sealpriv = user == CKU_USER ? sealobj->userpriv : sealobj->sopriv;

    uint32_t pobj_handle = tok->pobject.handle;

    // TODO evict sealobjhandle
    bool res = tpm_loadobj(tpm, pobj_handle, dpobjauth, sealpub, sealpriv, &sealobj->handle);
    if (!res) {
        goto error;
    }

    /* derive the sealed obj auth for use in tpm_unseal to get the wrapping key auth*/
    unsigned sealiters = user == CKU_USER ? sealobj->userauthiters : sealobj->soauthiters;
    twist sealsalt = user == CKU_USER ? sealobj->userauthsalt : sealobj->soauthsalt;
    sealobjauth = utils_pdkdf2_hmac_sha256_raw(pin, sealsalt, sealiters);
    if (!sealobjauth) {
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    wrappingobject *wobj = &tok->wrappingobject;
    twist wobjauth = tpm_unseal(tpm, sealobj->handle, sealobjauth);
    if (!wobjauth) {
        rv = CKR_PIN_INCORRECT;
        goto error;
    }

    /*
     * If SW objauth unwrapping is enabled, we use the
     * unsealed value as the key, else we use the TPM
     * wrapping key directly.
     *
     * The SW version of unsealed auth shall remain in
     * hex form where as the direct form shouldn't.
     *
     */
    if (tok->config.sym_support) {
        wobj->objauth = twistbin_unhexlify(wobjauth);
        twist_free(wobjauth);
        if (!wobj->objauth) {
            LOGE("Could not unhexlify wrapping object auth");
            goto error;
        }

        /* load the wrapping key */
        res = tpm_loadobj(tpm, pobj_handle, dpobjauth, wobj->pub, wobj->priv, &wobj->handle);
        if (!res) {
            goto error;
        }
    } else {
        wobj->objauth = wobjauth;
    }

    /* load the secondary object */
    sobject *sobj = &tok->sobject;
    res = tpm_loadobj(tpm, pobj_handle, dpobjauth, sobj->pub, sobj->priv, &sobj->handle);
    if (!res) {
        goto error;
    }

    /*
     * Indicate that the token has been logged in
     */
    tok->login_state = user == CKU_USER ? token_user_logged_in : token_so_logged_in;

    /*
     * State transition all *EXISTING* sessions in the table
     */
    session_table_login_event(tok->s_table, user);

    on_error_flush_session = false;
    rv = CKR_OK;

error:

    if (on_error_flush_session) {
        tpm_session_stop(tok->tctx);
    }

    twist_free(sealobjauth);

    return rv;
}

bool token_opdata_is_active(token *tok) {

    return tok->opdata.op != operation_none;
}

void token_opdata_set(token *tok, operation op, void *data) {

    tok->opdata.op = op;
    tok->opdata.data = data;
}

void token_opdata_clear(token *tok) {

    token_opdata_set(tok, operation_none, NULL);
}

CK_RV _token_opdata_get(token *tok, operation op, void **data) {

    if (op != tok->opdata.op) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    *data = tok->opdata.data;

    return CKR_OK;
}

void token_lock(token *t) {
    mutex_lock_fatal(t->mutex);
}

void token_unlock(token *t) {
    mutex_unlock_fatal(t->mutex);
}

#define ITERS 10000
#define SALT_SIZE 32

static CK_RV setup_new_pobjwrapping_data(pobject *pobj, twist newpin, twist *newkeysalthex, twist *newpobjauthhex) {

    CK_RV rv = CKR_GENERAL_ERROR;

    twist newpobjkeybin = NULL;
    twist newkeysaltbin = NULL;
    twist oldpobjauthhex = NULL;

    newkeysaltbin = utils_get_rand(SALT_SIZE);
    if (!newkeysaltbin) {
        goto out;
    }

    *newkeysalthex = twist_hexlify(newkeysaltbin);
    if (!*newkeysalthex) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    newpobjkeybin = utils_pdkdf2_hmac_sha256_bin_raw(newpin, newkeysaltbin, ITERS);
    if (!newpobjkeybin) {
        goto out;
    }

    oldpobjauthhex = twist_hexlify(pobj->objauth);
    if (!oldpobjauthhex) {
        LOGE("oom");
        goto out;
    }

    *newpobjauthhex = aes256_gcm_encrypt(newpobjkeybin, oldpobjauthhex);
    if (!*newpobjauthhex) {
        goto out;
    }

    rv = CKR_OK;

out:

    if (rv != CKR_OK) {
        twist_free(*newkeysalthex);
        twist_free(*newpobjauthhex);
        *newkeysalthex = NULL;
        *newpobjauthhex = NULL;
    }

    twist_free(newpobjkeybin);
    twist_free(newkeysaltbin);
    twist_free(oldpobjauthhex);

    return rv;
}

static CK_RV setup_new_object_auth(twist newpin, twist *newauthbin, twist *newauthhex, twist *newsalthex) {

    CK_RV rv = CKR_GENERAL_ERROR;

    twist newsaltbin = NULL;

    newsaltbin = utils_get_rand(SALT_SIZE);
    if (!newsaltbin) {
        goto out;
    }

    *newsalthex = twist_hexlify(newsaltbin);
    if (!*newsalthex) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    *newauthbin = utils_pdkdf2_hmac_sha256_bin_raw(newpin, newsaltbin, ITERS);
    if (!newauthbin) {
        goto out;
    }

    *newauthhex = twist_hexlify(*newauthbin);
    if (!*newauthhex) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    rv = CKR_OK;

out:

    if (rv != CKR_OK) {
        twist_free(*newauthhex);
        twist_free(*newsalthex);
        twist_free(*newauthbin);
        *newsalthex = NULL;
        *newauthhex = NULL;
        *newauthbin = NULL;
    }

    twist_free(newsaltbin);

    return rv;
}

static void change_token_mem_data(token *tok, bool is_so, uint32_t new_seal_handle, twist newkeysalthex, twist newpobjauthhex, twist newsalthex, twist newprivblob, twist newpubblob) {

    tok->sealobject.handle = new_seal_handle;
    twist *pobjauthkeysalt;
    twist *sopobjauth;
    twist *authsalt;
    twist *priv;
    twist *pub;
    unsigned *pobjauthkeyiters;
    unsigned *authiters;
    if (is_so) {
        pobjauthkeysalt  = &tok->sopobjauthkeysalt;
        pobjauthkeyiters = &tok->sopobjauthkeyiters;

        sopobjauth = &tok->sopobjauth;
        authiters = &tok->sealobject.soauthiters;
        authsalt = &tok->sealobject.soauthsalt;
        priv = &tok->sealobject.sopriv;
        pub = &tok->sealobject.sopub;
    } else {
        pobjauthkeysalt  = &tok->userpobjauthkeysalt;
        pobjauthkeyiters = &tok->userpobjauthkeyiters;

        sopobjauth = &tok->userpobjauth;
        authiters = &tok->sealobject.userauthiters;
        authsalt = &tok->sealobject.userauthsalt;
        priv = &tok->sealobject.userpriv;
        pub = &tok->sealobject.userpub;
    }

    twist_free(*pobjauthkeysalt);
    twist_free(*sopobjauth);
    twist_free(*authsalt);
    twist_free(*priv);

    *pobjauthkeysalt = newkeysalthex;
    *pobjauthkeyiters = ITERS;
    *sopobjauth = newpobjauthhex;
    *authiters = ITERS;
    *authsalt = newsalthex;
    *priv = newprivblob;

    if (newpubblob) {
        twist_free(*pub);
        *pub = newpubblob;
    }
}

CK_RV token_setpin(token *tok, CK_UTF8CHAR_PTR oldpin, CK_ULONG oldlen, CK_UTF8CHAR_PTR newpin, CK_ULONG newlen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    /* new primary auth wrapping data */
    twist newpobjauthhex = NULL;
    twist newkeysalthex = NULL;

    /* old primary object data */
    twist oldpobjauthhex = NULL;

    /* new seal auth data */
    twist newsalthex = NULL;
    twist newauthbin = NULL;
    twist newauthhex = NULL;

    twist newprivblob = NULL;

    /* pin data */
    twist toldpin = NULL;
    twist tnewpin = NULL;

    bool is_so = (tok->login_state == token_so_logged_in);

    toldpin = twistbin_new(oldpin, oldlen);
    if (!toldpin) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    tnewpin = twistbin_new(newpin, newlen);
    if (!tnewpin) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    /*
     * Step 1 - Generate new primary object wrapping key and wrap the pobj auth
     *
     * This will update the tokens table, the columns:
     *  - (so|user)pobjsuthkeysalt  --> newkeysalt
     *  - (so|user)pobjauthkeyiters --> newiters
     *  - (so|user)pobjauth         --> newpobjauth
     */
    rv = setup_new_pobjwrapping_data(&tok->pobject, tnewpin, &newkeysalthex, &newpobjauthhex);
    if (rv != CKR_OK) {
        goto out;
    }

    /*
     * Step 2 - Generate a new sealing auth value via pbkdf2 OSSL call
     *
     * This will update the sealobjects table, the columns:
     *  - (so|user)authsalt  --> newsalt
     *  - (so|user)authiters --> ITERS
     */
    rv = setup_new_object_auth(tnewpin, &newauthbin, &newauthhex, &newsalthex);
    if (rv != CKR_OK) {
        goto out;
    }

    /*
     * Step 3 - Generate the current auth value from oldpin
     */
    unsigned olditers = is_so ? tok->sealobject.soauthiters : tok->sealobject.userauthiters;
    twist oldsalt = is_so ? tok->sealobject.soauthsalt : tok->sealobject.userauthsalt;

    twist oldauth = utils_pdkdf2_hmac_sha256_raw(toldpin, oldsalt, olditers);
    if (!oldauth) {
        goto out;
    }

    /*
     * Step 4 - Call tpm2_changeauth and get a new private object portion
     *
     * This private blob will update table sealobjects (user|so)priv
     */
    rv = tpm_changeauth(tok->tctx, tok->pobject.handle, tok->sealobject.handle,
            oldauth, newauthbin,
            &newprivblob);
    twist_free(oldauth);
    if (rv != CKR_OK) {
        goto out;
    }

    /*
     * Step 5 - load up a new seal object with the new private blob
     */
    twist pubblob = is_so ? tok->sealobject.sopub : tok->sealobject.userpub;

    /* load and update new seal object */
    uint32_t new_seal_handle = 0;
    bool res = tpm_loadobj(tok->tctx, tok->pobject.handle, tok->pobject.objauth,
                pubblob, newprivblob,
                &new_seal_handle);
    if (!res) {
        goto out;
    }

    /*
     * Step X - update the db data
     */
    rv = db_update_for_pinchange(
            tok,
            is_so,
            /* primary object wrapping meta data */
            newkeysalthex,
            ITERS,
            newpobjauthhex,

            /* new seal object auth metadata */
            newsalthex,
            ITERS,

            /* private and public blobs */
            newprivblob,
            NULL);
    if (rv != CKR_OK) {
        goto out;
    }

    /* TODO: consider calling unload on old seal object handle and WARN on failure */

    /*
     * step 6 - update in-memory metadata for seal object and primary object
     */
    change_token_mem_data(tok, is_so, new_seal_handle, newkeysalthex, newpobjauthhex, newsalthex, newprivblob, NULL);

    rv = CKR_OK;

out:

    /* If the function failed, then these pointers ARE NOT CLAIMED and must be free'd */
    if (rv != CKR_OK) {
        twist_free(newkeysalthex);
        twist_free(newpobjauthhex);
        twist_free(newsalthex);
        twist_free(newprivblob);
    }

    twist_free(oldpobjauthhex);

    twist_free(newauthbin);
    twist_free(newauthhex);

    twist_free(toldpin);
    twist_free(tnewpin);

    return rv;
}

CK_RV token_initpin(token *tok, CK_UTF8CHAR_PTR newpin, CK_ULONG newlen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    twist tnewpin = NULL;

    twist newkeysalthex = NULL;
    twist newpobjauthhex = NULL;

    twist newsalthex = NULL;
    twist newauthhex = NULL;
    twist newauthbin = NULL;

    twist sealdata = NULL;

    twist newpubblob = NULL;
    twist newprivblob = NULL;

    tnewpin = twistbin_new(newpin, newlen);
    if (!tnewpin) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    /* Generate a new key to wrap the primary object data with based on new pin */
    rv = setup_new_pobjwrapping_data(&tok->pobject, tnewpin, &newkeysalthex, &newpobjauthhex);
    if (rv != CKR_OK) {
        goto out;
    }

    /* generate a new auth */
    rv = setup_new_object_auth(tnewpin, &newauthbin, &newauthhex, &newsalthex);
    if (rv != CKR_OK) {
        goto out;
    }

    /* we store the seal data in hex form, but it's in binary form in memory, so convert it */
    sealdata = twist_hexlify(tok->wrappingobject.objauth);
    if (!sealdata) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    /* create a new seal object and seal the data */
    uint32_t new_seal_handle = 0;
    rv = tpm2_create_seal_obj(tok->tctx,
            tok->pobject.objauth, tok->pobject.handle,
            newauthbin, tok->sealobject.userpub,
            sealdata,
            &newpubblob, &newprivblob, &new_seal_handle);
    if (rv != CKR_OK) {
        goto out;
    }

    /* update the db data */
    rv = db_update_for_pinchange(
            tok,
            false,
            /* primary object wrapping meta data */
            newkeysalthex,
            ITERS,
            newpobjauthhex,

            /* new seal object auth metadata */
            newsalthex,
            ITERS,

            /* private and public blobs */
            newprivblob,
            newpubblob);
    if (rv != CKR_OK) {
        goto out;
    }

     /* update in-memory metadata for seal object and primary object */
    change_token_mem_data(tok, false, new_seal_handle, newkeysalthex, newpobjauthhex, newsalthex, newprivblob, newpubblob);

    rv = CKR_OK;

out:

    /* If the function failed, then these pointers ARE NOT CLAIMED and must be free'd */
    if (rv != CKR_OK) {
        twist_free(newkeysalthex);
        twist_free(newpobjauthhex);
        twist_free(newsalthex);
        twist_free(newprivblob);
        twist_free(newpubblob);
    }

    twist_free(newauthbin);
    twist_free(newauthhex);
    twist_free(sealdata);

    twist_free(tnewpin);

    return rv;
}

