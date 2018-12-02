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

    const unsigned char token_sn[]   = TPM2_TOKEN_SERIAL_NUMBER;
    const unsigned char token_manuf[]  = TPM2_TOKEN_MANUFACTURER;
    const unsigned char token_model[]  = TPM2_TOKEN_MODEL;
    const unsigned char token_hwver[2] = TPM2_SLOT_HW_VERSION;
    const unsigned char token_fwver[2] = TPM2_SLOT_FW_VERSION;
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

    return CKR_OK;
}

CK_RV token_login(token *tok, twist pin, CK_USER_TYPE user) {

    twist sealobjauth = NULL;
    twist dpobjauth = NULL;

    CK_RV rv = CKR_GENERAL_ERROR;

    bool is_anyone_logged_in = token_is_any_user_logged_in(tok);
    if (is_anyone_logged_in) {
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    unsigned long ro;
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

    tpm_ctx *tpm = tok->tctx;

    /* load seal object */
    sealobject *sealobj = &tok->sealobject;
    twist sealpub = user == CKU_USER ? sealobj->userpub : sealobj->sopub;
    twist sealpriv = user == CKU_USER ? sealobj->userpriv : sealobj->sopriv;

    uint32_t pobj_handle = tok->pobject.handle;

    // TODO evict sealobjhandle
    uint32_t sealobjhandle;
    bool res = tpm_loadobj(tpm, pobj_handle, dpobjauth, sealpub, sealpriv, &sealobjhandle);
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
    twist wobjauth = tpm_unseal(tpm, sealobjhandle, sealobjauth);
    if (!wobjauth) {
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

    rv = CKR_OK;

error:

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

