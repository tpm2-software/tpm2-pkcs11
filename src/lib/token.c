/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "attrs.h"
#include "checks.h"
#include "db.h"
#include "list.h"
#include "object.h"
#include "pkcs11.h"
#include "session.h"
#include "session_table.h"
#include "slot.h"
#include "tpm.h"
#include "token.h"
#include "utils.h"

CK_RV token_min_init(token *t) {
    /*
     * Initialize the per-token session table
     */
    CK_RV rv = session_table_new(&t->s_table);
    if (rv != CKR_OK) {
        LOGE("Could not initialize session table");
        return rv;
    }

    /*
     * Initialize the per-token tpm context
     */
    rv = tpm_ctx_new(t->config.tcti, &t->tctx);
    if (rv != CKR_OK) {
        LOGE("Could not initialize tpm ctx: 0x%lx", rv);
        return rv;
    }

    rv = mutex_create(&t->mutex);
    if (rv != CKR_OK) {
        LOGE("Could not initialize mutex: 0x%lx", rv);
    }

    return rv;
}

void token_free_list(token *t, size_t len) {

    size_t i;
    for (i=0; i < len; i++) {
        token_free(&t[i]);
    }
    free(t);
}

CK_RV token_add_tobject_last(token *tok, tobject *t) {

    if (!tok->tobjects.tail) {
        t->l.prev = t->l.next = NULL;
        tok->tobjects.tail = tok->tobjects.head = t;
        t->obj_handle = 1;
        return CKR_OK;
    }

    CK_OBJECT_HANDLE handle = tok->tobjects.tail->obj_handle;
    if (handle == ~((CK_OBJECT_HANDLE)0)) {
        LOGE("Too many objects for token, id: %u, label: %*s", tok->id,
                (int)sizeof(tok->label), tok->label);
        return CKR_OK;
    }

    handle++;
    t->obj_handle = handle;
    tok->tobjects.tail->l.next = &t->l;
    t->l.prev = &tok->tobjects.tail->l;
    tok->tobjects.tail = t;
    return CKR_OK;
}

CK_RV token_add_tobject(token *tok, tobject *t) {

    if (!tok->tobjects.head) {
        t->l.prev = t->l.next = NULL;
        tok->tobjects.tail = tok->tobjects.head = t;
        t->obj_handle = 1;
        return CKR_OK;
    }

    /* minimum potential handle to add */
    CK_OBJECT_HANDLE index = 2;

    list *cur = &tok->tobjects.head->l;
    while(cur) {

        if (index == 0) {
            LOGE("Rollover, too many objects for token, id: %u, label: %*s", tok->id,
                    (int)sizeof(tok->label), tok->label);
            return CKR_OK;
        }

        tobject *c = list_entry(cur, tobject, l);

        /* end of list, just add it updating the tail pointer */
        if (!c->l.next) {
            t->obj_handle = index;
            t->l.prev = cur;
            cur->next = &t->l;
            tok->tobjects.tail = t;
            return CKR_OK;
        }

        tobject *n = list_entry(c->l.next, tobject, l);

        /* gap */
        if (n->obj_handle - c->obj_handle > 1) {
            assert(index < n->obj_handle && index > c->obj_handle);
            t->obj_handle = index;

            /* new object should point to next and previous */
            t->l.next = &n->l;
            t->l.prev = cur;

            /* existing object ahead should point back at new object */
            n->l.prev = &t->l;

            /* existing object behind should point forward at new object */
            c->l.next = &t->l;

            return CKR_OK;
        }

        index++;
        cur = cur->next;
    }

    LOGE("Could not insert tobject into token");

    return CKR_GENERAL_ERROR;
}

CK_RV token_find_tobject(token *tok, CK_OBJECT_HANDLE handle, tobject **tobj) {
    assert(tok);
    assert(tobj);

    if (!tok->tobjects.head) {
        return CKR_KEY_HANDLE_INVALID;
    }

    list *cur = &tok->tobjects.head->l;
    while(cur) {
        tobject *c = list_entry(cur, tobject, l);
        if (c->obj_handle == handle) {
            *tobj = c;
            return CKR_OK;
        }
        cur = cur->next;
    }

    return CKR_KEY_HANDLE_INVALID;
}

void token_rm_tobject(token *tok, tobject *t) {

    assert(tok->tobjects.head);
    assert(tok->tobjects.tail);

    if (t == tok->tobjects.head) {
        tok->tobjects.head = list_entry(tok->tobjects.head->l.next, tobject, l);
    } else if (t == tok->tobjects.tail) {
        /*
         * remove the tail by setting the tail equal to the previous list object
         * and setting the new tails next pointer to null as it's pointing to the
         * old tail location.
         */
        tok->tobjects.tail = list_entry(tok->tobjects.tail->l.prev, tobject, l);
        tok->tobjects.tail->l.next = NULL;
    } else {
        /*
         * the previous objects next pointer should point past
         * the removed object by pointing to it's next
         */
        t->l.prev->next = t->l.next;
        t->l.next->prev = t->l.prev;
    }

    t->l.next = t->l.prev = NULL;
}

static void sealobject_free(sealobject *sealobj) {
    twist_free(sealobj->soauthsalt);
    twist_free(sealobj->sopriv);
    twist_free(sealobj->sopub);
    twist_free(sealobj->userauthsalt);
    twist_free(sealobj->userpub);
    twist_free(sealobj->userpriv);
    sealobj->soauthsalt = NULL;
    sealobj->sopriv = NULL;
    sealobj->sopub = NULL;
    sealobj->userauthsalt = NULL;
    sealobj->userpub = NULL;
    sealobj->userpriv = NULL;
}

void token_free(token *t) {

    /*
     * for each session remove them
     */
    session_table_free_ctx_all(t);
    session_table_free(t->s_table);
    t->s_table = NULL;

    twist_free(t->pobject.objauth);
    t->pobject.objauth = NULL;

    sealobject_free(&t->sealobject);

    if (t->tobjects.head) {
        list *cur = &t->tobjects.head->l;
        while(cur) {
            tobject *tobj = list_entry(cur, tobject, l);
            cur = cur->next;
            tobject_free(tobj);
        }
    }
    t->tobjects.head = t->tobjects.tail = NULL;

    tpm_ctx_free(t->tctx);
    t->tctx = NULL;

    mutex_destroy(t->mutex);
    t->mutex = NULL;

    free(t->config.tcti);
    t->config.tcti = NULL;
}

CK_RV token_get_info (token *t, CK_TOKEN_INFO *info) {
    check_pointer(t);
    check_pointer(info);

    int rval;
    time_t rawtime;
    struct tm tminfo;

    memset(info, 0, sizeof(*info));

    rval = tpm_get_token_info(t->tctx, info);
    if (rval != CKR_OK) {
        return CKR_GENERAL_ERROR;
    }

    // Support Flags
    info->flags = CKF_RNG
        | CKF_LOGIN_REQUIRED;

    if (t->config.is_initialized) {
        info->flags |= CKF_TOKEN_INITIALIZED;
        info->flags |= CKF_USER_PIN_INITIALIZED;
    }

    // Identification
    str_padded_copy(info->label, t->label, sizeof(info->label));
    str_padded_copy(info->serialNumber, (unsigned char*) TPM2_TOKEN_SERIAL_NUMBER, sizeof(info->serialNumber));


    // Memory: TODO not sure what memory values should go here, the platform?
    info->ulFreePrivateMemory = ~0;
    info->ulFreePublicMemory = ~0;
    info->ulTotalPrivateMemory = ~0;
    info->ulTotalPublicMemory = ~0;

    // Maximums and Minimums
    info->ulMaxPinLen = 128;
    info->ulMinPinLen = 0;
    info->ulMaxSessionCount = MAX_NUM_OF_SESSIONS;
    info->ulMaxRwSessionCount = MAX_NUM_OF_SESSIONS;

    // Session
    session_table_get_cnt(t->s_table, &info->ulSessionCount, &info->ulRwSessionCount, NULL);

    // Time
    time (&rawtime);
    gmtime_r(&rawtime, &tminfo);
    strftime ((char *)info->utcTime, sizeof(info->utcTime), "%Y%m%d%H%M%S", &tminfo);
    // The last two bytes must be '0', not NULL/'\0' terminated.
    info->utcTime[14] = '0';
    info->utcTime[15] = '0';

    return CKR_OK;
}

CK_RV get_or_create_primary(token *t) {

    twist blob = NULL;

    /* if there is no primary object ... */
    if (t->pid) {
        return CKR_OK;
    }

    /* is there one in the db to use ? */
    CK_RV rv = db_get_first_pid(&t->pid);
    if (rv != CKR_OK) {
        return rv;
    }

    /* if so use it */
    if (t->pid) {
        /* tokens in the DB store already have an associated primary object */
        return db_init_pobject(t->pid, &t->pobject, t->tctx);
    }

    /* is their a PC client spec key ? */
    rv = tpm_get_existing_primary(t->tctx, &t->pobject.handle, &blob);
    if (rv != CKR_OK) {
        return rv;
    }

    /* nothing, create one */
    if (!t->pobject.handle) {
        rv = tpm_create_primary(t->tctx, &t->pobject.handle, &blob);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    assert(t->pobject.handle);

    rv = db_add_primary(blob, &t->pid);
    assert(t->pid);
    twist_free(blob);
    return rv;
}

CK_RV token_init(token *t, CK_BYTE_PTR pin, CK_ULONG pin_len, CK_BYTE_PTR label) {
    check_pointer(pin);
    check_pointer(label);

    CK_RV rv = CKR_GENERAL_ERROR;

    twist newauth = NULL;
    twist newsalthex = NULL;

    twist sopin = twistbin_new(pin, pin_len);
    if (!sopin) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    twist hexwrappingkey = utils_get_rand_hex_str(32);
    if (!sopin) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    /*
     * find or create a primary object and get the serialized blob
     * for it.
     */
    rv = get_or_create_primary(t);
    if (rv != CKR_OK) {
        LOGE("Could not find nor create a primary object");
        goto error;
    }

    rv = utils_setup_new_object_auth(sopin, &newauth, &newsalthex);
    if (rv != CKR_OK) {
        goto error;
    }

    /* we have a primary object, create the seal object underneath it */
    rv = tpm2_create_seal_obj(t->tctx, t->pobject.objauth, t->pobject.handle,
            newauth, NULL, hexwrappingkey, &t->sealobject.sopub,
            &t->sealobject.sopriv, &t->sealobject.handle);
    if (rv != CKR_OK) {
        LOGE("Could not create SO seal object");
        goto error;
    }

    t->sealobject.soauthsalt = newsalthex;
    newsalthex = NULL;

    memcpy(t->label, label, sizeof(t->label));

    /* TODO get TCTI config from ENV var and use throughout this process */
    t->config.is_initialized = true;

    rv = db_add_token(t);
    if (rv != CKR_OK) {
        LOGE("Could not add token to db");
        goto error;
    }

    assert(t->id);

    rv = slot_add_uninit_token();
    if (rv != CKR_OK) {
        LOGW("Could not add unitialized token");
    }

    rv =  CKR_OK;
out:
    twist_free(sopin);
    twist_free(newauth);
    twist_free(newsalthex);
    twist_free(hexwrappingkey);

    return rv;

error:
    token_free(t);
    token_min_init(t);
    t->config.is_initialized = false;
    goto out;
}

bool token_is_any_user_logged_in(token *tok) {

    return tok->login_state != token_no_one_logged_in;
}

bool token_is_user_logged_in(token *tok) {

    return tok->login_state & token_user_logged_in;
}

bool token_is_so_logged_in(token *tok) {

    return tok->login_state & token_so_logged_in;
}


void token_lock(token *t) {
    mutex_lock_fatal(t->mutex);
}

void token_unlock(token *t) {
    mutex_unlock_fatal(t->mutex);
}

static void change_token_mem_data(token *tok, bool is_so, uint32_t new_seal_handle,
        twist newsalthex, twist newprivblob, twist newpubblob) {

    tok->sealobject.handle = new_seal_handle;
    twist *authsalt;
    twist *priv;
    twist *pub;

    if (is_so) {
        authsalt = &tok->sealobject.soauthsalt;
        priv = &tok->sealobject.sopriv;
        pub = &tok->sealobject.sopub;
    } else {
        authsalt = &tok->sealobject.userauthsalt;
        priv = &tok->sealobject.userpriv;
        pub = &tok->sealobject.userpub;
    }

    twist_free(*authsalt);
    twist_free(*priv);

    *authsalt = newsalthex;
    *priv = newprivblob;

    if (newpubblob) {
        twist_free(*pub);
        *pub = newpubblob;
    }
}

CK_RV token_setpin(token *tok, CK_UTF8CHAR_PTR oldpin, CK_ULONG oldlen, CK_UTF8CHAR_PTR newpin, CK_ULONG newlen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    /* new seal auth data */
    twist newsalthex = NULL;
    twist newauthhex = NULL;

    twist newprivblob = NULL;

    /* pin data */
    twist toldpin = NULL;
    twist tnewpin = NULL;

    bool session_started = false;

    bool is_so = token_is_so_logged_in(tok);
    bool is_anyone_logged_in = token_is_any_user_logged_in(tok);

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
     * Step 1 - Generate a new sealing auth value derived from pin and salt
     *
     * This will be used to update the sealobjects table, the columns:
     *  - (so|user)authsalt  --> newsalt
     */
    rv = utils_setup_new_object_auth(tnewpin, &newauthhex, &newsalthex);
    if (rv != CKR_OK) {
        goto out;
    }

    /*
     * Step 2 - Generate the current auth value from oldpin
     */
    twist oldsalt = is_so ? tok->sealobject.soauthsalt : tok->sealobject.userauthsalt;

    twist oldauth = utils_hash_pass(toldpin, oldsalt);
    if (!oldauth) {
        goto out;
    }

    /* if no one is logged in, we need to start a session with the TPM */
    if (!is_anyone_logged_in) {
        rv = tpm_session_start(tok->tctx, tok->pobject.objauth, tok->pobject.handle);
        if (rv != CKR_OK) {
            LOGE("Could not start session with TPM");
            goto out;
        }
        session_started = true;

        assert(!tok->sealobject.handle);

        sealobject *sealobj = &tok->sealobject;

        twist sealpub = is_so ? sealobj->sopub : sealobj->userpub;
        twist sealpriv = is_so ? sealobj->sopriv : sealobj->userpriv;

        bool res = tpm_loadobj(tok->tctx, tok->pobject.handle, tok->pobject.objauth,
                sealpub, sealpriv, &sealobj->handle);
        if (!res) {
            rv = CKR_GENERAL_ERROR;
            goto out;
        }
    }

    /*
     * Step 3- Call tpm2_changeauth and get a new private object portion
     *
     * This private blob will update table sealobjects (user|so)priv
     */
    rv = tpm_changeauth(tok->tctx, tok->pobject.handle, tok->sealobject.handle,
            oldauth, newauthhex,
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

            /* new seal object auth metadata */
            newsalthex,

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
    change_token_mem_data(tok, is_so, new_seal_handle, newsalthex, newprivblob, NULL);

    rv = CKR_OK;

out:

    if (session_started) {
        rv = tpm_session_stop(tok->tctx);
        if (rv != CKR_OK) {
            LOGE("Could not stop session with TPM");
        }
        bool result = tpm_flushcontext(tok->tctx, tok->sealobject.handle);
        if (!result) {
            LOGW("Could not evict the seal object");
            assert(0);
            rv = CKR_GENERAL_ERROR;
        }
        tok->sealobject.handle = 0;
    }

    /* If the function failed, then these pointers ARE NOT CLAIMED and must be free'd */
    if (rv != CKR_OK) {
        twist_free(newsalthex);
        twist_free(newprivblob);
    }

    twist_free(newauthhex);

    twist_free(toldpin);
    twist_free(tnewpin);

    return rv;
}

CK_RV token_initpin(token *tok, CK_UTF8CHAR_PTR newpin, CK_ULONG newlen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    twist tnewpin = NULL;

    twist newkeysalthex = NULL;

    twist newsalthex = NULL;
    twist newauthhex = NULL;

    twist newpubblob = NULL;
    twist newprivblob = NULL;

    twist sealdata = NULL;

    tnewpin = twistbin_new(newpin, newlen);
    if (!tnewpin) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    /* generate a new auth */
    rv = utils_setup_new_object_auth(tnewpin, &newauthhex, &newsalthex);
    if (rv != CKR_OK) {
        goto out;
    }

    /* we store the seal data in hex form, but it's in binary form in memory, so convert it */
    sealdata = twist_hexlify(tok->wappingkey);
    if (!sealdata) {
        LOGE("oom");
        goto out;
    }

    /* create a new seal object and seal the data */
    uint32_t new_seal_handle = 0;

    rv = tpm2_create_seal_obj(tok->tctx,
            tok->pobject.objauth,
            tok->pobject.handle,
            newauthhex,
            tok->sealobject.userpub,
            sealdata,
            &newpubblob,
            &newprivblob,
            &new_seal_handle);
    if (rv != CKR_OK) {
        goto out;
    }

    /* update the db data */
    rv = db_update_for_pinchange(
            tok,
            false,
            /* new seal object auth metadata */
            newsalthex,

            /* private and public blobs */
            newprivblob,
            newpubblob);
    if (rv != CKR_OK) {
        goto out;
    }

     /* update in-memory metadata for seal object and primary object */
    change_token_mem_data(tok, false, new_seal_handle, newsalthex, newprivblob, newpubblob);

    rv = CKR_OK;

out:

    /* If the function failed, then these pointers ARE NOT CLAIMED and must be free'd */
    if (rv != CKR_OK) {
        twist_free(newkeysalthex);
        twist_free(newsalthex);
        twist_free(newprivblob);
        twist_free(newpubblob);
    }

    twist_free(sealdata);
    twist_free(newauthhex);

    twist_free(tnewpin);

    return rv;
}

CK_RV token_load_object(token *tok, CK_OBJECT_HANDLE key, tobject **loaded_tobj) {

    tpm_ctx *tpm = tok->tctx;

    CK_RV rv = token_find_tobject(tok, key, loaded_tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    tobject *tobj = *loaded_tobj;

    rv = tobject_user_increment(tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    /* this might not be the best place for this check */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_CLASS);
    if (!a) {
        LOGE("All objects expected to have CKA_CLASS, missing"
                " for tobj id: %u", tobj->id);
        return CKR_GENERAL_ERROR;
    }

    CK_OBJECT_CLASS v;
    rv = attr_CK_OBJECT_CLASS(a, &v);
    if (rv != CKR_OK) {
        return rv;
    }

    if (v != CKO_PRIVATE_KEY
            && v != CKO_PUBLIC_KEY
            && v != CKO_SECRET_KEY) {
        LOGE("Cannot use tobj id %u in a crypto operation", tobj->id);
        return CKR_KEY_HANDLE_INVALID;
    }

    /*
     * The object may already be loaded by the TPM or may just be
     * a public key object not-resident in the TPM.
     */
    if (tobj->tpm_handle || !tobj->pub) {
        *loaded_tobj = tobj;
        return CKR_OK;
    }

    bool result = tpm_loadobj(
            tpm,
            tok->pobject.handle, tok->pobject.objauth,
            tobj->pub, tobj->priv,
            &tobj->tpm_handle);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    rv = utils_ctx_unwrap_objauth(tok, tobj->objauth,
            &tobj->unsealed_auth);
    if (rv != CKR_OK) {
        LOGE("Error unwrapping tertiary object auth");
        return rv;
    }

    *loaded_tobj = tobj;
    return CKR_OK;
}
