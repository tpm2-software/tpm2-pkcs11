/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "mutex.h"
#include "pkcs11.h"
#include "session_ctx.h"
#include "tpm.h"
#include "twist.h"
#include "utils.h"

struct session_ctx {
    tpm_ctx *ctx;
    token *tok;
    session_ctx_state state;
    void *mutex;
    void *opdata[operation_count];
};

void session_ctx_free(session_ctx *ctx) {

    if (ctx->mutex) {
        mutex_destroy(ctx->mutex);
    }

    tpm_ctx_free(ctx->ctx);

    free(ctx);
}

CK_RV session_ctx_new(session_ctx **ctx, token *tok, bool is_rw) {

    session_ctx *s = calloc(1, sizeof(session_ctx));
    if (!s) {
        return CKR_HOST_MEMORY;
    }

    CK_RV rv = mutex_create(&s->mutex);
    if (rv != CKR_OK) {
        session_ctx_free(s);
        return rv;
    }

    s->ctx = tpm_ctx_new();
    if (!s->ctx) {
        LOGE("Error initializing TPM");
        session_ctx_free(s);
        return CKR_GENERAL_ERROR;
    }

    s->tok = tok;
    s->state = is_rw ?
            session_ctx_state_user_rw : session_ctx_state_user_ro;
    *ctx = s;

    return CKR_OK;
}

void session_ctx_lock(session_ctx *ctx) {
    mutex_lock_fatal(ctx->mutex);
}

void session_ctx_unlock(session_ctx *ctx) {
    mutex_unlock_fatal(ctx->mutex);
}

void session_ctx_opdata_set(session_ctx *ctx, operation op, void *opdata) {
    ctx->opdata[op] = opdata;
}

void *session_ctx_opdata_get(session_ctx *ctx, operation op) {
    return ctx->opdata[op];
}

tpm_ctx *session_ctx_get_tpm_ctx(session_ctx *ctx) {
    return ctx->ctx;
}

token *session_ctx_get_token(session_ctx *ctx) {
    return ctx->tok;
}

session_ctx_state session_ctx_state_get(session_ctx *ctx) {
    return ctx->state;
}

bool session_ctx_is_user_logged_in(session_ctx *ctx) {

    return ctx->state & session_ctx_state_user_loggedin;
}

CK_RV session_ctx_logout(session_ctx *ctx) {

    if (!((ctx->state & session_ctx_state_user_loggedin)
            || (ctx->state &session_ctx_state_so_loggedin))) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);

    // Evict the keys
    token *tok = session_ctx_get_token(ctx);
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

                twist_free(tobj->objauth);
                tobj->objauth = NULL;

                tobj->handle = 0;
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
    pobject *pobj = &tok->pobject;
    bool result = tpm_flushcontext(tpm, sobj->handle);
    assert(result);
    UNUSED(result);

    twist_free(sobj->objauth);
    sobj->objauth = NULL;
    sobj->handle = 0;

    // Kill primary object auth data
    twist_free(pobj->objauth);
    pobj->objauth = NULL;

    // Kill off any private state data;
    // This may need to move to something to deal with possible nested data
    // types in the future.

    operation op;
    for (op = operation_find; op < operation_count; op++) {
        void *opdata = session_ctx_opdata_get(ctx, op);
        free(opdata);
    }

    // Turn down logged in flags.
    ctx->state &= ~(session_ctx_state_user_loggedin
            | session_ctx_state_so_loggedin);

    return CKR_OK;
}


CK_RV session_ctx_login(session_ctx *ctx, twist pin, int usertype) {

    twist sealobjauth = NULL;
    twist dpobjauth = NULL;

    CK_RV rv = CKR_GENERAL_ERROR;

    token *t = session_ctx_get_token(ctx);

    /*
     * To login, we need to use PIN against the correct seal object.
     * Load that seal object, and use tpm2_unseal to extract the
     * wrapping key auth. Also, load the wrapping key and secondary object.
     * Then on actual key operation, we can load the tertiary object.
     */

    session_ctx_state state = session_ctx_state_get(ctx);
    session_ctx_state loginstate = usertype == CKU_USER ?
            session_ctx_state_user_loggedin : session_ctx_state_so_loggedin;
    if (state & loginstate) {
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    /* derive the primary object auth for loading the sealed and wrapping key up */
    unsigned pobjiters = usertype == CKU_USER ? t->userpobjauthkeyiters : t->sopobjauthkeyiters;
    twist pobjsalt = usertype == CKU_USER ? t->userpobjauthkeysalt : t->sopobjauthkeysalt;
    twist pobjauth = usertype == CKU_USER ? t->userpobjauth : t->sopobjauth;

    dpobjauth = decrypt(pin, pobjsalt, pobjiters, pobjauth);
    if (!dpobjauth) {
        return CKR_PIN_INCORRECT;
    }

    t->pobject.objauth = dpobjauth;

    tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);

    /* load seal object */
    sealobject *sealobj = &t->sealobject;
    twist sealpub = usertype == CKU_USER ? sealobj->userpub : sealobj->sopub;
    twist sealpriv = usertype == CKU_USER ? sealobj->userpriv : sealobj->sopriv;

    // TODO evict sealobjhandle
    uint32_t sealobjhandle;
    bool res = tpm_loadobj(tpm, t->pobject.handle, dpobjauth, sealpub, sealpriv, &sealobjhandle);
    if (!res) {
        goto error;
    }

    /* derive the sealed obj auth for use in tpm_unseal to get the wrapping key auth*/
    unsigned sealiters = usertype == CKU_USER ? sealobj->userauthiters : sealobj->soauthiters;
    twist sealsalt = usertype == CKU_USER ? sealobj->userauthsalt : sealobj->soauthsalt;
    sealobjauth = utils_pdkdf2_hmac_sha256_raw(pin, sealsalt, sealiters);
    if (!sealobjauth) {
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    wrappingobject *wobj = &t->wrappingobject;
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
    if (t->config.sym_support) {
        wobj->objauth = twistbin_unhexlify(wobjauth);
        twist_free(wobjauth);
        if (!wobj->objauth) {
            LOGE("Could not unhexlify wrapping object auth");
            goto error;
        }

        /* load the wrapping key */
        res = tpm_loadobj(tpm, t->pobject.handle, dpobjauth, wobj->pub, wobj->priv, &wobj->handle);
        if (!res) {
            goto error;
        }
    } else {
        wobj->objauth = wobjauth;
    }

    /* load the secondary object */
    sobject *sobj = &t->sobject;
    res = tpm_loadobj(tpm, t->pobject.handle, dpobjauth, sobj->pub, sobj->priv, &sobj->handle);
    if (!res) {
        goto error;
    }

    ctx->state |= loginstate;
    rv = CKR_OK;

error:

    twist_free(sealobjauth);

    return rv;
}

CK_RV unwrap_objauth(token *tok, tpm_ctx *tpm, wrappingobject *wobj, twist objauth, twist *unwrapped_auth) {

    twist tmp;
    if (tok->config.sym_support) {
        twist sobjauthraw = twistbin_unhexlify(objauth);
        if (!sobjauthraw) {
            LOGE("unhexlify objauth failed: %u-%s", twist_len(objauth), objauth);
            return CKR_HOST_MEMORY;
        }

        bool result = tpm_decrypt_handle(tpm, wobj->handle, wobj->objauth, CKM_AES_NULL,
                NULL, sobjauthraw, &tmp, NULL);
        if (!result) {
            LOGE("tpm_decrypt_handle failed");
            twist_free(sobjauthraw);
            return CKR_GENERAL_ERROR;
        }
    } else {
        twist swkey = twistbin_unhexlify(wobj->objauth);
        if (!swkey) {
            return CKR_GENERAL_ERROR;
        }
        tmp = aes256_gcm_decrypt(swkey, objauth);
        twist_free(swkey);
        if (!tmp) {
            return CKR_GENERAL_ERROR;
        }
    }

    twist sobjauthraw = twistbin_unhexlify(tmp);
    twist_free(tmp);
    if (!sobjauthraw) {
        LOGE("unhexlify failed");
        return CKR_HOST_MEMORY;
    }

    *unwrapped_auth = sobjauthraw;

    return CKR_OK;
}

CK_RV session_ctx_load_object(session_ctx *ctx, CK_OBJECT_HANDLE key, tobject **loaded_tobj) {

    token *tok = session_ctx_get_token(ctx);
    tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);

    if (!(ctx->state & session_ctx_state_user_loggedin)) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    if (!tok->tobjects) {
        return CKR_KEY_HANDLE_INVALID;
    }

    list *cur = &tok->tobjects->l;
    while(cur) {
        tobject *tobj = list_entry(cur, tobject, l);
        cur = cur->next;
        if (tobj->id != key) {
            continue;
        }

        // Already loaded, ignored.
        if (tobj->handle) {
            *loaded_tobj = tobj;
            return CKR_OK;
        }

        sobject *sobj = &tok->sobject;
        wrappingobject *wobj = &tok->wrappingobject;

        /*
         * Decrypt the secondary object auth value with either
         * the TPM wrapping key, or in the case of lack of TPM
         * support use Software.
         */
        twist sobjauthraw = NULL;
        CK_RV rv = unwrap_objauth(tok, tpm, wobj, sobj->objauth, &sobjauthraw);
        if (rv != CKR_OK) {
            LOGE("Error unwrapping secondary object auth");
            return rv;
        }

        bool result = tpm_loadobj(
                tpm,
                tok->sobject.handle, sobjauthraw,
                tobj->pub, tobj->priv,
                &tobj->handle);
        twist_free(sobjauthraw);
        if (!result) {
            return CKR_GENERAL_ERROR;
        }

        rv = unwrap_objauth(tok, tpm, wobj, tobj->objauth,
                &tobj->unsealed_auth);
        if (rv != CKR_OK) {
            LOGE("Error unwrapping tertiary object auth");
            return rv;
        }

        *loaded_tobj = tobj;
        return CKR_OK;
    }

    // Found no match on key id
    return CKR_KEY_HANDLE_INVALID;
}
