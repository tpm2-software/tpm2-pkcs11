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
#include "token.h"
#include "tpm.h"
#include "twist.h"
#include "utils.h"

struct session_ctx {

    /*
     * Switching the backend to esapi means we need to
     * register the primary objects persistent handle
     * on every ESAPI context created, so we need to
     * track per-session if we registered it, and what
     * the value it.
     */
    struct {
        bool is_registered;
        uint32_t registered_handle;
    } pobj_handle;

    tpm_ctx *ctx;
    token *tok;
    CK_FLAGS flags;
    CK_STATE state;
    void *mutex;
    void *opdata[operation_count];
};

void session_ctx_free(session_ctx *ctx) {

    if (!ctx) {
        return;
    }

    if (ctx->mutex) {
        mutex_destroy(ctx->mutex);
    }

    tpm_ctx_free(ctx->ctx);

    free(ctx);
}

/**
 * Sets the initial state of the a session context based on the tokens login state
 * and the flags present. Does no error checking.
 * @param ctx
 *  The session ctx to set
 * @param tok
 *  The token state to check
 * @param flags
 *  The session flags.
 */
static void session_set_initial_state(session_ctx *ctx, token *tok, CK_FLAGS flags) {

    switch(tok->login_state) {
    case token_no_one_logged_in:
        ctx->state = flags & CKF_RW_SESSION ?
                CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
        break;
    case token_user_logged_in:
        ctx->state = flags & CKF_RW_SESSION ?
                CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
        break;
    case token_so_logged_in:
        assert(flags & CKF_RW_SESSION);
        ctx->state = CKS_RW_SO_FUNCTIONS;
        break;
        /* no default */
    }
}

CK_RV session_ctx_new(session_ctx **ctx, token *tok, CK_FLAGS flags) {

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

    session_set_initial_state(s, tok, flags);

    s->tok = tok;

    s->flags = flags;

    *ctx = s;

    return CKR_OK;
}

void *_session_ctx_get_lock(session_ctx *ctx) {
    return ctx->mutex;
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

token *session_ctx_get_tok(session_ctx *ctx) {
    return ctx->tok;
}

CK_STATE session_ctx_state_get(session_ctx *ctx) {
    return ctx->state;
}

CK_FLAGS session_ctx_flags_get(session_ctx *ctx) {
    return ctx->flags;
}


bool session_ctx_is_user_logged_in(session_ctx *ctx) {

    return ctx->tok->login_state == token_user_logged_in;
}

static bool is_any_user_logged_in(session_ctx *ctx) {

    return ctx->tok->login_state != token_no_one_logged_in;
}

CK_RV session_ctx_token_logout(session_ctx *ctx) {

    CK_RV rv = CKR_GENERAL_ERROR;

    bool is_anyone_logged_in = is_any_user_logged_in(ctx);
    if (!is_anyone_logged_in) {
        rv = CKR_USER_NOT_LOGGED_IN;
        goto out;
    }

    /*
     * Use the cached session_ctx that called
     * C_Login() as it needs to unregister TPM
     * objects, as C_Login/C_Logout can be called
     * across sessions.
     *
     * Note that when swapping out you need to lock the
     * new session ctx, and unlock the old one.
     */
    token *tok = session_ctx_get_tok(ctx);

    assert(tok->login_session_ctx);

    if (tok->login_session_ctx != ctx) {
        session_ctx_lock(tok->login_session_ctx);
        session_ctx_unlock(ctx);
        ctx = tok->login_session_ctx;
    }

    /*
     * Ok now start evicting TPM objects from the right
     * context
     */
    tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);

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
    bool result = tpm_flushcontext(tpm, sobj->handle);
    assert(result);
    UNUSED(result);

    twist_free(sobj->objauth);
    sobj->objauth = NULL;
    sobj->handle = 0;

    // Kill primary object auth data
    pobject *pobj = &tok->pobject;
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

    /*
     * Clear the cached login session ctx
     */
    tok->login_session_ctx = NULL;

    /*
     * State transition all sessions in the table
     */
    session_table_logout_event(tok->s_table, ctx);

    /*
     * mark no one logged in
     */
    ctx->tok->login_state = token_no_one_logged_in;

    rv = CKR_OK;

out:
    session_ctx_unlock(ctx);

    return rv;
}

void session_ctx_login_event(session_ctx *ctx, CK_USER_TYPE usertype, bool take_lock) {

    /*
     * S/O REQUIRES a R/W start state and transitions
     * to CKS_RW_SO_FUNCTIONS
     *
     * Users can start in a RO or RW PUBLIC Session and transition
     * on that to either RO or RW USER FUNCTION state
     *
     * See Section 5 of:
     *  - https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11.pdf
     */
    if (take_lock) {
        session_ctx_lock(ctx);
    }

    if (usertype == CKU_SO) {
        assert(ctx->state == CKS_RW_PUBLIC_SESSION);
        ctx->state = CKS_RW_SO_FUNCTIONS;
    } else {
        assert(ctx->state == CKS_RO_PUBLIC_SESSION
                || ctx->state == CKS_RW_PUBLIC_SESSION);

        if (ctx->state == CKS_RO_PUBLIC_SESSION) {
            ctx->state = CKS_RO_USER_FUNCTIONS;
        } else {
            ctx->state = CKS_RW_USER_FUNCTIONS;
        }
    }

    if (take_lock) {
        session_ctx_unlock(ctx);
    }
}

void session_ctx_logout_event(session_ctx *ctx, bool take_lock) {

    /*
     * Returns a session back to it's initial state.
     * See the comment block insession_ctx_login() for details
     */
    if (take_lock) {
        session_ctx_lock(ctx);
    }

    if (ctx->state == CKS_RW_SO_FUNCTIONS
            || ctx->state == CKS_RW_USER_FUNCTIONS) {
        ctx->state = CKS_RW_PUBLIC_SESSION;
    } else {
        ctx->state = CKS_RO_PUBLIC_SESSION;
    }

    if (take_lock) {
        session_ctx_unlock(ctx);
    }
}

CK_RV session_ctx_token_login(session_ctx *ctx, twist pin, CK_USER_TYPE user) {

    twist sealobjauth = NULL;
    twist dpobjauth = NULL;

    CK_RV rv = CKR_GENERAL_ERROR;

    bool is_anyone_logged_in = is_any_user_logged_in(ctx);
    if (is_anyone_logged_in) {
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    token *t = session_ctx_get_tok(ctx);

    assert(t->login_session_ctx == NULL);

    unsigned long ro;
    session_table_get_cnt(t->s_table, NULL, NULL, &ro);

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
    unsigned pobjiters = user == CKU_USER ? t->userpobjauthkeyiters : t->sopobjauthkeyiters;
    twist pobjsalt = user == CKU_USER ? t->userpobjauthkeysalt : t->sopobjauthkeysalt;
    twist pobjauth = user == CKU_USER ? t->userpobjauth : t->sopobjauth;

    dpobjauth = decrypt(pin, pobjsalt, pobjiters, pobjauth);
    if (!dpobjauth) {
        return CKR_PIN_INCORRECT;
    }

    t->pobject.objauth = dpobjauth;

    tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);

    if (!ctx->pobj_handle.is_registered) {
        ctx->pobj_handle.registered_handle = t->pobject.handle;
        bool res = tpm_register_handle(tpm, &ctx->pobj_handle.registered_handle);
        if (!res) {
            goto error;
        }
        ctx->pobj_handle.is_registered = true;
    }

    /* load seal object */
    sealobject *sealobj = &t->sealobject;
    twist sealpub = user == CKU_USER ? sealobj->userpub : sealobj->sopub;
    twist sealpriv = user == CKU_USER ? sealobj->userpriv : sealobj->sopriv;

    uint32_t pobj_handle = ctx->pobj_handle.registered_handle;

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
        res = tpm_loadobj(tpm, pobj_handle, dpobjauth, wobj->pub, wobj->priv, &wobj->handle);
        if (!res) {
            goto error;
        }
    } else {
        wobj->objauth = wobjauth;
    }

    /* load the secondary object */
    sobject *sobj = &t->sobject;
    res = tpm_loadobj(tpm, pobj_handle, dpobjauth, sobj->pub, sobj->priv, &sobj->handle);
    if (!res) {
        goto error;
    }

    /*
     * Indicate that the token has been logged in
     */
    t->login_state = user == CKU_USER ? token_user_logged_in : token_so_logged_in;

    /*
     * Cache the login session
     */
    t->login_session_ctx = ctx;

    /*
     * State transition all *EXISTING* sessions in the table
     */
    session_table_login_event(t->s_table, user, ctx);

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

    token *tok = session_ctx_get_tok(ctx);
    tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);

    bool is_user_logged_in = session_ctx_is_user_logged_in(ctx);
    if (!is_user_logged_in) {
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
