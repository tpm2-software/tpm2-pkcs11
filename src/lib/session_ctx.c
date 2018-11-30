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
#include "session_table.h"
#include "token.h"
#include "tpm.h"
#include "twist.h"
#include "utils.h"

struct session_ctx {

    CK_FLAGS flags;
    CK_STATE state;
};

void session_ctx_free(session_ctx *ctx) {

    if (!ctx) {
        return;
    }

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
static void session_set_initial_state(session_ctx *ctx, token_login_state state, CK_FLAGS flags) {

    switch(state) {
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

CK_RV session_ctx_new(session_ctx **ctx, token_login_state state, CK_FLAGS flags) {

    session_ctx *s = calloc(1, sizeof(session_ctx));
    if (!s) {
        return CKR_HOST_MEMORY;
    }

    session_set_initial_state(s, state, flags);

    s->flags = flags;

    *ctx = s;

    return CKR_OK;
}

CK_STATE session_ctx_state_get(session_ctx *ctx) {
    return ctx->state;
}

CK_FLAGS session_ctx_flags_get(session_ctx *ctx) {
    return ctx->flags;
}

void session_ctx_login_event(session_ctx *ctx, CK_USER_TYPE usertype) {

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
}

void session_ctx_logout_event(session_ctx *ctx) {

    /*
     * Returns a session back to it's initial state.
     * See the comment block insession_ctx_login() for details
     */
    if (ctx->state == CKS_RW_SO_FUNCTIONS
            || ctx->state == CKS_RW_USER_FUNCTIONS) {
        ctx->state = CKS_RW_PUBLIC_SESSION;
    } else {
        ctx->state = CKS_RO_PUBLIC_SESSION;
    }
}

CK_RV unwrap_objauth(token *tok, tpm_ctx *tpm, wrappingobject *wobj, twist objauth, twist *unwrapped_auth) {

    twist unwrapped_raw;
    if (tok->config.sym_support) {
        twist objauthraw = twistbin_unhexlify(objauth);
        if (!objauthraw) {
            LOGE("unhexlify objauth failed: %u-%s", twist_len(objauth), objauth);
            return CKR_HOST_MEMORY;
        }

        bool result = tpm_decrypt_handle(tpm, wobj->handle, wobj->objauth, CKM_AES_NULL,
                NULL, objauthraw, &unwrapped_raw, NULL);
        if (!result) {
            LOGE("tpm_decrypt_handle failed");
            twist_free(objauthraw);
            return CKR_GENERAL_ERROR;
        }
    } else {
        twist swkey = twistbin_unhexlify(wobj->objauth);
        if (!swkey) {
            return CKR_GENERAL_ERROR;
        }
        unwrapped_raw = aes256_gcm_decrypt(swkey, objauth);
        twist_free(swkey);
        if (!unwrapped_raw) {
            return CKR_GENERAL_ERROR;
        }
    }

    twist objauth_unwrapped = twistbin_unhexlify(unwrapped_raw);
    twist_free(unwrapped_raw);
    if (!objauth_unwrapped) {
        LOGE("unhexlify failed");
        return CKR_HOST_MEMORY;
    }

    *unwrapped_auth = objauth_unwrapped;

    return CKR_OK;
}

CK_RV token_load_object(token *tok, CK_OBJECT_HANDLE key, tobject **loaded_tobj) {

    tpm_ctx *tpm = tok->tctx;

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
