/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include "config.h"
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

    token *tok;

    generic_opdata opdata;

    opdata_free_fn free;
};

void session_ctx_free(session_ctx *ctx) {

    if (!ctx) {
        return;
    }

    session_ctx_opdata_clear(ctx);

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

CK_RV session_ctx_new(session_ctx **ctx, token *tok, CK_FLAGS flags) {

    session_ctx *s = calloc(1, sizeof(session_ctx));
    if (!s) {
        return CKR_HOST_MEMORY;
    }

    session_set_initial_state(s, tok->login_state, flags);

    s->flags = flags;
    s->tok = tok;

    *ctx = s;

    return CKR_OK;
}

CK_STATE session_ctx_state_get(session_ctx *ctx) {
    return ctx->state;
}

CK_FLAGS session_ctx_flags_get(session_ctx *ctx) {
    return ctx->flags;
}

token *session_ctx_get_token(session_ctx *ctx) {
    return ctx->tok;
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

        bool result = tpm_loadobj(
                tpm,
                tok->sobject.handle, sobj->authraw,
                tobj->pub, tobj->priv,
                &tobj->handle);
        if (!result) {
            return CKR_GENERAL_ERROR;
        }

        CK_RV rv = utils_ctx_unwrap_objauth(tok, tobj->objauth,
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

CK_RV _session_ctx_opdata_get(session_ctx *ctx, operation op, void **data) {

    if (op != ctx->opdata.op) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    *data = ctx->opdata.data;

    return CKR_OK;
}

bool session_ctx_opdata_is_active(session_ctx *ctx) {

    return ctx->opdata.op != operation_none;
}

void session_ctx_opdata_set(session_ctx *ctx, operation op, void *data, opdata_free_fn fn) {

    ctx->opdata.op = op;
    ctx->opdata.data = data;
    ctx->free = fn;
}

void session_ctx_opdata_clear(session_ctx *ctx) {

    if (ctx->free && ctx->opdata.data) {
        ctx->free(&ctx->opdata.data);
    }

    session_ctx_opdata_set(ctx, operation_none, NULL, NULL);
}
