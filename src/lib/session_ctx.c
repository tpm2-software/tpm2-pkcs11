/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "attrs.h"
#include "log.h"
#include "mutex.h"
#include "pkcs11.h"
#include "session_ctx.h"
#include "session_table.h"
#include "token.h"
#include "twist.h"
#include "utils.h"
#include "backend.h"

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

void session_ctx_opdata_set(session_ctx *ctx, operation op, tobject *tobj, void *data, opdata_free_fn fn) {

    ctx->opdata.op = op;
    ctx->opdata.tobj = tobj;
    ctx->opdata.data = data;
    ctx->free = fn;
}

void session_ctx_opdata_clear(session_ctx *ctx) {

    if (ctx->free && ctx->opdata.data) {
        ctx->free(&ctx->opdata.data);
    }

    session_ctx_opdata_set(ctx, operation_none, NULL, NULL, NULL);
}

void session_ctx_delete_tobject_list(session_ctx *ctx)
{
   token_delete_tobject_list(ctx->tok);
}

static bool is_user(CK_USER_TYPE user) {
    return user == CKU_USER || user == CKU_CONTEXT_SPECIFIC;
}

tobject *session_ctx_opdata_get_tobject(session_ctx *ctx) {
    return ctx->opdata.tobj;
}

CK_RV session_ctx_login(session_ctx *ctx, CK_USER_TYPE user, CK_BYTE_PTR pin, CK_ULONG pinlen) {

    if (user != CKU_SO
            && user != CKU_USER
            && user != CKU_CONTEXT_SPECIFIC) {
        return CKR_USER_TYPE_INVALID;
    }

    CK_RV rv = CKR_GENERAL_ERROR;

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    bool is_anyone_logged_in = token_is_any_user_logged_in(tok);
    if (is_anyone_logged_in) {
        /* context specific user login's require USER logged in */
        if (user != CKU_CONTEXT_SPECIFIC ||
                tok->login_state != token_user_logged_in) {
            return CKR_USER_ALREADY_LOGGED_IN;
        }
    } else if (user == CKU_CONTEXT_SPECIFIC) {
        /*
         * is this a valid assertion? Most flows I see have a C_Login(user) before
         * the context specific login...
         */
        return CKR_USER_NOT_LOGGED_IN;
    }

    CK_ULONG ro;
    session_table_get_cnt(tok->s_table, NULL, NULL, &ro);

    if (user == CKU_SO && ro) {
        return CKR_SESSION_READ_ONLY_EXISTS;
    }

    /* so pin will NOT be set */
    if (!tok->config.is_initialized) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    /*
     * context specific logins require an active object
     * also the session state DOESN'T change, so we set
     * a flag that its a context specific login in the
     * session state for tracking so we can logout when
     * done and check state when an operation is occurring.
     */
    if (user == CKU_CONTEXT_SPECIFIC) {

        /* an object must be active */
        bool is_active = session_ctx_opdata_is_active(ctx);
        if (!is_active || !ctx->opdata.tobj) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
    }

    twist tpin = twistbin_new(pin, pinlen);
    if (!tpin) {
        return CKR_HOST_MEMORY;
    }

    rv = backend_token_unseal_wrapping_key(tok, is_user(user), tpin);
    twist_free(tpin);
    if (rv != CKR_OK) {
        LOGE("Error unsealing wrapping key");
        return rv;
    }

    /*
     * Indicate that the token has been logged in. For CKU_CONTEXT_SPECIFIC the spec
     * states that on both cases (appears to be fail or success of C_Login) session
     * state does not change. This is because C_Login(USER) should have already occurred
     * and is validated above.
     */
    if (user == CKU_CONTEXT_SPECIFIC) {
        /* object use verified */
        ctx->opdata.tobj->is_authenticated = true;
    } else {
        tok->login_state = user == CKU_USER ? token_user_logged_in : token_so_logged_in;

        /*
         * State transition all *EXISTING* sessions in the table
         */
        session_table_login_event(tok->s_table, user);
    }

    return CKR_OK;
}

CK_RV session_ctx_logout(session_ctx *ctx) {

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    bool is_anyone_logged_in = token_is_any_user_logged_in(tok);
    if (!is_anyone_logged_in) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    /* clear the wrapping key */
    assert(tok->wrappingkey);

    /* cleanse the wrapping key */
    if (tok->wrappingkey) {
        OPENSSL_cleanse((void *)tok->wrappingkey, twist_len(tok->wrappingkey));
        twist_free(tok->wrappingkey);
        tok->wrappingkey = NULL;
    }

    /*
     * Ok now start evicting TPM objects from the right
     * context
     */
    tpm_ctx *tpm = tok->tctx;

    /*
     * For each object:
     *   - Evict the TPM Handles
     *   - Cleanse CKA_VALUE fields for private values.
     */
    if (tok->tobjects.head) {

        list *cur = &tok->tobjects.head->l;
        while(cur) {
            tobject *tobj = list_entry(cur, tobject, l);
            cur = cur->next;

            /* if it's CKA_PRIVATE == CK_TRUE and it has a CKA_VALUE field, clear it */
            CK_BBOOL cka_private = attr_list_get_CKA_PRIVATE(tobj->attrs, CK_FALSE);
            CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_VALUE);
            if (cka_private && a && a->pValue && a->ulValueLen) {
                attr_pfree_cleanse(a);
            }

            if (tobj->tpm_handle) {
                bool result = tpm_flushcontext(tpm, tobj->tpm_handle);
                assert(result);
                UNUSED(result);
                tobj->tpm_handle = 0;

                /* Clear the unwrapped auth value for tertiary objects */
                twist_free(tobj->unsealed_auth);
                tobj->unsealed_auth = NULL;
            }
        }
    }

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

CK_RV session_ctx_get_info(session_ctx *ctx, CK_SESSION_INFO *info) {

    check_pointer(info);

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    info->flags = session_ctx_flags_get(ctx);

    info->slotID = tok->id;

    info->state = session_ctx_state_get(ctx);

    // We'll need to set this state error at some point, perhaps TSS2_RC's
    info->ulDeviceError = 0;

    return CKR_OK;
}

CK_RV session_ctx_tobject_authenticated(session_ctx *ctx) {

    tobject *tobj = session_ctx_opdata_get_tobject(ctx);
    assert(tobj);

    CK_ATTRIBUTE_PTR p = attr_get_attribute_by_type(tobj->attrs, CKA_ALWAYS_AUTHENTICATE);
    bool has_always_auth = false;
    if (p) {
        assert(p->ulValueLen == sizeof(CK_BBOOL));
        CK_BBOOL *b = (CK_BBOOL *)p->pValue;
        assert(*b == CK_TRUE || *b == CK_FALSE);
        has_always_auth = *b == CK_TRUE;
    }

    if(has_always_auth && !tobj->is_authenticated) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    return CKR_OK;
}
