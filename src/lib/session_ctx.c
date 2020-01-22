/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "attrs.h"
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

    bool on_error_flush_session = false;

    twist sealobjauth = NULL;

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

    tpm_ctx *tpm = tok->tctx;

    /*
     * context specific logins require an active object
     * also the session state DOESN'T change, so we set
     * a flag that its a context specific login in the
     * session state for tracking so we can logout when
     * done and check state when an operation is occurring.
     *
     * XXX This can be refactored with the rest of this function
     * to not dup the code.
     */
    if (user == CKU_CONTEXT_SPECIFIC) {

        /* an object must be active */
        bool is_active = session_ctx_opdata_is_active(ctx);
        if (!is_active || !ctx->opdata.tobj) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }

        /* we've verified that we did a full login already, so just verify pin */
        sealobject *sealobj = &tok->sealobject;

        /* do NOT free salt, this is owned by tobject lifesycle */
        twist sealsalt = is_user(user) ? sealobj->userauthsalt : sealobj->soauthsalt;
        twist tpin = twistbin_new(pin, pinlen);
        sealobjauth = utils_hash_pass(tpin, sealsalt);
        twist_free(tpin);
        if (!sealobjauth) {
            return CKR_HOST_MEMORY;
        }

        twist wrappingkeyhex = tpm_unseal(tpm, sealobj->handle, sealobjauth);
        twist_free(sealobjauth);
        if (!wrappingkeyhex) {
            return CKR_PIN_INCORRECT;
        }
        twist_free(wrappingkeyhex);

        /* object use verified */
        ctx->opdata.tobj->is_authenticated = true;

        return CKR_OK;
    }


    CK_RV tmp = tpm_session_start(tok->tctx, tok->pobject.objauth, tok->pobject.handle);
    if (tmp != CKR_OK) {
        return tmp;
    }

    on_error_flush_session = true;

    /* load seal object */
    sealobject *sealobj = &tok->sealobject;
    twist sealpub = is_user(user) ? sealobj->userpub : sealobj->sopub;
    twist sealpriv = is_user(user) ? sealobj->userpriv : sealobj->sopriv;

    uint32_t pobj_handle = tok->pobject.handle;
    twist pobjauth = tok->pobject.objauth;

    bool res = tpm_loadobj(tpm, pobj_handle, pobjauth, sealpub, sealpriv, &sealobj->handle);
    if (!res) {
        goto error;
    }

    twist tpin = twistbin_new(pin, pinlen);
    if (!tpin) {
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    /* derive the sealed obj auth for use in tpm_unseal to get the wrapping key auth*/
    twist sealsalt = is_user(user) ? sealobj->userauthsalt : sealobj->soauthsalt;
    sealobjauth = utils_hash_pass(tpin, sealsalt);
    twist_free(tpin);
    if (!sealobjauth) {
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    twist wrappingkeyhex = tpm_unseal(tpm, sealobj->handle, sealobjauth);
    if (!wrappingkeyhex) {
        rv = CKR_PIN_INCORRECT;
        goto error;
    }

    tok->wappingkey = twistbin_unhexlify(wrappingkeyhex);
    twist_free(wrappingkeyhex);
    if (!tok->wappingkey) {
        LOGE("Expected internal wrapping key in base 16 format");
        goto error;
    }

    /*
     * Indicate that the token has been logged in. For CKU_CONTEXT_SPECIFIC the spec
     * states that on both cases (appears to be fail or success of C_Login) session
     * state does not change. This is because C_Login(USER) should have already occured
     * and is validated above.
     */
    if (user != CKU_CONTEXT_SPECIFIC) {
        tok->login_state = user == CKU_USER ? token_user_logged_in : token_so_logged_in;

        /*
         * State transition all *EXISTING* sessions in the table
         */
        session_table_login_event(tok->s_table, user);
    }

    on_error_flush_session = false;
    rv = CKR_OK;

error:

    if (on_error_flush_session) {
        tpm_session_stop(tok->tctx);
    }

    twist_free(sealobjauth);

    return rv;
}

CK_RV session_ctx_logout(session_ctx *ctx) {

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    bool is_anyone_logged_in = token_is_any_user_logged_in(tok);
    if (!is_anyone_logged_in) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    /* clear the wrapping key */
    assert(tok->wappingkey);
    twist_free(tok->wappingkey);
    tok->wappingkey = NULL;

    /*
     * Ok now start evicting TPM objects from the right
     * context
     */
    tpm_ctx *tpm = tok->tctx;

    // Evict the keys
    if (tok->tobjects.head) {

        list *cur = &tok->tobjects.head->l;
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

    /* evict the seal object */
    bool result = tpm_flushcontext(tpm, tok->sealobject.handle);
    if (!result) {
        LOGW("Could not evict the seal object");
        assert(0);
    }
    tok->sealobject.handle = 0;

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
