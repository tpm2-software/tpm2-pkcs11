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

    /*
     * Up to two operations, when they are one of the pairs dual_pair() names; a free slot has
     * operation_none. The slots are kept in the order the operations started: opdata[0] is the
     * older, and opdata[1] is busy only if opdata[0] is.
     */
    generic_opdata opdata[2];

    opdata_free_fn free[2];
};

void session_ctx_free(session_ctx *ctx) {

    if (!ctx) {
        return;
    }

    /* clearing the older slot moves the newer one into it */
    while (ctx->opdata[0].op != operation_none) {
        session_ctx_opdata_clear(ctx, ctx->opdata[0].op);
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

/* The slot holding op, or NULL. */
static generic_opdata *opdata_slot(session_ctx *ctx, operation op) {

    size_t i;
    for (i = 0; i < ARRAY_LEN(ctx->opdata); i++) {
        if (ctx->opdata[i].op == op) {
            return &ctx->opdata[i];
        }
    }

    return NULL;
}

CK_RV _session_ctx_opdata_get(session_ctx *ctx, operation op, void **data) {

    generic_opdata *slot = op != operation_none ? opdata_slot(ctx, op) : NULL;
    if (!slot) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    *data = slot->data;

    return CKR_OK;
}

bool session_ctx_opdata_is_active(session_ctx *ctx) {

    return ctx->opdata[0].op != operation_none
            || ctx->opdata[1].op != operation_none;
}

/*
 * Whether a and b may be active together in a session: the four pairs of UG32 4.1, digest and
 * encrypt, decrypt and digest, sign and encrypt, decrypt and verify. Verify is C_VerifyInit's alone,
 * not verify-recover's or C_VerifySignatureInit's.
 */
static bool dual_pair(operation a, operation b) {

    static const operation pairs[][2] = {
        { operation_digest,  operation_encrypt },
        { operation_decrypt, operation_digest  },
        { operation_sign,    operation_encrypt },
        { operation_decrypt, operation_verify  },
    };

    size_t i;
    for (i = 0; i < ARRAY_LEN(pairs); i++) {
        if ((pairs[i][0] == a && pairs[i][1] == b)
                || (pairs[i][0] == b && pairs[i][1] == a)) {
            return true;
        }
    }

    return false;
}

CK_RV session_ctx_opdata_can_start(session_ctx *ctx, operation op) {

    operation a = ctx->opdata[0].op;
    operation b = ctx->opdata[1].op;

    if (a == operation_none && b == operation_none) {
        return CKR_OK;
    }

    /* one slot busy, with op's partner */
    if (a == operation_none || b == operation_none) {
        operation busy = a != operation_none ? a : b;
        if (dual_pair(busy, op)) {
            return CKR_OK;
        }
    }

    return CKR_OPERATION_ACTIVE;
}

void session_ctx_opdata_set(session_ctx *ctx, operation op, tobject *tobj, void *data, opdata_free_fn fn) {

    assert(op != operation_none);
    assert(session_ctx_opdata_can_start(ctx, op) == CKR_OK);

    generic_opdata *slot = opdata_slot(ctx, operation_none);
    assert(slot);
    if (!slot) {
        return;
    }

    size_t i = slot - ctx->opdata;

    slot->op = op;
    slot->tobj = tobj;
    slot->data = data;
    ctx->free[i] = fn;
}

void session_ctx_opdata_clear(session_ctx *ctx, operation op) {

    generic_opdata *slot = op != operation_none ? opdata_slot(ctx, op) : NULL;
    if (!slot) {
        return;
    }

    size_t i = slot - ctx->opdata;

    if (ctx->free[i] && slot->data) {
        ctx->free[i](&slot->data);
    }

    /* keep the slots in start order: the newer operation, if any, becomes the older */
    if (i == 0) {
        ctx->opdata[0] = ctx->opdata[1];
        ctx->free[0] = ctx->free[1];
        i = 1;
    }

    ctx->opdata[i].op = operation_none;
    ctx->opdata[i].tobj = NULL;
    ctx->opdata[i].data = NULL;
    ctx->free[i] = NULL;
}

/* The CK_MECHANISM_INFO flag C_SessionCancel names an operation by. */
CK_FLAGS session_ctx_operation_flag(operation op) {

    switch (op) {
    case operation_find:
        return CKF_FIND_OBJECTS;
    case operation_sign:
        return CKF_SIGN;
    case operation_verify:
    case operation_verify_signature:
        return CKF_VERIFY;
    case operation_verify_recover:
        return CKF_VERIFY_RECOVER;
    case operation_sign_recover:
        return CKF_SIGN_RECOVER;
    case operation_encrypt:
        return CKF_ENCRYPT;
    case operation_decrypt:
        return CKF_DECRYPT;
    case operation_digest:
        return CKF_DIGEST;
    case operation_message_sign:
        return CKF_MESSAGE_SIGN;
    case operation_message_verify:
        return CKF_MESSAGE_VERIFY;
    default:
        return 0;
    }
}

CK_RV session_ctx_cancel(session_ctx *ctx, CK_FLAGS flags) {

    CK_RV rv = CKR_OK;

    /* clearing a slot may move the other into it, so each pass looks again from the start */
    size_t i = 0;
    while (i < ARRAY_LEN(ctx->opdata)) {

        operation op = ctx->opdata[i].op;
        if (op == operation_none || !(session_ctx_operation_flag(op) & flags)) {
            i++;
            continue;
        }

        /* What ending the operation normally does: the key it loaded is released. */
        tobject *tobj = ctx->opdata[i].tobj;
        session_ctx_opdata_clear(ctx, op);
        if (!tobj) {
            continue;
        }

        tobj->is_authenticated = false;
        CK_RV tmp_rv = tobject_user_decrement(tobj);
        if (tmp_rv != CKR_OK && rv == CKR_OK) {
            rv = tmp_rv;
        }
    }

    return rv;
}

CK_RV session_ctx_get_validation_flags(session_ctx *ctx, CK_SESSION_VALIDATION_FLAGS_TYPE type,
        CK_FLAGS *flags) {

    UNUSED(ctx);
    check_pointer(flags);

    if (type != CKS_LAST_VALIDATION_OK) {
        return CKR_ARGUMENTS_BAD;
    }

    *flags = 0;
    return CKR_OK;
}

/* The operations S32 5.6.6 says a state is saved for: not find, recovery, nor message-based ones. */
static bool operation_is_saveable(operation op) {

    switch (op) {
    case operation_sign:
    case operation_verify:
    case operation_verify_signature:
    case operation_encrypt:
    case operation_decrypt:
    case operation_digest:
        return true;
    default:
        return false;
    }
}

CK_RV session_ctx_get_operation_state(session_ctx *ctx, CK_BYTE_PTR state, CK_ULONG_PTR state_len) {

    UNUSED(state);
    check_pointer(state_len);

    size_t i;
    for (i = 0; i < ARRAY_LEN(ctx->opdata); i++) {
        if (operation_is_saveable(ctx->opdata[i].op)) {
            /* the state is TPM objects and sessions, and OpenSSL contexts: none can leave */
            return CKR_STATE_UNSAVEABLE;
        }
    }

    return CKR_OPERATION_NOT_INITIALIZED;
}

CK_RV session_ctx_set_operation_state(session_ctx *ctx, CK_BYTE_PTR state, CK_ULONG state_len,
        CK_OBJECT_HANDLE encryption_key, CK_OBJECT_HANDLE authentication_key) {

    UNUSED(ctx);
    UNUSED(encryption_key);
    UNUSED(authentication_key);
    check_pointer(state);

    if (!state_len) {
        return CKR_ARGUMENTS_BAD;
    }

    /* C_GetOperationState never gives one out, so no state is one of this token's */
    return CKR_SAVED_STATE_INVALID;
}

CK_RV session_ctx_function_not_parallel(session_ctx *ctx) {

    UNUSED(ctx);
    return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV session_ctx_async_complete(session_ctx *ctx, CK_UTF8CHAR_PTR function_name,
        CK_ASYNC_DATA_PTR result) {

    UNUSED(ctx);
    UNUSED(result);
    check_pointer(function_name);

    return CKR_OPERATION_NOT_INITIALIZED;
}

CK_RV session_ctx_async_get_id(session_ctx *ctx, CK_UTF8CHAR_PTR function_name, CK_ULONG_PTR id) {

    UNUSED(ctx);
    check_pointer(function_name);
    check_pointer(id);

    return CKR_OPERATION_NOT_INITIALIZED;
}

CK_RV session_ctx_async_join(session_ctx *ctx, CK_UTF8CHAR_PTR function_name, CK_ULONG id,
        CK_BYTE_PTR data, CK_ULONG data_len) {

    UNUSED(ctx);
    UNUSED(id);
    UNUSED(data);
    UNUSED(data_len);
    check_pointer(function_name);

    /* no C_AsyncGetID ever gave an identifier */
    return CKR_SAVED_STATE_INVALID;
}

static bool is_user(CK_USER_TYPE user) {
    return user == CKU_USER || user == CKU_CONTEXT_SPECIFIC;
}

tobject *session_ctx_opdata_get_tobject(session_ctx *ctx, operation op) {

    generic_opdata *slot = op != operation_none ? opdata_slot(ctx, op) : NULL;
    return slot ? slot->tobj : NULL;
}

/* Whether the object has CKA_ALWAYS_AUTHENTICATE set. */
static bool tobject_always_authenticate(tobject *tobj) {

    CK_ATTRIBUTE_PTR p = attr_get_attribute_by_type(tobj->attrs, CKA_ALWAYS_AUTHENTICATE);
    if (!p) {
        return false;
    }

    assert(p->ulValueLen == sizeof(CK_BBOOL));
    CK_BBOOL *b = (CK_BBOOL *)p->pValue;
    assert(*b == CK_TRUE || *b == CK_FALSE);
    return *b == CK_TRUE;
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

        /* an operation with an object must be active */
        if (!ctx->opdata[0].tobj && !ctx->opdata[1].tobj) {
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
        /*
         * object use verified, for one key (PKCS#11 3.2 4.9: the login authenticates the active
         * key): that of the older operation whose CKA_ALWAYS_AUTHENTICATE key still waits for it.
         * A second such key, in the other operation, needs a login of its own. With none waiting,
         * the login succeeds and changes nothing.
         */
        size_t i;
        for (i = 0; i < ARRAY_LEN(ctx->opdata); i++) {
            tobject *tobj = ctx->opdata[i].tobj;
            if (tobj && tobject_always_authenticate(tobj) && !tobj->is_authenticated) {
                tobj->is_authenticated = true;
                break;
            }
        }
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

    /*
     * The cryptographic operations of the token end first (PKCS#11 3.2 5.6.10 lets them): their keys
     * are flushed below, so they would go on with a handle the TPM no longer has, holding the keys
     * meanwhile, and a context-specific login would outlive the user's. An object search uses no key
     * and goes on, as it always did.
     */
    token_cancel_all_operations(tok);

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

            /* Do not perform tpm_flushcontext when tpm_handle is 0 or the key is persistent. */
            if (tobj->tpm_esys_tr && !tobj->tpm_serialized_tr) {
                bool result = tpm_flushcontext(tpm, tobj->tpm_esys_tr);
                assert(result);
                UNUSED(result);
                tobj->tpm_esys_tr = 0;

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

CK_RV session_ctx_tobject_authenticated(session_ctx *ctx, operation op) {

    tobject *tobj = session_ctx_opdata_get_tobject(ctx, op);
    assert(tobj);

    if (tobject_always_authenticate(tobj) && !tobj->is_authenticated) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    return CKR_OK;
}

CK_RV session_ctx_login_user(session_ctx *ctx, CK_USER_TYPE user, CK_BYTE_PTR pin, CK_ULONG pinlen,
        CK_UTF8CHAR_PTR username, CK_ULONG username_len) {

    if (username_len && !username) {
        return CKR_ARGUMENTS_BAD;
    }

    /* A PIN only authenticates the token's one user or SO; a user name can't be checked against anything. */
    if (username_len) {
        LOGE("The token has no user names; use C_Login or C_LoginUser without one");
        return CKR_ARGUMENTS_BAD;
    }

    return session_ctx_login(ctx, user, pin, pinlen);
}
