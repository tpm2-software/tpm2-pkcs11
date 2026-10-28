/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "checks.h"
#include "log.h"
#include "message.h"
#include "object.h"
#include "session_ctx.h"
#include "sign.h"
#include "token.h"

/*
 * The process C_MessageSignInit or C_MessageVerifyInit started. Its session slot holds the key, so a
 * C_Login(CKU_CONTEXT_SPECIFIC) authenticates it, and C_SessionCancel or closing the session
 * releases it.
 */
typedef struct message_opdata message_opdata;
struct message_opdata {
    /* the mechanism, its parameter copied: each message's state refers to it */
    CK_MECHANISM mech;
    /* the state of the message in progress, or ready for the next; NULL once one ended */
    sign_opdata *msg;
    /* C_*MessageBegin started the message, which the last C_*MessageNext ends */
    bool begun;
};

static void message_opdata_free(message_opdata **m) {

    if (!*m) {
        return;
    }

    if ((*m)->msg) {
        sign_opdata_free(&(*m)->msg);
    }

    free((*m)->mech.pParameter);
    free(*m);
    *m = NULL;
}

/* What a message of the process is: a signature for message signing, else a verification. */
static operation message_kind(operation op) {
    return op == operation_message_sign ? operation_sign : operation_verify;
}

static CK_RV message_init(operation op, session_ctx *ctx, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    check_pointer(mechanism);

    LOGV("mechanism: 0x%lx\n\thas_params: %s\n\tlen: %lu", mechanism->mechanism,
            mechanism->pParameter ? "yes" : "no", mechanism->ulParameterLen);

    /* pairs with nothing */
    CK_RV rv = session_ctx_opdata_can_start(ctx, op);
    if (rv != CKR_OK) {
        return rv;
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    /* From here on, a failure goes through error, which releases the key and what was made. */
    tobject *tobj = NULL;
    rv = token_load_object(tok, key, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    message_opdata *m = calloc(1, sizeof(*m));
    if (!m) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    /* the caller's parameter needn't outlive the call, and the process does */
    m->mech = *mechanism;
    m->mech.pParameter = NULL;
    if (mechanism->pParameter) {
        size_t len = mechanism->ulParameterLen ? mechanism->ulParameterLen : 1;
        m->mech.pParameter = calloc(1, len);
        if (!m->mech.pParameter) {
            LOGE("oom");
            rv = CKR_HOST_MEMORY;
            goto error;
        }
        memcpy(m->mech.pParameter, mechanism->pParameter, mechanism->ulParameterLen);
    }

    /* validates the key and mechanism as C_SignInit or C_VerifyInit, and readies the first message */
    rv = sign_opdata_new(ctx, message_kind(op), &m->mech, tobj, &m->msg);
    if (rv != CKR_OK) {
        goto error;
    }

    session_ctx_opdata_set(ctx, op, tobj, m, (opdata_free_fn)message_opdata_free);

    return CKR_OK;

error:
    message_opdata_free(&m);
    tobject_user_decrement(tobj);

    return rv;
}

/* No mechanism takes a per-message parameter (S32 5.14.2, 5.16.2). */
static CK_RV check_param(CK_VOID_PTR param, CK_ULONG param_len) {

    if (param || param_len) {
        LOGE("The mechanism takes no message parameter");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return CKR_OK;
}

/* The state of the message about to start, made if the last message used it up. */
static CK_RV message_start(operation op, session_ctx *ctx, message_opdata *m) {

    if (m->msg) {
        return CKR_OK;
    }

    tobject *tobj = session_ctx_opdata_get_tobject(ctx, op);
    assert(tobj);

    return sign_opdata_new(ctx, message_kind(op), &m->mech, tobj, &m->msg);
}

/*
 * Ends the message, not the process: the key stays held, and a CKA_ALWAYS_AUTHENTICATE key wants
 * its context-specific login again for the next.
 */
static void message_end(operation op, session_ctx *ctx, message_opdata *m) {

    if (m->msg) {
        sign_opdata_free(&m->msg);
    }

    m->begun = false;

    tobject *tobj = session_ctx_opdata_get_tobject(ctx, op);
    assert(tobj);
    tobj->is_authenticated = false;
}

static CK_RV message_begin(operation op, session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len) {

    message_opdata *m = NULL;
    CK_RV rv = session_ctx_opdata_get(ctx, op, &m);
    if (rv != CKR_OK) {
        return rv;
    }

    if (m->begun) {
        LOGE("A message is in progress: end it with its last part");
        return CKR_OPERATION_ACTIVE;
    }

    /* nothing started, so nothing to end */
    rv = check_param(param, param_len);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = session_ctx_tobject_authenticated(ctx, op);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = message_start(op, ctx, m);
    if (rv != CKR_OK) {
        return rv;
    }

    m->begun = true;

    return CKR_OK;
}

static CK_RV message_final(operation op, session_ctx *ctx) {

    message_opdata *m = NULL;
    CK_RV rv = session_ctx_opdata_get(ctx, op, &m);
    if (rv != CKR_OK) {
        return rv;
    }

    /* ends a message in progress too, and releases the key */
    return session_ctx_cancel(ctx, session_ctx_operation_flag(op));
}

/*
 * The S32 5.2 length convention, answered before the data is fed, so a length query or
 * CKR_BUFFER_TOO_SMALL keeps the message as it was, for the call to be made again.
 */
static CK_RV sign_length(sign_opdata *msg, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len,
        bool *answered) {

    CK_ULONG len = 0;
    CK_RV rv = sign_opdata_sig_len(msg, &len);
    if (rv != CKR_OK) {
        return rv;
    }

    *answered = true;

    if (!signature) {
        *signature_len = len;
        return CKR_OK;
    }

    if (*signature_len < len) {
        *signature_len = len;
        return CKR_BUFFER_TOO_SMALL;
    }

    *answered = false;
    return CKR_OK;
}

CK_RV message_sign_init(session_ctx *ctx, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    return message_init(operation_message_sign, ctx, mechanism, key);
}

CK_RV sign_message(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len,
        CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {

    const operation op = operation_message_sign;

    message_opdata *m = NULL;
    CK_RV rv = session_ctx_opdata_get(ctx, op, &m);
    if (rv != CKR_OK) {
        return rv;
    }

    /* not in the middle of a multi-part message, which it leaves be */
    if (m->begun) {
        LOGE("C_SignMessage inside a message begun with C_SignMessageBegin");
        return CKR_OPERATION_ACTIVE;
    }

    /* From here on, a failure goes through out, which ends the message. */
    rv = check_param(param, param_len);
    if (rv != CKR_OK) {
        goto out;
    }

    if (!signature_len || (!data && data_len)) {
        rv = CKR_ARGUMENTS_BAD;
        goto out;
    }

    /* a context-specific login still to come keeps the message, for the call to be made again */
    rv = session_ctx_tobject_authenticated(ctx, op);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = message_start(op, ctx, m);
    if (rv != CKR_OK) {
        goto out;
    }

    bool answered = false;
    rv = sign_length(m->msg, signature, signature_len, &answered);
    if (rv != CKR_OK && !answered) {
        goto out;
    }
    if (answered) {
        return rv;
    }

    rv = sign_opdata_update(m->msg, data, data_len);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = sign_opdata_final(ctx, m->msg, signature, signature_len, true);

out:
    message_end(op, ctx, m);

    return rv;
}

CK_RV sign_message_begin(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len) {

    return message_begin(operation_message_sign, ctx, param, param_len);
}

CK_RV sign_message_next(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len,
        CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {

    const operation op = operation_message_sign;

    message_opdata *m = NULL;
    CK_RV rv = session_ctx_opdata_get(ctx, op, &m);
    if (rv != CKR_OK) {
        return rv;
    }

    if (!m->begun) {
        LOGE("C_SignMessageNext without C_SignMessageBegin");
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    /* From here on, a failure goes through out, which ends the message. */
    rv = check_param(param, param_len);
    if (rv != CKR_OK) {
        goto out;
    }

    if (!data && data_len) {
        rv = CKR_ARGUMENTS_BAD;
        goto out;
    }

    rv = session_ctx_tobject_authenticated(ctx, op);
    if (rv != CKR_OK) {
        return rv;
    }

    /* a NULL pulSignatureLen: more parts follow */
    if (!signature_len) {
        rv = sign_opdata_update(m->msg, data, data_len);
        if (rv != CKR_OK) {
            goto out;
        }
        return CKR_OK;
    }

    /* the last part, which a length query doesn't feed, as it is given again */
    bool answered = false;
    rv = sign_length(m->msg, signature, signature_len, &answered);
    if (rv != CKR_OK && !answered) {
        goto out;
    }
    if (answered) {
        return rv;
    }

    rv = sign_opdata_update(m->msg, data, data_len);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = sign_opdata_final(ctx, m->msg, signature, signature_len, false);

out:
    message_end(op, ctx, m);

    return rv;
}

CK_RV message_sign_final(session_ctx *ctx) {

    return message_final(operation_message_sign, ctx);
}

CK_RV message_verify_init(session_ctx *ctx, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    return message_init(operation_message_verify, ctx, mechanism, key);
}

CK_RV verify_message(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len,
        CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG signature_len) {

    const operation op = operation_message_verify;

    message_opdata *m = NULL;
    CK_RV rv = session_ctx_opdata_get(ctx, op, &m);
    if (rv != CKR_OK) {
        return rv;
    }

    if (m->begun) {
        LOGE("C_VerifyMessage inside a message begun with C_VerifyMessageBegin");
        return CKR_OPERATION_ACTIVE;
    }

    /* From here on, a failure goes through out, which ends the message. */
    rv = check_param(param, param_len);
    if (rv != CKR_OK) {
        goto out;
    }

    /* a signature of the wrong length, empty even, is an invalid signature, not a bad argument */
    if ((!data && data_len) || (!signature && signature_len)) {
        rv = CKR_ARGUMENTS_BAD;
        goto out;
    }

    rv = session_ctx_tobject_authenticated(ctx, op);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = message_start(op, ctx, m);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = sign_opdata_update(m->msg, data, data_len);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = verify_opdata_final(ctx, m->msg, signature, signature_len);

out:
    message_end(op, ctx, m);

    return rv;
}

CK_RV verify_message_begin(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len) {

    return message_begin(operation_message_verify, ctx, param, param_len);
}

CK_RV verify_message_next(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len,
        CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG signature_len) {

    const operation op = operation_message_verify;

    message_opdata *m = NULL;
    CK_RV rv = session_ctx_opdata_get(ctx, op, &m);
    if (rv != CKR_OK) {
        return rv;
    }

    if (!m->begun) {
        LOGE("C_VerifyMessageNext without C_VerifyMessageBegin");
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    /* From here on, a failure goes through out, which ends the message. */
    rv = check_param(param, param_len);
    if (rv != CKR_OK) {
        goto out;
    }

    if (!data && data_len) {
        rv = CKR_ARGUMENTS_BAD;
        goto out;
    }

    rv = session_ctx_tobject_authenticated(ctx, op);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = sign_opdata_update(m->msg, data, data_len);
    if (rv != CKR_OK) {
        goto out;
    }

    /* a NULL pSignature: more parts follow */
    if (!signature) {
        return CKR_OK;
    }

    /* the last part ends the message, whatever the result (S32 5.16.4) */
    rv = verify_opdata_final(ctx, m->msg, signature, signature_len);

out:
    message_end(op, ctx, m);

    return rv;
}

CK_RV message_verify_final(session_ctx *ctx) {

    return message_final(operation_message_verify, ctx);
}

CK_RV message_crypt_init(session_ctx *ctx, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    UNUSED(ctx);
    UNUSED(key);
    assert(mechanism);

    LOGV("Mechanism 0x%lx doesn't encrypt or decrypt messages", mechanism->mechanism);
    return CKR_MECHANISM_INVALID;
}

CK_RV message_crypt_not_initialized(session_ctx *ctx) {

    UNUSED(ctx);
    return CKR_OPERATION_NOT_INITIALIZED;
}
