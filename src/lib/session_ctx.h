/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_SESSION_CTX_H_
#define SRC_PKCS11_SESSION_CTX_H_

#include "mutex.h"
#include "object.h"
#include "pkcs11.h"
#include "tpm.h"
#include "utils.h"
#include "token.h"

typedef struct token token;

typedef struct session_ctx session_ctx;

/**
 * Frees a session context
 * @param ctx
 *  The session context to free
 */
void session_ctx_free(session_ctx *ctx);

/**
 * Creates a new session context within a given token.
 * @param ctx
 *  The new session context generated,
 * @param tok
 *  The token to associate with the session_context
 * @param flags
 *  The session flags
 * @return
 *  CKR_OK on success.
 */
CK_RV session_ctx_new(session_ctx **ctx, token *tok, CK_FLAGS flags);

/**
 * Internal locking routine, use the session_ctx_lock and session_ctx_unlock macros.
 * @param ctx
 *  The session to lock
 */
void *_session_ctx_get_lock(session_ctx *ctx);

/**
 * Lock session_ctx and abort on failure.
 * @param ctx
 *  The session to lock
 */
#define session_ctx_lock(ctx) \
    mutex_lock_fatal(_session_ctx_get_lock(ctx))

/**
 * Unock session_ctx and abort on failure.
 * @param ctx
 *  The session to lock
 */
#define session_ctx_unlock(ctx) \
    mutex_unlock_fatal(_session_ctx_get_lock(ctx))

/**
 * Given a session_context, retrieve the associated token.
 *
 * @param ctx
 *  The session_ctx to query for the token.
 * @return
 *  The token pointer.
 */
token *session_ctx_get_tok(session_ctx *ctx);

/**
 * Get the state of the session
 * @param ctx
 *  Session context to query
 * @return
 *  The CK_STATE flags.
 */
CK_STATE session_ctx_state_get(session_ctx *ctx);

/**
 * Get the CK_Fstate of the session
 * @param ctx
 *  Session context to query
 * @return
 *  The CK_STATE flags.
 */
CK_FLAGS session_ctx_flags_get(session_ctx *ctx);

CK_RV session_ctx_load_object(session_ctx *ctx, CK_OBJECT_HANDLE key, tobject **loaded_tobj);

/**
 * Given a user, performs a login event, causing a transition to it's correct end state based
 * on current session state and user triggering the event.
 *
 * See Section 5 of:
 *   https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11.pdf
 *
 * @param ctx
 *  The session context to transition.
 * @param user
 *  The user performing the login, ie state transition trigger.
 */
void session_ctx_login_event(session_ctx *ctx, CK_USER_TYPE user);

/**
 * Given a user, performs a logout event, causing a transition to it's correct
 * initial state based on current session state and user triggering the event.
 *
 * See Section 5 of:
 *   https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11.pdf
 *
 * @param ctx
 *  The session context to transition.
 */
void session_ctx_logout_event(session_ctx *ctx);

/**
 * True if the session state is either:
 *  1. CKS_RO_USER_FUNCTIONS
 *  2. CKS_RW_USER_FUNCTIONS
 * @param ctx
 *  The session context to query state
 * @return
 *  true if the session state is CKS_RO_USER_FUNCTIONS or
 *  CKS_RW_USER_FUNCTIONS, false otherwise.
 */
static inline bool session_ctx_user_state_ok(session_ctx *ctx) {

    CK_STATE state = session_ctx_state_get(ctx);
    return (state == CKS_RO_USER_FUNCTIONS) || (state == CKS_RW_USER_FUNCTIONS);
}

#endif /* SRC_PKCS11_SESSION_CTX_H_ */
