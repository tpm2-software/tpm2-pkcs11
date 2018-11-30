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

typedef enum token_login_state token_login_state;
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
 * @param state
 *  The token login state for setting the proper initial session state.
 * @param flags
 *  The session flags
 * @return
 *  CKR_OK on success.
 */
CK_RV session_ctx_new(session_ctx **ctx, token_login_state state, CK_FLAGS flags);

/**
 * Internal locking routine, use the session_ctx_lock and session_ctx_unlock macros.
 * @param ctx
 *  The session to lock
 */
void *_session_ctx_get_lock(session_ctx *ctx);

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

// XXX moveme
CK_RV token_load_object(token *tok, CK_OBJECT_HANDLE key, tobject **loaded_tobj);

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

#endif /* SRC_PKCS11_SESSION_CTX_H_ */
