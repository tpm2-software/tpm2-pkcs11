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

typedef struct token token;

typedef enum operation operation;
enum operation {
    operation_find,
    operation_sign,
    operation_verify,
    operation_encrypt,
    operation_decrypt,
    operation_digest,
    operation_count
};

typedef struct session_ctx session_ctx;

void session_ctx_free(session_ctx *ctx);
CK_RV session_ctx_new(session_ctx **ctx, token *tok, CK_FLAGS flags);

void *_session_ctx_get_lock(session_ctx *ctx);

#define session_ctx_lock(ctx) \
    mutex_lock_fatal(_session_ctx_get_lock(ctx))

#define session_ctx_unlock(ctx) \
    mutex_unlock_fatal(_session_ctx_get_lock(ctx))

void session_ctx_opdata_set(session_ctx *ctx, operation op, void *opdata);
void *session_ctx_opdata_get(session_ctx *ctx, operation op);

tpm_ctx *session_ctx_get_tpm_ctx(session_ctx *ctx);

token *session_ctx_get_tok(session_ctx *ctx);

CK_STATE session_ctx_state_get(session_ctx *ctx);

CK_FLAGS session_ctx_flags_get(session_ctx *ctx);

bool session_ctx_is_user_logged_in(session_ctx *ctx);

/**
 * Causes a login event to be propagated through the token
 * associated with the session context. A login event is
 * Propagated by:
 *   1. setting the token level who is logged in state with whom is logged in.
 *   2. updating all open session states in the session table
 * @param ctx
 *  The session context to update
 * @param pin
 *  The pin
 * @param user
 *  The user
 * @return
 *  CKR_OK on success, anything else is a failure.
 * @note
 *  Locking:
 *    Callee expects caller to *TAKE* the session_ctx lock
 *    Callee expects caller to *RELEASE* session ctx_lock
 */
CK_RV session_ctx_token_login(session_ctx *ctx, twist pin, CK_USER_TYPE user);

/**
 * Generates a logout event to be propagated through the token associated
 * with the session context. A logout event is propagated by:
 *   1. setting the token level who is logged in state to no one is logged in.
 *   2. setting all existing sessions back to their original state.
 *
 * @param ctx
 *  The context triggering the login event
 * @return
 *  CKR_OK on success, anything else is a failure.
 * @note
 *  Locking:
 *    Callee expects caller to take the session_ctx lock.
 *    Callee releases session_ctx_lock.
 */
CK_RV session_ctx_token_logout(session_ctx *ctx);

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
 * @param take_lock
 *  true to lock the session context, false not to lock it (must already be locked).
 */
void session_ctx_login_event(session_ctx *ctx, CK_USER_TYPE user, bool take_lock);

/**
 * Given a user, performs a logout event, causing a transition to it's correct
 * initial state based on current session state and user triggering the event.
 *
 * See Section 5 of:
 *   https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11.pdf
 *
 * @param ctx
 *  The session context to transition.
 * @param take_lock
 *  true to lock the session context, false not to lock it (must already be locked).
 */
void session_ctx_logout_event(session_ctx *ctx, bool take_lock);

#endif /* SRC_PKCS11_SESSION_CTX_H_ */
