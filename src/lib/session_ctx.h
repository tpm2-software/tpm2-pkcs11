/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_SESSION_CTX_H_
#define SRC_PKCS11_SESSION_CTX_H_

#include "mutex.h"
#include "object.h"
#include "pkcs11.h"
#include "tpm.h"
#include "utils.h"

typedef enum token_login_state token_login_state;
typedef struct session_ctx session_ctx;

typedef enum operation operation;
enum operation {
    operation_none = 0,
    operation_find,
    operation_sign,
    operation_verify,
    operation_encrypt,
    operation_decrypt,
    operation_digest,
    operation_count
};

typedef struct generic_opdata generic_opdata;
struct generic_opdata {
    operation op;
    tobject *tobj;
    void *data;
};

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
 *  The token the session is created on.
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

token *session_ctx_get_token(session_ctx *ctx);

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
 * Determines if the opdata is in use
 * @param ctx
 *  The token
 * @return
 */
bool session_ctx_opdata_is_active(session_ctx *ctx);

typedef void (*opdata_free_fn)(void **opdata);

/**
 * Sets operational specific data. Callers should take care to ensure
 * no other users are using it by calling session_ctx_opdata_is_active()
 * before setting the data.
 *
 * @param tok
 *  The session_ctx to set operational data on
 * @param op
 *  The operation setting the data
 * @param tobj
 *   The active object or NULL if no single active object (like find objects has a list)
 * @param data
 *  The data to set
 */
void session_ctx_opdata_set(session_ctx *ctx, operation op, tobject *tobj, void *data, opdata_free_fn fn);

/**
 * Returns the active object for the session, or NULL.
 * @param ctx
 *  The session context
 * @returns
 *  The tobject or NULL.
 */
tobject *session_ctx_opdata_get_tobject(session_ctx *ctx);

/**
 * Clears the session_ctx opdata state. NOTE that callers
 * are required to perfrom memory managment on what
 * is stored in the void pointer.
 * @param tok
 *  The session_ctx to clear operational data from.
 */
void session_ctx_opdata_clear(session_ctx *ctx);

/**
 * Sets the operation specific state data
 * @param tok
 *  The token to set the operation state data
 * @param op
 *  The operation setting it
 * @param data
 *  The data to set
 * @return
 *  CKR_OK on success.
 */
#define session_ctx_opdata_get(ctx, op, data) _session_ctx_opdata_get(ctx, op, (void **)data)
CK_RV _session_ctx_opdata_get(session_ctx *ctx, operation op, void **data);

/**
 * Causes a login event to be propagated through the token
 * associated with the session context if the user is not CKU_CONTEXT_SPECIFIC. A login event is
 * Propagated by:
 *   1. setting the token level who is logged in state with whom is logged in.
 *   2. updating all open session states in the session table
 *
 * If the user is CKU_CONTEXT_SPECIIFC the session state is marked that it's "logged in" and a
 * logout should occur at the end. If a login request for CKU_USER occurs after a CKU_CONTEXT_SPECIFIC
 * call, an error is thrown.
 *
 * @param ctx
 *  The session context to update, and possibly the global state of the
 *  associated token.
 * @param user
 *  The user
 * @param pin
 *  The pin
 * @param pinlen
 *   The length of the pin in bytes.
 * @return
 *  CKR_OK on success, anything else is a failure.
 */
CK_RV session_ctx_login(session_ctx *ctx, CK_USER_TYPE user, CK_BYTE_PTR pin, CK_ULONG pinlen);

/**
 * Generates a logout event to be propagated throughout the token.
 * A logout event is propagated by:
 *   1. setting the token level "who is logged in state" to no one is logged in.
 *   2. setting all existing sessions back to their original state.
 *
 * @param tok
 *  The token to propagate the login event
 * @return
 *  CKR_OK on success, anything else is a failure.
 */
CK_RV session_ctx_logout(session_ctx *ctx);

/**
 * Gets session info
 * @param ctx
 *  session ctx
 * @param info
 *  structure to populate
 * @return
 *  CKR_OK on success, anything else is a failure.
 */
CK_RV session_ctx_get_info(session_ctx *ctx, CK_SESSION_INFO *info);

/**
 * True if the object has been authenticated for use.
 * @param ctx
 * @return
 */
CK_RV session_ctx_tobject_authenticated(session_ctx *ctx);

#endif /* SRC_PKCS11_SESSION_CTX_H_ */
