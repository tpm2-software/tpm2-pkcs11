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
    operation_verify_recover,
    operation_encrypt,
    operation_decrypt,
    operation_digest,
    operation_verify_signature,
    operation_sign_recover,
    /* C_MessageSignInit and C_MessageVerifyInit's processes, which pair with nothing */
    operation_message_sign,
    operation_message_verify,
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
typedef struct token token;
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
 * Determines if any operation is active in the session. Find and derive, which pair with nothing,
 * need the session free.
 * @param ctx
 *  The session context
 * @return
 *  true if either operation slot is in use.
 */
bool session_ctx_opdata_is_active(session_ctx *ctx);

/**
 * Whether operation op may start in the session: a session holds two operations when they are one
 * of the four pairs of PKCS#11 (digest and encrypt, decrypt and digest, sign and encrypt, decrypt and
 * verify; verify being operation_verify alone).
 * @param ctx
 *  The session context
 * @param op
 *  The operation to start
 * @return
 *  CKR_OK if both slots are free, or the one busy holds op's partner in a pair;
 *  CKR_OPERATION_ACTIVE otherwise.
 */
CK_RV session_ctx_opdata_can_start(session_ctx *ctx, operation op);

typedef void (*opdata_free_fn)(void **opdata);

/**
 * Sets operational specific data in a free slot. Callers must first check
 * session_ctx_opdata_can_start() (or session_ctx_opdata_is_active() for an
 * operation that needs the session to itself).
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
 * Returns the object of the session's operation op, or NULL.
 * @param ctx
 *  The session context
 * @param op
 *  The operation whose object to return
 * @returns
 *  The tobject or NULL.
 */
tobject *session_ctx_opdata_get_tobject(session_ctx *ctx, operation op);

/**
 * Clears the slot of operation op, freeing its data with the function it was set with, and leaves
 * the other operation be; does nothing if op isn't active. Releasing the operation's object is the
 * caller's.
 * @param ctx
 *  The session_ctx to clear operational data from.
 * @param op
 *  The operation to clear.
 */
void session_ctx_opdata_clear(session_ctx *ctx, operation op);

/**
 * Gets the operation specific state data, from whichever slot holds op
 * @param ctx
 *  The session context
 * @param op
 *  The operation whose data to get
 * @param data
 *  The data
 * @return
 *  CKR_OK on success, CKR_OPERATION_NOT_INITIALIZED if op isn't active.
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
 * If the user is CKU_CONTEXT_SPECIFIC an active operation with an object is needed, and one object
 * is marked authenticated, until its operation ends: the CKA_ALWAYS_AUTHENTICATE object of the
 * operation started first that isn't yet. A second such object, of the other operation, needs a
 * second login. If a login request for CKU_USER occurs after a CKU_CONTEXT_SPECIFIC
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
 * C_LoginUser: the token has no user names, so a call without one is C_Login, and one with a user
 * name is refused.
 */
CK_RV session_ctx_login_user(session_ctx *ctx, CK_USER_TYPE user, CK_BYTE_PTR pin, CK_ULONG pinlen,
        CK_UTF8CHAR_PTR username, CK_ULONG username_len);

/**
 * Ends each of the session's active operations that flags name (CKF_ENCRYPT, CKF_SIGN,
 * CKF_FIND_OBJECTS, ...), as C_SessionCancel and a C_*Init with a NULL mechanism do, releasing its
 * key; the other is left be.
 * @param ctx
 *  The session context.
 * @param flags
 *  The CK_MECHANISM_INFO flags of the operations to end.
 * @return
 *  CKR_OK, or the first error releasing an operation's key reported.
 */
CK_RV session_ctx_cancel(session_ctx *ctx, CK_FLAGS flags);

/**
 * The CK_MECHANISM_INFO flag of an operation, as session_ctx_cancel() takes it: CKF_SIGN,
 * CKF_VERIFY (verify and verify-signature), CKF_ENCRYPT, CKF_MESSAGE_SIGN, ...
 * @param op
 *  The operation.
 * @return
 *  Its flag, or 0 for operation_none.
 */
CK_FLAGS session_ctx_operation_flag(operation op);

/**
 * C_GetSessionValidationFlags: the token has no validation (FIPS 140-3 or otherwise) to indicate, so
 * the flags are 0.
 */
CK_RV session_ctx_get_validation_flags(session_ctx *ctx, CK_SESSION_VALIDATION_FLAGS_TYPE type,
        CK_FLAGS *flags);

/**
 * C_GetOperationState (S32 5.6.6): no state is ever saved, for an operation's state is TPM objects
 * and OpenSSL contexts that can't leave the token.
 * @return
 *  CKR_ARGUMENTS_BAD for a NULL state_len.
 *  CKR_STATE_UNSAVEABLE while a sign, verify, encrypt, decrypt or digest operation is active.
 *  CKR_OPERATION_NOT_INITIALIZED otherwise, as with only a find, a recovery or a message-based
 *  operation, none of which the standard saves.
 */
CK_RV session_ctx_get_operation_state(session_ctx *ctx, CK_BYTE_PTR state, CK_ULONG_PTR state_len);

/**
 * C_SetOperationState (S32 5.6.7): CKR_SAVED_STATE_INVALID, as session_ctx_get_operation_state()
 * gives none out; CKR_ARGUMENTS_BAD for no state.
 */
CK_RV session_ctx_set_operation_state(session_ctx *ctx, CK_BYTE_PTR state, CK_ULONG state_len,
        CK_OBJECT_HANDLE encryption_key, CK_OBJECT_HANDLE authentication_key);

/** C_GetFunctionStatus and C_CancelFunction (S32 5.20): legacy, CKR_FUNCTION_NOT_PARALLEL. */
CK_RV session_ctx_function_not_parallel(session_ctx *ctx);

/*
 * The asynchronous functions (S32 5.21). No session is asynchronous (C_OpenSession refuses
 * CKF_ASYNC_SESSION), so no function is ever running asynchronously. A NULL function name, or a
 * NULL id for C_AsyncGetID, is CKR_ARGUMENTS_BAD.
 */

/** C_AsyncComplete: CKR_OPERATION_NOT_INITIALIZED, as C_AsyncGetID gives for no operation. */
CK_RV session_ctx_async_complete(session_ctx *ctx, CK_UTF8CHAR_PTR function_name,
        CK_ASYNC_DATA_PTR result);

/** C_AsyncGetID: CKR_OPERATION_NOT_INITIALIZED, the code 5.21.2 names for no asynchronous operation. */
CK_RV session_ctx_async_get_id(session_ctx *ctx, CK_UTF8CHAR_PTR function_name, CK_ULONG_PTR id);

/** C_AsyncJoin: CKR_SAVED_STATE_INVALID, as no identifier was ever given out. */
CK_RV session_ctx_async_join(session_ctx *ctx, CK_UTF8CHAR_PTR function_name, CK_ULONG id,
        CK_BYTE_PTR data, CK_ULONG data_len);

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
 * Whether the object of operation op may be used: CKR_USER_NOT_LOGGED_IN if it has
 * CKA_ALWAYS_AUTHENTICATE and no C_Login(CKU_CONTEXT_SPECIFIC) authenticated it since the operation
 * started.
 * @param ctx
 *  The session context
 * @param op
 *  The active operation, which must have an object.
 * @return
 *  CKR_OK or CKR_USER_NOT_LOGGED_IN.
 */
CK_RV session_ctx_tobject_authenticated(session_ctx *ctx, operation op);

#endif /* SRC_PKCS11_SESSION_CTX_H_ */
