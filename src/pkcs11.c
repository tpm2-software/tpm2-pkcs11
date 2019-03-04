/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include "config.h"

#include <assert.h>
#include <string.h>

#include "pkcs11.h"

#include "digest.h"
#include "encrypt.h"
#include "key.h"
#include "log.h"
#include "general.h"
#include "object.h"
#include "random.h"
#include "session.h"
#include "sign.h"
#include "slot.h"
#include "token.h"

// TODO REMOVE ME
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/**
 * Logs an "enter" function stub via LOGV
 */
#define _TRACE_CALL    LOGV("enter \"%s\"", __func__)

/**
 * Logs an "return" function stub with return value. It expects rv to be declared
 * as a CK_RV and contain the actual return value
 */
#define _TRACE_RET(rv) LOGV("return \"%s\" value: %lu", __func__, rv);

/**
 * Calls a user supplied function with arguments logging the function entry and
 * exit.
 *
 * It ensures that the library has been initialized.
 *
 * IT PERFORMS NO STATE checks and has NO access to the token, thus it's useful
 * for routines like C_Init().
 * @param fn
 *   The user function to run.
 * @param varargs
 *  The arguments to pass to fn
 * @return
 *  The rv value of running fn.
 */
#define TOKEN_CALL_INIT(fn, ...) \
     CK_RV rv = CKR_GENERAL_ERROR; \
    _TRACE_CALL; \
    _CHECK_INIT(out); \
    rv = fn(__VA_ARGS__); \
  out: \
    _TRACE_RET(rv); \
    return rv;

#define TOKEN_CALL(fn, ...) \
     CK_RV rv = CKR_GENERAL_ERROR; \
    _TRACE_CALL; \
    rv = fn(__VA_ARGS__); \
    _TRACE_RET(rv); \
    return rv;

#define TOKEN_CALL_NO_INIT(fn, ...) \
    CK_RV rv = CKR_GENERAL_ERROR; \
    _TRACE_CALL; \
    _CHECK_NO_INIT(out); \
    rv = fn(__VA_ARGS__); \
  out: \
    _TRACE_RET(rv); \
    return rv;

/**
 * Returns CKR_FUNCTION_NOT_SUPPORTED and if NDEBUG is 0, will cause an
 * assert(0) failure.
 * @return
 *  CKR_FUNCTION_NOT_SUPPORTED
 */
#define TOKEN_UNSUPPORTED \
        _TRACE_CALL; \
        assert(0); \
        _TRACE_RET(CKR_FUNCTION_NOT_SUPPORTED); \
        return CKR_FUNCTION_NOT_SUPPORTED;

/**
 * Checks that the library is initialized, if not goes to a user specified
 * label. Requires rv to be defined as a CK_RV type.
 * @param label
 *  The label to go to on failure.
 * @return
 *  Sets rv to CKR_CRYPTOKI_NOT_INITIALIZED.
 */
#define _CHECK_INIT(label) \
    if (!general_is_init()) { \
        rv = CKR_CRYPTOKI_NOT_INITIALIZED; \
        goto label; \
    }

/**
 * Checks that the library is NOT initialized, if not goes to a user specified
 * label. Requires rv to be defined as a CK_RV type.
 * @param label
 *  The label to go to on failure.
 * @return
 *  Sets rv to CKR_CRYPTOKI_ALREADY_INITIALIZED.
 */
#define _CHECK_NO_INIT(label) \
    if (general_is_init()) { \
        rv = CKR_CRYPTOKI_ALREADY_INITIALIZED; \
        goto label; \
    }

/**
 * Interface to calling into the internal interface from a cryptoki
 * routine that takes slot id. Performs all locking on token.
 *
 * @note
 *  - Requires a CK_RV rv to be declared.
 *  - Performs **NO** auth checking. The slot routines implemented
 *    do not need a particular state AFAIK.
 *  - manages token locking
 *
 * @param userfun
 *  The userfunction to call, ie the internal API.
 * @param ...
 *  The arguments to the internal API call from cryptoki.
 * @return
 *  The internal API's result as rv.
 */
#define TOKEN_WITH_LOCK_BY_SLOT(userfunc, slot, ...) \
do { \
    \
    _TRACE_CALL; \
    CK_RV rv = CKR_GENERAL_ERROR; \
    _CHECK_INIT(out); \
    \
    token *t = slot_get_token(slot); \
    if (!t) { \
        rv = CKR_SLOT_ID_INVALID; \
        goto out; \
    } \
    \
    token_lock(t); \
    rv = userfunc(t, ##__VA_ARGS__); \
    token_unlock(t); \
  out: \
    _TRACE_RET(rv); \
    return rv; \
} while (0)

/**
 * Raw interface (DO NOT USE DIRECTLY) for calling into the internal interface from a cryptoki
 * routine that takes a session handle. Performs all locking on token.
 *
 * @note
 *  - Requires a CK_RV rv to be declared.
 *  - do not use directly, use the ones with auth model.
 *  - manages token locking
 *
 * @param userfun
 *  The userfunction to call, ie the internal API.
 * @param ...
 *  The arguments to the internal API call from cryptoki.
 * @return
 *  The internal API's result as rv.
 */
#define __TOKEN_WITH_LOCK_BY_SESSION(authfn, userfunc, session, ...) \
do { \
    _TRACE_CALL; \
    CK_RV rv = CKR_GENERAL_ERROR; \
    \
    _CHECK_INIT(out); \
    \
    token *t = NULL; \
    session_ctx *ctx = NULL; \
    rv = session_lookup(session, &t, &ctx); \
    if (rv != CKR_OK) { \
        goto out; \
    } \
    \
    rv = authfn(ctx); \
    if (rv != CKR_OK) { \
        goto unlock; \
    } \
    rv = userfunc(ctx, ##__VA_ARGS__); \
  unlock: \
    token_unlock(t); \
  out: \
    _TRACE_RET(rv); \
    return rv; \
} while (0)

#define __TOKEN_WITH_LOCK_BY_SESSION_TOKEN(authfn, userfunc, session, ...) \
do { \
    _TRACE_CALL; \
    CK_RV rv = CKR_GENERAL_ERROR; \
    \
    _CHECK_INIT(out); \
    \
    token *t = NULL; \
    session_ctx *ctx = NULL; \
    rv = session_lookup(session, &t, &ctx); \
    if (rv != CKR_OK) { \
        goto out; \
    } \
    \
    rv = authfn(ctx); \
    if (rv != CKR_OK) { \
        goto unlock; \
    } \
    rv = userfunc(t, ##__VA_ARGS__); \
  unlock: \
    token_unlock(t); \
  out: \
    _TRACE_RET(rv); \
    return rv; \
} while (0)

/*
 * Same as: __TOKEN_WITH_LOCK_BY_SESSION but hands the session_ctx to the internal routine.
 */
#define __TOKEN_WITH_LOCK_BY_SESSION_KEEP_CTX(authfn, userfunc, session, ...) \
do { \
    \
    _TRACE_CALL; \
    CK_RV rv = CKR_GENERAL_ERROR; \
    _CHECK_INIT(out); \
    \
    token *t = NULL; \
    session_ctx *ctx = NULL; \
    rv = session_lookup(session, &t, &ctx); \
    if (rv != CKR_OK) { \
        goto out; \
    } \
    \
    rv = authfn(ctx); \
    if (rv != CKR_OK) { \
        goto unlock; \
    } \
    rv = userfunc(t, ctx, ##__VA_ARGS__); \
  unlock: \
    token_unlock(t); \
  out: \
    _TRACE_RET(rv); \
    return rv; \
} while (0)

/*
 * Below you'll find the auth routines that validate session
 * context. Becuase session context is required to be in a
 * certain state for things, these auth plugins check a vary
 * specific condition. Add more if you need different checks.
 */
static inline CK_RV auth_min_ro_pub(session_ctx *ctx) {

    UNUSED(ctx);
    return CKR_OK;
}

static inline CK_RV auth_min_ro_user(session_ctx *ctx) {

    CK_STATE state = session_ctx_state_get(ctx);
    switch(state) {
    case CKS_RO_USER_FUNCTIONS:
        /* falls-thru */
    case CKS_RW_USER_FUNCTIONS:
        return CKR_OK;
        /* no default */
    }

    return CKR_USER_NOT_LOGGED_IN;
}

static inline CK_RV auth_min_rw_user(session_ctx *ctx) {

    CK_STATE state = session_ctx_state_get(ctx);
    switch(state) {
    case CKS_RO_USER_FUNCTIONS:
        return CKR_SESSION_READ_ONLY;
    case CKS_RW_USER_FUNCTIONS:
        return CKR_OK;
        /* no default */
    }

    return CKR_USER_NOT_LOGGED_IN;
}


static inline CK_RV auth_min_rw_so(session_ctx *ctx) {

    CK_STATE state = session_ctx_state_get(ctx);
    switch(state) {
    case CKS_RW_SO_FUNCTIONS:
        return CKR_OK;
        /* no default */
    }

    return CKR_USER_NOT_LOGGED_IN;
}

static inline CK_RV auth_any_logged_in(session_ctx *ctx) {
    CK_STATE state = session_ctx_state_get(ctx);
    switch(state) {
    case CKS_RO_USER_FUNCTIONS:
    case CKS_RW_USER_FUNCTIONS:
    case CKS_RW_SO_FUNCTIONS:
        return CKR_OK;
        /* no default */
    }

    return CKR_USER_NOT_LOGGED_IN;
}

/*
 * C_SetPIN can only be called in the:
 *  - “R/W Public Session” state
 *  - “R/W SO Functions” state
 *  - “R/W User Functions” state
 *
 * An attempt to call it from a session in any other state fails with
 * error CKR_SESSION_READ_ONLY.
 */
static inline CK_RV auth_set_pin_state(session_ctx *ctx) {
    CK_STATE state = session_ctx_state_get(ctx);
    switch(state) {
    case CKS_RW_PUBLIC_SESSION:
    case CKS_RW_SO_FUNCTIONS:
    case CKS_RW_USER_FUNCTIONS:
        return CKR_OK;
        /* no default */
    }

    return CKR_SESSION_READ_ONLY;
}

static inline CK_RV auth_init_pin_state(session_ctx *ctx) {

    CK_STATE state = session_ctx_state_get(ctx);
    switch(state) {
    case CKS_RW_SO_FUNCTIONS:
        return CKR_OK;
        /* no default */
    }

    return CKR_SESSION_READ_ONLY;
}

/*
 * The macros below are used to call into the cryptoki API and perform a myriad of checking using certain
 * auth models. Not using these is dangerous.
 */

/*
 * Does what __TOKEN_WITH_LOCK_BY_SESSION does, and checks that the session is at least RO Public Ie any session would work.
 */
#define TOKEN_WITH_LOCK_BY_SESSION_PUB_RO(userfunc, session, ...) __TOKEN_WITH_LOCK_BY_SESSION(auth_min_ro_pub, userfunc, session, ##__VA_ARGS__)

/*
 * Does what TOKEN_WITH_LOCK_BY_SESSION_PUB_RO does, but passes the session_ctx to the internal api.
 */
#define TOKEN_WITH_LOCK_BY_SESSION_PUB_RO_KEEP_CTX(userfunc, session, ...) __TOKEN_WITH_LOCK_BY_SESSION_KEEP_CTX(auth_min_ro_pub, userfunc, session, ##__VA_ARGS__)

/*
 * Does what __TOKEN_WITH_LOCK_BY_SESSION does, and checks that the session is at least RW Public. Ie no one logged in and R/W session.
 */
#define TOKEN_WITH_LOCK_BY_SESSION_PUB_RW(userfunc, session, ...) __TOKEN_WITH_LOCK_BY_SESSION(auth_min_rw_pub, userfunc, session, ##__VA_ARGS__)

/*
 * Does what __TOKEN_WITH_LOCK_BY_SESSION does, and checks that the session is at least RO User. Ie user logged in and R/O or R/W session.
 */
#define TOKEN_WITH_LOCK_BY_SESSION_USER_RO(userfunc, session, ...) __TOKEN_WITH_LOCK_BY_SESSION(auth_min_ro_user, userfunc, session, ##__VA_ARGS__)

/*
 * Does what __TOKEN_WITH_LOCK_BY_SESSION does, and checks that the session is at least RO User. Ie user logged in and R/W session.
 */
#define TOKEN_WITH_LOCK_BY_SESSION_USER_RW(userfunc, session, ...) __TOKEN_WITH_LOCK_BY_SESSION(auth_min_rw_user, userfunc, session, ##__VA_ARGS__)

/*
 * Does what __TOKEN_WITH_LOCK_BY_SESSION does, and checks that the session is at least RW So. Ie so logged in and R/W session.
 */
#define TOKEN_WITH_LOCK_BY_SESSION_SO_RW(userfunc, session, ...) __TOKEN_WITH_LOCK_BY_SESSION(auth_min_rw_so, userfunc, session, ##__VA_ARGS__)

/*
 * Does what __TOKEN_WITH_LOCK_BY_SESSION does, and checks that the session is at least RO User. Ie user or so logged in and R/O or R/W session.
 */
#define TOKEN_WITH_LOCK_BY_SESSION_LOGGED_IN(userfunc, session, ...) __TOKEN_WITH_LOCK_BY_SESSION_TOKEN(auth_any_logged_in, userfunc, session, ##__VA_ARGS__)

#define TOKEN_WITH_LOCK_BY_SESSION_SET_PIN_STATE(userfunc, session, ...) __TOKEN_WITH_LOCK_BY_SESSION_TOKEN(auth_set_pin_state, userfunc, session, ##__VA_ARGS__)

#define TOKEN_WITH_LOCK_BY_SESSION_INIT_PIN_STATE(userfunc, session, ...) __TOKEN_WITH_LOCK_BY_SESSION_TOKEN(auth_init_pin_state, userfunc, session, ##__VA_ARGS__)


CK_RV C_Initialize (void *init_args) {
    TOKEN_CALL_NO_INIT(general_init, init_args);
}

CK_RV C_Finalize (void *pReserved) {
    TOKEN_CALL_INIT(general_finalize, pReserved);
}

CK_RV C_GetInfo (CK_INFO *info) {
    TOKEN_CALL_INIT(general_get_info, info);
}

CK_RV C_GetFunctionList (CK_FUNCTION_LIST **function_list) {
    TOKEN_CALL(general_get_func_list, function_list);
}

CK_RV C_GetSlotList (CK_BYTE token_present, CK_SLOT_ID *slot_list, CK_ULONG_PTR count) {
    TOKEN_CALL_INIT(slot_get_list, token_present, slot_list, count);
}

CK_RV C_GetSlotInfo (CK_SLOT_ID slotID, CK_SLOT_INFO *info) {
    TOKEN_CALL_INIT(slot_get_info, slotID, info);
}

CK_RV C_GetTokenInfo (CK_SLOT_ID slotID, CK_TOKEN_INFO *info) {
    TOKEN_WITH_LOCK_BY_SLOT(token_get_info, slotID, info);
}

CK_RV C_WaitForSlotEvent (CK_FLAGS flags, CK_SLOT_ID *slot, void *pReserved) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_GetMechanismList (CK_SLOT_ID slotID, CK_MECHANISM_TYPE *mechanism_list, CK_ULONG_PTR count) {
    TOKEN_CALL_INIT(slot_mechanism_list_get, slotID, mechanism_list, count);
}

CK_RV C_GetMechanismInfo (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *info) {
    TOKEN_CALL_INIT(slot_mechanism_info_get, slotID, type, info);
}

CK_RV C_InitToken (CK_SLOT_ID slotID, CK_BYTE_PTR pin, CK_ULONG pin_len, CK_BYTE_PTR label) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_InitPIN (CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len) {
    TOKEN_WITH_LOCK_BY_SESSION_INIT_PIN_STATE(token_initpin, session, pin, pin_len);
}

CK_RV C_SetPIN (CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR old_pin, CK_ULONG old_len, CK_UTF8CHAR_PTR new_pin, CK_ULONG new_len) {
    TOKEN_WITH_LOCK_BY_SESSION_SET_PIN_STATE(token_setpin, session, old_pin, old_len, new_pin, new_len);
}

CK_RV C_OpenSession (CK_SLOT_ID slotID, CK_FLAGS flags, void *application, CK_NOTIFY notify, CK_SESSION_HANDLE *session) {
    TOKEN_CALL_INIT(session_open, slotID, flags, application, notify, session);
}

CK_RV C_CloseSession (CK_SESSION_HANDLE session) {
    TOKEN_CALL_INIT(session_close, session);
}

CK_RV C_CloseAllSessions (CK_SLOT_ID slotID) {
    TOKEN_CALL_INIT(session_closeall, slotID);
}

CK_RV C_GetSessionInfo (CK_SESSION_HANDLE session, CK_SESSION_INFO *info) {
    TOKEN_WITH_LOCK_BY_SESSION_PUB_RO_KEEP_CTX(session_get_info, session, info);
}

CK_RV C_GetOperationState (CK_SESSION_HANDLE session, CK_BYTE_PTR operation_state, CK_ULONG_PTR operation_state_len) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_SetOperationState (CK_SESSION_HANDLE session, CK_BYTE_PTR operation_state, CK_ULONG operation_state_len, CK_OBJECT_HANDLE encryption_key, CK_OBJECT_HANDLE authentiation_key) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_Login (CK_SESSION_HANDLE session, CK_USER_TYPE user_type, CK_BYTE_PTR pin, CK_ULONG pin_len) {
    TOKEN_WITH_LOCK_BY_SESSION_PUB_RO(session_login, session, user_type, pin, pin_len);
}

CK_RV C_Logout (CK_SESSION_HANDLE session) {
    TOKEN_WITH_LOCK_BY_SESSION_LOGGED_IN(session_logout, session);
}

CK_RV C_CreateObject (CK_SESSION_HANDLE session, CK_ATTRIBUTE *templ, CK_ULONG count, CK_OBJECT_HANDLE *object) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_CopyObject (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE *templ, CK_ULONG count, CK_OBJECT_HANDLE *new_object) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_DestroyObject (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_GetObjectSize (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ULONG_PTR size) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_GetAttributeValue (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR templ, CK_ULONG count) {
    TOKEN_WITH_LOCK_BY_SESSION_PUB_RO(object_get_attributes, session, object, templ, count);
}

CK_RV C_SetAttributeValue (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE *templ, CK_ULONG count) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_FindObjectsInit (CK_SESSION_HANDLE session, CK_ATTRIBUTE *templ, CK_ULONG count) {
    TOKEN_WITH_LOCK_BY_SESSION_PUB_RO(object_find_init, session, templ, count);
}

CK_RV C_FindObjects (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *object, CK_ULONG max_object_count, CK_ULONG_PTR object_count) {
    TOKEN_WITH_LOCK_BY_SESSION_PUB_RO(object_find, session, object, max_object_count, object_count);
}

CK_RV C_FindObjectsFinal (CK_SESSION_HANDLE session) {
    TOKEN_WITH_LOCK_BY_SESSION_PUB_RO(object_find_final, session);
}

CK_RV C_EncryptInit (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(encrypt_init, session, mechanism, key);
}

CK_RV C_Encrypt (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(encrypt_oneshot, session, data, data_len, encrypted_data, encrypted_data_len);
}

CK_RV C_EncryptUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(encrypt_update, session, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV C_EncryptFinal (CK_SESSION_HANDLE session, CK_BYTE_PTR last_encrypted_part, CK_ULONG_PTR last_encrypted_part_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(encrypt_final, session, last_encrypted_part, last_encrypted_part_len);
}

CK_RV C_DecryptInit (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(decrypt_init, session, mechanism, key);
}

CK_RV C_Decrypt (CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_data, CK_ULONG encrypted_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(decrypt_oneshot, session, encrypted_data, encrypted_data_len, data, data_len);
}

CK_RV C_DecryptUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_part, CK_ULONG encrypted_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(decrypt_update, session, encrypted_part, encrypted_part_len, part, part_len);
}

CK_RV C_DecryptFinal (CK_SESSION_HANDLE session, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(decrypt_final, session, last_part, last_part_len);
}

CK_RV C_DigestInit (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(digest_init, session, mechanism);
}

CK_RV C_Digest (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(digest_oneshot, session, data, data_len, digest, digest_len);
}

CK_RV C_DigestUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(digest_update, session, part, part_len);
}

CK_RV C_DigestKey (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_DigestFinal (CK_SESSION_HANDLE session, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(digest_final, session, digest, digest_len);
}

CK_RV C_SignInit (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(sign_init, session, mechanism, key);
}

CK_RV C_Sign (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(sign, session, data, data_len, signature, signature_len);
}

CK_RV C_SignUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(sign_update, session, part, part_len);
}

CK_RV C_SignFinal (CK_SESSION_HANDLE session, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(sign_final, session, signature, signature_len);
}

CK_RV C_SignRecoverInit (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_SignRecover (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_VerifyInit (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(verify_init, session, mechanism, key);
}

CK_RV C_Verify (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG signature_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(verify, session, data, data_len, signature, signature_len);
}

CK_RV C_VerifyUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(verify_update, session, part, part_len);
}

CK_RV C_VerifyFinal (CK_SESSION_HANDLE session, CK_BYTE_PTR signature, CK_ULONG signature_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(verify_final, session, signature, signature_len);
}

CK_RV C_VerifyRecoverInit (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_VerifyRecover (CK_SESSION_HANDLE session, CK_BYTE_PTR signature, CK_ULONG signature_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_DigestEncryptUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_DecryptDigestUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_part, CK_ULONG encrypted_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_SignEncryptUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_DecryptVerifyUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_part, CK_ULONG encrypted_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_GenerateKey (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_ATTRIBUTE *templ, CK_ULONG count, CK_OBJECT_HANDLE *key) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_GenerateKeyPair (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_ATTRIBUTE *public_key_template, CK_ULONG public_key_attribute_count, CK_ATTRIBUTE *private_key_template, CK_ULONG private_key_attribute_count, CK_OBJECT_HANDLE *public_key, CK_OBJECT_HANDLE *private_key) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RW(key_gen, session, mechanism, public_key_template, public_key_attribute_count, private_key_template, private_key_attribute_count, public_key, private_key);
}

CK_RV C_WrapKey (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_UnwrapKey (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_key_len, CK_ATTRIBUTE *templ, CK_ULONG attribute_count, CK_OBJECT_HANDLE *key) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_DeriveKey (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE *templ, CK_ULONG attribute_count, CK_OBJECT_HANDLE *key) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_SeedRandom (CK_SESSION_HANDLE session, CK_BYTE_PTR seed, CK_ULONG seed_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(seed_random, session, seed, seed_len);
}

CK_RV C_GenerateRandom (CK_SESSION_HANDLE session, CK_BYTE_PTR random_data, CK_ULONG random_len) {
    TOKEN_WITH_LOCK_BY_SESSION_USER_RO(random_get, session, random_data, random_len);
}

CK_RV C_GetFunctionStatus (CK_SESSION_HANDLE session) {
    TOKEN_UNSUPPORTED;
}

CK_RV C_CancelFunction (CK_SESSION_HANDLE session) {
    TOKEN_UNSUPPORTED;
}

// TODO REMOVE ME
#pragma GCC diagnostic pop
