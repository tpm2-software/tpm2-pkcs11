/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_LIB_MESSAGE_H_
#define SRC_LIB_MESSAGE_H_

#include "pkcs11.h"
#include "session_ctx.h"

/*
 * Message-based signing and verification (S32 5.14, 5.16): C_MessageSignInit holds the key for any
 * number of messages, each signed in one part, or in several between C_SignMessageBegin and the
 * C_SignMessageNext with a pulSignatureLen, until C_MessageSignFinal. No mechanism takes a
 * per-message parameter. A message's failure ends that message, not the process; a
 * CKA_ALWAYS_AUTHENTICATE key wants its context-specific login for each message.
 */

CK_RV message_sign_init(session_ctx *ctx, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key);

CK_RV sign_message(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len,
        CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len);

CK_RV sign_message_begin(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len);

CK_RV sign_message_next(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len,
        CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len);

CK_RV message_sign_final(session_ctx *ctx);

CK_RV message_verify_init(session_ctx *ctx, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key);

CK_RV verify_message(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len,
        CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG signature_len);

CK_RV verify_message_begin(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len);

CK_RV verify_message_next(session_ctx *ctx, CK_VOID_PTR param, CK_ULONG param_len,
        CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG signature_len);

CK_RV message_verify_final(session_ctx *ctx);

/*
 * Message-based encryption and decryption (S32 5.9, 5.11): no mechanism the token lists has
 * CKF_MESSAGE_ENCRYPT or CKF_MESSAGE_DECRYPT, AES-GCM and AES-CCM not being among them, so no such
 * process ever starts.
 */

/**
 * C_MessageEncryptInit and C_MessageDecryptInit with a mechanism: CKR_MECHANISM_INVALID for every
 * one. A NULL mechanism ends the process there isn't, which the caller does through
 * session_ctx_cancel().
 */
CK_RV message_crypt_init(session_ctx *ctx, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key);

/** The per-message functions and C_Message*Final: CKR_OPERATION_NOT_INITIALIZED. */
CK_RV message_crypt_not_initialized(session_ctx *ctx);

#endif /* SRC_LIB_MESSAGE_H_ */
