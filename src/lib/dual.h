/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef _SRC_LIB_DUAL_H_
#define _SRC_LIB_DUAL_H_

#include "pkcs11.h"
#include "session_ctx.h"

/*
 * The dual-function updates (S32 5.17), each the composition of the two updates of a pair of
 * operations active in the session (UG32 4.1). Both must be active, else
 * CKR_OPERATION_NOT_INITIALIZED, and neither is touched.
 *
 * The encrypt-side functions (digest-encrypt, sign-encrypt) take the 5.2 buffer convention of the
 * encryption: a length query, or a buffer too small, feeds the digest or signature nothing. The
 * decrypt-side functions (decrypt-digest, decrypt-verify) decrypt first and feed the digest or
 * verification the plaintext actually returned. What C_DecryptFinal returns (the block CBC-PAD
 * holds back) isn't passed on (S32 5.17.2): the application passes it with C_DigestUpdate or
 * C_VerifyUpdate before ending that operation.
 *
 * A key waiting for its context-specific login (CKR_USER_NOT_LOGGED_IN) leaves both operations as
 * they were, for the call to be made again. Any other error ends both.
 */
CK_RV dual_digest_encrypt_update(session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR enc, CK_ULONG_PTR enc_len);

CK_RV dual_decrypt_digest_update(session_ctx *ctx, CK_BYTE_PTR enc, CK_ULONG enc_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len);

CK_RV dual_sign_encrypt_update(session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR enc, CK_ULONG_PTR enc_len);

CK_RV dual_decrypt_verify_update(session_ctx *ctx, CK_BYTE_PTR enc, CK_ULONG enc_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len);

#endif
