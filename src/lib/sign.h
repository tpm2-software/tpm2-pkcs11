/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef _SRC_LIB_SIGN_H_
#define _SRC_LIB_SIGN_H_

#include "pkcs11.h"
#include "session_ctx.h"

/*
 * The state of one signature or verification, apart from the session: the C_Sign* and C_Verify*
 * operations keep one in their session slot, a message-based process one per message.
 */
typedef struct sign_opdata sign_opdata;

/**
 * Checks that the key may do operation op with the mechanism, as C_SignInit and C_VerifyInit do,
 * and makes the state of one signature (op operation_sign or operation_sign_recover) or
 * verification (any other).
 * @param ctx
 *  The session.
 * @param op
 *  The kind of operation.
 * @param mech
 *  The mechanism, which the state refers to (its parameter isn't copied).
 * @param tobj
 *  The key, which the caller holds (tobject_user_increment) for as long as the state lives.
 * @param out
 *  The state made, for sign_opdata_free().
 * @return
 *  CKR_OK, or why the key and mechanism can't do op.
 */
CK_RV sign_opdata_new(session_ctx *ctx, operation op, CK_MECHANISM_PTR mech, tobject *tobj,
        sign_opdata **out);

void sign_opdata_free(sign_opdata **opdata);

/** Feeds a part of the data to the state. */
CK_RV sign_opdata_update(sign_opdata *op, CK_BYTE_PTR part, CK_ULONG len);

/**
 * Signs what the state was fed, with the S32 5.2 convention. A length query (sig NULL) or
 * CKR_BUFFER_TOO_SMALL leaves the state for the call to be made again: as it was, or, if
 * is_oneshot (C_Sign, which gives the data again), emptied of the data. Anything else uses it up.
 * It doesn't check a CKA_ALWAYS_AUTHENTICATE login, nor release the key.
 */
CK_RV sign_opdata_final(session_ctx *ctx, sign_opdata *op, CK_BYTE_PTR sig, CK_ULONG_PTR sig_len,
        bool is_oneshot);

/**
 * Checks the signature over what the state was fed, and uses the state up. It doesn't check a
 * CKA_ALWAYS_AUTHENTICATE login, nor release the key.
 */
CK_RV verify_opdata_final(session_ctx *ctx, sign_opdata *op, CK_BYTE_PTR sig, CK_ULONG sig_len);

/** The signature length of the state's key and mechanism, what a length query answers. */
CK_RV sign_opdata_sig_len(sign_opdata *op, CK_ULONG_PTR sig_len);

CK_RV sign_init(session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV sign_update(session_ctx *ctx, unsigned char *part, unsigned long part_len);

CK_RV sign_final_ex(session_ctx *ctx, unsigned char *signature, unsigned long *signature_len, bool is_oneshot);

static inline CK_RV sign_final(session_ctx *ctx, unsigned char *signature, unsigned long *signature_len) {
    return sign_final_ex(ctx, signature, signature_len, false);
}

CK_RV sign(session_ctx *ctx, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len);

CK_RV verify_init(session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV verify_update(session_ctx *ctx, unsigned char *part, unsigned long part_len);

CK_RV verify_final(session_ctx *ctx, unsigned char *signature, unsigned long signature_len);

CK_RV verify(session_ctx *ctx, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long signature_len);

CK_RV verify_signature_init(session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key,
        CK_BYTE_PTR signature, CK_ULONG signature_len);

CK_RV verify_signature_update(session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len);

CK_RV verify_signature_final(session_ctx *ctx);

CK_RV verify_signature(session_ctx *ctx, CK_BYTE_PTR data, CK_ULONG data_len);

CK_RV sign_recover_init(session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV sign_recover(session_ctx *ctx, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len);

CK_RV verify_recover_init (session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV verify_recover (session_ctx *ctx, CK_BYTE_PTR signature, CK_ULONG signature_len,
        CK_BYTE_PTR data, CK_ULONG_PTR data_len);

#endif
