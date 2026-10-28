/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"

#include <openssl/crypto.h>

#include "checks.h"
#include "digest.h"
#include "dual.h"
#include "encrypt.h"
#include "log.h"
#include "session_ctx.h"
#include "sign.h"
#include "utils.h"

/*
 * Both operations must be active, and their keys usable: a key waiting for its context-specific
 * login gives CKR_USER_NOT_LOGGED_IN before either half takes anything, so both stay as they were
 * for the call after the login (#953). A digest has no key.
 */
static CK_RV both_ready(session_ctx *ctx, operation a, operation b) {

    void *data = NULL;
    if (session_ctx_opdata_get(ctx, a, &data) != CKR_OK
            || session_ctx_opdata_get(ctx, b, &data) != CKR_OK) {
        LOGE("A dual function needs both its operations active");
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    operation ops[] = { a, b };
    size_t i;
    for (i = 0; i < ARRAY_LEN(ops); i++) {
        if (ops[i] == operation_digest) {
            continue;
        }
        CK_RV rv = session_ctx_tobject_authenticated(ctx, ops[i]);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    return CKR_OK;
}

static CK_RV feed(session_ctx *ctx, operation op, CK_BYTE_PTR part, CK_ULONG part_len) {

    switch (op) {
    case operation_digest:
        return digest_update_op(ctx, NULL, part, part_len);
    case operation_sign:
        return sign_update(ctx, part, part_len);
    case operation_verify:
        return verify_update(ctx, part, part_len);
    default:
        return CKR_GENERAL_ERROR;
    }
}

/*
 * Digest-encrypt and sign-encrypt: the encryption's length first, by its 5.2 query, so a length
 * query or a buffer too small feeds the other half nothing; then the other half, then the
 * encryption.
 */
static CK_RV encrypt_side(session_ctx *ctx, operation other, CK_BYTE_PTR part, CK_ULONG part_len,
        CK_BYTE_PTR enc, CK_ULONG_PTR enc_len) {

    check_pointer(part);
    check_pointer(enc_len);

    CK_RV rv = both_ready(ctx, other, operation_encrypt);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG needed = 0;
    rv = encrypt_update_op(ctx, NULL, part, part_len, NULL, &needed);
    if (rv != CKR_OK) {
        goto out;
    }

    if (!enc) {
        *enc_len = needed;
        return CKR_OK;
    }

    if (*enc_len < needed) {
        *enc_len = needed;
        return CKR_BUFFER_TOO_SMALL;
    }

    rv = feed(ctx, other, part, part_len);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = encrypt_update(ctx, part, part_len, enc, enc_len);

out:
    /* an error in either half ends both */
    if (rv != CKR_OK) {
        session_ctx_cancel(ctx, CKF_ENCRYPT | session_ctx_operation_flag(other));
    }

    return rv;
}

/*
 * Decrypt-digest and decrypt-verify: the decryption first, and the other half gets only the
 * plaintext it returns. CBC-PAD holds the last block back, and what C_DecryptFinal returns isn't
 * passed on (S32 5.17.2): the application feeds it with C_DigestUpdate or C_VerifyUpdate.
 */
static CK_RV decrypt_side(session_ctx *ctx, operation other, CK_BYTE_PTR enc, CK_ULONG enc_len,
        CK_BYTE_PTR part, CK_ULONG_PTR part_len) {

    check_pointer(enc);
    check_pointer(part_len);

    CK_RV rv = both_ready(ctx, operation_decrypt, other);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = decrypt_update(ctx, enc, enc_len, part, part_len);
    if (rv == CKR_BUFFER_TOO_SMALL) {
        /* nothing taken, as for C_DecryptUpdate */
        return rv;
    }
    if (rv != CKR_OK) {
        goto out;
    }

    /* a length query: nothing decrypted, nothing to feed */
    if (!part) {
        return CKR_OK;
    }

    if (*part_len) {
        rv = feed(ctx, other, part, *part_len);
        if (rv != CKR_OK) {
            /* the plaintext is of a failed call: it isn't returned */
            OPENSSL_cleanse(part, *part_len);
            *part_len = 0;
        }
    }

out:
    /* an error in either half ends both */
    if (rv != CKR_OK) {
        session_ctx_cancel(ctx, CKF_DECRYPT | session_ctx_operation_flag(other));
    }

    return rv;
}

CK_RV dual_digest_encrypt_update(session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR enc, CK_ULONG_PTR enc_len) {

    return encrypt_side(ctx, operation_digest, part, part_len, enc, enc_len);
}

CK_RV dual_decrypt_digest_update(session_ctx *ctx, CK_BYTE_PTR enc, CK_ULONG enc_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) {

    return decrypt_side(ctx, operation_digest, enc, enc_len, part, part_len);
}

CK_RV dual_sign_encrypt_update(session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR enc, CK_ULONG_PTR enc_len) {

    return encrypt_side(ctx, operation_sign, part, part_len, enc, enc_len);
}

CK_RV dual_decrypt_verify_update(session_ctx *ctx, CK_BYTE_PTR enc, CK_ULONG enc_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) {

    return decrypt_side(ctx, operation_verify, enc, enc_len, part, part_len);
}
