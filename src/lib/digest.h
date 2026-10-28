/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_LIB_DIGEST_H_
#define SRC_LIB_DIGEST_H_

#include <stdint.h>
#include <stdbool.h>

#include <openssl/evp.h>

#include "object.h"
#include "pkcs11.h"
#include "session_ctx.h"

typedef struct digest_op_data digest_op_data;
struct digest_op_data {
    tobject *tobj;
    CK_MECHANISM mechanism;
    EVP_MD_CTX *mdctx;
    /* C_DigestUpdate has run, so the operation is multi-part: C_Digest is refused. */
    bool updated;
};

digest_op_data *digest_op_data_new(void);
void digest_op_data_free(digest_op_data **opdata);

CK_RV digest_init_op(session_ctx *ctx, digest_op_data *supplied_opdata, CK_MECHANISM_PTR mechanism);
static inline CK_RV digest_init(session_ctx *ctx, CK_MECHANISM_PTR mechanism) {
    return digest_init_op(ctx, NULL, mechanism);
}

CK_RV digest_update_op(session_ctx *ctx, digest_op_data *supplied_opdata, CK_BYTE_PTR part, CK_ULONG part_len);
static inline CK_RV digest_update(session_ctx *ctx, unsigned char *part, unsigned long part_len) {
    return digest_update_op(ctx, NULL, part, part_len);
}

/**
 * Digests a secret key's value as the next part of the active digest (C_DigestKey). Only a secret
 * key whose value the host holds can be: one in the TPM never gives its value out.
 * @param ctx
 *  The session.
 * @param key
 *  The secret key.
 * @return
 *  CKR_OK on success.
 *  CKR_OPERATION_NOT_INITIALIZED when no digest is active.
 *  CKR_KEY_HANDLE_INVALID when key isn't an object.
 *  CKR_KEY_INDIGESTIBLE when it isn't a secret key, or its value isn't on the host.
 */
CK_RV digest_key(session_ctx *ctx, CK_OBJECT_HANDLE key);

CK_RV digest_final_op(session_ctx *ctx, digest_op_data *supplied_opdata, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len);
static inline CK_RV digest_final(session_ctx *ctx, unsigned char *digest, unsigned long *digest_len) {
    return digest_final_op(ctx, NULL, digest, digest_len);
}

CK_RV digest_oneshot(session_ctx *ctx, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len);

#endif /* SRC_LIB_DIGEST_H_ */
