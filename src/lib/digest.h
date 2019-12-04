/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
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
    CK_MECHANISM_TYPE mechanism;
    EVP_MD_CTX *mdctx;
};

bool digest_is_supported(CK_MECHANISM_TYPE type);

digest_op_data *digest_op_data_new(void);
void digest_op_data_free(digest_op_data **opdata);

CK_RV digest_init_op(session_ctx *ctx, digest_op_data *supplied_opdata, CK_MECHANISM_TYPE mechanism);
static inline CK_RV digest_init(session_ctx *ctx, CK_MECHANISM *mechanism) {
    return digest_init_op(ctx, NULL, mechanism->mechanism);
}

CK_RV digest_update_op(session_ctx *ctx, digest_op_data *supplied_opdata, CK_BYTE_PTR part, CK_ULONG part_len);
static inline CK_RV digest_update(session_ctx *ctx, unsigned char *part, unsigned long part_len) {
    return digest_update_op(ctx, NULL, part, part_len);
}

CK_RV digest_final_op(session_ctx *ctx, digest_op_data *supplied_opdata, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len);
static inline CK_RV digest_final(session_ctx *ctx, unsigned char *digest, unsigned long *digest_len) {
    return digest_final_op(ctx, NULL, digest, digest_len);
}

CK_RV digest_oneshot(session_ctx *ctx, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len);

#endif /* SRC_LIB_DIGEST_H_ */
