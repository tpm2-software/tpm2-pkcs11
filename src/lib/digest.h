/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_LIB_DIGEST_H_
#define SRC_LIB_DIGEST_H_

#include <stdint.h>
#include <stdbool.h>

#include <openssl/evp.h>

#include "pkcs11.h"
#include "object.h"

typedef struct token token;

typedef struct digest_op_data digest_op_data;
struct digest_op_data {
    bool use_sw_hash;
    tobject *tobj;
    CK_MECHANISM_TYPE mechanism;
    union {
        uint32_t sequence_handle;
        EVP_MD_CTX *mdctx;
    };
};

digest_op_data *digest_op_data_new(void);
void digest_op_data_free(digest_op_data **opdata);

CK_RV digest_init_op(token *tok, digest_op_data *opdata, CK_MECHANISM_TYPE mechanism);
static inline CK_RV digest_init(token *tok, CK_MECHANISM *mechanism) {
    return digest_init_op(tok, NULL, mechanism->mechanism);
}

CK_RV digest_update_op(token *tok, digest_op_data *opdata, unsigned char *part, unsigned long part_len);
static inline CK_RV digest_update(token *tok, unsigned char *part, unsigned long part_len) {
    return digest_update_op(tok, NULL, part, part_len);
}

CK_RV digest_final_op(token *tok, digest_op_data *opdata, unsigned char *digest, unsigned long *digest_len);
static inline CK_RV digest_final(token *tok, unsigned char *digest, unsigned long *digest_len) {
    return digest_final_op(tok, NULL, digest, digest_len);
}

CK_RV digest_oneshot(token *tok, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len);

#endif /* SRC_LIB_DIGEST_H_ */
