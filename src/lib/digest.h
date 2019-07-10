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

#include "object.h"
#include "pkcs11.h"

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

CK_RV digest_sw_init(digest_op_data *opdata);
CK_RV digest_sw_update(digest_op_data *opdata, const void *d, size_t cnt);
CK_RV digest_sw_final(digest_op_data *opdata, CK_BYTE_PTR md, CK_ULONG_PTR s);

digest_op_data *digest_op_data_new(void);
void digest_op_data_free(digest_op_data **opdata);

#endif /* SRC_LIB_DIGEST_H_ */
