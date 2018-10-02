/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_UTILS_H_
#define SRC_PKCS11_UTILS_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "pkcs11.h"
#include "twist.h"

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#define UNUSED(x) (void)x

static inline int max(size_t a, size_t b) {
    return a > b ? a : b;
}

static inline int min(size_t a, size_t b) {
    return a < b ? a : b;
}

static inline void str_padded_copy(unsigned char * dst, const unsigned char * src, size_t dst_len) {
    memset(dst, ' ', dst_len - 1);
    memcpy(dst, src, min(strlen((char *)(src)), dst_len));
}

twist utils_pdkdf2_hmac_sha256_raw(const twist pin, const twist salt,
        int iterations);

twist utils_pdkdf2_hmac_sha256(const twist pin, const twist salt, int iterations);

twist decrypt(const twist pin, const twist salt, unsigned iters, const twist objauth);

twist aes256_gcm_decrypt(const twist key, const twist objauth);

/**
 * Retrieves the size in bytes of a hash algorithm
 * @param mttype
 *  The mechanism type.
 * @return
 *  The size in bytes or 0 if unknown.
 */
size_t utils_get_halg_size(CK_MECHANISM_TYPE mttype);

#endif /* SRC_PKCS11_UTILS_H_ */
