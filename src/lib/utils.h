/* SPDX-License-Identifier: BSD-2-Clause */
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

#include "pkcs11.h"
#include "twist.h"

#define SALT_HEX_STR_SIZE 64 /* 64 hex chars is 32 bits entropy */

#define xstr(s) str(s)
#define str(s) #s

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))
#define ARRAY_BYTES(l, t) (l * sizeof(t[0]))

#define UNUSED(x) (void)x

#define goto_error_false(r) if(!r) { goto error; }

int str_to_ul(const char *val, size_t *res);

static inline void str_padded_copy(CK_UTF8CHAR_PTR dst, const CK_UTF8CHAR_PTR src, size_t dst_len) {
    memset(dst, ' ', dst_len);
    memcpy(dst, src, strnlen((char *)(src), dst_len));
}

twist utils_hash_pass(const twist pin, const twist salt);

twist aes256_gcm_decrypt(const twist key, const twist objauth);

twist aes256_gcm_encrypt(twist keybin, twist plaintextbin);

/**
 * Retrieves the size in bytes of a hash algorithm
 * @param mttype
 *  The mechanism type.
 * @return
 *  The size in bytes or 0 if unknown.
 */
size_t utils_get_halg_size(CK_MECHANISM_TYPE mttype);

/**
 * True if a mechanism is a "raw" sign. A raw signing operation
 * is defined as a signing structure constructed by the application,
 * for instance mechanism type CKM_RSA_PKCS.
 * @param mech
 *  The mechanism to check.
 * @return
 *  True if it is a raw signature, else it isn't.
 */
bool utils_mech_is_raw_sign(CK_MECHANISM_TYPE mech);

/**
 * True if the mechanism is an RSA PKCS v1.5 signing
 * scheme.
 * @param mech
 *  The mechanism to check
 * @return
 *  True if it is, false otherwise.
 */
bool utils_mech_is_rsa_pkcs(CK_MECHANISM_TYPE mech);

/**
 * True if the mechanism is an EC ECDSA signing scheme.
 * @param mech
 *  The mechanism to check.
 * @return
 *  True if it is, false otherwise.
 */
bool utils_mech_is_ecdsa(CK_MECHANISM_TYPE mech);

/**
 *
 * @param size
 * @return
 */
twist utils_get_rand_hex_str(size_t size);

CK_RV utils_setup_new_object_auth(twist newpin, twist *newauthhex, twist *newsalthex);

static inline CK_RV utils_new_random_object_auth(twist *newauthbin, twist *newauthhex) {
    return utils_setup_new_object_auth(NULL, newauthbin, newauthhex);
}

typedef struct tpm_ctx tpm_ctx;
typedef struct token token;
CK_RV utils_ctx_unwrap_objauth(token *tok, twist objauth, twist *unwrapped_auth);
CK_RV utils_ctx_wrap_objauth(token *tok, twist objauth, twist *wrapped_auth);

/**
 * Given an attribute of CKA_EC_PARAMS returns the nid value.
 * @param ecparams
 *  The DER X9.62 parameters value
 * @param nid
 *  The nid to set
 * @return
 *  CKR_OK on success.
 */
CK_RV ec_params_to_nid(CK_ATTRIBUTE_PTR ecparams, int *nid);

/**
 * This is a hack to work around clearing a pointer that scan-build
 * thinks needs to be deallocated.
 * @param h
 *  The ptr to NULL
 */
void __clear_ptr(void **h);

#endif /* SRC_PKCS11_UTILS_H_ */
