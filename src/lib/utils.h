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

#include "pkcs11.h"
#include "twist.h"

#define ITERS 10000
#define SALT_SIZE 32

#define xstr(s) str(s)
#define str(s) #s

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#define UNUSED(x) (void)x

static inline int max(size_t a, size_t b) {
    return a > b ? a : b;
}

static inline int min(size_t a, size_t b) {
    return a < b ? a : b;
}

static inline void str_padded_copy(unsigned char * dst, const unsigned char * src, size_t dst_len) {
    memset(dst, ' ', dst_len);
    memcpy(dst, src, min(strlen((char *)(src)), dst_len));
}

/**
 *
 * @param pin
 * @param salt
 * @param iterations
 * @return
 */
twist utils_pdkdf2_hmac_sha256_raw(const twist pin, const twist salt,
        int iterations);

/**
 *
 * @param pin
 * @param binsalt
 * @param iterations
 * @return
 */
twist utils_pdkdf2_hmac_sha256_bin_raw(const twist pin, const twist binsalt,
        int iterations);

twist utils_pdkdf2_hmac_sha256(const twist pin, const twist salt, int iterations);

twist decrypt(const twist pin, const twist salt, unsigned iters, const twist objauth);

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
 *
 * @param size
 * @return
 */
twist utils_get_rand(size_t size);

CK_RV utils_setup_new_object_auth(twist newpin, twist *newauthbin, twist *newauthhex, twist *newsalthex);

static inline CK_RV utils_new_random_object_auth(twist *newauthbin, twist *newauthhex) {
    return utils_setup_new_object_auth(NULL, newauthbin, newauthhex, NULL);
}

typedef struct tpm_ctx tpm_ctx;
typedef struct wrappingobject wrappingobject;
typedef struct token token;
CK_RV utils_ctx_unwrap_objauth(token *tok, twist objauth, twist *unwrapped_auth);
CK_RV utils_ctx_wrap_objauth(token *tok, twist objauth, twist *wrapped_auth);

#define ATTR_HANDLER_IGNORE NULL

typedef struct attr_handler attr_handler;
struct attr_handler {
    CK_ULONG value;
    CK_RV (*handler)(CK_ATTRIBUTE_PTR attr, CK_ULONG count, void *userdat);
};

CK_RV utils_handle_attrs(const attr_handler *handlers, size_t handler_count, CK_ATTRIBUTE_PTR attrs, CK_ULONG attr_count, void *udata);

CK_RV utils_attr_deep_copy(CK_ATTRIBUTE_PTR attrs, CK_ULONG attr_count, CK_ATTRIBUTE_PTR copy);

typedef struct mech_handler mech_handler;
struct mech_handler {
    CK_ULONG mechanism;
    CK_RV (*handler)(CK_MECHANISM_PTR mech, CK_ULONG count, void *userdat);
};

CK_RV utils_handle_mechs(const mech_handler *handlers, size_t handler_count, CK_MECHANISM_PTR mechs, CK_ULONG mech_count, void *udata);

CK_RV utils_mech_deep_copy(CK_MECHANISM_PTR mech, CK_ULONG count, CK_MECHANISM_PTR copy);

CK_RV utils_mech_free(CK_MECHANISM_PTR mechs, CK_ULONG mech_count, CK_MECHANISM_PTR copy);

CK_RV utils_attr_free(CK_ATTRIBUTE_PTR attrs, CK_ULONG attr_count);

#define UTILS_GENERIC_ATTR_TYPE_CONVERT(T) \
    static CK_RV generic_##T(CK_ATTRIBUTE_PTR attr, T *x) { \
    \
        if (attr->ulValueLen != sizeof(*x)) { \
            return CKR_ATTRIBUTE_VALUE_INVALID; \
        } \
    \
        *x = *(T *)attr->pValue; \
    \
        return CKR_OK; \
    }

#endif /* SRC_PKCS11_UTILS_H_ */
