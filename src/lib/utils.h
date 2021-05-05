/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_UTILS_H_
#define SRC_PKCS11_UTILS_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "pkcs11.h"
#include "twist.h"

#define SALT_HEX_STR_SIZE 64
#define AUTH_HEX_STR_SIZE 32

#define xstr(s) str(s)
#define str(s) #s

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))
#define ARRAY_BYTES(l, t) (l * sizeof(t[0]))

#define UNUSED(x) (void)x

#define SAFE_FREE(x) do { free(x); x = NULL; } while (0)

#define SAFE_CAST(m, r) \
    do { \
        if (!m->pParameter || m->ulParameterLen != sizeof(typeof(*r))) { \
            return CKR_MECHANISM_PARAM_INVALID; \
        } \
        \
        r = (typeof(r))m->pParameter; \
    } while (0)

#define goto_error_false(r) if(!r) { goto error; }

int str_to_ul(const char *val, size_t *res);

#define str_padded_copy(dst, src) _str_padded_copy(dst, sizeof(dst), src, strnlen((const char *)src, sizeof(src)))
static inline void _str_padded_copy(CK_UTF8CHAR_PTR dst, size_t dst_len, const CK_UTF8CHAR *src, size_t src_len) {
    memset(dst, ' ', dst_len);
    memcpy(dst, src, src_len);
    LOGE("BILL(%zu): %.*s\n", dst_len, dst_len, dst);
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
 *
 * @param size
 * @return
 */
twist utils_get_rand_hex_str(size_t size);

CK_RV utils_setup_new_object_auth(twist newpin, twist *newauthhex, twist *newsalthex);

static inline CK_RV utils_new_random_object_auth(twist *newauthhex) {
    return utils_setup_new_object_auth(NULL, newauthhex, NULL);
}

CK_RV utils_ctx_unwrap_objauth(twist wrappingkey, twist objauth, twist *unwrapped_auth);
CK_RV utils_ctx_wrap_objauth(twist wrappingkey, twist objauth, twist *wrapped_auth);

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
 * Removes a PKCS7 padding on a 16 byte block.
 * @param in
 *  The PKCS5 padded input.
 * @param inlen
 *  The length of the input, should be multiples of block size. Set on successful
 *  calls to the size of the data with the padding stripped.
 * @param out
 *  The unpadded output.
 * @param outlen
 *  Input: The length of the output buffer.
 *  Output: The length of the unpadded buffer.
 * @return
 *  CKR_OK on success.
 */
CK_RV remove_pkcs7_pad(CK_BYTE_PTR in, CK_ULONG inlen,
        CK_BYTE_PTR out, CK_ULONG_PTR outlen);

/**
 * Applies a PKCS7 padding to a blocksize of 16.
 * @param in
 *  The buffer to pad to AES blocksize of 16.
 * @param inlen
 *  The length of the input buffer.
 * @param out
 *  The padded output.
 * @param outlen
 *  Input: The length of the output buffer.
 *  Output: The length of the padded buffer.
 * @return
 *  Returns CKR_OK on success.
 */
CK_RV apply_pkcs7_pad(const CK_BYTE_PTR in, CK_ULONG inlen,
        CK_BYTE_PTR out, CK_ULONG_PTR outlen);

/*
 * Work around bugs in clang not including the builtins, and when asan is enabled
 * ending up in a nightmare of having both the ASAN and BUILTINS defined and linked
 * properly.
 *  See:
 *  - https://bugs.llvm.org/show_bug.cgi?id=16404
 *  - https://lists.gnu.org/archive/html/bug-gnulib/2019-08/msg00076.html
 */
#ifdef DISABLE_OVERFLOW_BUILTINS
#include <assert.h>
#include <openssl/bn.h>

#if defined(NDEBUG)
#error "Emulated overflow support is not evaluated for non-debug release use." \
        "Fix toolchain and use overflow builtins. To compile configure with --debug"
#endif

#ifndef WORDS_BIGENDIAN
static void be_to_host(unsigned char *from, unsigned char *to, size_t len) {
#ifndef WORDS_BIGENDIAN
    size_t i;
    for (i=0; i < len; i++) {
        to[len -i -1] = from[i];
    }
#else
    memcpy(from, to, len);
#endif
}
#endif

typedef int (*arithmetic_fn)(BIGNUM *a, BN_ULONG w);

static bool _do_safe_arithmetic(void *r, BN_ULONG a, BN_ULONG b,
        size_t size_of_r,
        arithmetic_fn fn) {

    unsigned char bufr[sizeof(size_t)] = { 0 };
    assert(sizeof(bufr) >= size_of_r);

    BIGNUM *bna = BN_new();
    assert(bna);

    int rc = BN_add_word(bna, a);
    assert(rc);

    rc = fn(bna, b);
    assert(rc);

    int num_of_bytes = BN_num_bytes(bna);
    if (num_of_bytes > size_of_r) {
        BN_free(bna);
        return true;
    }

    if (!num_of_bytes) {
        BN_free(bna);
        memset(r, 0, size_of_r);
        return false;
    }

    /* BN_bn2binpad would be nice, but OSSL 1.0.2 is lacking this */
    assert(num_of_bytes <= size_of_r);
    off_t offset = size_of_r - num_of_bytes;
    rc = BN_bn2bin(bna, &bufr[offset]);
    BN_free(bna);
    assert(rc);

    be_to_host(bufr, r, size_of_r);

    return false;
}

#define _safe_add(r, a, b) _do_safe_arithmetic(&r, a, b, \
        sizeof(r), BN_add_word)

#define _safe_adde(r, a) _do_safe_arithmetic(&r, r, a, \
        sizeof(r), BN_add_word)

#define _safe_mul(r, a, b) _do_safe_arithmetic(&r, a, b, \
        sizeof(r), BN_mul_word)

#define _safe_mule(r, a) _do_safe_arithmetic(&r, r, a, \
        sizeof(r), BN_mul_word)
#else
#define set_safe_rc(x) /* NOP */
#define _safe_add(r, a, b) __builtin_add_overflow(a, b, &r)
#define _safe_adde(r, a)   __builtin_add_overflow(a, r, &r)
#define _safe_mul(r, a, b) __builtin_mul_overflow(a, b, &r)
#define _safe_mule(r, a)   __builtin_mul_overflow(a, r, &r)
#endif

#define safe_add(r, a, b) do { if (_safe_add(r, a, b)) { LOGE("overflow"); abort(); } } while(0)
#define safe_adde(r, a)   do { if (_safe_adde(r, a)) { LOGE("overflow"); abort(); } } while(0)
#define safe_mul(r, a, b) do { if (_safe_mul(r, a, b)) { LOGE("overflow"); abort(); } } while(0)
#define safe_mule(r, a)   do { if (_safe_mule(r, a)) { LOGE("overflow"); abort(); } } while(0)

#endif /* SRC_PKCS11_UTILS_H_ */
