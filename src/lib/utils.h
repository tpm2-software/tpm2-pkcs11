/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_UTILS_H_
#define SRC_PKCS11_UTILS_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

#if defined(FUZZING) || !defined(NDEBUG)
#define WEAK __attribute__((weak))
#define DEBUG_VISIBILITY
#else
#define WEAK
#define DEBUG_VISIBILITY static
#endif

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

/*
 * Work around bugs in clang not including the builtins, and when asan is enabled
 * ending up in a nightmare of having both the ASAN and BUILTINS defined and linked
 * properly.
 *  See:
 *  - https://bugs.llvm.org/show_bug.cgi?id=16404
 *  - https://lists.gnu.org/archive/html/bug-gnulib/2019-08/msg00076.html
 */
#ifdef DISABLE_OVERFLOW_BUILTINS
#define _safe_add(r, a, b) 0; do { r = a + b; } while(0)
#define _safe_adde(r, a)   0; do { r += a;    } while(0)
#define _safe_mul(r, a, b) 0; do { r = a * b; } while(0)
#define _safe_mule(r, a)   0; do { r *= a;    } while(0)
#define safe_add(r, a, b) do { r = a + b; } while(0)
#define safe_adde(r, a)   do { r += a;    } while(0)
#define safe_mul(r, a, b) do { r = a * b; } while(0)
#define safe_mule(r, a)   do { r *= a;    } while(0)
#else
#define _safe_add(r, a, b) __builtin_add_overflow(a, b, &r)
#define _safe_adde(r, a)   __builtin_add_overflow(a, r, &r)
#define _safe_mul(r, a, b) __builtin_mul_overflow(a, b, &r)
#define _safe_mule(r, a)   __builtin_mul_overflow(a, r, &r)
#define safe_add(r, a, b) do { if (_safe_add(r, a, b)) { LOGE("overflow"); abort(); } } while(0)
#define safe_adde(r, a)   do { if (_safe_adde(r, a)) { LOGE("overflow"); abort(); } } while(0)
#define safe_mul(r, a, b) do { if (_safe_mul(r, a, b)) { LOGE("overflow"); abort(); } } while(0)
#define safe_mule(r, a)   do { if (_safe_mule(r, a)) { LOGE("overflow"); abort(); } } while(0)
#endif

#endif /* SRC_PKCS11_UTILS_H_ */
