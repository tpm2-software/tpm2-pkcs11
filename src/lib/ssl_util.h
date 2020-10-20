/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SRC_LIB_SSL_UTIL_H_
#define SRC_LIB_SSL_UTIL_H_

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "pkcs11.h"

#include "log.h"
#include "object.h"
#include "twist.h"

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL && !defined(LIBRESSL_VERSION_NUMBER)) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L) /* OpenSSL 1.1.0 */
#define LIB_TPM2_OPENSSL_OPENSSL_PRE11
/* LibreSSL does not appear to have evperr.h, so their is no need to define this otherwise */
#elif (OPENSSL_VERSION_NUMBER >= 0x1010100fL) /* OpenSSL 1.1.1 */
#define LIB_TPM2_OPENSSL_OPENSSL_POST111 0x1010100f
#endif

/* OpenSSL Backwards Compat APIs */
#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
#include <string.h>
size_t EC_POINT_point2buf(const EC_GROUP *group, const EC_POINT *point,
                          point_conversion_form_t form,
                          unsigned char **pbuf, BN_CTX *ctx);

const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x);

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);

static inline void *OPENSSL_memdup(const void *dup, size_t l) {

    void *p = OPENSSL_malloc(l);
    if (!p) {
        return NULL;
    }

    memcpy(p, dup, l);
    return p;
}

#endif

#ifndef RSA_PSS_SALTLEN_DIGEST
#define RSA_PSS_SALTLEN_DIGEST -1
#endif

/* Utility APIs */

#define SSL_UTIL_LOGE(m) LOGE("%s: %s", m, ERR_error_string(ERR_get_error(), NULL));

CK_RV ssl_util_tobject_to_evp(EVP_PKEY **outpkey, tobject *obj);

CK_RV ssl_util_encrypt(EVP_PKEY *pkey,
        int padding, twist label, const EVP_MD *md,
        CK_BYTE_PTR ptext, CK_ULONG ptextlen,
        CK_BYTE_PTR ctext, CK_ULONG_PTR ctextlen);

CK_RV ssl_util_sig_verify(EVP_PKEY *pkey,
        int padding, const EVP_MD *md,
        CK_BYTE_PTR digest, CK_ULONG digest_len,
        CK_BYTE_PTR signature, CK_ULONG signature_len);

CK_RV ssl_util_verify_recover(EVP_PKEY *pkey,
        int padding, const EVP_MD *md,
        CK_BYTE_PTR signature, CK_ULONG signature_len,
        CK_BYTE_PTR data, CK_ULONG_PTR data_len);

typedef int (*fn_EVP_PKEY_init)(EVP_PKEY_CTX *ctx);

CK_RV ssl_util_setup_evp_pkey_ctx(EVP_PKEY *pkey,
        int padding, const EVP_MD *md,
        fn_EVP_PKEY_init init_fn,
        EVP_PKEY_CTX **outpkey_ctx);

#endif /* SRC_LIB_SSL_UTIL_H_ */
