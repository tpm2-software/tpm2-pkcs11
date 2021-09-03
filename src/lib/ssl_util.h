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

#include "attrs.h"
#include "log.h"
#include "twist.h"

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL && !defined(LIBRESSL_VERSION_NUMBER)) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L) /* OpenSSL 1.1.0 */
#define LIB_TPM2_OPENSSL_OPENSSL_PRE11
/* LibreSSL does not appear to have evperr.h, so their is no need to define this otherwise */
#elif (OPENSSL_VERSION_NUMBER >= 0x1010100fL) /* OpenSSL 1.1.1 */
#define LIB_TPM2_OPENSSL_OPENSSL_POST111 0x1010100f
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x30000000) /* OpenSSL 3.0.0 */
#define LIB_TPM2_OPENSSL_OPENSSL_POST300 0x1010100f
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

CK_RV ssl_util_attrs_to_evp(attr_list *attrs, EVP_PKEY **outpkey);

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

CK_RV ssl_util_add_PKCS1_PSS(EVP_PKEY *pkey,
        const CK_BYTE_PTR inbuf, const EVP_MD *md,
        CK_BYTE_PTR outbuf);

CK_RV ssl_util_add_PKCS1_TYPE_1(const CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG outbuflen);

CK_RV ssl_util_check_PKCS1_TYPE_2(const CK_BYTE_PTR inbuf, CK_ULONG inlen, CK_ULONG rsa_len,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outbuflen);

twist ssl_util_hash_pass(const twist pin, const twist salt);

/**
 * Given an attribute of CKA_EC_PARAMS returns the nid value.
 * @param ecparams
 *  The DER X9.62 parameters value
 * @param nid
 *  The nid to set
 * @return
 *  CKR_OK on success.
 */
CK_RV ssl_util_params_to_nid(CK_ATTRIBUTE_PTR ecparams, int *nid);

#endif /* SRC_LIB_SSL_UTIL_H_ */
