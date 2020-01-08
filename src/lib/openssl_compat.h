/* SPDX-License-Identifier: BSD-2-Clause */
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

#ifndef SRC_LIB_OPENSSL_COMPAT_H_
#define SRC_LIB_OPENSSL_COMPAT_H_

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL && !defined(LIBRESSL_VERSION_NUMBER)) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L) /* OpenSSL 1.1.0 */
#define LIB_TPM2_OPENSSL_OPENSSL_PRE11
#endif


#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
size_t EC_POINT_point2buf(const EC_GROUP *group, const EC_POINT *point,
                          point_conversion_form_t form,
                          unsigned char **pbuf, BN_CTX *ctx);

const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x);

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);

#endif

#endif /* SRC_LIB_OPENSSL_COMPAT_H_ */
