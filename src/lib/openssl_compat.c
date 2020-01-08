/* SPDX-License-Identifier: BSD-2-Clause */
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "openssl_compat.h"

#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)

/*
 * Pre openssl 1.1 doesn't have EC_POINT_point2buf, so use EC_POINT_point2oct to
 * create an API compatible version of it.
 */
size_t EC_POINT_point2buf(const EC_GROUP *group, const EC_POINT *point,
                          point_conversion_form_t form,
                          unsigned char **pbuf, BN_CTX *ctx) {

    /* Get the required buffer length */
    size_t len = EC_POINT_point2oct(group, point, form, NULL, 0, NULL);
    if (!len) {
        return 0;
    }

    /* allocate it */
    unsigned char *buf = OPENSSL_malloc(len);
    if (!buf) {
        return 0;
    }

    /* convert it */
    len = EC_POINT_point2oct(group, point, form, buf, len, ctx);
    if (!len) {
        OPENSSL_free(buf);
        return 0;
    }

    *pbuf = buf;
    return len;
}

size_t OBJ_length(const ASN1_OBJECT *obj) {

    if (!obj) {
        return 0;
    }

    return obj->length;
}

const unsigned char *OBJ_get0_data(const ASN1_OBJECT *obj) {

    if (!obj) {
        return NULL;
    }

    return obj->data;
}

const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x) {
    return ASN1_STRING_data((ASN1_STRING *)x);
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {

    if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL)) {
        return 0;
    }

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }

    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }

    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}

#endif
