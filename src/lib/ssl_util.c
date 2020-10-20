/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "log.h"
#include "pkcs11.h"
#include "ssl_util.h"
#include "twist.h"

#if defined(LIB_TPM2_OPENSSL_OPENSSL_POST111)
#include <openssl/evperr.h>
#endif

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

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {

    if (!r || !s) {
        return 0;
    }

    BN_free(sig->r);
    BN_free(sig->s);

    sig->r = r;
    sig->s = s;

    return 1;
}

EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey) {
    if (pkey->type != EVP_PKEY_EC) {
        return NULL;
    }

    return pkey->pkey.ec;
}
#endif

static CK_RV convert_pubkey_RSA(RSA **outkey, attr_list *attrs) {

    RSA *rsa = NULL;
    BIGNUM *e = NULL, *n = NULL;

    CK_ATTRIBUTE_PTR exp = attr_get_attribute_by_type(attrs, CKA_PUBLIC_EXPONENT);
    if (!exp) {
        LOGE("RSA Object must have attribute CKA_PUBLIC_EXPONENT");
        return CKR_GENERAL_ERROR;
    }

    CK_ATTRIBUTE_PTR mod = attr_get_attribute_by_type(attrs, CKA_MODULUS);
    if (!mod) {
        LOGE("RSA Object must have attribute CKA_MODULUS");
        return CKR_GENERAL_ERROR;
    }

    rsa = RSA_new();
    if (!rsa) {
        SSL_UTIL_LOGE("Failed to allocate OpenSSL RSA structure");
        goto error;
    }

    e = BN_bin2bn(exp->pValue, exp->ulValueLen, NULL);
    if (!e) {
        SSL_UTIL_LOGE("Failed to convert exponent to SSL internal format");
        goto error;
    }

    n = BN_bin2bn(mod->pValue, mod->ulValueLen, NULL);
    if (!n) {
        SSL_UTIL_LOGE("Failed to convert modulus to SSL internal format");
        goto error;
    }

    if (!RSA_set0_key(rsa, n, e, NULL)) {
        SSL_UTIL_LOGE("Failed to set RSA modulus and exponent components");
        RSA_free(rsa);
        BN_free(e);
        BN_free(n);
        goto error;
    }

    *outkey = rsa;

    return CKR_OK;

error:
    RSA_free(rsa);
    if (e) {
        BN_free(e);
    }
    if (n) {
        BN_free(n);
    }

    return CKR_GENERAL_ERROR;
}

static CK_RV convert_pubkey_ECC(EC_KEY **outkey, attr_list *attrs) {

    EC_KEY *key = EC_KEY_new();
    if (!key) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    CK_ATTRIBUTE_PTR ecparams = attr_get_attribute_by_type(attrs, CKA_EC_PARAMS);
    if (!ecparams) {
        LOGE("ECC Key must have attribute CKA_EC_PARAMS");
        return CKR_GENERAL_ERROR;
    }

    CK_ATTRIBUTE_PTR ecpoint = attr_get_attribute_by_type(attrs, CKA_EC_POINT);
    if (!ecpoint) {
        LOGE("ECC Key must have attribute CKA_EC_POINT");
        return CKR_GENERAL_ERROR;
    }

    /* set params */
    const unsigned char *x = ecparams->pValue;
    EC_KEY *k = d2i_ECParameters(&key, &x, ecparams->ulValueLen);
    if (!k) {
        SSL_UTIL_LOGE("Could not update key with EC Parameters");
        EC_KEY_free(key);
        return CKR_GENERAL_ERROR;
    }

    /* set point */
    x = ecpoint->pValue;
    ASN1_OCTET_STRING *os = d2i_ASN1_OCTET_STRING(NULL, &x, ecpoint->ulValueLen);
    if (os) {
        x = os->data;
        k = o2i_ECPublicKey(&key, &x, os->length);
        ASN1_STRING_free(os);
        if (!k) {
            SSL_UTIL_LOGE("Could not update key with EC Points");
            EC_KEY_free(key);
            return CKR_GENERAL_ERROR;
        }
    }

    *outkey = key;
    return CKR_OK;
}

CK_RV ssl_util_tobject_to_evp(EVP_PKEY **outpkey, tobject *obj) {

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(obj->attrs, CKA_KEY_TYPE);
    if (!a) {
        LOGE("Expected object to have attribute CKA_KEY_TYPE");
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    CK_KEY_TYPE key_type = CKK_RSA;
    CK_RV rv = attr_CK_KEY_TYPE(a, &key_type);
    if (rv != CKR_OK) {
        LOGE("Could not convert CK_KEY_TYPE");
        return rv;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    if (key_type == CKK_EC) {
        EC_KEY *e = NULL;
        rv = convert_pubkey_ECC(&e, obj->attrs);
        if (rv != CKR_OK) {
            return rv;
        }
        int rc = EVP_PKEY_assign_EC_KEY(pkey, e);
        if (!rc) {
            SSL_UTIL_LOGE("Could not set pkey with ec key");
            EC_KEY_free(e);
            EVP_PKEY_free(pkey);
            return CKR_GENERAL_ERROR;
        }
    } else if (key_type == CKK_RSA) {
        RSA *r = NULL;
        rv = convert_pubkey_RSA(&r, obj->attrs);
        if (rv != CKR_OK) {
            return rv;
        }
        int rc = EVP_PKEY_assign_RSA(pkey, r);
        if (!rc) {
            SSL_UTIL_LOGE("Could not set pkey with rsa key");
            RSA_free(r);
            EVP_PKEY_free(pkey);
            return CKR_GENERAL_ERROR;
        }
    } else {
        LOGE("Invalid CKA_KEY_TYPE, got: %lu", key_type);
        EVP_PKEY_free(pkey);
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    *outpkey = pkey;

    return CKR_OK;
}

CK_RV ssl_util_encrypt(EVP_PKEY *pkey,
        int padding, twist label, const EVP_MD *md,
        CK_BYTE_PTR ptext, CK_ULONG ptextlen,
        CK_BYTE_PTR ctext, CK_ULONG_PTR ctextlen) {

    assert(pkey);

    CK_RV rv = CKR_GENERAL_ERROR;

    if (!ctext) {
        *ctextlen = EVP_PKEY_size(pkey);
        return CKR_OK;
    }

    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx) {
        LOGE("OOM");
        return CKR_HOST_MEMORY;
    }

    int rc = EVP_PKEY_encrypt_init(pkey_ctx);
    if (rc <= 0) {
        SSL_UTIL_LOGE("EVP_PKEY_encrypt_init");
        goto error;
    }

    if (padding) {
        rc = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding);
        if (rc <= 0) {
            SSL_UTIL_LOGE("Could not set padding");
            goto error;
        }
    }

    if (label) {
        assert(padding == RSA_PKCS1_OAEP_PADDING);

        /* make a copy since OSSL calls OSSL_free on label */
        size_t len = twist_len(label);
        char *label2 = OPENSSL_memdup(label, len);
        if (!label2) {
            LOGE("oom");
            return CKR_HOST_MEMORY;
        }

        rc = EVP_PKEY_CTX_set0_rsa_oaep_label(pkey_ctx,
                label2, len);
        if (rc <= 0) {
            SSL_UTIL_LOGE("EVP_PKEY_CTX_set0_rsa_oaep_label");
            goto error;
        }
    }

    if (md) {
        assert(padding == RSA_PKCS1_OAEP_PADDING);
        rc = EVP_PKEY_CTX_set_rsa_oaep_md(pkey_ctx, md);
        if (rc <= 0) {
            SSL_UTIL_LOGE("EVP_PKEY_CTX_set_rsa_oaep_md");
            goto error;
        }
    }

    size_t outlen = *ctextlen;
    rc = EVP_PKEY_encrypt(pkey_ctx, ctext, &outlen, ptext, ptextlen);
    if (rc <= 0) {
        unsigned long r = ERR_get_error();
        int reason = ERR_GET_REASON(r);
        if (reason == EVP_R_BUFFER_TOO_SMALL) {
            *ctextlen = EVP_PKEY_size(pkey);
            rv = CKR_BUFFER_TOO_SMALL;
        } else {
            LOGE("Could not perform RSA public encrypt: %s", ERR_error_string(r, NULL));
        }
        goto error;
    }

    *ctextlen = outlen;
    rv = CKR_OK;

error:
    EVP_PKEY_CTX_free(pkey_ctx);

    return rv;
}

CK_RV ssl_util_setup_evp_pkey_ctx(EVP_PKEY *pkey,
        int padding, const EVP_MD *md,
        fn_EVP_PKEY_init init_fn,
        EVP_PKEY_CTX **outpkey_ctx) {

    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx) {
        SSL_UTIL_LOGE("EVP_PKEY_CTX_new failed");
        return CKR_GENERAL_ERROR;
    }

    int rc = init_fn(pkey_ctx);
    if (!rc) {
        SSL_UTIL_LOGE("EVP_PKEY_verify_init failed");
        goto error;
    }

    if (padding) {
        rc = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding);
        if (!rc) {
            SSL_UTIL_LOGE("EVP_PKEY_CTX_set_rsa_padding failed");
            goto error;
        }
    }

    rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, md);
    if (!rc) {
        SSL_UTIL_LOGE("EVP_PKEY_CTX_set_signature_md failed");
        goto error;
    }

    *outpkey_ctx = pkey_ctx;

    return CKR_OK;

error:
    EVP_PKEY_CTX_free(pkey_ctx);
    return CKR_GENERAL_ERROR;
}

static CK_RV do_sig_verify_rsa(EVP_PKEY *pkey,
        int padding, const EVP_MD *md,
        CK_BYTE_PTR digest, CK_ULONG digest_len,
        CK_BYTE_PTR signature, CK_ULONG signature_len) {

    CK_RV rv = CKR_GENERAL_ERROR;

    EVP_PKEY_CTX *pkey_ctx = NULL;
    rv = ssl_util_setup_evp_pkey_ctx(pkey, padding, md,
            EVP_PKEY_verify_init, &pkey_ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    int rc = EVP_PKEY_verify(pkey_ctx, signature, signature_len, digest, digest_len);
    if (rc < 0) {
        SSL_UTIL_LOGE("EVP_PKEY_verify failed");
    } else if (rc == 1) {
        rv = CKR_OK;
    } else {
        rv = CKR_SIGNATURE_INVALID;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    return rv;
}

static CK_RV create_ecdsa_sig(CK_BYTE_PTR sig, CK_ULONG siglen, ECDSA_SIG **outsig) {

    if (siglen & 1) {
        LOGE("Expected ECDSA signature length to be even, got : %lu",
                siglen);
        return CKR_SIGNATURE_LEN_RANGE;
    }

    size_t len = siglen >> 1;

    unsigned char *rbuf = sig;
    unsigned char *sbuf = &sig[len];

    BIGNUM *r = BN_bin2bn(rbuf, len, NULL);
    if (!r) {
        LOGE("Could not make bignum for r");
        return CKR_GENERAL_ERROR;
    }

    BIGNUM *s = BN_bin2bn(sbuf, len, NULL);
    if (!s) {
        LOGE("Could not make bignum for s");
        BN_free(r);
        return CKR_GENERAL_ERROR;
    }

    ECDSA_SIG *ossl_sig = ECDSA_SIG_new();
    if (!ossl_sig) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    int rc = ECDSA_SIG_set0(ossl_sig, r, s);
    if (!rc) {
        LOGE("Could not call ECDSA_SIG_set0");
        ECDSA_SIG_free(ossl_sig);
        return CKR_GENERAL_ERROR;
    }

    *outsig = ossl_sig;

    return CKR_OK;
}

static CK_RV do_sig_verify_ec(EVP_PKEY *pkey,
        CK_BYTE_PTR digest, CK_ULONG digest_len,
        CK_BYTE_PTR signature, CK_ULONG signature_len) {

    EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
    if (!eckey) {
        LOGE("Expected EC Key");
        return CKR_GENERAL_ERROR;
    }

    /*
     * OpenSSL expects ASN1 framed signatures, PKCS11 does flate
     * R + S signatures, so convert it to ASN1 framing.
     * See:
     *   https://github.com/tpm2-software/tpm2-pkcs11/issues/277
     * For details.
     */
    ECDSA_SIG *ossl_sig = NULL;
    CK_RV rv = create_ecdsa_sig(signature, signature_len, &ossl_sig);
    if (rv != CKR_OK) {
        return rv;
    }

    int rc = ECDSA_do_verify(digest, digest_len, ossl_sig, eckey);
    if (rc < 0) {
        ECDSA_SIG_free(ossl_sig);
        SSL_UTIL_LOGE("ECDSA_do_verify failed");
        return CKR_GENERAL_ERROR;
    }
    ECDSA_SIG_free(ossl_sig);

    return rc == 1 ? CKR_OK : CKR_SIGNATURE_INVALID;
}

CK_RV ssl_util_sig_verify(EVP_PKEY *pkey,
        int padding, const EVP_MD *md,
        CK_BYTE_PTR digest, CK_ULONG digest_len,
        CK_BYTE_PTR signature, CK_ULONG signature_len) {

    int type = EVP_PKEY_type(EVP_PKEY_id(pkey));
    switch (type) {
    case EVP_PKEY_RSA:
        return do_sig_verify_rsa(pkey, padding, md,
                digest, digest_len,
                signature, signature_len);
    case EVP_PKEY_EC:
        return do_sig_verify_ec(pkey, digest, digest_len,
                signature, signature_len);
    default:
        LOGE("Unknown PKEY type, got: %d", type);
        return CKR_GENERAL_ERROR;
    }
}

CK_RV ssl_util_verify_recover(EVP_PKEY *pkey,
        int padding, const EVP_MD *md,
        CK_BYTE_PTR signature, CK_ULONG signature_len,
        CK_BYTE_PTR data, CK_ULONG_PTR data_len) {

    int type = EVP_PKEY_type(EVP_PKEY_id(pkey));
    if (type != EVP_PKEY_RSA) {
        LOGE("Cannot perform verify recover on non RSA key types");
        return CKR_GENERAL_ERROR;
    }

    EVP_PKEY_CTX *pkey_ctx = NULL;
    CK_RV rv = ssl_util_setup_evp_pkey_ctx(pkey, padding, md,
            EVP_PKEY_verify_recover_init, &pkey_ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    int rc = EVP_PKEY_verify_recover(pkey_ctx, data, (size_t*) data_len,
            signature, signature_len);
    if (rc < 0) {
        SSL_UTIL_LOGE("EVP_PKEY_verify_recover failed");
    } else if (rc == 1) {
        rv = CKR_OK;
    } else {
        rv = CKR_SIGNATURE_INVALID;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    return rv;
}
