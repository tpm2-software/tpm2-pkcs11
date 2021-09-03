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

#include "attrs.h"
#include "log.h"
#include "pkcs11.h"
#include "ssl_util.h"
#include "twist.h"

#if defined(LIB_TPM2_OPENSSL_OPENSSL_POST111)
#include <openssl/evperr.h>
#endif

#if defined(LIB_TPM2_OPENSSL_OPENSSL_POST300)
#include <openssl/core_names.h>
#endif

/*
 * TODO Port these routines
 * Deprecated function block to port
 *
 * There are no padding routine replacements in OSSL 3.0.
 *   - per Matt Caswell (maintainer) on mailing list.
 * Signature verification can likely be done with EVP Verify interface.
 */
#if defined(LIB_TPM2_OPENSSL_OPENSSL_POST300)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

CK_RV ssl_util_add_PKCS1_PSS(EVP_PKEY *pkey,
        const CK_BYTE_PTR inbuf, const EVP_MD *md,
        CK_BYTE_PTR outbuf) {

    RSA *rsa = (RSA *)EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        return CKR_GENERAL_ERROR;
    }

    int rc = RSA_padding_add_PKCS1_PSS(rsa, outbuf,
        inbuf, md, -1);

    return rc == 1 ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV ssl_util_add_PKCS1_TYPE_1(const CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG outbuflen) {

    return RSA_padding_add_PKCS1_type_1(outbuf, outbuflen,
            inbuf, inlen) == 1 ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV ssl_util_check_PKCS1_TYPE_2(const CK_BYTE_PTR inbuf, CK_ULONG inlen, CK_ULONG rsa_len,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outbuflen) {

    int rc = RSA_padding_check_PKCS1_type_2(outbuf, *outbuflen,
               inbuf, inlen, rsa_len);
    if (rc < 0) {
        return CKR_GENERAL_ERROR;
    }

    /* cannot be negative due to check above */
    *outbuflen = rc;
    return CKR_OK;
}

#if defined(LIB_TPM2_OPENSSL_OPENSSL_POST300)
#pragma GCC diagnostic pop
#endif

#if defined(LIB_TPM2_OPENSSL_OPENSSL_POST300)

static CK_RV get_RSA_evp_pubkey(CK_ATTRIBUTE_PTR e_attr, CK_ATTRIBUTE_PTR n_attr, EVP_PKEY **out_pkey) {

    OSSL_PARAM params[] = {
        OSSL_PARAM_BN("n", n_attr->pValue, n_attr->ulValueLen),
        OSSL_PARAM_BN("e", e_attr->pValue, e_attr->ulValueLen),
        OSSL_PARAM_END
    };

    /* convert params to EVP key */
    EVP_PKEY_CTX *evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!evp_ctx) {
        SSL_UTIL_LOGE("EVP_PKEY_CTX_new_id");
        return CKR_GENERAL_ERROR;
    }

    int rc = EVP_PKEY_fromdata_init(evp_ctx);
    if (rc != 1) {
        SSL_UTIL_LOGE("EVP_PKEY_fromdata_init");
        EVP_PKEY_CTX_free(evp_ctx);
        return CKR_GENERAL_ERROR;
    }

    rc = EVP_PKEY_fromdata(evp_ctx, out_pkey, EVP_PKEY_PUBLIC_KEY, params);
    if (rc != 1) {
        SSL_UTIL_LOGE("EVP_PKEY_fromdata");
        EVP_PKEY_CTX_free(evp_ctx);
        return CKR_GENERAL_ERROR;
    }

    EVP_PKEY_CTX_free(evp_ctx);

    return CKR_OK;
}

static CK_RV get_EC_evp_pubkey(CK_ATTRIBUTE_PTR ecparams, CK_ATTRIBUTE_PTR ecpoint, EVP_PKEY **out_pkey) {

    /*
     * The simplest way I have found to deal with this is to convert the ASN1 object in
     * the ecparams attribute (was done previously with d2i_ECParameters) is to a nid and
     * then take the int nid and convert it to a friendly name like prime256v1.
     * EVP_PKEY_fromdata can handle group by name.
     *
     * Per the spec this is "DER-encoding of an ANSI X9.62 Parameters value".
     */
    int curve_id = 0;
    CK_RV rv = ssl_util_params_to_nid(ecparams, &curve_id);
    if (rv != CKR_OK) {
        LOGE("Could not get nid from params");
        return rv;
    }

    /* Per the spec CKA_EC_POINT attribute is the "DER-encoding of ANSI X9.62 ECPoint value Q */
    const unsigned char *x = ecpoint->pValue;
    ASN1_OCTET_STRING *os = d2i_ASN1_OCTET_STRING(NULL, &x, ecpoint->ulValueLen);
    if (!os) {
        SSL_UTIL_LOGE("d2i_ASN1_OCTET_STRING: %s");
        return CKR_GENERAL_ERROR;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)OBJ_nid2sn(curve_id), 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, os->data, os->length),
        OSSL_PARAM_END
    };

    /* convert params to EVP key */
    EVP_PKEY_CTX *evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!evp_ctx) {
        SSL_UTIL_LOGE("EVP_PKEY_CTX_new_id");
        OPENSSL_free(os);
        return CKR_GENERAL_ERROR;
    }

    int rc = EVP_PKEY_fromdata_init(evp_ctx);
    if (rc != 1) {
        SSL_UTIL_LOGE("EVP_PKEY_fromdata_init: %s");
        EVP_PKEY_CTX_free(evp_ctx);
        OPENSSL_free(os);
        return CKR_GENERAL_ERROR;
    }

    rc = EVP_PKEY_fromdata(evp_ctx, out_pkey, EVP_PKEY_PUBLIC_KEY, params);
    if (rc != 1) {
        SSL_UTIL_LOGE("EVP_PKEY_fromdata");
        EVP_PKEY_CTX_free(evp_ctx);
        OPENSSL_free(os);
        return CKR_GENERAL_ERROR;
    }

    EVP_PKEY_CTX_free(evp_ctx);
    OPENSSL_free(os);

    return CKR_OK;
}

#else

static CK_RV get_RSA_evp_pubkey(CK_ATTRIBUTE_PTR e_attr, CK_ATTRIBUTE_PTR n_attr, EVP_PKEY **out_pkey) {

    BIGNUM *e = BN_bin2bn(e_attr->pValue, e_attr->ulValueLen, NULL);
    if (!e) {
        LOGE("Could not convert exponent to bignum");
        return CKR_GENERAL_ERROR;
    }

    BIGNUM *n = BN_bin2bn(n_attr->pValue, n_attr->ulValueLen, NULL);
    if (!n) {
        LOGE("Could not convert modulus to bignum");
        BN_free(e);
        return CKR_GENERAL_ERROR;
    }

    RSA *rsa = RSA_new();
    if (!rsa) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    int rc = RSA_set0_key(rsa, n, e, NULL);
    if (!rc) {
        LOGE("Could not set modulus and exponent to OSSL RSA key");
        BN_free(n);
        BN_free(e);
        RSA_free(rsa);
        return CKR_GENERAL_ERROR;
    }

    /* assigned to RSA key */
    n = e = NULL;

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        SSL_UTIL_LOGE("EVP_PKEY_new");
        RSA_free(rsa);
        return CKR_GENERAL_ERROR;
    }

    rc = EVP_PKEY_assign_RSA(pkey, rsa);
    if (rc != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return CKR_GENERAL_ERROR;
    }

    *out_pkey = pkey;

    return CKR_OK;
}

static CK_RV get_EC_evp_pubkey(CK_ATTRIBUTE_PTR ecparams, CK_ATTRIBUTE_PTR ecpoint, EVP_PKEY **out_pkey) {

    EC_KEY *ecc = EC_KEY_new();
    if (!ecc) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    /* set params */
    const unsigned char *x = ecparams->pValue;
    EC_KEY *k = d2i_ECParameters(&ecc, &x, ecparams->ulValueLen);
    if (!k) {
        SSL_UTIL_LOGE("Could not update key with EC Parameters");
        EC_KEY_free(ecc);
        return CKR_GENERAL_ERROR;
    }

    /* set point */
    x = ecpoint->pValue;
    ASN1_OCTET_STRING *os = d2i_ASN1_OCTET_STRING(NULL, &x, ecpoint->ulValueLen);
    if (os) {
        x = os->data;
        k = o2i_ECPublicKey(&ecc, &x, os->length);
        ASN1_STRING_free(os);
        if (!k) {
            SSL_UTIL_LOGE("Could not update key with EC Points");
            EC_KEY_free(ecc);
            return CKR_GENERAL_ERROR;
        }
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        SSL_UTIL_LOGE("EVP_PKEY_new");
        EC_KEY_free(ecc);
        return CKR_GENERAL_ERROR;
    }

    int rc = EVP_PKEY_assign_EC_KEY(pkey, ecc);
    if (!rc) {
        SSL_UTIL_LOGE("Could not set pkey with ec key");
        EC_KEY_free(ecc);
        EVP_PKEY_free(pkey);
        return CKR_GENERAL_ERROR;
    }

    *out_pkey = pkey;
    return CKR_OK;
}
#endif

CK_RV ssl_util_attrs_to_evp(attr_list *attrs, EVP_PKEY **outpkey) {

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, CKA_KEY_TYPE);
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

    else if (key_type == CKK_SHA_1_HMAC ||
               key_type == CKK_SHA256_HMAC ||
               key_type == CKK_SHA384_HMAC ||
               key_type == CKK_SHA512_HMAC ||
               key_type == CKK_GENERIC_SECRET) {
           /* Ignore HMAC keys no public operation possible */
           *outpkey = NULL;
           return CKR_OK;
    }

    EVP_PKEY *pkey = NULL;

    if (key_type == CKK_EC) {

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

        rv = get_EC_evp_pubkey(ecparams, ecpoint, &pkey);
        if (rv != CKR_OK) {
            return rv;
        }

    } else if (key_type == CKK_RSA) {

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

        rv = get_RSA_evp_pubkey(exp, mod, &pkey);
        if (rv != CKR_OK) {
            return rv;
        }

    } else {
        LOGE("Invalid CKA_KEY_TYPE, got: %lu", key_type);
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    assert(pkey);
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

    if (md) {
        rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, md);
        if (!rc) {
            SSL_UTIL_LOGE("EVP_PKEY_CTX_set_signature_md failed");
            goto error;
        }
    }

    *outpkey_ctx = pkey_ctx;

    return CKR_OK;

error:
    EVP_PKEY_CTX_free(pkey_ctx);
    return CKR_GENERAL_ERROR;
}

static CK_RV sig_verify(EVP_PKEY_CTX *ctx,
        const unsigned char *sig, size_t siglen,
        const unsigned char *tbs, size_t tbslen) {

    CK_RV rv = CKR_GENERAL_ERROR;
    int rc = EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen);
    if (rc < 0) {
        SSL_UTIL_LOGE("EVP_PKEY_verify failed");
    } else if (rc == 1) {
        rv = CKR_OK;
    } else {
        rv = CKR_SIGNATURE_INVALID;
    }

    return rv;
}

static CK_RV create_ecdsa_sig(CK_BYTE_PTR sig, CK_ULONG siglen,
        unsigned char  **outbuf, size_t *outlen) {

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

    int sig_len =i2d_ECDSA_SIG(ossl_sig, NULL);
    if (sig_len <= 0) {
        if (rc < 0) {
            SSL_UTIL_LOGE("ECDSA_do_verify failed");
        } else {
            LOGE("Expected length to be greater than 0");
        }
        ECDSA_SIG_free(ossl_sig);
        return CKR_GENERAL_ERROR;
    }

    unsigned char *buf = calloc(1, sig_len);
    if (!buf) {
        LOGE("oom");
        ECDSA_SIG_free(ossl_sig);
        return CKR_HOST_MEMORY;
    }

    unsigned char *p = buf;
    int sig_len2 = i2d_ECDSA_SIG(ossl_sig, &p);
    if (sig_len2 < 0) {
        SSL_UTIL_LOGE("ECDSA_do_verify failed");
        ECDSA_SIG_free(ossl_sig);
        free(buf);
        return CKR_GENERAL_ERROR;
    }

    assert(sig_len == sig_len2);

    ECDSA_SIG_free(ossl_sig);

    *outbuf = buf;
    *outlen = sig_len;

    return CKR_OK;
}

static CK_RV do_sig_verify_ec(EVP_PKEY *pkey,
        const EVP_MD *md,
        CK_BYTE_PTR digest, CK_ULONG digest_len,
        CK_BYTE_PTR signature, CK_ULONG signature_len) {

    /*
     * OpenSSL expects ASN1 framed signatures, PKCS11 does flat
     * R + S signatures, so convert it to ASN1 framing.
     * See:
     *   https://github.com/tpm2-software/tpm2-pkcs11/issues/277
     * For details.
     */
    unsigned char *buf = NULL;
    size_t buflen = 0;
    CK_RV rv = create_ecdsa_sig(signature, signature_len, &buf, &buflen);
    if (rv != CKR_OK) {
        return rv;
    }

    EVP_PKEY_CTX *pkey_ctx = NULL;
    rv = ssl_util_setup_evp_pkey_ctx(pkey, 0, md,
            EVP_PKEY_verify_init, &pkey_ctx);
    if (rv != CKR_OK) {
        free(buf);
        return rv;
    }

    rv = sig_verify(pkey_ctx, buf, buflen, digest, digest_len);

    EVP_PKEY_CTX_free(pkey_ctx);
    free(buf);

    return rv;
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

    rv = sig_verify(pkey_ctx, signature, signature_len, digest, digest_len);

    EVP_PKEY_CTX_free(pkey_ctx);
    return rv;
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
        return do_sig_verify_ec(pkey, md, digest, digest_len,
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

twist ssl_util_hash_pass(const twist pin, const twist salt) {


    twist out = NULL;
    unsigned char md[SHA256_DIGEST_LENGTH];

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        SSL_UTIL_LOGE("EVP_MD_CTX_new");
        return NULL;
    }

    int rc = EVP_DigestInit(ctx, EVP_sha256());
    if (rc != 1) {
        SSL_UTIL_LOGE("EVP_DigestInit");
        goto error;
    }

    rc = EVP_DigestUpdate(ctx, pin, twist_len(pin));
    if (rc != 1) {
        SSL_UTIL_LOGE("EVP_DigestUpdate");
        goto error;
    }

    rc = EVP_DigestUpdate(ctx, salt, twist_len(salt));
    if (rc != 1) {
        SSL_UTIL_LOGE("EVP_DigestUpdate");
        goto error;
    }

    unsigned int len = sizeof(md);
    rc = EVP_DigestFinal(ctx, md, &len);
    if (rc != 1) {
        SSL_UTIL_LOGE("EVP_DigestFinal");
        goto error;
    }

    /* truncate the password to 32 characters */
    out = twist_hex_new((char *)md, sizeof(md)/2);

error:
    EVP_MD_CTX_free(ctx);

    return out;
}

CK_RV ssl_util_params_to_nid(CK_ATTRIBUTE_PTR ecparams, int *nid) {

    const unsigned char *p = ecparams->pValue;

    ASN1_OBJECT *a = d2i_ASN1_OBJECT(NULL, &p, ecparams->ulValueLen);
    if (!a) {
        LOGE("Unknown CKA_EC_PARAMS value");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    *nid = OBJ_obj2nid(a);
    ASN1_OBJECT_free(a);

    return CKR_OK;
}
