/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "attrs.h"
#include "checks.h"
#include "log.h"
#include "mech.h"
#include "object.h"
#include "ssl_util.h"
#include "pkcs11.h"
#include "tpm.h"
#include "utils.h"

#define MAX_MECHS 128

typedef enum mechanism_flags mechanism_flags;
enum mechanism_flags {
    mf_tpm_supported = 1 << 0,
    mf_is_keygen     = 1 << 1,
    mf_is_synthetic  = 1 << 3,
    mf_is_digester   = 1 << 4,
    mf_sign          = 1 << 5,
    mf_verify        = 1 << 6,
    mf_encrypt       = 1 << 7,
    mf_decrypt       = 1 << 8,
    mf_rsa           = 1 << 9,
    mf_ecc           = 1 << 10,
    mf_aes           = 1 << 11,
    mf_force_synthetic     = 1 << 11,
};

/*
 * Validates that the mechanism parameters are sane and supported
 */
typedef CK_RV (*fn_validator)(CK_MECHANISM_PTR mech, attr_list *attrs);

/*
 * Some crypto operations can be synthesized (padding done off hw and raw crypto performed)
 * This routine would do all those steps.
 */
typedef CK_RV (*fn_synthesizer)(CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);

typedef CK_RV (*fn_get_halg)(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE *halg);

typedef CK_RV (*fn_get_digester)(CK_MECHANISM_PTR mech, const EVP_MD **md);

typedef CK_RV (*fn_get_tpm_opdata)(tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **encdata);

typedef struct mdetail mdetail;
struct mdetail {
    CK_MECHANISM_TYPE type;

    fn_validator validator;
    fn_synthesizer synthesizer;
    fn_get_tpm_opdata get_tpm_opdata;
    fn_get_halg get_halg;
    fn_get_digester get_digester;

    int padding;

    mechanism_flags flags;
};

#define DO_INIT(tctx) \
do { \
    CK_RV rv = mech_init(tctx); \
    if (rv != CKR_OK) { \
        return rv; \
    } \
} while (0)

static CK_RV rsa_keygen_validator(CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_pkcs_validator(CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_pss_validator(CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_oaep_validator(CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_pkcs_hash_validator(CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_pss_hash_validator(CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV ecc_keygen_validator(CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV ecdsa_validator(CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV hash_validator(CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_pkcs_synthesizer(CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);
static CK_RV rsa_pss_synthesizer(CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);
static CK_RV rsa_pkcs_hash_synthesizer(CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);
static CK_RV rsa_pss_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);
static CK_RV rsa_oaep_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);
static CK_RV sha1_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);
static CK_RV sha256_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);
static CK_RV sha384_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);
static CK_RV sha512_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);

static CK_RV rsa_pss_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md);
static CK_RV rsa_oaep_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md);
static CK_RV sha1_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md);
static CK_RV sha256_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md);
static CK_RV sha384_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md);
static CK_RV sha512_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md);

static CK_RV tpm_rsa_pss_get_opdata(tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata);

static bool _g_is_initialized = false;

static mdetail _g_mechs[MAX_MECHS] = {

    /* RSA */
    { .type = CKM_RSA_PKCS_KEY_PAIR_GEN, .validator = rsa_keygen_validator, .flags = mf_is_keygen|mf_rsa },

    { .type = CKM_RSA_X_509, .flags = mf_is_synthetic|mf_sign|mf_verify|mf_encrypt|mf_decrypt|mf_rsa, .get_tpm_opdata = tpm_rsa_pkcs_get_opdata, .padding = RSA_NO_PADDING },

    { .type = CKM_RSA_PKCS,      .flags = mf_force_synthetic|mf_sign|mf_verify|mf_encrypt|mf_decrypt|mf_rsa, .validator = rsa_pkcs_validator, .synthesizer = rsa_pkcs_synthesizer, .get_tpm_opdata = tpm_rsa_pkcs_get_opdata, .padding = RSA_PKCS1_PADDING },

    { .type = CKM_RSA_PKCS_PSS,  .flags = mf_sign|mf_verify|mf_rsa, .validator = rsa_pss_validator,  .get_halg = rsa_pss_get_halg,  .get_digester = rsa_pss_get_digester, .synthesizer = rsa_pss_synthesizer, .get_tpm_opdata = tpm_rsa_pss_get_opdata, .padding = RSA_PKCS1_PSS_PADDING },

    { .type = CKM_RSA_PKCS_OAEP, . flags = mf_encrypt|mf_decrypt|mf_rsa,  .validator = rsa_oaep_validator, .get_halg = rsa_oaep_get_halg, .get_digester = rsa_oaep_get_digester, .get_tpm_opdata = tpm_rsa_oaep_get_opdata, .padding = RSA_PKCS1_OAEP_PADDING },

    { .type = CKM_SHA1_RSA_PKCS,   .flags = mf_sign|mf_verify|mf_rsa, .validator = rsa_pkcs_hash_validator, .synthesizer = rsa_pkcs_hash_synthesizer, .get_halg = sha1_get_halg, .get_digester = sha1_get_digester,     .get_tpm_opdata = tpm_rsa_pkcs_sha1_get_opdata,   .padding = RSA_PKCS1_PADDING },
    { .type = CKM_SHA256_RSA_PKCS, .flags = mf_sign|mf_verify|mf_rsa, .validator = rsa_pkcs_hash_validator, .synthesizer = rsa_pkcs_hash_synthesizer, .get_halg = sha256_get_halg, .get_digester = sha256_get_digester, .get_tpm_opdata = tpm_rsa_pkcs_sha256_get_opdata, .padding = RSA_PKCS1_PADDING },
    { .type = CKM_SHA384_RSA_PKCS, .flags = mf_sign|mf_verify|mf_rsa, .validator = rsa_pkcs_hash_validator, .synthesizer = rsa_pkcs_hash_synthesizer, .get_halg = sha384_get_halg, .get_digester = sha384_get_digester, .get_tpm_opdata = tpm_rsa_pkcs_sha384_get_opdata, .padding = RSA_PKCS1_PADDING },
    { .type = CKM_SHA512_RSA_PKCS, .flags = mf_sign|mf_verify|mf_rsa, .validator = rsa_pkcs_hash_validator, .synthesizer = rsa_pkcs_hash_synthesizer, .get_halg = sha512_get_halg, .get_digester = sha512_get_digester, .get_tpm_opdata = tpm_rsa_pkcs_sha512_get_opdata, .padding = RSA_PKCS1_PADDING },

    { .type = CKM_SHA1_RSA_PKCS_PSS,   .flags = mf_sign|mf_verify|mf_rsa, .validator = rsa_pss_hash_validator, .get_halg = sha1_get_halg, .get_digester = sha1_get_digester,     .synthesizer = rsa_pss_synthesizer, .get_tpm_opdata = tpm_rsa_pss_sha1_get_opdata,   .padding = RSA_PKCS1_PSS_PADDING },
    { .type = CKM_SHA256_RSA_PKCS_PSS, .flags = mf_sign|mf_verify|mf_rsa, .validator = rsa_pss_hash_validator, .get_halg = sha256_get_halg, .get_digester = sha256_get_digester, .synthesizer = rsa_pss_synthesizer, .get_tpm_opdata = tpm_rsa_pss_sha256_get_opdata, .padding = RSA_PKCS1_PSS_PADDING },
    { .type = CKM_SHA384_RSA_PKCS_PSS, .flags = mf_sign|mf_verify|mf_rsa, .validator = rsa_pss_hash_validator, .get_halg = sha384_get_halg, .get_digester = sha384_get_digester, .synthesizer = rsa_pss_synthesizer, .get_tpm_opdata = tpm_rsa_pss_sha384_get_opdata, .padding = RSA_PKCS1_PSS_PADDING },
    { .type = CKM_SHA512_RSA_PKCS_PSS, .flags = mf_sign|mf_verify|mf_rsa, .validator = rsa_pss_hash_validator, .get_halg = sha512_get_halg, .get_digester = sha512_get_digester, .synthesizer = rsa_pss_synthesizer, .get_tpm_opdata = tpm_rsa_pss_sha512_get_opdata, .padding = RSA_PKCS1_PSS_PADDING },

    /* EC */
    { .type = CKM_EC_KEY_PAIR_GEN, .flags = mf_is_keygen|mf_ecc,      .validator = ecc_keygen_validator },

    { .type = CKM_ECDSA,           .flags = mf_sign|mf_verify|mf_ecc, .validator = ecdsa_validator, .get_tpm_opdata = tpm_ec_ecdsa_get_opdata },

    { .type = CKM_ECDSA_SHA1,      .flags = mf_sign|mf_verify|mf_ecc, .validator = ecdsa_validator, .get_halg = sha1_get_halg, .get_digester = sha1_get_digester, .get_tpm_opdata = tpm_ec_ecdsa_sha1_get_opdata },

    /* AES */
    { .type = CKM_AES_KEY_GEN, .flags = mf_is_keygen|mf_aes },

    { .type = CKM_AES_CBC,    .flags = mf_encrypt|mf_decrypt|mf_aes, .get_tpm_opdata = tpm_aes_cbc_get_opdata },
    { .type = CKM_AES_CFB128, .flags = mf_encrypt|mf_decrypt|mf_aes, .get_tpm_opdata = tpm_aes_cfb_get_opdata },
    { .type = CKM_AES_ECB,    .flags = mf_encrypt|mf_decrypt|mf_aes, .get_tpm_opdata = tpm_aes_ecb_get_opdata },

    /* hashing */
    { .type = CKM_SHA_1,  .flags = mf_is_digester|mf_aes, .validator = hash_validator, .get_digester = sha1_get_digester },
    { .type = CKM_SHA256, .flags = mf_is_digester|mf_aes, .validator = hash_validator, .get_digester = sha256_get_digester },
    { .type = CKM_SHA384, .flags = mf_is_digester|mf_aes, .validator = hash_validator, .get_digester = sha384_get_digester },
    { .type = CKM_SHA512, .flags = mf_is_digester|mf_aes, .validator = hash_validator, .get_digester = sha512_get_digester },
};

static struct {
    CK_ULONG bits;
    bool supported;
} _g_rsa_keysizes [] = {
    { .bits = 1024 },
    { .bits = 2048 },
    { .bits = 3072 },
    { .bits = 4096 },
};

static struct {
    int nid;
    bool supported;
} _g_ecc_curve_nids [] = {
    { .nid = NID_X9_62_prime192v1 },
    { .nid = NID_secp224r1        },
    { .nid = NID_X9_62_prime256v1 },
    { .nid = NID_secp384r1,       },
    { .nid = NID_secp521r1,       },
};

#define _L(a) (a->ulValueLen/sizeof(CK_MECHANISM_TYPE))
#define _P(a) ((CK_MECHANISM_TYPE_PTR)a->pValue)

static mdetail *mlookup(CK_MECHANISM_TYPE t) {

    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(_g_mechs); i++) {
        mdetail *m = &_g_mechs[i];
        if (m->type == t) {
            return m;
        }
    }

    return NULL;
}

static CK_RV has_raw_rsa(attr_list *attrs) {

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, CKA_ALLOWED_MECHANISMS);
    if (!a) {
        LOGE("Expected CKA_ALLOWED_MECHANISMS");
        return CKR_GENERAL_ERROR;
    }

    /* If the TPM doesn't support it, it needs to support raw sign */
    bool supported = false;
    CK_ULONG i;
    for (i=0; i < _L(a); i++) {
        CK_MECHANISM_TYPE t = _P(a)[i];
        if (t == CKM_RSA_X_509) {
            supported = true;
            break;
        }
    }

    return supported ? CKR_OK : CKR_MECHANISM_INVALID;
}

CK_RV hash_validator(CK_MECHANISM_PTR mech, attr_list *attrs) {
    UNUSED(attrs);

    /* hashers don't take params */
    if (mech->pParameter || mech->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* all known hashing digests are supported in software */

    return CKR_OK;
}

CK_RV rsa_pkcs_validator(CK_MECHANISM_PTR mech, attr_list *attrs) {

    /*
     * CKM_RSA_PKCS has the PKCS v1.5 signing structure computed by the client
     * and requires only padding, so no parameters should be set
     */
    if (mech->pParameter || mech->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return has_raw_rsa(attrs);
}

CK_RV rsa_pkcs_hash_validator(CK_MECHANISM_PTR mech, attr_list *attrs) {

    /* CKM_<HASH>_RSA_PKCS takes no params */
    if (mech->pParameter || mech->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* it needs to be supported */
    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    /* if the TPM supports it natively, we're done */
    if (m->flags & mf_tpm_supported) {
        return CKR_OK;
    }

    return has_raw_rsa(attrs);
}

CK_RV rsa_pss_validator(CK_MECHANISM_PTR mech, attr_list *attrs) {
    UNUSED(attrs);

    /* it needs to be supported */
    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    CK_RSA_PKCS_PSS_PARAMS_PTR params;
    SAFE_CAST(mech, params);

    /* no SHA224 support AFAIK */
    if (params->mgf == CKG_MGF1_SHA224) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    CK_MECHANISM_TYPE halg = 0;
    CK_RV rv = m->get_halg(mech, &halg);
    if (rv != CKR_OK) {
        return rv;
    }

    if (halg != params->hashAlg) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /*
     * The TPM fixes the MGF to the hash algorithm and the salt to the hashlen.
     */
    if (params->hashAlg == CKM_SHA_1
            && ((params->mgf != CKG_MGF1_SHA1) ||(params->sLen != 20)) ) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (params->hashAlg == CKM_SHA256
            && ((params->mgf != CKG_MGF1_SHA256) ||(params->sLen != 32)) ) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (params->hashAlg == CKM_SHA384
            && ((params->mgf != CKG_MGF1_SHA384) ||(params->sLen != 48)) ) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (params->hashAlg == CKM_SHA512
            && ((params->mgf != CKG_MGF1_SHA512) ||(params->sLen != 64)) ) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /*
     * now that the PSS portion IS supported AND the mechanism params check out,
     * we need raw RSA, do we have it?
     */
    return has_raw_rsa(attrs);
}

CK_RV rsa_oaep_validator(CK_MECHANISM_PTR mech, attr_list *attrs) {
    UNUSED(attrs);

    /* it needs to be supported */
    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    CK_RSA_PKCS_OAEP_PARAMS_PTR params;
    SAFE_CAST(mech, params);

    /* no SHA224 support AFAIK */
    if (params->mgf == CKG_MGF1_SHA224) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    CK_MECHANISM_TYPE halg = 0;
    CK_RV rv = m->get_halg(mech, &halg);
    if (rv != CKR_OK) {
        return rv;
    }

    if (halg != params->hashAlg) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (!params->source) {

        if (params->pSourceData || params->ulSourceDataLen) {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        return CKR_OK;
    }

    if (params->source != CKZ_DATA_SPECIFIED) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /*
     * now that the OAEP portion IS supported AND the mechanism params check out,
     * is supported natively?
     */
    if (m->flags & mf_tpm_supported) {
        return CKR_OK;
    }

    return CKR_MECHANISM_INVALID;
}

CK_RV rsa_pss_hash_validator(CK_MECHANISM_PTR mech, attr_list *attrs) {

    /* it needs to be supported */
    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    /* this may have an argument */
    if (mech->pParameter || mech->ulParameterLen) {
        return rsa_pss_validator(mech, attrs);
    }

    /*
     * now that the PSS portion IS supported AND the mechanism params check out,
     * we need raw RSA, do we have it?
     */
    return has_raw_rsa(attrs);
}

CK_RV rsa_keygen_validator(CK_MECHANISM_PTR mech, attr_list *attrs) {

    /* it needs to be supported */
    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    /* this requires no argument */
    if (!mech->pParameter || !mech->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, CKA_MODULUS);
    if (!a) {
        return CKR_TEMPLATE_INCOMPLETE;
    }

    CK_ULONG bits = a->ulValueLen * 8;

    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(_g_rsa_keysizes); i++) {
        if (_g_rsa_keysizes[i].bits == bits) {
            return _g_rsa_keysizes[i].supported ?
                    CKR_OK : CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    return CKR_ATTRIBUTE_VALUE_INVALID;
}

CK_RV ecc_keygen_validator(CK_MECHANISM_PTR mech, attr_list *attrs) {

    /* it needs to be supported */
    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    /* this requires no argument */
    if (!mech->pParameter || !mech->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, CKA_EC_PARAMS);
    if (!a) {
        return CKR_TEMPLATE_INCOMPLETE;
    }

    int nid = 0;
    CK_RV rv = ec_params_to_nid(a, &nid);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(_g_rsa_keysizes); i++) {
        if (_g_ecc_curve_nids[i].nid == nid) {
            return _g_ecc_curve_nids[i].supported ?
                    CKR_OK : CKR_MECHANISM_INVALID;
        }
    }

    return CKR_MECHANISM_INVALID;
}

CK_RV ecdsa_validator(CK_MECHANISM_PTR mech, attr_list *attrs) {
    UNUSED(attrs);

    /* ECDSA and ECDSA SHA1 are always supported */

    /* it needs to be supported */
    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    /* this does not require an argument */
    if (mech->pParameter || mech->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return CKR_OK;
}

CK_RV sha1_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg) {
    UNUSED(mech);
    *halg = CKM_SHA_1;
    return CKR_OK;
}

CK_RV sha256_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg) {
    UNUSED(mech);
    *halg = CKM_SHA256;
    return CKR_OK;
}

CK_RV sha384_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg) {
    UNUSED(mech);
    *halg = CKM_SHA384;
    return CKR_OK;
}

CK_RV sha512_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg) {
    UNUSED(mech);
    *halg = CKM_SHA512;
    return CKR_OK;
}

static CK_RV rsa_pss_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg) {

    /* this should never fail on the look up */
    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        return CKR_GENERAL_ERROR;
    }

    CK_RSA_PKCS_PSS_PARAMS_PTR params;
    SAFE_CAST(mech, params);

    *halg = params->hashAlg;

    return CKR_OK;
}

static CK_RV rsa_oaep_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg) {

    CK_RSA_PKCS_OAEP_PARAMS_PTR params;
    SAFE_CAST(mech, params);

    *halg = params->hashAlg;

    return CKR_OK;
}

CK_RV rsa_pss_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md) {

    CK_MECHANISM_TYPE halg = 0;
    CK_RV rv = rsa_pss_get_halg(mech, &halg);
    if (rv != CKR_OK) {
        return rv;
    }

    mdetail *m = mlookup(halg);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    return m->get_digester(mech, md);
}

CK_RV rsa_oaep_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md) {

    CK_MECHANISM_TYPE halg = 0;
    CK_RV rv = rsa_oaep_get_halg(mech, &halg);
    if (rv != CKR_OK) {
        return rv;
    }

    mdetail *m = mlookup(halg);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    return m->get_digester(mech, md);
}

CK_RV sha1_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md) {
    UNUSED(mech);
    *md = EVP_sha1();
    return CKR_OK;
}

CK_RV sha256_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md) {
    UNUSED(mech);
    *md = EVP_sha256();
    return CKR_OK;
}

CK_RV sha384_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md) {
    UNUSED(mech);
    *md = EVP_sha384();
    return CKR_OK;
}

CK_RV sha512_get_digester(CK_MECHANISM_PTR mech, const EVP_MD **md) {
    UNUSED(mech);
    *md = EVP_sha512();
    return CKR_OK;
}

static CK_RV mech_init(tpm_ctx *tctx) {

    if (_g_is_initialized) {
        return CKR_OK;
    }

    /*
     * Get the mechanisms
     */
    CK_MECHANISM_TYPE tpm_mechs[MAX_MECHS];
    CK_ULONG tpm_mechs_len = ARRAY_LEN(tpm_mechs);
    CK_RV rv = tpm2_getmechanisms(tctx, tpm_mechs, &tpm_mechs_len);
    if (rv != CKR_OK) {
        return rv;
    }

    assert(tpm_mechs_len <= ARRAY_LEN(_g_mechs));

    /*
     * Update whether or not the TPM supports it ot not
     * and any other metadata
     */
    CK_ULONG i;
    for (i=0; i < tpm_mechs_len; i++) {
        CK_MECHANISM_TYPE t = tpm_mechs[i];
        mdetail *m = NULL;
        CK_ULONG j;
        for (j=0; j < ARRAY_LEN(_g_mechs); j++) {
            m = &_g_mechs[j];
            if (m->type == t) {
                m->flags |= mf_tpm_supported;
                break;
            }
        }
    }

    mdetail *m = mlookup(CKM_RSA_PKCS_KEY_PAIR_GEN);
    if (m) {
        /* get supported RSA key bit sizes */
        for (i=0; i < ARRAY_LEN(_g_rsa_keysizes); i++) {
            rv = tpm_is_rsa_keysize_supported(tctx, _g_rsa_keysizes[i].bits);
            if (rv == CKR_MECHANISM_INVALID) {
                continue;
            }

            if(rv == CKR_OK) {
                _g_rsa_keysizes[i].supported = true;
                continue;
            }

            return rv;
        }
    } else {
        LOGV("RSA Keygen not detected");
    }

    m = mlookup(CKM_EC_KEY_PAIR_GEN);
    if (m) {
        /* get supported ECC curves */
        for (i=0; i < ARRAY_LEN(_g_ecc_curve_nids); i++) {
            rv = tpm_is_ecc_curve_supported(tctx, _g_ecc_curve_nids[i].nid);
            if (rv == CKR_MECHANISM_INVALID) {
                continue;
            }

            if(rv == CKR_OK) {
                _g_ecc_curve_nids[i].supported = true;
                continue;
            }

            return rv;
        }
    } else {
        LOGV("EC Keygen not detected");
    }

    _g_is_initialized = true;

    return CKR_OK;
}

CK_RV rsa_pkcs_synthesizer(CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen) {
    UNUSED(mech);

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, CKA_MODULUS_BITS);
    if (!a) {
        LOGE("Signing key has no CKA_MODULUS_BITS");
        return CKR_GENERAL_ERROR;
    }

    if (a->ulValueLen != sizeof(CK_ULONG)) {
        LOGE("Modulus bit pointer data not size of CK_ULONG, got %lu, expected %zu",
                a->ulValueLen, sizeof(CK_ULONG));
        return CKR_GENERAL_ERROR;
    }

    CK_ULONG_PTR keybits = (CK_ULONG_PTR)a->pValue;

    size_t padded_len = *keybits / 8;

    if (*outlen < padded_len) {
        LOGE("Internal buffer is too small, got: %lu, required %lu",
                *outlen, padded_len);
        return CKR_GENERAL_ERROR;
    }

    /* Apply the PKCS1.5 padding */
    int rc = RSA_padding_add_PKCS1_type_1(outbuf, padded_len,
            inbuf, inlen);
    if (!rc) {
        LOGE("Applying RSA padding failed");
        return CKR_GENERAL_ERROR;
    }

    *outlen = padded_len;

    return CKR_OK;
}

CK_RV rsa_pss_synthesizer(CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen) {

    const EVP_MD *md = NULL;
    CK_RV rv = mech_get_digester(mech, &md);
    if (rv != CKR_OK) {
        LOGE("Could not get digester for mech: 0x%lx", mech->mechanism);
        return rv;
    }

    int expected_len = EVP_MD_size(md);
    if (expected_len <= 0) {
        LOGE("Hash size cannot be 0 or negative, got: %d",
                expected_len);
        return CKR_GENERAL_ERROR;
    }

    if (inlen != (unsigned)expected_len) {
        LOGE("Expected input size to be hash size, %lu != %d",
                inlen, expected_len);
        return CKR_GENERAL_ERROR;
    }

    CK_ATTRIBUTE_PTR modulus_attr = attr_get_attribute_by_type(attrs, CKA_MODULUS);
    if (!modulus_attr) {
        LOGE("Signing key has no CKA_MODULUS");
        return CKR_GENERAL_ERROR;
    }

    CK_ATTRIBUTE_PTR exp_attr = attr_get_attribute_by_type(attrs, CKA_PUBLIC_EXPONENT);
    if (!exp_attr) {
        LOGE("Signing key has no CKA_PUBLIC_EXPONENT");
        return CKR_GENERAL_ERROR;
    }

    if (modulus_attr->ulValueLen > *outlen) {
        LOGE("Output buffer is too small, got: %lu, required at least %lu",
                *outlen, modulus_attr->ulValueLen);
        return CKR_GENERAL_ERROR;
    }

    BIGNUM *e = BN_bin2bn(exp_attr->pValue, exp_attr->ulValueLen, NULL);
    if (!e) {
        LOGE("Could not convert exponent to bignum");
        return CKR_GENERAL_ERROR;
    }

    BIGNUM *n = BN_bin2bn(modulus_attr->pValue, modulus_attr->ulValueLen, NULL);
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

    rc = RSA_padding_add_PKCS1_PSS(rsa, outbuf,
            inbuf, md, -1);
    RSA_free(rsa);
    if (!rc) {
        LOGE("Applying RSA padding failed");
        return CKR_GENERAL_ERROR;
    }

    *outlen = modulus_attr->ulValueLen;

    return CKR_OK;
}

CK_RV rsa_pkcs_hash_synthesizer(CK_MECHANISM_PTR mech, attr_list *attrs, CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen) {

    assert(mech);
    assert(outlen);

    /* These headers are defined in the following RFC
     *   - https://www.ietf.org/rfc/rfc3447.txt
     *     - Page 42
     */
    static const CK_BYTE pkcs1_5_hdr_sha1[15] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
        0x05, 0x00, 0x04, 0x14,
    };

    static const CK_BYTE pkcs1_5_hdr_sha256[19] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    };

    static const CK_BYTE pkcs1_5_hdr_sha384[19] = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
    };

    static const CK_BYTE pkcs1_5_hdr_sha512[19] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
    };

    const CK_BYTE *hdr;
    size_t hdr_size;

    switch(mech->mechanism) {
    case CKM_SHA1_RSA_PKCS:
        hdr = pkcs1_5_hdr_sha1;
        hdr_size = sizeof(pkcs1_5_hdr_sha1);
        break;
    case CKM_SHA256_RSA_PKCS:
        hdr = pkcs1_5_hdr_sha256;
        hdr_size = sizeof(pkcs1_5_hdr_sha256);
        break;
    case CKM_SHA384_RSA_PKCS:
        hdr = pkcs1_5_hdr_sha384;
        hdr_size = sizeof(pkcs1_5_hdr_sha384);
        break;
    case CKM_SHA512_RSA_PKCS:
        hdr = pkcs1_5_hdr_sha512;
        hdr_size = sizeof(pkcs1_5_hdr_sha512);
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    size_t hash_len = utils_get_halg_size(mech->mechanism);
    if (!hash_len) {
        LOGE("Unknown hash size, got 0x%x", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (inlen != hash_len) {
        LOGE("Expected input hash length to match expected hash length,"
                "got: %lu, expected: %lu", inlen, hash_len);
    }

    size_t total_size = hdr_size + hash_len;

    CK_BYTE hdr_buf[4096];
    if (total_size > sizeof(hdr_buf)) {
        LOGE("Internal buffer is too small, got: %lu, required %lu",
                total_size, sizeof(hdr_buf));
        return CKR_GENERAL_ERROR;
    }

    /*
     * Build and populate a buffer with hdr + hash
     */
    memcpy(hdr_buf, hdr, hdr_size);
    memcpy(&hdr_buf[hdr_size], inbuf, hash_len);

    return rsa_pkcs_synthesizer(mech, attrs, hdr_buf, total_size, outbuf, outlen);
}

CK_RV tpm_rsa_pss_get_opdata(tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {

    check_pointer(mech);
    check_pointer(outdata);

    CK_MECHANISM_TYPE halg = 0;
    CK_RV rv = rsa_pss_get_halg(mech, &halg);
    if (rv != CKR_OK) {
        return rv;
    }

    mdetail *m = mlookup(halg);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    CK_MECHANISM flat = { 0 };
    switch (halg) {
    case CKM_SHA_1:
        flat.mechanism = CKM_SHA1_RSA_PKCS_PSS;
        break;
    case CKM_SHA256:
        flat.mechanism = CKM_SHA256_RSA_PKCS_PSS;
        break;
    case CKM_SHA384:
        flat.mechanism = CKM_SHA384_RSA_PKCS_PSS;
        break;
    case CKM_SHA512:
        flat.mechanism = CKM_SHA512_RSA_PKCS_PSS;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    m = mlookup(flat.mechanism);
    if (!m) {
        return CKR_MECHANISM_INVALID;
    }

    return m->get_tpm_opdata(tctx, mech, tobj, outdata);
}

static CK_RV get_rsa_mechinfo(tpm_ctx *tctx, CK_MECHANISM_INFO_PTR info) {

    CK_ULONG min = 0;
    CK_ULONG max = 0;
    CK_RV rv = tpm_find_max_rsa_keysize(tctx, &min, &max);
    if (rv != CKR_OK) {
        return rv;
    }

    info->ulMinKeySize = min;
    info->ulMaxKeySize = max;

    return CKR_OK;
}

static CK_RV get_ecc_mechinfo(tpm_ctx *tctx, CK_MECHANISM_INFO_PTR info) {

    CK_ULONG max = 0;
    CK_ULONG min = 0;
    CK_RV rv = tpm_find_ecc_keysizes(tctx, &min, &max);
    if (rv != CKR_OK) {
        return rv;
    }

    info->ulMinKeySize = min;
    info->ulMaxKeySize = max;

    return CKR_OK;
}

static CK_RV get_aes_mechinfo(tpm_ctx *tctx, CK_MECHANISM_INFO_PTR info) {

    CK_ULONG max = 0;
    CK_ULONG min = 0;
    CK_RV rv = tpm_find_aes_keysizes(tctx, &min, &max);
    if (rv != CKR_OK) {
        return rv;
    }

    info->ulMinKeySize = min;
    info->ulMaxKeySize = max;

    return CKR_OK;
}

static bool is_mech_supported(mdetail *m) {

    mechanism_flags f = m->flags;

    return (f & mf_tpm_supported) ||
           (f & mf_is_keygen)     ||
           (f & mf_is_digester);
}

CK_RV mech_get_supported(tpm_ctx *tctx, CK_MECHANISM_TYPE_PTR mechlist, CK_ULONG_PTR count) {

    CK_RV rv = CKR_GENERAL_ERROR;

    DO_INIT(tctx);

    check_pointer(count);

    CK_ULONG supported = 0;

    CK_MECHANISM_TYPE tmp[MAX_MECHS];

    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(_g_mechs); i++) {
        mdetail *m = &_g_mechs[i];

        /* is it supported ? */
        bool is_supported = is_mech_supported(m);
        if (!is_supported) {
            continue;
        }

        supported++;

        assert(supported <= ARRAY_LEN(tmp));

        tmp[supported] = m->type;
    }

    if (mechlist) {
        if (supported > *count) {
            rv = CKR_BUFFER_TOO_SMALL;
            goto out;
        }
        memcpy(mechlist, tmp, supported * sizeof(mechlist[0]));
    }

    rv = CKR_OK;

out:
    *count = supported;

    return rv;
}

CK_RV mech_validate(tpm_ctx *tctx, CK_MECHANISM_PTR mech, attr_list *attrs) {

    check_pointer(mech);

    DO_INIT(tctx);

    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        LOGE("Mechanism not supported, got: 0x%x", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    /* if their is no validator, don't do anything but a look up */
    if (!m->validator) {
        return CKR_OK;
    }

    /* if it's not a keygen template, make sure the object supports it */
    if (!(m->flags & mf_is_keygen)) {
        CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, CKA_ALLOWED_MECHANISMS);
        if (!a) {
            LOGE("Expected object to have: CKA_ALLOWED_MECHANISMS");
            return CKR_GENERAL_ERROR;
        }

        CK_ULONG count = a->ulValueLen/sizeof(CK_MECHANISM_TYPE);
        CK_MECHANISM_TYPE_PTR mt = (CK_MECHANISM_TYPE_PTR)a->pValue;

        bool found = false;

        CK_ULONG i;
        for(i=0; i < count; i++) {
            CK_MECHANISM_TYPE t = mt[i];
            if (t == mech->mechanism) {
                found = true;
                break;
            }
        }

        if (!found) {
            return CKR_MECHANISM_INVALID;
        }
    }

    return m->validator(mech, attrs);
}

CK_RV mech_synthesize(tpm_ctx *tctx,
        CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen) {

    check_pointer(mech);

    DO_INIT(tctx);

    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        LOGE("Mechanism not supported, got: 0x%x", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    /* if it's supported by the tpm we don't need to call
     * the synthesizer, just memcpy in to out.
     */
    if ((m->flags & mf_tpm_supported)
            && !(m->flags & mf_force_synthetic)) {
        if (outbuf) {
            if (*outlen < inlen) {
                return CKR_BUFFER_TOO_SMALL;
            }
            memcpy(outbuf, inbuf, inlen);
        }
        *outlen = inlen;
        return CKR_OK;
    }

    if (!m->synthesizer) {
        LOGE("Cannot synthesize mechanism: 0x%lx", m->type);
        return CKR_MECHANISM_INVALID;
    }

    return m->synthesizer(mech, attrs, inbuf, inlen, outbuf, outlen);
}

CK_RV mech_is_synthetic(tpm_ctx *tctx, CK_MECHANISM_PTR mech,
        bool *is_synthetic) {

    check_pointer(mech);

    DO_INIT(tctx);

    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        LOGE("Mechanism not supported, got: 0x%x", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    *is_synthetic = (!(m->flags & mf_tpm_supported))
            || (m->flags & mf_is_synthetic)
            || (m->flags & mf_force_synthetic);

    return CKR_OK;
}

CK_RV mech_is_hashing_needed(CK_MECHANISM_PTR mech,
        bool *is_hashing_needed) {

    check_pointer(mech);
    check_pointer(is_hashing_needed);

    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        LOGE("Mechanism not supported, got: 0x%x", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (!m->get_halg) {
        *is_hashing_needed = false;
        return CKR_OK;
    }

    CK_MECHANISM_TYPE halg;
    CK_RV rv = m->get_halg(mech, &halg);
    if (rv != CKR_OK) {
        return rv;
    }

    *is_hashing_needed = halg != 0;

    return CKR_OK;
}

CK_RV mech_get_digest_alg(CK_MECHANISM_PTR mech,
        CK_MECHANISM_TYPE *mech_type) {

    check_pointer(mech);
    check_pointer(mech_type);

    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        LOGE("Mechanism not supported, got: 0x%x", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (!m->get_halg) {
        return CKR_MECHANISM_INVALID;
    }

    return m->get_halg(mech, mech_type);
}

CK_RV mech_get_digester(CK_MECHANISM_PTR mech,
        const EVP_MD **md) {

    check_pointer(mech);
    check_pointer(md);

    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        LOGE("Mechanism not supported, got: 0x%x", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (!m->get_digester) {
        return CKR_MECHANISM_INVALID;
    }

    return m->get_digester(mech, md);
}

CK_RV mech_get_tpm_opdata(tpm_ctx *tctx, CK_MECHANISM_PTR mech,
        tobject *tobj, tpm_op_data **opdata) {

    check_pointer(tctx);
    check_pointer(opdata);

    DO_INIT(tctx);

    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        LOGE("Mechanism not supported, got: 0x%x", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (!m->get_tpm_opdata) {
        return CKR_MECHANISM_INVALID;
    }

    return m->get_tpm_opdata(tctx, mech, tobj, opdata);
}

CK_RV mech_get_padding(CK_MECHANISM_PTR mech, int *padding) {

    check_pointer(mech);
    check_pointer(padding);

    mdetail *m = mlookup(mech->mechanism);
    if (!m) {
        LOGE("Mechanism not supported, got: 0x%x", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    *padding = m->padding;

    return CKR_OK;
}

CK_RV mech_get_label(CK_MECHANISM_PTR mech, twist *label) {

    check_pointer(mech);
    check_pointer(label);

    if (mech->mechanism != CKM_RSA_PKCS_OAEP) {
        *label = NULL;
        return CKR_OK;
    }

    CK_RSA_PKCS_OAEP_PARAMS_PTR params;
    SAFE_CAST(mech, params);

    /* empty label ? */
    if (!params->ulSourceDataLen) {
        *label = NULL;
        return CKR_OK;
    }

    /* non empty label */
    twist t = twistbin_new(params->pSourceData, params->ulSourceDataLen);
    if (!t) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    *label = t;

    return CKR_OK;
}

CK_RV mech_get_info(tpm_ctx *tctx, CK_MECHANISM_TYPE mech_type, CK_MECHANISM_INFO_PTR info) {

    check_pointer(tctx);
    check_pointer(info);

    memset(info, 0, sizeof(*info));

    DO_INIT(tctx);

    mdetail *m = mlookup(mech_type);
    if (!m) {
        LOGE("Mechanism not supported, got: 0x%x", mech_type);
        return CKR_MECHANISM_INVALID;
    }

    if (m->flags & mf_is_keygen) {
        info->flags |= (m->flags & mf_aes) ?
                CKF_GENERATE :
                CKF_GENERATE_KEY_PAIR;
    }

    if (m->flags & mf_tpm_supported) {
        info->flags |= CKF_HW;
    }

    if (m->flags & mf_sign) {
        info->flags |= CKF_SIGN;
    }

    if (m->flags & mf_verify) {
        info->flags |= CKF_VERIFY;
    }

    if (m->flags & mf_encrypt) {
        info->flags |= CKF_ENCRYPT;
    }

    if (m->flags & mf_decrypt) {
        info->flags |= CKF_DECRYPT;
    }

    /* functions below here return */
    if (m->flags & mf_is_digester) {
        info->flags |= CKF_DIGEST;
        return CKR_OK;
    }

    if (m->flags & mf_rsa) {
        return get_rsa_mechinfo(tctx, info);
    }

    if (m->flags & mf_aes) {
        return get_aes_mechinfo(tctx, info);
    }

    if (m->flags & mf_ecc) {
        return get_ecc_mechinfo(tctx, info);
    }

    LOGE("Unknown mechanism, got: 0x%lx", mech_type);

    return CKR_MECHANISM_INVALID;
}
