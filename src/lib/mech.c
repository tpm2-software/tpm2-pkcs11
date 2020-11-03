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
    mf_force_synthetic = 1 << 12,
};

typedef struct mdetail_entry mdetail_entry;
typedef struct nid_detail nid_detail;
typedef struct rsa_detail rsa_detail;

struct rsa_detail {
    CK_ULONG bits;
    bool supported;
};

struct nid_detail {
    int nid;
    bool supported;
};

/*
 * Validates that the mechanism parameters are sane and supported
 */
typedef CK_RV (*fn_validator)(mdetail *details, CK_MECHANISM_PTR mech, attr_list *attrs);

/*
 * Some crypto operations can be synthesized (padding done off hw and raw crypto performed)
 * This routine would do all those steps.
 */
typedef CK_RV (*fn_synthesizer)(mdetail *m,
        CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);

typedef CK_RV (*fn_get_halg)(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE *halg);

typedef CK_RV (*fn_get_digester)(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md);

typedef CK_RV (*fn_get_tpm_opdata)(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **encdata);

struct mdetail_entry {
    CK_MECHANISM_TYPE type;

    fn_validator validator;
    fn_synthesizer synthesizer;
    fn_get_tpm_opdata get_tpm_opdata;
    fn_get_halg get_halg;
    fn_get_digester get_digester;

    int padding;

    mechanism_flags flags;
};

struct mdetail {
    size_t mdetail_len;
    mdetail_entry *mech_entries;

    size_t rsa_detail_len;
    rsa_detail *rsa_entries;

    size_t nid_detail_len;
    nid_detail *nid_entries;
};

static CK_RV rsa_keygen_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_pkcs_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_pss_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_oaep_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_pkcs_hash_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_pss_hash_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV ecc_keygen_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV ecdsa_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV hash_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs);
static CK_RV rsa_pkcs_synthesizer(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);
static CK_RV rsa_pss_synthesizer(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);
static CK_RV rsa_pkcs_hash_synthesizer(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);
static CK_RV rsa_pss_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);
static CK_RV rsa_oaep_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);
static CK_RV sha1_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);
static CK_RV sha256_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);
static CK_RV sha384_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);
static CK_RV sha512_get_halg(CK_MECHANISM_PTR mech, CK_MECHANISM_TYPE_PTR halg);

static CK_RV rsa_pss_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md);
static CK_RV rsa_oaep_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md);
static CK_RV sha1_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md);
static CK_RV sha256_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md);
static CK_RV sha384_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md);
static CK_RV sha512_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md);

static const mdetail_entry _g_mechs_templ[] = {

    /* RSA */
    { .type = CKM_RSA_PKCS_KEY_PAIR_GEN, .validator = rsa_keygen_validator, .flags = mf_is_keygen|mf_rsa },

    { .type = CKM_RSA_X_509, .flags = mf_is_synthetic|mf_sign|mf_verify|mf_encrypt|mf_decrypt|mf_rsa, .get_tpm_opdata = tpm_rsa_pkcs_get_opdata, .padding = RSA_NO_PADDING },

    { .type = CKM_RSA_PKCS,      .flags = mf_force_synthetic|mf_sign|mf_verify|mf_encrypt|mf_decrypt|mf_rsa, .validator = rsa_pkcs_validator, .synthesizer = rsa_pkcs_synthesizer, .get_tpm_opdata = tpm_rsa_pkcs_get_opdata, .padding = RSA_PKCS1_PADDING },

    { .type = CKM_RSA_PKCS_PSS,  .flags = mf_sign|mf_verify|mf_rsa, .validator = rsa_pss_validator, .synthesizer = rsa_pss_synthesizer, .get_digester = rsa_pss_get_digester, .get_tpm_opdata = tpm_rsa_pss_get_opdata, .padding = RSA_PKCS1_PSS_PADDING },

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

const rsa_detail _g_rsa_keysizes_templ [] = {
    { .bits = 1024 },
    { .bits = 2048 },
    { .bits = 3072 },
    { .bits = 4096 },
};

const nid_detail _g_ecc_curve_nids_templ [] = {
    { .nid = NID_X9_62_prime192v1 },
    { .nid = NID_secp224r1        },
    { .nid = NID_X9_62_prime256v1 },
    { .nid = NID_secp384r1,       },
    { .nid = NID_secp521r1,       },
};

static mdetail_entry *mlookup(mdetail *details, CK_MECHANISM_TYPE t) {

    CK_ULONG i;
    for (i=0; i < details->mdetail_len; i++) {
        mdetail_entry *m = &details->mech_entries[i];
        if (m->type == t) {
            return m;
        }
    }

    return NULL;
}

static CK_RV mech_init(tpm_ctx *tctx, mdetail *m) {

    /*
     * Get the mechanisms
     */
    CK_MECHANISM_TYPE tpm_mechs[MAX_MECHS];
    CK_ULONG tpm_mechs_len = ARRAY_LEN(tpm_mechs);
    CK_RV rv = tpm2_getmechanisms(tctx, tpm_mechs, &tpm_mechs_len);
    if (rv != CKR_OK) {
        return rv;
    }

    assert(tpm_mechs_len <= m->mdetail_len);

    /*
     * Update whether or not the TPM supports it ot not
     * and any other metadata
     */
    CK_ULONG i;
    for (i=0; i < tpm_mechs_len; i++) {
        CK_MECHANISM_TYPE t = tpm_mechs[i];
        mdetail_entry *d = NULL;
        CK_ULONG j;
        for (j=0; j < m->mdetail_len; j++) {
            d = &m->mech_entries[j];
            if (d->type == t) {
                d->flags |= mf_tpm_supported;
                break;
            }
        }
    }

    mdetail_entry *d = mlookup(m, CKM_RSA_PKCS_KEY_PAIR_GEN);
    if (d) {
        /* get supported RSA key bit sizes */
        for (i=0; i < m->rsa_detail_len; i++) {
            rv = tpm_is_rsa_keysize_supported(tctx, m->rsa_entries[i].bits);
            if (rv == CKR_MECHANISM_INVALID) {
                continue;
            }

            if(rv == CKR_OK) {
                m->rsa_entries[i].supported = true;
                continue;
            }

            return rv;
        }
    } else {
        LOGV("RSA Keygen not detected");
    }

    d = mlookup(m, CKM_EC_KEY_PAIR_GEN);
    if (d) {
        /* get supported ECC curves */
        for (i=0; i < m->nid_detail_len; i++) {
            rv = tpm_is_ecc_curve_supported(tctx, m->nid_entries[i].nid);
            if (rv == CKR_MECHANISM_INVALID) {
                continue;
            }

            if(rv == CKR_OK) {
                m->nid_entries[i].supported = true;
                continue;
            }

            return rv;
        }
    } else {
        LOGV("EC Keygen not detected");
    }

    return CKR_OK;
}

void mdetail_free(mdetail **mdtl) {
    if (!mdtl || !*mdtl) {
        return;
    }

    mdetail *m = *mdtl;

    free(m->mech_entries);
    free(m->nid_entries);
    free(m->rsa_entries);
    free(m);
    *mdtl = NULL;
}

void mdetail_set_pss_status(mdetail *m, bool pss_sigs_good) {

    CK_MECHANISM_TYPE mtypes[] = {
        CKM_RSA_PKCS_PSS,
        CKM_SHA1_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
    };

    size_t i = 0;
    for (i=0; i < ARRAY_LEN(mtypes); i++) {
        CK_MECHANISM_TYPE t = mtypes[i];

        mdetail_entry *d = mlookup(m, t);
        assert(d);

        if (pss_sigs_good) {
            d->flags |= mf_tpm_supported;
        } else {
            d->flags &= ~mf_tpm_supported;
        }
    }
}

CK_RV mdetail_new(tpm_ctx *ctx, mdetail **mout, pss_config_state pss_sig_state) {
    assert(mout);

    mdetail_entry *d = calloc(1, sizeof(_g_mechs_templ));
    if (!d) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    nid_detail *n = calloc(1, sizeof(_g_ecc_curve_nids_templ));
    if (!n) {
        LOGE("oom");
        free(d);
        return CKR_HOST_MEMORY;
    }

    rsa_detail *r = calloc(1, sizeof(_g_rsa_keysizes_templ));
    if (!r) {
        LOGE("oom");
        free(d);
        free(n);
        return CKR_HOST_MEMORY;
    }

    mdetail *m = calloc(1, sizeof(mdetail));
    if (!m) {
        LOGE("oom");
        free(d);
        free(n);
        free(r);
        return CKR_HOST_MEMORY;
    }

    memcpy(d, _g_mechs_templ, sizeof(_g_mechs_templ));
    m->mdetail_len = ARRAY_LEN(_g_mechs_templ);
    m->mech_entries = d;

    memcpy(n, _g_ecc_curve_nids_templ, sizeof(_g_ecc_curve_nids_templ));
    m->nid_detail_len = ARRAY_LEN(_g_ecc_curve_nids_templ);
    m->nid_entries = n;

    memcpy(r, _g_rsa_keysizes_templ, sizeof(_g_rsa_keysizes_templ));
    m->rsa_detail_len = ARRAY_LEN(_g_rsa_keysizes_templ);
    m->rsa_entries = r;

    /*
     * TODO
     * make mech_init smarter by caching the various RSA and EC curve
     * information in the YAML token config. Thus reduce TPM round trips.
     * See https://github.com/tpm2-software/tpm2-pkcs11/issues/455
     */
    CK_RV rv = mech_init(ctx, m);
    if (rv != CKR_OK) {
        LOGE("mech_init failed: 0x%lx", rv);
        free(m);
        free(d);
        free(n);
        free(r);
        return rv;
    }

    /*
     * Some tokens know their PSS state, always use it. The TPM backend code
     * might get it wrong, as it *ONLY* checks TPMA_MODES in the properties.
     * Else we will figure it out when we need to sign, which is when it really
     * matters.
     */
    if (pss_sig_state != pss_config_state_unk) {
        bool pss_sigs_good = (pss_sig_state == pss_config_state_good)
                ? true : false;
        LOGV("Updating mech detail table that PSS signatures are: %s",
                pss_sigs_good ? "good" : "bad");
        mdetail_set_pss_status(m, pss_sigs_good);
    }

    *mout = m;

    return CKR_OK;
};

#define _L(a) (a->ulValueLen/sizeof(CK_MECHANISM_TYPE))
#define _P(a) ((CK_MECHANISM_TYPE_PTR)a->pValue)

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

CK_RV hash_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs) {
    UNUSED(attrs);
    UNUSED(m);

    /* hashers don't take params */
    if (mech->pParameter || mech->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* all known hashing digests are supported in software */

    return CKR_OK;
}

CK_RV rsa_pkcs_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs) {
    UNUSED(m);

    /*
     * CKM_RSA_PKCS has the PKCS v1.5 signing structure computed by the client
     * and requires only padding, so no parameters should be set
     */
    if (mech->pParameter || mech->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return has_raw_rsa(attrs);
}

CK_RV rsa_pkcs_hash_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs) {

    /* CKM_<HASH>_RSA_PKCS takes no params */
    if (mech->pParameter || mech->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* it needs to be supported */
    mdetail_entry *d = mlookup(m, mech->mechanism);
    if (!d) {
        return CKR_MECHANISM_INVALID;
    }

    /* if the TPM supports it natively, we're done */
    if (d->flags & mf_tpm_supported) {
        return CKR_OK;
    }

    return has_raw_rsa(attrs);
}

CK_RV rsa_pss_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs) {
    UNUSED(attrs);

    /* it needs to be supported */
    mdetail_entry *d = mlookup(m, mech->mechanism);
    if (!d) {
        return CKR_MECHANISM_INVALID;
    }

    CK_RSA_PKCS_PSS_PARAMS_PTR params;
    SAFE_CAST(mech, params);

    /* no SHA224 support AFAIK */
    if (params->mgf == CKG_MGF1_SHA224) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /*
     * The TPM fixes the MGF to the hash algorithm and the salt to the hashlen.
     */
    CK_MECHANISM test_type = { 0 };
    if (params->hashAlg == CKM_SHA_1) {
        if ((params->mgf != CKG_MGF1_SHA1) ||(params->sLen != 20)) {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        test_type.mechanism = CKM_SHA1_RSA_PKCS_PSS;

    } else if (params->hashAlg == CKM_SHA256) {

        if ((params->mgf != CKG_MGF1_SHA256) ||(params->sLen != 32)) {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        test_type.mechanism = CKM_SHA256_RSA_PKCS_PSS;

    } else if (params->hashAlg == CKM_SHA384) {
        if ((params->mgf != CKG_MGF1_SHA384) ||(params->sLen != 48)) {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        test_type.mechanism = CKM_SHA384_RSA_PKCS_PSS;

    } else if (params->hashAlg == CKM_SHA512) {
        if ((params->mgf != CKG_MGF1_SHA512) ||(params->sLen != 64)) {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        test_type.mechanism = CKM_SHA512_RSA_PKCS_PSS;

    } else {
        LOGE("Unknown hash algorithm: 0x%lx", params->hashAlg);
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* Is it synthetic or native TPM supported ?*/
    bool is_synthetic = true;
    CK_RV rv = mech_is_synthetic(m, &test_type, &is_synthetic);
    if (rv != CKR_OK) {
        return rv;
    }

    /*
     * For synthetic operations we need raw RSA do we have it? Else we're
     * fine
     */
    return is_synthetic ? has_raw_rsa(attrs) : CKR_OK;
}

CK_RV rsa_oaep_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs) {
    UNUSED(attrs);

    /* it needs to be supported */
    mdetail_entry *d = mlookup(m, mech->mechanism);
    if (!d) {
        return CKR_MECHANISM_INVALID;
    }

    CK_RSA_PKCS_OAEP_PARAMS_PTR params;
    SAFE_CAST(mech, params);

    /* no SHA224 support AFAIK */
    if (params->mgf == CKG_MGF1_SHA224) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    CK_MECHANISM_TYPE halg = 0;
    CK_RV rv = d->get_halg(mech, &halg);
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
    if (d->flags & mf_tpm_supported) {
        return CKR_OK;
    }

    return CKR_MECHANISM_INVALID;
}

CK_RV rsa_pss_hash_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs) {

    /* this may have an argument */
    if (mech->pParameter || mech->ulParameterLen) {
        return rsa_pss_validator(m, mech, attrs);
    }

    /*
     * now that the PSS portion IS supported AND the mechanism params check out,
     * we need raw RSA, do we have it?
     */
    return has_raw_rsa(attrs);
}

CK_RV rsa_keygen_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs) {

    /* this requires no argument */
    if (!mech->pParameter || !mech->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, CKA_MODULUS);
    if (!a) {
        return CKR_TEMPLATE_INCOMPLETE;
    }

    CK_ULONG bits = 0;
    safe_mul(bits, a->ulValueLen, 8);

    CK_ULONG i;
    for (i=0; i < m->mdetail_len; i++) {
        if (m->rsa_entries[i].bits == bits) {
            return m->rsa_entries[i].supported ?
                    CKR_OK : CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    return CKR_ATTRIBUTE_VALUE_INVALID;
}

CK_RV ecc_keygen_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs) {

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
    for (i=0; i < m->nid_detail_len; i++) {
        if (m->nid_entries[i].nid == nid) {
            return m->nid_entries[i].supported ?
                    CKR_OK : CKR_MECHANISM_INVALID;
        }
    }

    return CKR_MECHANISM_INVALID;
}

CK_RV ecdsa_validator(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs) {
    UNUSED(attrs);
    UNUSED(m);

    /* ECDSA and ECDSA SHA1 are always supported */

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

CK_RV rsa_pss_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md) {

    CK_MECHANISM_TYPE halg = 0;
    CK_RV rv = rsa_pss_get_halg(mech, &halg);
    if (rv != CKR_OK) {
        return rv;
    }

    mdetail_entry *d = mlookup(m, halg);
    if (!d) {
        return CKR_MECHANISM_INVALID;
    }

    return d->get_digester(m, mech, md);
}

CK_RV rsa_oaep_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md) {

    CK_MECHANISM_TYPE halg = 0;
    CK_RV rv = rsa_oaep_get_halg(mech, &halg);
    if (rv != CKR_OK) {
        return rv;
    }

    mdetail_entry *d = mlookup(m, halg);
    if (!d) {
        return CKR_MECHANISM_INVALID;
    }

    return d->get_digester(m, mech, md);
}

CK_RV sha1_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md) {
    UNUSED(mech);
    UNUSED(m);
    *md = EVP_sha1();
    return CKR_OK;
}

CK_RV sha256_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md) {
    UNUSED(mech);
    UNUSED(m);
    *md = EVP_sha256();
    return CKR_OK;
}

CK_RV sha384_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md) {
    UNUSED(mech);
    UNUSED(m);
    *md = EVP_sha384();
    return CKR_OK;
}

CK_RV sha512_get_digester(mdetail *m, CK_MECHANISM_PTR mech, const EVP_MD **md) {
    UNUSED(mech);
    UNUSED(m);
    *md = EVP_sha512();
    return CKR_OK;
}

CK_RV rsa_pkcs_synthesizer(mdetail *mdtl,
        CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen) {
    UNUSED(mech);
    UNUSED(mdtl);

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

CK_RV rsa_pss_synthesizer(mdetail *mdtl,
        CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen) {

    const EVP_MD *md = NULL;
    CK_RV rv = mech_get_digester(mdtl, mech, &md);
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

CK_RV rsa_pkcs_hash_synthesizer(mdetail *mdtl,
        CK_MECHANISM_PTR mech, attr_list *attrs, CK_BYTE_PTR inbuf, CK_ULONG inlen,
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
        LOGE("Unknown hash size, got 0x%lx", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (inlen != hash_len) {
        LOGE("Expected input hash length to match expected hash length,"
                "got: %lu, expected: %lu", inlen, hash_len);
    }

    size_t total_size = 0;
    safe_add(total_size, hdr_size, hash_len);

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

    return rsa_pkcs_synthesizer(mdtl, mech, attrs, hdr_buf, total_size, outbuf, outlen);
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

static bool is_mech_supported(mdetail_entry *d) {

    mechanism_flags f = d->flags;

    return (f & mf_tpm_supported) ||
           (f & mf_is_keygen)     ||
           (f & mf_is_digester);
}

CK_RV mech_get_supported(mdetail *m, CK_MECHANISM_TYPE_PTR mechlist, CK_ULONG_PTR count) {

    CK_RV rv = CKR_GENERAL_ERROR;

    check_pointer(count);

    CK_ULONG supported = 0;

    CK_MECHANISM_TYPE tmp[MAX_MECHS];

    CK_ULONG i;
    for (i=0; i < m->mdetail_len; i++) {
        mdetail_entry *d = &m->mech_entries[i];

        /* is it supported ? */
        bool is_supported = is_mech_supported(d);
        if (!is_supported) {
            continue;
        }

        assert(supported <= ARRAY_LEN(tmp));
        tmp[supported] = d->type;
        supported++;
    }

    if (mechlist) {
        if (supported > *count) {
            rv = CKR_BUFFER_TOO_SMALL;
            goto out;
        }
        if (supported) {
            size_t bytes = 0;
            safe_mul(bytes, supported, sizeof(mechlist[0]));
            memcpy(mechlist, tmp, bytes);
        }
    }

    rv = CKR_OK;

out:
    *count = supported;

    return rv;
}

CK_RV mech_validate(mdetail *m, CK_MECHANISM_PTR mech, attr_list *attrs) {

    check_pointer(mech);

    mdetail_entry *d = mlookup(m, mech->mechanism);
    if (!d) {
        LOGV("Mechanism not supported, got: 0x%lx", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    /* if their is no validator, don't do anything but a look up */
    if (!d->validator) {
        return CKR_OK;
    }

    /* if it's not a keygen template, make sure the object supports it */
    if (!(d->flags & mf_is_keygen)) {
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

    return d->validator(m, mech, attrs);
}

CK_RV mech_synthesize(
        mdetail *mdtl,
        CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen) {

    check_pointer(mech);

    mdetail_entry *d = mlookup(mdtl, mech->mechanism);
    if (!d) {
        LOGE("Mechanism not supported, got: 0x%lx", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    /* if it's supported by the tpm we don't need to call
     * the synthesizer, just memcpy in to out.
     */
    if ((d->flags & mf_tpm_supported)
            && !(d->flags & mf_force_synthetic)) {
        if (outbuf) {
            if (*outlen < inlen) {
                return CKR_BUFFER_TOO_SMALL;
            }
            memcpy(outbuf, inbuf, inlen);
        }
        *outlen = inlen;
        return CKR_OK;
    }

    if (!d->synthesizer) {
        LOGE("Cannot synthesize mechanism: 0x%lx", d->type);
        return CKR_MECHANISM_INVALID;
    }

    return d->synthesizer(mdtl, mech, attrs, inbuf, inlen, outbuf, outlen);
}

CK_RV mech_is_synthetic(mdetail *m, CK_MECHANISM_PTR mech,
        bool *is_synthetic) {

    check_pointer(m);
    check_pointer(mech);
    check_pointer(is_synthetic);

    mdetail_entry *d = mlookup(m, mech->mechanism);
    if (!d) {
        LOGE("Mechanism not supported, got: 0x%lx", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    *is_synthetic = (!(d->flags & mf_tpm_supported))
            || (d->flags & mf_is_synthetic)
            || (d->flags & mf_force_synthetic);

    return CKR_OK;
}

CK_RV mech_is_hashing_needed(mdetail *m,
        CK_MECHANISM_PTR mech,
        bool *is_hashing_needed) {

    check_pointer(m);
    check_pointer(mech);
    check_pointer(is_hashing_needed);

    mdetail_entry *d = mlookup(m, mech->mechanism);
    if (!d) {
        LOGE("Mechanism not supported, got: 0x%lx", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (!d->get_halg) {
        *is_hashing_needed = false;
        return CKR_OK;
    }

    CK_MECHANISM_TYPE halg;
    CK_RV rv = d->get_halg(mech, &halg);
    if (rv != CKR_OK) {
        return rv;
    }

    *is_hashing_needed = halg != 0;

    return CKR_OK;
}

CK_RV mech_is_hashing_knowledge_needed(mdetail *m,
    CK_MECHANISM_PTR mech,
    bool *is_hashing_knowledge_needed) {

    check_pointer(m);
    check_pointer(mech);
    check_pointer(is_hashing_knowledge_needed);

    mdetail_entry *d = mlookup(m, mech->mechanism);
    if (!d) {
        LOGE("Mechanism not supported, got: 0x%lx", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    *is_hashing_knowledge_needed = d->get_digester;

    return CKR_OK;
}

CK_RV mech_get_digest_alg(mdetail *m,
        CK_MECHANISM_PTR mech,
        CK_MECHANISM_TYPE *mech_type) {

    check_pointer(m);
    check_pointer(mech);
    check_pointer(mech_type);

    mdetail_entry *d = mlookup(m, mech->mechanism);
    if (!d) {
        LOGE("Mechanism not supported, got: 0x%lx", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (!d->get_halg) {
        LOGE("Mechanism 0x%lx has no get_halg()", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    return d->get_halg(mech, mech_type);
}

CK_RV mech_get_digester(
        mdetail *mdtl,
        CK_MECHANISM_PTR mech,
        const EVP_MD **md) {

    check_pointer(mech);
    check_pointer(md);

    mdetail_entry *d = mlookup(mdtl, mech->mechanism);
    if (!d) {
        LOGV("Mechanism not supported, got: 0x%lx", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (!d->get_digester) {
        LOGE("Mechanism 0x%lx has no get_digester()", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    return d->get_digester(mdtl, mech, md);
}

CK_RV mech_get_tpm_opdata(mdetail *mdtl,
        tpm_ctx *tctx,
        CK_MECHANISM_PTR mech,
        tobject *tobj, tpm_op_data **opdata) {

    check_pointer(mdtl);
    check_pointer(tctx);
    check_pointer(opdata);

    mdetail_entry *d = mlookup(mdtl, mech->mechanism);
    if (!d) {
        LOGE("Mechanism not supported, got: 0x%lx", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (!d->get_tpm_opdata) {
        return CKR_MECHANISM_INVALID;
    }

    return d->get_tpm_opdata(mdtl, tctx, mech, tobj, opdata);
}

CK_RV mech_get_padding(mdetail *m, CK_MECHANISM_PTR mech, int *padding) {

    check_pointer(mech);
    check_pointer(padding);

    mdetail_entry *d = mlookup(m, mech->mechanism);
    if (!d) {
        LOGE("Mechanism not supported, got: 0x%lx", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    *padding = d->padding;

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

CK_RV mech_get_info(mdetail *m, tpm_ctx *tctx,
        CK_MECHANISM_TYPE mech_type, CK_MECHANISM_INFO_PTR info) {

    check_pointer(m);
    check_pointer(tctx);
    check_pointer(info);

    memset(info, 0, sizeof(*info));

    mdetail_entry *d = mlookup(m, mech_type);
    if (!d) {
        LOGE("Mechanism not supported, got: 0x%lx", mech_type);
        return CKR_MECHANISM_INVALID;
    }

    if (d->flags & mf_is_keygen) {
        info->flags |= (d->flags & mf_aes) ?
                CKF_GENERATE :
                CKF_GENERATE_KEY_PAIR;
    }

    if (d->flags & mf_tpm_supported) {
        info->flags |= CKF_HW;
    }

    if (d->flags & mf_sign) {
        info->flags |= CKF_SIGN;
    }

    if (d->flags & mf_verify) {
        info->flags |= CKF_VERIFY;
    }

    if (d->flags & mf_encrypt) {
        info->flags |= CKF_ENCRYPT;
    }

    if (d->flags & mf_decrypt) {
        info->flags |= CKF_DECRYPT;
    }

    /* functions below here return */
    if (d->flags & mf_is_digester) {
        info->flags |= CKF_DIGEST;
        return CKR_OK;
    }

    if (d->flags & mf_rsa) {
        return get_rsa_mechinfo(tctx, info);
    }

    if (d->flags & mf_aes) {
        return get_aes_mechinfo(tctx, info);
    }

    if (d->flags & mf_ecc) {
        return get_ecc_mechinfo(tctx, info);
    }

    LOGE("Unknown mechanism, got: 0x%lx", mech_type);

    return CKR_MECHANISM_INVALID;
}
