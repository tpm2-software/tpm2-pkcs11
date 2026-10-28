/* SPDX-License-Identifier: BSD-2-Clause */

/* config can control how other headers behave, include first */
#include "config.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include <arpa/inet.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include "attrs.h"
#include "checks.h"
#include "digest.h"
#include "encrypt.h"
#include "log.h"
#include "mutex.h"
#include "pkcs11.h"
#include "ssl_util.h"
#include "tpm.h"
#include "utils.h"

#ifndef ESAPI_MANAGE_FLAGS
#define ESAPI_MANAGE_FLAGS 0
#endif

#define DEFAULT_SEAL_TEMPLATE { \
        .size = 0, \
        .publicArea = { \
            .type = TPM2_ALG_KEYEDHASH, \
            .nameAlg = TPM2_ALG_SHA256, \
            .objectAttributes = ( \
                TPMA_OBJECT_USERWITHAUTH | \
                TPMA_OBJECT_FIXEDTPM | \
                TPMA_OBJECT_FIXEDPARENT \
            ), \
            .authPolicy = { \
                .size = 0, \
            }, \
            .parameters.keyedHashDetail = { \
                .scheme = { \
                    .scheme = TPM2_ALG_NULL, \
                    .details = { \
                        .hmac = { \
                            .hashAlg = TPM2_ALG_SHA256 \
                        } \
                    } \
                } \
            }, \
            .unique.keyedHash = { \
                .size = 0, \
                .buffer = {}, \
            }, \
        } \
    }

/*
 * The provisioning guidance states that this 0x81000001 should be the SRK
 * See:
 *   - https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
 */
#define DEFAULT_SRK_HANDLE 0x81000001

/* Return code when TPM is in DA Lockout mode */

static const TPM2B_PUBLIC rsa_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes =
                TPMA_OBJECT_FIXEDTPM
              | TPMA_OBJECT_FIXEDPARENT
              | TPMA_OBJECT_SENSITIVEDATAORIGIN
              | TPMA_OBJECT_USERWITHAUTH
              | TPMA_OBJECT_DECRYPT
              | TPMA_OBJECT_SIGN_ENCRYPT,
        .authPolicy = {
             .size = 0,
         },
        .parameters.rsaDetail = {
             .symmetric = {
                 .algorithm = TPM2_ALG_NULL,
             },
             .scheme = {
                  .scheme = TPM2_ALG_NULL
              },
             .keyBits = 2048,
             .exponent = 0,
         },
        .unique.rsa = {
             .size = 0,
         },
    },
};

static const TPM2B_PUBLIC ecc_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes =
            TPMA_OBJECT_FIXEDTPM
            | TPMA_OBJECT_FIXEDPARENT
            | TPMA_OBJECT_SENSITIVEDATAORIGIN
            | TPMA_OBJECT_USERWITHAUTH
            | TPMA_OBJECT_SIGN_ENCRYPT,
        .authPolicy = {
            .size = 0,
        },
        .parameters.eccDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_NULL,
                .keyBits.aes = 0,
                .mode.aes = 0,
            },
            .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {
                   // {.hashAlg = TPM2_ALG_SHA1}
                }
            },
            .curveID = TPM2_ECC_NIST_P256,
            .kdf = {.scheme =
                TPM2_ALG_NULL,.details = {}
            }
        },
        .unique.ecc = {
            .x = {.size = 0,.buffer = {}},
            .y = {.size = 0,.buffer = {}}
        },
    },
};

/**
 * Maps 4-byte manufacturer identifier to manufacturer name.
 */
static const char *TPM2_MANUFACTURER_MAP[][2] = {
    {"ATML", "Atmel"},
    {"INTC", "Intel"},
    {"IFX ", "Infineon"},
    {"IBM ", "IBM"},
    {"NTC ", "Nuvoton"},
    {"STM ", "STMicro"}
};

struct tpm_ctx {
    TSS2_TCTI_CONTEXT *tcti_ctx;
    ESYS_CONTEXT *esys_ctx;
    bool esapi_manage_session_flags;
    ESYS_TR hmac_session;
    TPMA_SESSION old_flags;
    TPMA_SESSION original_flags;
    TPMS_CAPABILITY_DATA *tpms_fixed_property_cache;
    TPMS_CAPABILITY_DATA *tpms_alg_cache;
    TPMS_CAPABILITY_DATA *tpms_cc_cache;

    bool did_check_for_createloaded;
    bool use_createloaded;

    bool did_check_for_encdec2;
    bool use_encdec2;
};

#define TPM2B_INIT(xsize) { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)

struct tpm_op_data {

    tpm_ctx *ctx;

    tobject *tobj;

    CK_KEY_TYPE op_type;

    mdetail *mdtl;
    CK_MECHANISM mech;

    union {
        struct {
            TPMT_SIG_SCHEME sig;
            TPMT_RSA_DECRYPT raw;
            TPM2B_DATA label;
        } rsa;
        struct {
            TPMT_SIG_SCHEME sig;
        } hmac;
        struct {
            TPMI_ALG_SYM_MODE mode;
            TPM2B_IV iv;
            struct {
                BIGNUM *counter;
            } ctr;
            struct {
                CK_ULONG len;
                CK_BYTE data[16];
            } prev;
        } sym;
        struct {
            TPMT_SIG_SCHEME sig;
        } ecc;
    };
};

static inline tpm_op_data *tpm_opdata_new(mdetail *mdtl, CK_MECHANISM_PTR mech) {
    tpm_op_data *opdata = (tpm_op_data *)calloc(1, sizeof(tpm_op_data));
    if (opdata) {
        opdata->mdtl = mdtl;
        opdata->mech = *mech;
    }
    return opdata;
}

static ESYS_CONTEXT* esys_ctx_init(TSS2_TCTI_CONTEXT *tcti_ctx) {

    ESYS_CONTEXT *esys_ctx = NULL;
    TSS2_RC rval = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_Initialize: 0x%x", rval);
        return NULL;
    }

    return esys_ctx;
}

static void flags_turndown(tpm_ctx *ctx, TPMA_SESSION flags) {

    if (ctx->esapi_manage_session_flags) {
        return;
    }

    TSS2_RC rc = Esys_TRSess_GetAttributes(ctx->esys_ctx, ctx->hmac_session, &ctx->old_flags);
    assert(rc == TPM2_RC_SUCCESS);
    if (rc != TSS2_RC_SUCCESS) {
        LOGW("Esys_TRSess_SetAttributes: 0x%x", rc);
        return;
    }

    assert(ctx->old_flags == ctx->original_flags);

    TPMA_SESSION new_flags = (ctx->old_flags & (~flags));
    rc = Esys_TRSess_SetAttributes(ctx->esys_ctx, ctx->hmac_session, new_flags, 0xff);
    assert(rc == TSS2_RC_SUCCESS);
    if (rc != TSS2_RC_SUCCESS) {
        LOGW("Esys_TRSess_SetAttributes: 0x%x", rc);
    }
}

static void flags_restore(tpm_ctx *ctx) {

    if (ctx->esapi_manage_session_flags) {
        return;
    }

    assert(ctx->old_flags == ctx->original_flags);

    TSS2_RC rc = Esys_TRSess_SetAttributes(ctx->esys_ctx, ctx->hmac_session, ctx->old_flags, 0xff);
    assert(rc == TSS2_RC_SUCCESS);
    if (rc != TSS2_RC_SUCCESS) {
        LOGW("Esys_TRSess_SetAttributes: 0x%x", rc);
    }
}

#define SAFE_ESYS_FREE(ptr) do { Esys_Free(ptr); ctx->tpms_alg_cache = NULL; } while (0)

void tpm_ctx_free(tpm_ctx *ctx) {

    if (!ctx) {
        return;
    }

    /* free the per-tpm caches of properties */
    SAFE_ESYS_FREE(ctx->tpms_alg_cache);
    SAFE_ESYS_FREE(ctx->tpms_cc_cache);
    SAFE_ESYS_FREE(ctx->tpms_fixed_property_cache);

    Esys_Finalize(&ctx->esys_ctx);
    if (ctx->tcti_ctx) {
        Tss2_TctiLdr_Finalize(&ctx->tcti_ctx);
    }

    free(ctx);
}

static bool set_esys_auth(ESYS_CONTEXT *esys_ctx, ESYS_TR handle, twist auth) {

    TPM2B_AUTH tpm_auth = TPM2B_EMPTY_INIT;

    if (auth) {
        size_t auth_len = twist_len(auth);
        if (auth_len > sizeof(tpm_auth.buffer)) {
            LOGE("Auth value too large, got %zu expected < %zu",
                    auth_len, sizeof(tpm_auth.buffer));
            return false;
        }

        tpm_auth.size = auth_len;
        memcpy(tpm_auth.buffer, auth, auth_len);
    }

    TSS2_RC rval = Esys_TR_SetAuth(esys_ctx, handle, &tpm_auth);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_SetAuth: 0x%x:", rval);
        return false;
    }

    return true;
}

static bool set_esys_auth_string(ESYS_CONTEXT *esys_ctx, ESYS_TR handle, const char *auth) {

    TPM2B_AUTH tpm_auth = TPM2B_EMPTY_INIT;

    if (auth) {
        size_t auth_len = strlen(auth);
        if (auth_len > sizeof(tpm_auth.buffer)) {
            LOGE("Auth value too large, got %zu expected < %zu",
                    auth_len, sizeof(tpm_auth.buffer));
            return false;
        }

        tpm_auth.size = auth_len;
        memcpy(tpm_auth.buffer, auth, auth_len);
    }

    TSS2_RC rval = Esys_TR_SetAuth(esys_ctx, handle, &tpm_auth);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_SetAuth: 0x%x:", rval);
        return false;
    }

    return true;
}

bool tpm_session_active(tpm_ctx *ctx) {
    return (!!ctx->hmac_session);
}

CK_RV tpm_session_start(tpm_ctx *ctx, twist auth, uint32_t handle) {

    assert(!ctx->hmac_session);

    bool res = set_esys_auth(ctx->esys_ctx, handle, auth);
    if (!res) {
        return CKR_GENERAL_ERROR;
    }

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 },
        .mode = { .aes = TPM2_ALG_CFB }
    };

    TPMA_SESSION session_attrs =
        TPMA_SESSION_CONTINUESESSION
      | TPMA_SESSION_DECRYPT
      | TPMA_SESSION_ENCRYPT;

    ESYS_TR session = ESYS_TR_NONE;
    TSS2_RC rc = Esys_StartAuthSession(ctx->esys_ctx,
            handle, //tpmkey
            handle, //bind
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            NULL,
            TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
            &session);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_StartAuthSession: %s", Tss2_RC_Decode(rc));
        return CKR_GENERAL_ERROR;
    }

    rc = Esys_TRSess_SetAttributes(ctx->esys_ctx, session, session_attrs,
                                      0xff);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_TRSess_SetAttributes: %s", Tss2_RC_Decode(rc));
        rc = Esys_FlushContext(ctx->esys_ctx,
                session);
        if (rc != TSS2_RC_SUCCESS) {
            LOGW("Esys_FlushContext: %s", Tss2_RC_Decode(rc));
        }
        return CKR_GENERAL_ERROR;
    }

    ctx->original_flags = session_attrs;

    ctx->hmac_session = session;

    return CKR_OK;
}

CK_RV tpm_session_stop(tpm_ctx *ctx) {

    TSS2_RC rc = Esys_FlushContext(ctx->esys_ctx,
            ctx->hmac_session);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_FlushContext: %s", Tss2_RC_Decode(rc));
        return CKR_GENERAL_ERROR;
    }

    ctx->hmac_session = 0;

    return CKR_OK;
}

/* will not hold ownership of tcti */
CK_RV tpm_ctx_new_fromtcti(void *tcti, tpm_ctx **tctx) {

    ESYS_CONTEXT *esys = NULL;

    tpm_ctx *t = calloc(1, sizeof(*t));
    if (!t) {
        return CKR_HOST_MEMORY;
    }

    esys = esys_ctx_init(tcti);
    if (!esys) {
        goto error;
    }

    /* populate */
    t->esys_ctx = esys;

    /*
     * allow TPM2_PKCS11_ESAPI_MANAGE_FLAGS to override the configure time default on whether or
     * not ESAPI should manage the flags or if the TPM code should do it.
     */
    const char *c = getenv("TPM2_PKCS11_ESAPI_MANAGE_FLAGS");
    t->esapi_manage_session_flags = c ? true : !!ESAPI_MANAGE_FLAGS;

    /* assign back (return via pointer) */
    *tctx = t;

    return CKR_OK;

error:
    tpm_ctx_free(t);
    return CKR_GENERAL_ERROR;
}

/* will initialize and own the tcti context */
CK_RV tpm_ctx_new(const char *config, tpm_ctx **tctx) {

    TSS2_TCTI_CONTEXT *tcti = NULL;

    /* no specific config, try environment */
    if (!config) {
        config = getenv(TPM2_PKCS11_TCTI);
    }

    LOGV("tcti=%s", config ? config : "(null)");
    TSS2_RC rc = Tss2_TctiLdr_Initialize(config, &tcti);
    if (rc != TSS2_RC_SUCCESS) {
        return CKR_GENERAL_ERROR;
    }

    CK_RV rv = tpm_ctx_new_fromtcti(tcti, tctx);
    (*tctx)->tcti_ctx = tcti;
    return rv;
}

static CK_RV tpm_get_properties(tpm_ctx *ctx, TPMS_CAPABILITY_DATA **d) {

    if (ctx->tpms_fixed_property_cache) {
        *d = ctx->tpms_fixed_property_cache;
        return CKR_OK;
    }

    assert(!ctx->tpms_fixed_property_cache);

    TPM2_CAP capability = TPM2_CAP_TPM_PROPERTIES;
    UINT32 property = TPM2_PT_FIXED;
    UINT32 propertyCount = TPM2_MAX_TPM_PROPERTIES;
    TPMS_CAPABILITY_DATA *capabilityData;
    TPMI_YES_NO moreData;

    TSS2_RC rval = Esys_GetCapability(ctx->esys_ctx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        capability,
        property, propertyCount, &moreData, &capabilityData);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_GetCapability: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    /* this cannot overflow */
    if (!capabilityData ||
        capabilityData->data.tpmProperties.count < TPM2_PT_VENDOR_STRING_4 - TPM2_PT_FIXED + 1) {
        LOGE("TPM did not reply with correct amount of capabilities");
        Esys_Free(capabilityData);
        return CKR_GENERAL_ERROR;
    }

    *d = ctx->tpms_fixed_property_cache = capabilityData;
    return CKR_OK;
}

static CK_RV find_fixed_cap(TPMS_CAPABILITY_DATA *d, TPM2_PT property, CK_ULONG_PTR value) {

    TPML_TAGGED_TPM_PROPERTY *t = &d->data.tpmProperties;
    TPMS_TAGGED_PROPERTY *p = t->tpmProperty;

    CK_ULONG i;
    for (i=0; i < t->count; i++) {
            if (property == p[i].property) {
                *value = p[i].value;
                return CKR_OK;
            }
    }

    return CKR_MECHANISM_INVALID;
}

CK_RV tpm_find_max_rsa_keysize(tpm_ctx *tctx, CK_ULONG_PTR min, CK_ULONG_PTR max) {

    TPMT_PUBLIC_PARMS input = { 0 };

    input.type = TPM2_ALG_RSA;
    input.parameters.rsaDetail.exponent = 0;
    input.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    input.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;

    static CK_ULONG max_found = 0;

    if (max_found) {
        *min = 1024;
        *max = max_found;
        return CKR_OK;
    }

    TPM2_KEY_BITS i;
    for(i=2; i < 5; i++) {
        input.parameters.rsaDetail.keyBits = 1024 * i; /* 2048, 3072, 4096... (cannot overflow)*/
        TSS2_RC rval = Esys_TestParms(tctx->esys_ctx,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &input);
        if (rval != TSS2_RC_SUCCESS) {
            TSS2_RC refusal = utils_format_one_code(rval);
            if (refusal == TPM2_RC_KEY_SIZE || refusal == TPM2_RC_VALUE) {
                continue;
            }
            if (refusal & TPM2_RC_FMT1) {
                return CKR_MECHANISM_INVALID;
            }
            return CKR_GENERAL_ERROR;
        }

        /* key size was good */
        if (max_found < input.parameters.rsaDetail.keyBits) {
            max_found = input.parameters.rsaDetail.keyBits;
        }
    }

    *min = 1024;
    *max = max_found;

    return CKR_OK;
}

CK_RV tpm_get_algorithms(tpm_ctx *ctx, TPMS_CAPABILITY_DATA **capabilityData);

static TPM2_ALGORITHM_ID nid_to_tpm2alg(int nid) {

    switch (nid) {
    case NID_X9_62_prime192v1:
        return TPM2_ECC_NIST_P192;
    case NID_secp224r1:
        return TPM2_ECC_NIST_P224;
    case NID_X9_62_prime256v1:
        return TPM2_ECC_NIST_P256;
    case NID_secp384r1:
        return TPM2_ECC_NIST_P384;
    case NID_secp521r1:
        return TPM2_ECC_NIST_P521;
    default:
        LOGE("Unsupported nid to tpm EC algorithm mapping, got nid: %d", nid);
        return TPM2_ALG_ERROR;
    }
}

CK_RV tpm_is_rsa_keysize_supported(tpm_ctx *tctx, CK_ULONG test_size) {

    TPMT_PUBLIC_PARMS input = { 0 };

    input.type = TPM2_ALG_RSA;
    input.parameters.rsaDetail.exponent = 0;
    input.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    input.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    input.parameters.rsaDetail.keyBits = test_size;

    TSS2_RC rval = Esys_TestParms(tctx->esys_ctx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &input);
    if (rval != TSS2_RC_SUCCESS) {
        TSS2_RC refusal = utils_format_one_code(rval);
        if (refusal == TPM2_RC_KEY_SIZE || refusal == TPM2_RC_VALUE) {
            return CKR_MECHANISM_INVALID;
        }
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV tpm_is_ecc_curve_supported(tpm_ctx *tctx, int nid) {

    TPMT_PUBLIC_PARMS input = { 0 };

    input.type = TPM2_ALG_ECC;
    input.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    input.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    input.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;

    input.parameters.eccDetail.curveID = nid_to_tpm2alg(nid);
    if (input.parameters.eccDetail.curveID == TPM2_ALG_ERROR) {
        return CKR_MECHANISM_INVALID;
    }

    TSS2_RC rval = Esys_TestParms(tctx->esys_ctx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &input);
    if (rval != TSS2_RC_SUCCESS) {
        TSS2_RC refusal = utils_format_one_code(rval);
        if (refusal == TPM2_RC_CURVE || refusal == TPM2_RC_VALUE) {
            return CKR_MECHANISM_INVALID;
        }
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV tpm_find_ecc_keysizes(tpm_ctx *tctx, CK_ULONG_PTR min, CK_ULONG_PTR max) {

    static bool cached = false;
    static CK_ULONG found_max = 0;
    static CK_ULONG found_min = ~0;

    if (cached) {
        *min = found_min/8;
        *max = found_max/8;
        return CKR_OK;
    }

    TPMT_PUBLIC_PARMS input = { 0 };

    input.type = TPM2_ALG_ECC;
    input.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    input.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    input.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;

    struct {
        TPM2_ALG_ID alg;
        unsigned size;
    } tests[] = {
        { TPM2_ECC_NIST_P192, 192 * 8 },
        { TPM2_ECC_NIST_P224, 224 * 8 },
        { TPM2_ECC_NIST_P256, 256 * 8 },
        { TPM2_ECC_NIST_P384, 384 * 8 },
        { TPM2_ECC_NIST_P521, 521 * 8 },
        { TPM2_ECC_BN_P256,   256 * 8 },
        { TPM2_ECC_BN_P638,   638 * 8 },
        { TPM2_ECC_SM2_P256,  256 * 8 },
    };


    TPM2_ALG_ID i;
    for(i=0; i < ARRAY_LEN(tests); i++) {
        input.parameters.eccDetail.curveID = tests[i].alg;
        TSS2_RC rval = Esys_TestParms(tctx->esys_ctx,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &input);
        if (rval != TSS2_RC_SUCCESS) {
            /* A curve the TPM refuses is left out, as tpm_is_ecc_curve_supported() does. */
            TSS2_RC refusal = utils_format_one_code(rval);
            if (refusal == TPM2_RC_CURVE || refusal == TPM2_RC_VALUE) {
                continue;
            }
            LOGE("Esys_TestParms: %s", Tss2_RC_Decode(rval));
            return CKR_GENERAL_ERROR;
        }

        if (tests[i].size > found_max) {
            found_max = tests[i].size;
        }

        if (tests[i].size < found_min) {
            found_min = tests[i].size;
        }

    }

    *max = found_max/8;
    *min = found_min/8;
    cached = true;

    return CKR_OK;
}

/*
 * The largest AES key the TPM takes, by TPM2_TestParms, for a TPM that leaves the required
 * TPM2_PT_CONTEXT_SYM_SIZE out of its fixed properties (wolfTPM's fwTPM, for one). Every TPM
 * takes 128 bits, and CFB, the mode of a storage key.
 */
static CK_RV tpm_test_aes_max_keysize(tpm_ctx *tctx, CK_ULONG *bits) {

    static const UINT16 sizes[] = { 256, 192 };

    size_t i;
    for (i = 0; i < ARRAY_LEN(sizes); i++) {
        TPMT_PUBLIC_PARMS input = {
            .type = TPM2_ALG_SYMCIPHER,
            .parameters.symDetail.sym = {
                .algorithm = TPM2_ALG_AES,
                .keyBits.aes = sizes[i],
                .mode.aes = TPM2_ALG_CFB,
            },
        };

        TSS2_RC rval = Esys_TestParms(tctx->esys_ctx,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &input);
        if (rval == TSS2_RC_SUCCESS) {
            *bits = sizes[i];
            return CKR_OK;
        }

        TSS2_RC refusal = utils_format_one_code(rval);
        if (refusal != TPM2_RC_KEY_SIZE && refusal != TPM2_RC_VALUE
                && refusal != TPM2_RC_SYMMETRIC) {
            LOGE("Esys_TestParms: %s", Tss2_RC_Decode(rval));
            return CKR_GENERAL_ERROR;
        }
    }

    *bits = 128;
    return CKR_OK;
}

CK_RV tpm_find_aes_keysizes(tpm_ctx *tctx, CK_ULONG_PTR min, CK_ULONG_PTR max) {

    /* ok it's supported, what are the key sizes? */
    static CK_ULONG _max = 0;
    static const CK_ULONG _min = 128;
    if (_max) {
        *min = _min/8;
        *max = _max/8;
        return CKR_OK;
    }

    TPMS_CAPABILITY_DATA *fixed_property_data = NULL;
    CK_RV rv = tpm_get_properties(tctx, &fixed_property_data);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = find_fixed_cap(fixed_property_data,
            TPM2_PT_CONTEXT_SYM_SIZE, &_max);
    if (rv == CKR_MECHANISM_INVALID) {
        rv = tpm_test_aes_max_keysize(tctx, &_max);
    }
    if (rv != CKR_OK) {
        return rv;
    }

    /* if it's supported 128bits is min by spec IIUC */
    /* convert to bytes for return values */
    *min = _min/8;
    *max = _max/8;

    return CKR_OK;
}

static UINT32 fixed_prop_or_zero(TPMS_CAPABILITY_DATA *d, TPM2_PT property) {

    CK_ULONG value = 0;
    return find_fixed_cap(d, property, &value) == CKR_OK ? (UINT32)value : 0;
}

CK_RV tpm_get_token_info (tpm_ctx *ctx, CK_TOKEN_INFO *info) {

    check_pointer(ctx);
    check_pointer(info);

    TPMS_CAPABILITY_DATA *capabilityData = NULL;

    CK_RV rv = tpm_get_properties(ctx, &capabilityData);
    if (rv !=CKR_OK) {
        return rv;
    }

    /*
     * A TPM can leave properties out of the list, so they're looked up by tag rather than
     * by their offset from TPM2_PT_FIXED; a missing one reads as 0.
     */
#define fixed_prop(p) fixed_prop_or_zero(capabilityData, (p))

    // Use Spec revision as HW Version
    UINT32 revision = fixed_prop(TPM2_PT_REVISION);
    info->hardwareVersion.major = revision / 100;
    info->hardwareVersion.minor = revision % 100;

    // Use Firmware Version as FW Version
    UINT32 version = fixed_prop(TPM2_PT_FIRMWARE_VERSION_1);
    // Most vendors seem to use 00MM.00mm as format for TPM2_PT_FIRMWARE_VERSION_1
    // Unfortunately we only have 1 byte for major and minor each.
    info->firmwareVersion.major = (version >> 16) & 0xFF;
    info->firmwareVersion.minor = version  & 0xFF;

    // Use Vendor ID as Manufacturer ID
    unsigned char manufacturerID[sizeof(UINT32)+1] = {0}; // 4 bytes + '\0' as temp storage
    UINT32 manufacturer = ntohl(fixed_prop(TPM2_PT_MANUFACTURER));
    memcpy(manufacturerID, (unsigned char*) &manufacturer, sizeof(uint32_t));
    str_padded_copy(info->manufacturerID, manufacturerID);

    // Map human readable Manufacturer String, if available,
    // otherwise 4 byte ID was already padded and will be used.
    for (unsigned int i=0; i < ARRAY_LEN(TPM2_MANUFACTURER_MAP); i++){
        if (!strncasecmp((char *)info->manufacturerID, TPM2_MANUFACTURER_MAP[i][0], 4)) {
            _str_padded_copy(info->manufacturerID, sizeof(info->manufacturerID),
                    (const CK_UTF8CHAR_PTR)TPM2_MANUFACTURER_MAP[i][1], strlen(TPM2_MANUFACTURER_MAP[i][1]));
        }
    }

    // Use Vendor String as Model description
    UINT32 vendor[4];
    vendor[0] = ntohl(fixed_prop(TPM2_PT_VENDOR_STRING_1));
    vendor[1] = ntohl(fixed_prop(TPM2_PT_VENDOR_STRING_2));
    vendor[2] = ntohl(fixed_prop(TPM2_PT_VENDOR_STRING_3));
    vendor[3] = ntohl(fixed_prop(TPM2_PT_VENDOR_STRING_4));
    _str_padded_copy(info->model, sizeof(info->model), (unsigned char*)
            &vendor, sizeof(vendor));

#undef fixed_prop

    return CKR_OK;
}

bool tpm_getrandom(tpm_ctx *ctx, BYTE *data, size_t size) {

    size_t offset = 0;

    bool result = false;

    /*
     * This will get re-used once allocated by esys
     */
    TPM2B_DIGEST *rand_bytes = NULL;

    while (size) {

        UINT16 request_size = size > sizeof(rand_bytes->buffer) ?
                sizeof(rand_bytes->buffer) : size;

        TSS2_RC rval = Esys_GetRandom(
            ctx->esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            request_size,
            &rand_bytes);
        if (rval != TSS2_RC_SUCCESS) {
            LOGE("Esys_GetRandom: %s:", Tss2_RC_Decode(rval));
            Esys_Free(rand_bytes);
            goto out;
        }

        memcpy(&data[offset], rand_bytes->buffer, rand_bytes->size);

        offset += rand_bytes->size;
        size -= rand_bytes->size;
        Esys_Free(rand_bytes);
        rand_bytes = NULL;
    }

    result = true;

out:

    return result;
}

CK_RV tpm_stirrandom(tpm_ctx *ctx, CK_BYTE_PTR seed, CK_ULONG seed_len) {

    TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;;

    size_t offset = 0;
    while(offset < seed_len) {
        TPM2B_SENSITIVE_DATA stir;

        size_t left = seed_len - offset;
        size_t chunk = left > sizeof(stir.buffer) ? sizeof(stir.buffer) : left;

        stir.size = chunk;
        memcpy(stir.buffer, &seed[offset], chunk);

        rc = Esys_StirRandom(
            ctx->esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &stir);
        if (rc != TSS2_RC_SUCCESS) {
            LOGE("Esys_StirRandom: %s:", Tss2_RC_Decode(rc));
            return CKR_GENERAL_ERROR;
        }

        offset += seed_len;
    }

    return CKR_OK;
}

bool tpm_get_name(tpm_ctx *ctx, uint32_t handle, twist *name) {

    TPM2B_NAME *tname = NULL;

    TSS2_RC rval = Esys_TR_GetName(ctx->esys_ctx, handle, &tname);
    if (rval != TSS2_RC_SUCCESS) {
        return false;
    }

    twist t = twistbin_new(tname->name, tname->size);
    Esys_Free(tname);
    if (!t) {
        LOGE("OOM");
        return false;
    }

    *name = t;

    return true;
}

bool tpm_deserialize_handle(tpm_ctx *ctx, twist handle_blob, uint32_t *handle) {

    TSS2_RC rval = Esys_TR_Deserialize(ctx->esys_ctx,
                        (uint8_t *)handle_blob,
                        twist_len(handle_blob), handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_Deserialize: %s:", Tss2_RC_Decode(rval));
        return false;
    }

    return true;
}

bool tpm_contextload_handle(tpm_ctx *ctx, twist handle_blob, uint32_t *handle) {
    TPMS_CONTEXT blob;

    TSS2_RC rval = Tss2_MU_TPMS_CONTEXT_Unmarshal((uint8_t *)handle_blob, twist_len(handle_blob),
                                                  NULL, &blob);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPMS_CONTEXT_Unmarshal: %s:", Tss2_RC_Decode(rval));
        return false;
    }

    rval = Esys_ContextLoad(ctx->esys_ctx, &blob, handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_ContextLoad: %s:", Tss2_RC_Decode(rval));
        return false;
    }

    return true;
}

static CK_RV tpm_load(tpm_ctx *ctx,
        uint32_t phandle,
        TPM2B_PUBLIC *pub, twist priv_data,
        uint32_t *handle) {

    TPM2B_PRIVATE priv = { .size = 0 };
    size_t len = twist_len(priv_data);

    size_t offset = 0;
    TSS2_RC rval = Tss2_MU_TPM2B_PRIVATE_Unmarshal((uint8_t *)priv_data, len, &offset, &priv);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPM2B_PRIVATE_Unmarshal: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    rval = Esys_Load(
           ctx->esys_ctx,
           phandle,
           ctx->hmac_session,
           ESYS_TR_NONE,
           ESYS_TR_NONE,
           &priv,
           pub,
           handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_Load: %s:", Tss2_RC_Decode(rval));
        return rval == TPM2_RC_LOCKOUT ?
                CKR_PIN_LOCKED : CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

static bool tpm_loadexternal(tpm_ctx *ctx,
        TPM2B_PUBLIC *pub,
        uint32_t *handle) {

    TSS2_RC rval;
#ifdef ESYS_3
    rval = Esys_LoadExternal(
           ctx->esys_ctx,
           ESYS_TR_NONE,
           ESYS_TR_NONE,
           ESYS_TR_NONE,
           NULL,
           pub,
           ESYS_TR_RH_NULL,
           handle);
#else /* ESYS_3 */
    rval = Esys_LoadExternal(
           ctx->esys_ctx,
           ESYS_TR_NONE,
           ESYS_TR_NONE,
           ESYS_TR_NONE,
           NULL,
           pub,
           TPM2_RH_NULL,
           handle);
#endif /* ESYS_3 */
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_LoadExternal: %s:", Tss2_RC_Decode(rval));
        return false;
    }

    return true;
}

CK_RV tpm_loadobj(
        tpm_ctx *ctx,
        uint32_t phandle, twist auth,
        twist pub_data, twist priv_data,
        uint32_t *handle) {

    TPM2B_PUBLIC pub = { .size = 0 };
    size_t len = twist_len(pub_data);

    size_t offset = 0;
    TSS2_RC rval = Tss2_MU_TPM2B_PUBLIC_Unmarshal((uint8_t *)pub_data, len, &offset, &pub);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPM2B_PRIVATE_Unmarshal: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    bool tmp_rc = set_esys_auth(ctx->esys_ctx, phandle, auth);
    if (!tmp_rc) {
        return CKR_GENERAL_ERROR;
    }

    if (priv_data) {
        return tpm_load(ctx, phandle, &pub, priv_data, handle);

    }

    return tpm_loadexternal(ctx, &pub, handle) ?
            CKR_OK : CKR_GENERAL_ERROR;
}

bool tpm_flushcontext(tpm_ctx *ctx, uint32_t handle) {

    TSS2_RC rval = Esys_FlushContext(
                ctx->esys_ctx,
                handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_FlushContext: %s", Tss2_RC_Decode(rval));
        return false;
    }

    return true;
}

twist tpm_unseal(tpm_ctx *ctx, uint32_t handle, twist objauth) {

    twist t = NULL;

    bool result = set_esys_auth(ctx->esys_ctx, handle, objauth);
    if (!result) {
        return NULL;
    }

    TPM2B_SENSITIVE_DATA *unsealed_data = NULL;

    flags_turndown(ctx, TPMA_SESSION_DECRYPT);

    TSS2_RC rc = Esys_Unseal(
            ctx->esys_ctx,
            handle,
            ctx->hmac_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &unsealed_data);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("Esys_Unseal: %s", Tss2_RC_Decode(rc));
        goto out;
    }

    t = twistbin_new(unsealed_data->buffer, unsealed_data->size);

    free(unsealed_data);
out:

    flags_restore(ctx);
    return t;
}

static CK_RV flatten_rsassa(TPMS_SIGNATURE_RSASSA *rsassa, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    if (sig && *siglen < rsassa->sig.size) {
        *siglen = rsassa->sig.size;
        return CKR_BUFFER_TOO_SMALL;
    }

    *siglen = rsassa->sig.size;

    if (sig) {
        memcpy(sig, rsassa->sig.buffer, *siglen);
    }

    return CKR_OK;
}

static CK_RV flatten_rsapss(TPMS_SIGNATURE_RSAPSS *rsapss, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    if (sig && *siglen < rsapss->sig.size) {
        *siglen = rsapss->sig.size;
        return CKR_BUFFER_TOO_SMALL;
    }

    *siglen = rsapss->sig.size;

    if (sig) {
        memcpy(sig, rsapss->sig.buffer, *siglen);
    }

    return CKR_OK;
}

static CK_RV flatten_ecdsa(TPMS_SIGNATURE_ECDSA *ecdsa, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    TPM2B_ECC_PARAMETER *R = &ecdsa->signatureR;
    TPM2B_ECC_PARAMETER *S = &ecdsa->signatureS;

    /*
     * From PKCS#11 Current Mechanisms Specification:
     *
     * "For the purposes of these mechanisms, an ECDSA signature is an
     * octet string of even length which is at most two times nLen
     * octets, where nLen is the length in octets of the base point
     * order n. The signature octets correspond to the concatenation
     * of the ECDSA values r and s, both represented as an octet
     * string of equal length of at most nLen with the most
     * significant byte first."
     */

    /*
     * From TCG TPM 2.0, Part 1: Architecture, Appendix C.8:
     *
     * "When ECC parameters are returned by the TPM as output
     * parameters in a response, they must be padded with zeros to the
     * length of the respective curve (e.g., 32 bytes for NIST
     * P-256)."
     */

    if (R->size != S->size) {
        LOGE("TPM returned ECC signature with inconsistent padding");
        return CKR_DEVICE_ERROR;
    }

    /* this can't overflow, but it doesn't hurt */
    CK_ULONG rs = 0;
    safe_add(rs, R->size, S->size);

    /* the caller's buffer length, before it's replaced by the signature's */
    CK_ULONG capacity = *siglen;
    *siglen = rs;

    if (!sig) {
        return CKR_OK;
    }

    if (rs > capacity) {
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(sig, R->buffer, R->size);
    memcpy(sig + R->size, S->buffer, S->size);
    return CKR_OK;
}

static CK_RV flatten_hmac(TPMT_HA *hmac, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    CK_ULONG buffer_len = 0;
    switch(hmac->hashAlg) {
    case TPM2_ALG_SHA1:
        buffer_len = 20;
        break;
    case TPM2_ALG_SHA256:
        buffer_len = 32;
        break;
    case TPM2_ALG_SHA384:
        buffer_len = 48;
        break;
    case TPM2_ALG_SHA512:
        buffer_len = 64;
        break;
    default:
        LOGE("Could not flatten HMAC signature");
        return CKR_GENERAL_ERROR;
    }

    if (buffer_len > *siglen) {
        return CKR_BUFFER_TOO_SMALL;
    }

    /* copy N bytes (digest length) from the biggest buffer union */
    memcpy(sig, hmac->digest.sha512, buffer_len);
    *siglen = buffer_len;

    return CKR_OK;
}

static CK_RV sig_flatten(TPMT_SIGNATURE *signature, TPMT_SIG_SCHEME *scheme, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    switch(scheme->scheme) {
    case TPM2_ALG_RSASSA:
        return flatten_rsassa(&signature->signature.rsassa, sig, siglen);
    case TPM2_ALG_RSAPSS:
        return flatten_rsapss(&signature->signature.rsapss, sig, siglen);
    case TPM2_ALG_ECDSA:
        return flatten_ecdsa(&signature->signature.ecdsa, sig, siglen);
    case TPM2_ALG_HMAC:
        return flatten_hmac(&signature->signature.hmac, sig, siglen);
        /* no default */
    }

    return CKR_GENERAL_ERROR;
}

/* Whether the TPM implements the algorithm alg, by its TPM2_CAP_ALGS list. */
static CK_RV tpm_has_alg(tpm_ctx *ctx, TPM2_ALG_ID alg, bool *has) {

    TPMS_CAPABILITY_DATA *algs = NULL;
    CK_RV rv = tpm_get_algorithms(ctx, &algs);
    if (rv != CKR_OK) {
        return rv;
    }

    *has = false;
    UINT32 i;
    for (i = 0; i < algs->data.algorithms.count; i++) {
        if (algs->data.algorithms.algProperties[i].alg == alg) {
            *has = true;
            break;
        }
    }

    return CKR_OK;
}

/* The size in bits of the order of the curve nid names, or 0 for one the token doesn't know. */
static unsigned ecc_order_bits(int nid) {
    switch (nid) {
    case NID_X9_62_prime192v1:
        return 192;
    case NID_secp224r1:
        return 224;
    case NID_X9_62_prime256v1:
        return 256;
    case NID_secp384r1:
        return 384;
    case NID_secp521r1:
        return 521;
        /* no default */
    }

    return 0;
}

/*
 * Fits an ECDSA digest to a hash the TPM implements. TPM2_Sign takes a digest only as long as its
 * scheme's hash, and a TPM need not implement every hash (the TCG reference implementation has no
 * SHA-512 by default). ECDSA signs the digest as an integer, its leftmost bitlen(n) bits (FIPS 186-5,
 * 6.4.1), so the same signature comes from the digest cut to bitlen(n) bits when it's longer, and from
 * the digest with zero bytes before it, under a hash no longer than the order. The digest's own hash
 * (the mechanism's, or the one its length names for CKM_ECDSA) is used when the TPM has it, except SHA-1:
 * a TPM may list SHA-1 and still refuse signatures with it (libtpms's no-sha1-signing, on a FIPS host),
 * so a digest that fits a longer hash is signed under that, and SHA-1 is the last resort.
 */
static CK_RV ecdsa_fit_digest(tpm_op_data *opdata, TPMT_SIG_SCHEME *scheme, TPM2B_DIGEST *digest) {

    /* in the order to try them: the shortest first, SHA-1 last */
    static const struct {
        TPMI_ALG_HASH halg;
        UINT16 size;
    } hashes[] = {
        { TPM2_ALG_SHA256, SHA256_DIGEST_LENGTH },
        { TPM2_ALG_SHA384, SHA384_DIGEST_LENGTH },
        { TPM2_ALG_SHA512, SHA512_DIGEST_LENGTH },
        { TPM2_ALG_SHA1,   SHA_DIGEST_LENGTH    },
    };

    CK_ATTRIBUTE_PTR ecparams = attr_get_attribute_by_type(opdata->tobj->attrs, CKA_EC_PARAMS);
    if (!ecparams) {
        LOGE("Expected EC key to have CKA_EC_PARAMS");
        return CKR_GENERAL_ERROR;
    }

    int nid = 0;
    CK_RV rv = ssl_util_params_to_nid(ecparams, &nid);
    if (rv != CKR_OK) {
        return rv;
    }

    unsigned order_bits = ecc_order_bits(nid);
    if (!order_bits) {
        LOGE("Unsupported curve, nid: %d", nid);
        return CKR_GENERAL_ERROR;
    }

    /* The digest's own hash, when the TPM has it */
    TPMI_ALG_HASH own = scheme->details.any.hashAlg;
    size_t i;
    for (i = 0; own == TPM2_ALG_ERROR && i < ARRAY_LEN(hashes); i++) {
        if (hashes[i].size == digest->size) {
            own = hashes[i].halg;
        }
    }

    bool has = false;
    if (own != TPM2_ALG_ERROR && own != TPM2_ALG_SHA1) {
        rv = tpm_has_alg(opdata->ctx, own, &has);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    if (has) {
        scheme->details.any.hashAlg = own;
        return CKR_OK;
    }

    /* Cut to the leftmost bitlen(n) bits; only P-521's order isn't whole bytes, and no digest is that long */
    UINT16 full_size = digest->size;
    if (digest->size * 8u > order_bits) {
        if (order_bits % 8) {
            LOGE("Cannot fit a %u-byte digest to a %u-bit order", digest->size, order_bits);
            return CKR_DATA_LEN_RANGE;
        }
        digest->size = order_bits / 8;
    }

    /*
     * The first hash the TPM has that fits: the digest's length, or a longer one the digest is zero-padded
     * to if that is no longer than the order (or the zeros would be what the TPM keeps). A digest cut to
     * the order can instead be a longer prefix of itself, for a hash no shorter than the order: the TPM
     * cuts it to the same leftmost bits (P-224's 28 bytes fit no hash, say).
     */
    for (i = 0; i < ARRAY_LEN(hashes); i++) {
        UINT16 size = hashes[i].size;
        bool exact = size == digest->size;
        bool padded = size > digest->size && size * 8u <= order_bits;
        bool prefix = full_size > digest->size && size > digest->size && size <= full_size
                && size * 8u >= order_bits;
        if (!exact && !padded && !prefix) {
            continue;
        }

        rv = tpm_has_alg(opdata->ctx, hashes[i].halg, &has);
        if (rv != CKR_OK) {
            return rv;
        }
        if (!has) {
            continue;
        }

        if (padded) {
            UINT16 pad = size - digest->size;
            memmove(&digest->buffer[pad], digest->buffer, digest->size);
            memset(digest->buffer, 0, pad);
        }
        /* a prefix is still in the buffer, past the cut */
        digest->size = size;
        scheme->details.any.hashAlg = hashes[i].halg;
        return CKR_OK;
    }

    LOGE("The TPM has no hash an ECDSA digest of %u bytes fits on a %u-bit curve", digest->size, order_bits);
    return CKR_DATA_LEN_RANGE;
}

static CK_RV tpm_hmac_large(tpm_op_data *opdata, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    tobject *tobj = opdata->tobj;
    assert(tobj);

    tpm_ctx *tctx = opdata->ctx;
    assert(tctx);

    twist auth = tobj->unsealed_auth;
    TPMI_DH_OBJECT handle = tobj->tpm_esys_tr;

    ESYS_TR session = tctx->hmac_session;

    TPMI_ALG_HASH halg = opdata->hmac.sig.details.hmac.hashAlg;

    bool result = set_esys_auth(opdata->ctx->esys_ctx, handle, auth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    TPM2B_AUTH seq_auth = {
            .size = 32
    };

    int rc = RAND_bytes(seq_auth.buffer, seq_auth.size);
    if (rc != 1) {
        LOGE("Could not generate random sequence auth value for HMAC");
        return CKR_GENERAL_ERROR;
    }

    ESYS_TR seq_handle = ESYS_TR_NONE;

    TSS2_RC rval = Esys_HMAC_Start(tctx->esys_ctx,
            handle,
            session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &seq_auth,
            halg,
            &seq_handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_HMAC_Start: %s", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    TPM2B_MAX_BUFFER buffer = { 0 };

    CK_ULONG bytes_remaining = datalen;
    while (bytes_remaining > sizeof(buffer.buffer)) {

        off_t offset = datalen - bytes_remaining;
        memcpy(buffer.buffer, &data[offset], sizeof(buffer.buffer));
        buffer.size = sizeof(buffer.buffer);

        rval = Esys_SequenceUpdate(tctx->esys_ctx,
                seq_handle,
                session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &buffer);
        if (rval != TSS2_RC_SUCCESS) {
            LOGE("Esys_SequenceUpdate: %s", Tss2_RC_Decode(rval));
            /* XXX what to do with a sequence handle? */
            return CKR_GENERAL_ERROR;
        }

        bytes_remaining -= sizeof(buffer.buffer);
    }

    assert(bytes_remaining <= sizeof(buffer.buffer));

    off_t offset = datalen - bytes_remaining;
    memcpy(buffer.buffer, &data[offset], bytes_remaining);
    buffer.size = bytes_remaining;

    TPM2B_DIGEST *hmac = NULL;
    TPMT_TK_HASHCHECK *ticket = NULL;

    rval = Esys_SequenceComplete(tctx->esys_ctx,
        seq_handle,
        session,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &buffer,
        ESYS_TR_RH_NULL,
        &hmac,
        &ticket
        );
    if (rval != TSS2_RC_SUCCESS) {
        /* XXX what to do with a sequence handle? */
        LOGE("Esys_SequenceComplete: %s", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    Esys_Free(ticket);

    *siglen = hmac->size;

    if (sig && *siglen < hmac->size) {
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    if (sig) {
        memcpy(sig, hmac->buffer, hmac->size);
    }

    rv = CKR_OK;

out:
    Esys_Free(hmac);

    return rv;
}

static CK_RV tpm_hmac(tpm_op_data *opdata, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    TPM2B_MAX_BUFFER buffer = { 0 };
    if (sizeof(buffer.buffer) < datalen) {
        /* doesn't fit in a oneshot call, do it in a multiple call */
        return tpm_hmac_large(opdata, data, datalen, sig, siglen);
    }

    /* one shot call */
    tobject *tobj = opdata->tobj;
    assert(tobj);

    tpm_ctx *tctx = opdata->ctx;
    assert(tctx);

    twist auth = tobj->unsealed_auth;
    TPMI_DH_OBJECT handle = tobj->tpm_esys_tr;

    ESYS_TR session = tctx->hmac_session;

    TPMI_ALG_HASH halg = opdata->hmac.sig.details.hmac.hashAlg;

    bool result = set_esys_auth(opdata->ctx->esys_ctx, handle, auth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    /* size checked in entry to determine if one shot or not */
    memcpy(buffer.buffer, data, datalen);
    buffer.size = datalen;


    TPM2B_DIGEST *hmac = NULL;

    TSS2_RC rval = Esys_HMAC(tctx->esys_ctx,
            handle,
            session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &buffer,
            halg,
            &hmac);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_Sign: %s", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    *siglen = hmac->size;

    if (sig && *siglen < hmac->size) {
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    if (sig) {
        memcpy(sig, hmac->buffer, hmac->size);
    }

    rv = CKR_OK;

out:
    Esys_Free(hmac);
    return rv;
}

CK_RV tpm_sign(tpm_op_data *opdata, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {
    assert(opdata);

    tobject *tobj = opdata->tobj;
    assert(tobj);

    tpm_ctx *tctx = opdata->ctx;
    assert(tctx);

    twist auth = tobj->unsealed_auth;
    TPMI_DH_OBJECT handle = tobj->tpm_esys_tr;
    ESYS_CONTEXT *ectx = tctx->esys_ctx;
    ESYS_TR session = tctx->hmac_session;
    TPMT_SIG_SCHEME *scheme = NULL;
    switch(opdata->op_type) {
        case CKK_RSA:
            scheme = &opdata->rsa.sig;
            break;
        case CKK_EC:
            scheme = &opdata->ecc.sig;
            break;
        case CKK_GENERIC_SECRET:
            return tpm_hmac(opdata, data, datalen, sig, siglen);
        default:
            LOGE("Unknown opdata op_type selector for sign, got: 0x%lx", opdata->op_type);
            return CKR_GENERAL_ERROR;
    }


    TPM2B_DIGEST tdigest;
    if (sizeof(tdigest.buffer) < datalen) {
        return CKR_DATA_LEN_RANGE;
    }
    memcpy(tdigest.buffer, data, datalen);
    tdigest.size = datalen;

    bool result = set_esys_auth(opdata->ctx->esys_ctx, handle, auth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = TPM2B_EMPTY_INIT
    };

    /* a copy: CKM_ECDSA's hash depends on each digest */
    TPMT_SIG_SCHEME ecc_scheme;
    if (opdata->op_type == CKK_EC) {
        ecc_scheme = *scheme;
        CK_RV rv = ecdsa_fit_digest(opdata, &ecc_scheme, &tdigest);
        if (rv != CKR_OK) {
            return rv;
        }
        scheme = &ecc_scheme;
    }

    flags_turndown(opdata->ctx, TPMA_SESSION_ENCRYPT);

    TPMT_SIGNATURE *signature = NULL;
    TSS2_RC rval = Esys_Sign(
            ectx,
            handle,
            session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &tdigest,
            scheme,
            &validation,
            &signature);
    flags_restore(opdata->ctx);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_Sign: %s", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    CK_RV rv = sig_flatten(signature, scheme, sig, siglen);

    Esys_Free(signature);

    return rv;
}

CK_RV tpm_verify(tpm_op_data *opdata, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG siglen) {
    assert(opdata);

    /*
     * Only HMAC should be going the way of verify to the TPM, asym ciphers should use SW for both ease of
     * integration with certificate objects but performance as well.
     */
    assert(opdata->op_type == CKK_GENERIC_SECRET);

    CK_BYTE cmp_sig[sizeof(((TPM2B_MAX_BUFFER *)NULL)->buffer)];
    CK_ULONG cmp_sig_len = sizeof(cmp_sig);

    CK_RV rv = tpm_hmac(opdata, data, datalen, cmp_sig, &cmp_sig_len);
    if (rv != CKR_OK) {
        return rv;
    }

    if (cmp_sig_len != siglen) {
        return CKR_SIGNATURE_INVALID;
    }

    return CRYPTO_memcmp(sig, cmp_sig, cmp_sig_len) == 0 ? CKR_OK : CKR_SIGNATURE_INVALID;
}

CK_RV tpm_readpub(tpm_ctx *ctx,
        uint32_t handle,

        TPM2B_PUBLIC **public,
        TPM2B_NAME **name,
        TPM2B_NAME **qualified_name) {

    TSS2_RC rval = Esys_ReadPublic(ctx->esys_ctx, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            public, name, qualified_name);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_ReadPublic: %s", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

static CK_RV get_oaep_mgf1_alg(tpm_ctx *tpm, uint32_t handle, CK_RSA_PKCS_MGF_TYPE_PTR mgf) {

    TPM2B_PUBLIC *public = NULL;
    TPM2B_NAME *name = NULL;
    TPM2B_NAME *qualified_name = NULL;

    CK_RV rv = tpm_readpub(tpm, handle, &public, &name, &qualified_name);
    if (rv != CKR_OK) {
        return rv;
    }

    switch(public->publicArea.nameAlg) {
    case TPM2_ALG_SHA1:
        *mgf = CKG_MGF1_SHA1;
        break;
    case TPM2_ALG_SHA256:
        *mgf = CKG_MGF1_SHA256;
        break;
    case TPM2_ALG_SHA384:
        *mgf = CKG_MGF1_SHA384;
        break;
    case TPM2_ALG_SHA512:
        *mgf = CKG_MGF1_SHA512;
        break;
    default:
        rv = CKR_GENERAL_ERROR;
    }

    free(public);
    free(name);
    free(qualified_name);

    return rv;
}

static TPMI_ALG_HASH mech_to_hash_alg(CK_MECHANISM_TYPE t) {

    switch(t) {
    case CKM_SHA_1:
        return TPM2_ALG_SHA1;
    case CKM_SHA256:
        return TPM2_ALG_SHA256;
    case CKM_SHA384:
        return TPM2_ALG_SHA384;
    case CKM_SHA512:
        return TPM2_ALG_SHA512;
        /* no default */
    }

    return TPM2_ALG_ERROR;
}

static void set_common_opdata(tpm_op_data *opdata, tpm_ctx *tctx, tobject *tobj, CK_KEY_TYPE key_type) {

    opdata->tobj = tobj;
    opdata->ctx = tctx;
    opdata->op_type = key_type;
}

CK_RV tpm_rsa_oaep_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    assert(outdata);
    assert(mech);
    UNUSED(m);

    /*
     * At the current moment, this is the only thing that cannot be flattened and requires PARAMS
     * and a TPM ctx for verifying the hash alg. Others just pass along the tctx via the opdata
     */

    CK_RSA_PKCS_OAEP_PARAMS_PTR params = NULL;
    SAFE_CAST(mech, params);

    if (mech->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (params->source != CKZ_DATA_SPECIFIED
            && params->pSourceData != NULL
            && params->ulSourceDataLen != 0) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /*
     * TPM is hardcoded to MGF1 + <name alg> in the TPM, make sure what is requested is supported
     */
    CK_RSA_PKCS_MGF_TYPE supported_mgf;
    CK_RV rv = get_oaep_mgf1_alg(tctx, tobj->tpm_esys_tr, &supported_mgf);
    if (rv != CKR_OK) {
        return rv;
    }
    /*  TODO revisit - why does it return not supported here. It works though
    if (params->mgf != supported_mgf) {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    */

    tpm_op_data *opdata = tpm_opdata_new(m, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.raw.scheme = TPM2_ALG_OAEP;

    opdata->rsa.raw.details.anySig.hashAlg = mech_to_hash_alg(params->hashAlg);
    if (opdata->rsa.raw.details.anySig.hashAlg == TPM2_ALG_ERROR) {
        tpm_opdata_free(&opdata);
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /*
     * The TPM hashes the label and runs MGF1 itself, so it decrypts only with a hash it implements (the
     * TCG reference implementation has no SHA-512 by default): refuse another here, rather than fail
     * the decryption with CKR_GENERAL_ERROR. Encryption, with the public key, is done in software and
     * doesn't come here.
     */
    bool has = false;
    rv = tpm_has_alg(tctx, opdata->rsa.raw.details.anySig.hashAlg, &has);
    if (rv != CKR_OK || !has) {
        if (rv == CKR_OK) {
            LOGE("The TPM doesn't implement the OAEP hash 0x%lx", params->hashAlg);
        }
        tpm_opdata_free(&opdata);
        return rv != CKR_OK ? rv : CKR_MECHANISM_PARAM_INVALID;
    }

    if (params->ulSourceDataLen > sizeof(opdata->rsa.label.buffer)) {
        tpm_opdata_free(&opdata);
        return CKR_MECHANISM_PARAM_INVALID;
    }

    opdata->rsa.label.size = params->ulSourceDataLen;
    if (params->ulSourceDataLen) {
        if (!params->pSourceData) {
            tpm_opdata_free(&opdata);
            return CKR_MECHANISM_PARAM_INVALID;
        }
        /*
         * The TPM takes only a label that is a NUL-terminated string, and refuses any other with
         * TPM_RC_VALUE (TPM 2.0 Part 3, TPM2_RSA_Decrypt): refuse it here, as a parameter the
         * token doesn't support, rather than fail the decryption with CKR_GENERAL_ERROR.
         */
        const CK_BYTE *label = params->pSourceData;
        if (label[params->ulSourceDataLen - 1] != 0) {
            LOGE("The TPM supports only an OAEP label that ends with a zero byte");
            tpm_opdata_free(&opdata);
            return CKR_MECHANISM_PARAM_INVALID;
        }
        memcpy(opdata->rsa.label.buffer, params->pSourceData, params->ulSourceDataLen);
    }

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_rsa_pkcs_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(m);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(m, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.raw.scheme = TPM2_ALG_NULL;
    opdata->rsa.label.size = 0;

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_rsa_pss_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(m);

    check_pointer(mech);
    check_pointer(outdata);

    CK_RSA_PKCS_PSS_PARAMS_PTR params;
    SAFE_CAST(mech, params);

    tpm_op_data *opdata = tpm_opdata_new(m, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.sig.scheme = TPM2_ALG_RSAPSS;

    switch (params->hashAlg) {
    case CKM_SHA_1:
        opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA1;
        break;
    case CKM_SHA256:
        opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA256;
        break;
    case CKM_SHA384:
        opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA384;
        break;
    case CKM_SHA512:
        opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA512;
        break;
    default:
        tpm_opdata_free(&opdata);
        return CKR_MECHANISM_INVALID;
    }

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_rsa_pss_sha1_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.sig.scheme = TPM2_ALG_RSAPSS;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA1;

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_rsa_pss_sha256_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.sig.scheme = TPM2_ALG_RSAPSS;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA256;

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_rsa_pss_sha384_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.sig.scheme = TPM2_ALG_RSAPSS;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA384;

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_rsa_pss_sha512_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.sig.scheme = TPM2_ALG_RSAPSS;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA512;

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_rsa_pkcs_sha1_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.sig.scheme = TPM2_ALG_RSASSA;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA1;

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_rsa_pkcs_sha256_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.sig.scheme = TPM2_ALG_RSASSA;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA256;

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_rsa_pkcs_sha384_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.sig.scheme = TPM2_ALG_RSASSA;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA384;

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_rsa_pkcs_sha512_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->rsa.sig.scheme = TPM2_ALG_RSASSA;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA512;

    set_common_opdata(opdata, tctx, tobj, CKK_RSA);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_ec_ecdsa_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->ecc.sig.scheme = TPM2_ALG_ECDSA;

    /*
     * we don't know the proper algorithm to set until ESys_Sign() is called,
     * where ecdsa_fit_digest() picks it from the digest's length.
     */
    opdata->ecc.sig.details.any.hashAlg = TPM2_ALG_ERROR;

    set_common_opdata(opdata, tctx, tobj, CKK_EC);

    *outdata = opdata;

    return CKR_OK;
}

static CK_RV tpm_ec_ecdsa_get_opdata_common(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj,
        TPMI_ALG_HASH halg, tpm_op_data **outdata) {

    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->ecc.sig.scheme = TPM2_ALG_ECDSA;
    opdata->ecc.sig.details.any.hashAlg = halg;

    set_common_opdata(opdata, tctx, tobj, CKK_EC);

    *outdata = opdata;

    return CKR_OK;
}

#define TPM_EC_ECDSA_GET_OPDATA(name, halg) \
CK_RV tpm_ec_ecdsa_##name##_get_opdata(mdetail *mdtl, \
    tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, \
    tpm_op_data **outdata) { \
    return tpm_ec_ecdsa_get_opdata_common(mdtl, tctx, mech, tobj, \
            halg, outdata); \
}

TPM_EC_ECDSA_GET_OPDATA(sha1, TPM2_ALG_SHA1)
TPM_EC_ECDSA_GET_OPDATA(sha256, TPM2_ALG_SHA256)
TPM_EC_ECDSA_GET_OPDATA(sha384, TPM2_ALG_SHA384)
TPM_EC_ECDSA_GET_OPDATA(sha512, TPM2_ALG_SHA512)

static CK_RV aes_common_opdata(tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data *opdata) {

    if (mech->ulParameterLen > sizeof(opdata->sym.iv.buffer) ||
            mech->ulParameterLen % 8 ||
            (mech->ulParameterLen && !mech->pParameter)) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* ECB has no IV, and memcpy() takes no NULL pointer, even for nothing */
    opdata->sym.iv.size = mech->ulParameterLen;
    if (mech->ulParameterLen) {
        memcpy(opdata->sym.iv.buffer, mech->pParameter, mech->ulParameterLen);
    }
    opdata->tobj = tobj;
    opdata->ctx = tctx;
    opdata->op_type = CKK_AES;

    return CKR_OK;
}

CK_RV tpm_aes_cbc_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->sym.mode = TPM2_ALG_CBC;

    CK_RV rv = aes_common_opdata(tctx, mech, tobj, opdata);
    if (rv != CKR_OK) {
        free(opdata);
        return rv;
    }

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_aes_cfb_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->sym.mode = TPM2_ALG_CFB;

    CK_RV rv = aes_common_opdata(tctx, mech, tobj, opdata);
    if (rv != CKR_OK) {
        free(opdata);
        return rv;
    }

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_aes_ecb_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->sym.mode = TPM2_ALG_ECB;

    CK_RV rv = aes_common_opdata(tctx, mech, tobj, opdata);
    if (rv != CKR_OK) {
        free(opdata);
        return rv;
    }

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_aes_ctr_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    assert(outdata);
    assert(mech);

    CK_AES_CTR_PARAMS *params = NULL;
    SAFE_CAST(mech, params);

    /*
     * The TPM has the counter bits equal to block size,
     * so it should be set to use the FULL cb value which is
     * 16 bytes.
     */
    if (params->ulCounterBits != (8 * sizeof(params->cb))) {
        LOGE("TPM Requires ulCounterBits to be %zu, got %lu", sizeof(params->cb),
                params->ulCounterBits);
        return CKR_MECHANISM_PARAM_INVALID;
    }

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->sym.mode = TPM2_ALG_CTR;

    opdata->tobj = tobj;
    opdata->ctx = tctx;
    opdata->op_type = CKK_AES;

    /* to detect overflow, start a counter at 0 and detect when it overflows 16 bytes */
    opdata->sym.ctr.counter = BN_new();
    if (!opdata->sym.ctr.counter) {
        free(opdata);
        return CKR_HOST_MEMORY;
    }

    /* the counter buffer and the iv buffer should be big enough */
    assert(sizeof(params->cb) <= sizeof(opdata->sym.iv.buffer));

    /* The counter value for the TPM IS THE WHOLE IV, SO USE IV */
    opdata->sym.iv.size = sizeof(params->cb);
    memcpy(opdata->sym.iv.buffer, params->cb, sizeof(params->cb));

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_hmac_sha1_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->hmac.sig.scheme = TPM2_ALG_HMAC;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA1;

    set_common_opdata(opdata, tctx, tobj, CKK_GENERIC_SECRET);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_hmac_sha256_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->hmac.sig.scheme = TPM2_ALG_HMAC;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA256;

    set_common_opdata(opdata, tctx, tobj, CKK_GENERIC_SECRET);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_hmac_sha384_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->hmac.sig.scheme = TPM2_ALG_HMAC;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA384;

    set_common_opdata(opdata, tctx, tobj, CKK_GENERIC_SECRET);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_hmac_sha512_get_opdata(mdetail *mdtl,
        tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata) {
    UNUSED(mdtl);
    UNUSED(mech);
    assert(outdata);
    assert(mech);

    tpm_op_data *opdata = tpm_opdata_new(mdtl, mech);
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->hmac.sig.scheme = TPM2_ALG_HMAC;
    opdata->rsa.sig.details.any.hashAlg = TPM2_ALG_SHA512;

    set_common_opdata(opdata, tctx, tobj, CKK_GENERIC_SECRET);

    *outdata = opdata;

    return CKR_OK;
}

void tpm_opdata_reset(tpm_op_data *opdata) {
    if (opdata) {
        opdata->sym.prev.len = 0;
    }
}

void tpm_opdata_free(tpm_op_data **opdata) {

    if (opdata) {

        if (*opdata && (*opdata)->mech.mechanism == CKM_AES_CTR) {
            BN_free((*opdata)->sym.ctr.counter);
            (*opdata)->sym.ctr.counter = NULL;
        }

        /* the block held back between calls may be plaintext: a key being wrapped, say */
        if (*opdata) {
            OPENSSL_cleanse(*opdata, sizeof(**opdata));
        }

        free(*opdata);
        *opdata = NULL;
    }
}

/*
 * What a TPM2_RSA_Decrypt refusal means to PKCS#11. The TPM checks the ciphertext (TPM_RC_VALUE: not below
 * the modulus, or, for a padded scheme, badly padded; TPM_RC_SIZE: not the modulus' length) and may refuse
 * the scheme itself (TPM_RC_SCHEME: a TPM restricted to FIPS-approved schemes refuses unpadded RSA, which
 * PKCS#1 v1.5 here is built on). Anything else is the TPM failing.
 */
static CK_RV rsa_decrypt_refusal(TSS2_RC rc) {

    /* the same format-one code with or without the parameter it's tied to */
    switch (utils_format_one_code(rc)) {
    case TPM2_RC_VALUE:
        return CKR_ENCRYPTED_DATA_INVALID;
    case TPM2_RC_SIZE:
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    case TPM2_RC_SCHEME:
        return CKR_FUNCTION_FAILED;
    default:
        return CKR_GENERAL_ERROR;
    }
}

CK_RV tpm_rsa_decrypt(tpm_op_data *tpm_enc_data,
        CK_BYTE_PTR ctext, CK_ULONG ctextlen,
        CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen) {

    LOGV("Performing TPM RSA Decrypt");

    CK_RV rv = CKR_GENERAL_ERROR;

    tpm_ctx *ctx = tpm_enc_data->ctx;

    TPMT_RSA_DECRYPT *scheme = &tpm_enc_data->rsa.raw;
    TPM2B_DATA *label = &tpm_enc_data->rsa.label;

    /*
     * Validate that the data to perform the operation on, typically
     * ciphertext on RSA decrypt, fits in the buffer for the TPM and
     * populate it.
     */
    TPM2B_PUBLIC_KEY_RSA tpm_ctext = { .size = ctextlen };
    if (ctextlen > sizeof(tpm_ctext.buffer)) {
        return CKR_ARGUMENTS_BAD;
    }
    memcpy(tpm_ctext.buffer, ctext, ctextlen);

    twist auth = tpm_enc_data->tobj->unsealed_auth;
    ESYS_TR handle = tpm_enc_data->tobj->tpm_esys_tr;
    bool result = set_esys_auth(ctx->esys_ctx, handle, auth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    TPM2B_PUBLIC_KEY_RSA *tpm_ptext;

    TSS2_RC rc = Esys_RSA_Decrypt(
            ctx->esys_ctx,
            handle,
            ctx->hmac_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &tpm_ctext,
            scheme,
            label,
            &tpm_ptext);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("Esys_RSA_Decrypt: %s", Tss2_RC_Decode(rc));
        return rsa_decrypt_refusal(rc);
    }

    if (!ptext) {
        *ptextlen = tpm_ctext.size;
        rv = CKR_OK;
        goto out;
    }

    if (*ptextlen < tpm_ctext.size) {
        *ptextlen = tpm_ctext.size;
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    *ptextlen = tpm_ptext->size;
    memcpy(ptext, tpm_ptext->buffer, tpm_ptext->size);

    rv = CKR_OK;

out:
    /* the plaintext may be a key being unwrapped */
    OPENSSL_cleanse(tpm_ptext->buffer, sizeof(tpm_ptext->buffer));
    free(tpm_ptext);

    return rv;
}

static TSS2_RC tpm_get_cc(tpm_ctx *tpm, TPMS_CAPABILITY_DATA **capabilityData) {
    assert(tpm);
    assert(tpm->esys_ctx);
    assert(capabilityData);

    if (tpm->tpms_cc_cache) {
        *capabilityData = tpm->tpms_cc_cache;
        return CKR_OK;
    }

    TPM2_CAP capability = TPM2_CAP_COMMANDS;
    UINT32 property = TPM2_CC_FIRST;
    UINT32 propertyCount = TPM2_MAX_CAP_CC;
    TPMI_YES_NO moreData;

    TSS2_RC rval = Esys_GetCapability(tpm->esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            capability,
            property, propertyCount, &moreData, capabilityData);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_GetCapability: %s", Tss2_RC_Decode(rval));
        return rval;
    }

    tpm->tpms_cc_cache = *capabilityData;

    return TSS2_RC_SUCCESS;
}

static TSS2_RC tpm_supports_cc(tpm_ctx *tpm, TPMA_CC check_cc, bool *is_supported) {

	/* do not free, value is cached */
    TPMS_CAPABILITY_DATA *capabilityData = NULL;
    CK_RV rval = tpm_get_cc(tpm, &capabilityData);
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }

    size_t i;
    for (i=0; i < capabilityData->data.command.count; i++) {
        TPMA_CC cca = capabilityData->data.command.commandAttributes[i];
        TPM2_CC cc = cca & TPMA_CC_COMMANDINDEX_MASK;
        if (cc == check_cc) {
            *is_supported = true;
            return TSS2_RC_SUCCESS;
        }
    }

    *is_supported = false;
    return TSS2_RC_SUCCESS;
}

static TSS2_RC do_part_encrypt_decrypt(
        tpm_ctx *ctx, uint32_t handle,
        TPMI_ALG_SYM_MODE mode, TPMI_YES_NO is_decrypt,
        const TPM2B_MAX_BUFFER *data_in, const TPM2B_IV *iv_in,
        TPM2B_MAX_BUFFER **data_out, TPM2B_IV **iv_out) {

    TSS2_RC rval = TSS2_RC_SUCCESS;

    /* figure out what command to use */
    if (!ctx->did_check_for_encdec2) {
        /* do not free, value is cached */
        rval = tpm_supports_cc(ctx, TPM2_CC_EncryptDecrypt2,
                &ctx->use_encdec2);
        if (rval != TSS2_RC_SUCCESS) {
            return rval;
        }
    }

    /* setup the output structures */
    unsigned version = 2;
    if (ctx->use_encdec2) {
        rval = Esys_EncryptDecrypt2(
            ctx->esys_ctx,
            handle,
            ctx->hmac_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            data_in,
            is_decrypt,
            mode,
            iv_in,
            data_out,
            iv_out);
    } else {
        version = 1;
        flags_turndown(ctx, TPMA_SESSION_DECRYPT);
        rval = Esys_EncryptDecrypt(
            ctx->esys_ctx,
            handle,
            ctx->hmac_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            is_decrypt,
            mode,
            iv_in,
            data_in,
            data_out,
            iv_out);
        flags_restore(ctx);
    }

    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_EncryptDecrypt%u: %s", version,
                Tss2_RC_Decode(rval));
    }

    return rval;
}

static CK_RV encrypt_decrypt(tpm_ctx *ctx, uint32_t handle, twist objauth, TPMI_ALG_SYM_MODE mode, TPMI_YES_NO is_decrypt,
        TPM2B_IV *iv, CK_BYTE_PTR data_in, CK_ULONG data_in_len, CK_BYTE_PTR data_out, CK_ULONG_PTR data_out_len) {

    /*
     * Handle 5.2 style queries for output buffer size
     *
     * XXX This might not be the best spot, and logic may need to be extended
     * for different modes to include padding sizes, not sure yet.
     */
    if (!data_out) {
        *data_out_len = data_in_len;
        return CKR_OK;
    } else if(data_in_len > *data_out_len) {
        *data_out_len = data_in_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    bool result = set_esys_auth(ctx->esys_ctx, handle, objauth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    TPM2B_IV empty_iv = { .size = sizeof(empty_iv.buffer), .buffer = { 0 } };

    /*
     * Copy the data into TPM structures
     */
    TPM2B_IV current_iv = iv ? *iv : empty_iv;

    size_t offset = 0;
    size_t remaining = (size_t)data_in_len;

    while (remaining != 0) {

        TPM2B_MAX_BUFFER tpm_data_in = (TPM2B_MAX_BUFFER){ 0 };

        /* How much can we encrypt in this part, bounded by TPM data structure sizes */
        size_t part_len_sz = remaining > sizeof(tpm_data_in.buffer) ?
                sizeof(tpm_data_in.buffer) : remaining;
        CK_ULONG part_len = (CK_ULONG)part_len_sz;

        /* copy it into the structure and set size */
        tpm_data_in.size = part_len;
        memcpy(tpm_data_in.buffer, &data_in[offset], part_len);

        /* send to TPM */
        TPM2B_MAX_BUFFER *tpm_data_out = NULL;
        TPM2B_IV *tpm_iv_out = NULL;
        TSS2_RC rc = do_part_encrypt_decrypt(ctx, handle, mode, is_decrypt,
                &tpm_data_in, &current_iv,
                &tpm_data_out, &tpm_iv_out);
        if (rc != TSS2_RC_SUCCESS) {
            OPENSSL_cleanse(&tpm_data_in, sizeof(tpm_data_in));
            return CKR_GENERAL_ERROR;
        }

        /* shuffle/update IV for next iteration */
        /*
         * For CBC and CTR, derive the next IV locally to ensure
         * consistent chaining semantics across TPM stacks.
         * - CBC encrypt: next IV = last output block
         * - CBC decrypt: next IV = last input block
         * - CTR: increment 128-bit counter by number of 16-byte blocks
         * For other modes (e.g., CFB/ECB), if TPM provided an IV, use it.
         */
        if (mode == TPM2_ALG_CBC) {
            const CK_BYTE *src = NULL;
            /* part_len should always be a multiple of 16 for CBC/CTR */
            if (part_len >= 16) {
                if (!is_decrypt) {
                    /* encrypt: use last output block */
                    src = &tpm_data_out->buffer[part_len - 16];
                } else {
                    /* decrypt: use last input block */
                    src = &tpm_data_in.buffer[part_len - 16];
                }
                current_iv.size = 16;
                memcpy(current_iv.buffer, src, 16);
            }
        } else if (mode == TPM2_ALG_CTR) {
            /* For CTR, increment the 128-bit counter by blocks processed */
            uint32_t blocks = part_len / 16;
            if (blocks) {
                size_t i = sizeof(current_iv.buffer);
                uint32_t carry = blocks;
                while (i > 0 && carry) {
                    i--;
                    unsigned int sum = (unsigned int)current_iv.buffer[i] + (carry & 0xFFu);
                    current_iv.buffer[i] = (CK_BYTE)(sum & 0xFFu);
                    carry = (sum >> 8) + (carry >> 8);
                }
                current_iv.size = (uint16_t)sizeof(current_iv.buffer);
            }
        } else {
            /* ECB/CFB or other modes: prefer TPM-provided IV if available */
            if (tpm_iv_out && tpm_iv_out->size) {
                current_iv = *tpm_iv_out;
            }
        }
        Esys_Free(tpm_iv_out);
        tpm_iv_out = NULL;

        /* shuffle to output buffer */
        assert(tpm_data_out->size == part_len);
        memcpy(&data_out[offset], tpm_data_out->buffer, part_len);

        /* the plaintext, on one side or the other, may be a key being wrapped or unwrapped */
        OPENSSL_cleanse(tpm_data_out->buffer, part_len);
        OPENSSL_cleanse(&tpm_data_in, sizeof(tpm_data_in));
        Esys_Free(tpm_data_out);
        tpm_data_out = NULL;

        /* update the offset and remaining for the next go around */
        offset += part_len_sz;
        remaining -= part_len_sz;
    }

    assert(offset == (size_t)data_in_len);

    /* update the operations IV */
    *iv = current_iv;

    /* set the output size */
    *data_out_len = data_in_len;

    return CKR_OK;
}

/*
 * These align with the specifications TPMI_YES_NO values as understood for encryptdecrypt routines.
 */
#define ENCRYPT 0
#define DECRYPT 1

static CK_RV do_buffered_encdec(tpm_op_data *tpm_enc_data,
        int encdec,
        CK_BYTE_PTR in, CK_ULONG inlen,
        CK_BYTE_PTR out, CK_ULONG_PTR outlen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    tpm_ctx *ctx = tpm_enc_data->ctx;
    TPMI_ALG_SYM_MODE mode = tpm_enc_data->sym.mode;
    TPM2B_IV *iv = &tpm_enc_data->sym.iv;

    twist auth = tpm_enc_data->tobj->unsealed_auth;
    ESYS_TR handle = tpm_enc_data->tobj->tpm_esys_tr;

    /* final calls don't have input data, they just exhaust the internal buffer if present */
    bool is_final = !in;

    /*
     * if the application doesn't ask for a block boundary,
     * buffer the extra till later when you can make a block.
     * Manipulate the input to the TPM to be on a boundary.
     */
    binarybuffer data[] = {
        { .data = tpm_enc_data->sym.prev.data, .size = tpm_enc_data->sym.prev.len },
        { .data = in,                          .size = inlen                      },
    };

    twist full_buffer = twistbin_create(data, ARRAY_LEN(data));
    if (!full_buffer) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    /* pass only the "good blocks here */
    size_t full_buffer_len = twist_len(full_buffer);
    CK_ULONG extralen = full_buffer_len % 16;
    CK_ULONG blocks = full_buffer_len / 16;
    CK_ULONG modified_full_buffer_len = full_buffer_len - extralen;

    /*
     * Hold a block back on the following conditions:
     * 1. Decrypt, as one block will have padding. Encrypt can just fire off blocks like
     *    normal. Decrypt will need a final block to strip padding from.
     * 2. Its not the final round, the final round better be right or error.
     * 3. There are blocks to hold back
     * 4. There is NO extra data, just send the blocks we have.
     *    the blocks we have.
     * 5. We have a padding mechanism, so we need to hold it back for possible final pad.
     */
    bool hold_block_back = encdec == DECRYPT
            && !is_final
            && blocks > 0
            && extralen == 0
            && tpm_enc_data->mech.mechanism == CKM_AES_CBC_PAD;

    /* the last block is held back, whatever the number before it */
    if (hold_block_back) {
        blocks--;
        extralen = 16;
        modified_full_buffer_len = blocks * 16;
    }

    /*
     * A 5.2 style length query, or a buffer too small, takes nothing: the call with the buffer does
     * the work. The length counts the block a decrypt would hold back, as it may be data, so it
     * suffices whatever C_DecryptFinal finds.
     */
    CK_ULONG bound = full_buffer_len - (full_buffer_len % 16);
    if (!out) {
        *outlen = bound;
        rv = CKR_OK;
        goto error;
    }

    if (blocks && modified_full_buffer_len > *outlen) {
        *outlen = bound;
        rv = CKR_BUFFER_TOO_SMALL;
        goto error;
    }

    if (blocks) {

        if (tpm_enc_data->mech.mechanism == CKM_AES_CTR) {

            /* Detect CTR wrapping, ie CTR should never repeat itself */
            int rc = BN_add_word(tpm_enc_data->sym.ctr.counter, blocks);
            if (!rc) {
                SSL_UTIL_LOGE("BN_add_word");
                rv = CKR_GENERAL_ERROR;
                goto error;
            }

            /* it shouldn't be over 16 bytes */
            int bytes = BN_num_bytes(tpm_enc_data->sym.ctr.counter);
            assert(bytes >= 0);
            if ((unsigned)bytes > sizeof(((CK_AES_CTR_PARAMS *)NULL)->cb)) {
                LOGE("CTR counter wrapped");
                rv = CKR_DATA_LEN_RANGE;
                goto error;
            }
        }

        rv = encrypt_decrypt(ctx, handle, auth, mode, encdec,
                iv,
                (CK_BYTE_PTR)full_buffer, modified_full_buffer_len,
                out, outlen);
        if (rv != CKR_OK) {
            goto error;
        }
    } else {
        /* no blocks to encrypt, nothing to output */
        *outlen = 0;
    }

    /* if we have extra data, save it for next round */
    /* make sure we don't exceed the space of the internal static buffer */
    if (extralen > sizeof(tpm_enc_data->sym.prev.data)) {
        LOGE("Internal buffer too small");
        rv = CKR_GENERAL_ERROR;
        goto error;
    }

    tpm_enc_data->sym.prev.len = extralen;
    if (extralen) {
        memcpy(tpm_enc_data->sym.prev.data, &full_buffer[modified_full_buffer_len], extralen);
    }

    rv = CKR_OK;

error:
    /* plaintext when encrypting */
    OPENSSL_cleanse((void *)full_buffer, full_buffer_len);
    twist_free(full_buffer);

    return rv;
}

CK_RV tpm_encrypt(crypto_op_data *opdata,
        CK_BYTE_PTR ptext, CK_ULONG ptextlen,
        CK_BYTE_PTR ctext, CK_ULONG_PTR ctextlen) {

    tpm_op_data *tpm_enc_data = opdata->tpm_opdata;

    if (tpm_enc_data->op_type == CKK_RSA) {
        return tpm_rsa_decrypt(tpm_enc_data, ptext, ptextlen, ctext, ctextlen);
    }

    return do_buffered_encdec(tpm_enc_data, ENCRYPT, ptext, ptextlen,
            ctext, ctextlen);
}

static CK_RV common_final_encrypt_decrypt(int encdec, crypto_op_data *opdata,
        CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {

    tpm_op_data *tpm_enc_data = opdata->tpm_opdata;

    CK_RV rv = CKR_GENERAL_ERROR;

    /* non-aes things don't matter */
    if (opdata->tpm_opdata->op_type != CKK_AES) {
        if (last_part_len) {
            *last_part_len = 0;
        }
        return CKR_OK;
    }

    /*
     * For padding modes, this is where you would apply the pad or error
     * for non-padding modes
     */

    if (opdata->tpm_opdata->mech.mechanism == CKM_AES_CBC_PAD) {
        /* if it's a padding mode, apply the pad */
        if (encdec == ENCRYPT) {

            /*
             * pad the data preserving the extra data
             * This call might be for buffer size, so we don't want to attempt to apply padding
             * twice, so we only copy the padded data into the internal buffer as needed.
             */
            CK_BYTE out[sizeof(opdata->tpm_opdata->sym.prev.data)];
            CK_ULONG outlen = sizeof(out);
            rv = mech_synthesize(tpm_enc_data->mdtl,
                    &tpm_enc_data->mech, tpm_enc_data->tobj->attrs,
                    opdata->tpm_opdata->sym.prev.data,
                    opdata->tpm_opdata->sym.prev.len,
                    out,
                    &outlen);
            if (rv != CKR_OK) {
                return rv;
            }

            /* just asking for size as in 5.2 style returns */
            if (!last_part) {
                OPENSSL_cleanse(out, sizeof(out));
                *last_part_len = outlen;
                return CKR_OK;
            }

            if (outlen > *last_part_len) {
                OPENSSL_cleanse(out, sizeof(out));
                *last_part_len = outlen;
                return CKR_BUFFER_TOO_SMALL;
            }

            /* swap the internal buffer with the padded variant for the last call */
            opdata->tpm_opdata->sym.prev.len = outlen;
            memcpy(opdata->tpm_opdata->sym.prev.data, out, outlen);
            OPENSSL_cleanse(out, sizeof(out));

            rv = do_buffered_encdec(tpm_enc_data, encdec,
                    NULL, 0,
                    last_part, last_part_len);
        } else {
            /* remove the pad */

            /* nothing held back, as after C_Decrypt's length query: a length query has nothing */
            if (!last_part && !tpm_enc_data->sym.prev.len) {
                *last_part_len = 0;
                return CKR_OK;
            }

            /*
             * A length query, or a buffer too small, leaves the held-back block, and the IV that
             * decrypts it, to the call that takes the plaintext.
             */
            TPM2B_IV saved_iv = tpm_enc_data->sym.iv;
            CK_ULONG saved_len = tpm_enc_data->sym.prev.len;
            CK_BYTE saved[sizeof(tpm_enc_data->sym.prev.data)];
            memcpy(saved, tpm_enc_data->sym.prev.data, saved_len);

            /* decrypt into the padded buffer */
            CK_BYTE padded[16];
            CK_ULONG padded_len = sizeof(padded);
            rv = do_buffered_encdec(tpm_enc_data, encdec,
                    NULL, 0,
                    padded, &padded_len);
            if (rv != CKR_OK) {
                return rv;
            }

            /* remove the pad */
            CK_BYTE out[sizeof(padded)];
            CK_ULONG outlen = sizeof(out);

            rv = mech_unsynthesize(tpm_enc_data->mdtl,
                    &tpm_enc_data->mech, tpm_enc_data->tobj->attrs,
                    padded,
                    padded_len,
                    out,
                    &outlen);
            OPENSSL_cleanse(padded, sizeof(padded));

            /* just asking for size as in 5.2 style returns, too small a buffer, or a bad pad */
            if (rv != CKR_OK || !last_part || outlen > *last_part_len) {
                tpm_enc_data->sym.iv = saved_iv;
                tpm_enc_data->sym.prev.len = saved_len;
                memcpy(tpm_enc_data->sym.prev.data, saved, saved_len);
                OPENSSL_cleanse(out, sizeof(out));
                if (rv != CKR_OK) {
                    return rv;
                }
                *last_part_len = outlen;
                return !last_part ? CKR_OK : CKR_BUFFER_TOO_SMALL;
            }

            *last_part_len = outlen;
            memcpy(last_part, out, outlen);
            OPENSSL_cleanse(out, sizeof(out));
        }
        /* no extra data, nothing to do */
    } else if (opdata->tpm_opdata->sym.prev.len) {
        /* mode should be one of the non padding modes */
            assert(
                (opdata->tpm_opdata->mech.mechanism == CKM_AES_CBC)
            ||  (opdata->tpm_opdata->mech.mechanism == CKM_AES_CFB128)
            ||  (opdata->tpm_opdata->mech.mechanism == CKM_AES_ECB)
            ||  (opdata->tpm_opdata->mech.mechanism == CKM_AES_CTR));
            rv = CKR_DATA_LEN_RANGE;
    } else {
        /* everything ended on a block boundary */
        assert(opdata->tpm_opdata->sym.prev.len == 0);
        *last_part_len = opdata->tpm_opdata->sym.prev.len;
        rv = CKR_OK;
    }

    return rv;
}

CK_RV tpm_final_encrypt(crypto_op_data *opdata,
        CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {

    return common_final_encrypt_decrypt(ENCRYPT, opdata, last_part, last_part_len);
}

CK_RV tpm_decrypt(crypto_op_data *opdata,
        CK_BYTE_PTR ctext, CK_ULONG ctextlen,
        CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen) {

    tpm_op_data *tpm_enc_data = opdata->tpm_opdata;

    if (tpm_enc_data->op_type == CKK_RSA) {
        CK_BYTE buf[4096];
        CK_ULONG buf_len = sizeof(buf);

        /*
         * CKM_RSA_PKCS: a TPM with RSAES takes the padding off itself, so it needn't do raw RSA,
         * which a FIPS profile may not. A copy, as encrypting with the private key shares the
         * opdata's raw scheme.
         */
        tpm_op_data rsaes;
        if (tpm_enc_data->mech.mechanism == CKM_RSA_PKCS) {
            bool has = false;
            CK_RV rv = tpm_has_alg(tpm_enc_data->ctx, TPM2_ALG_RSAES, &has);
            if (rv != CKR_OK) {
                return rv;
            }
            if (has) {
                rsaes = *tpm_enc_data;
                rsaes.rsa.raw.scheme = TPM2_ALG_RSAES;

                rv = tpm_rsa_decrypt(&rsaes, ctext, ctextlen, buf, &buf_len);
                if (rv != CKR_OK) {
                    return rv;
                }

                if (ptext && *ptextlen < buf_len) {
                    rv = CKR_BUFFER_TOO_SMALL;
                } else if (ptext) {
                    memcpy(ptext, buf, buf_len);
                }
                *ptextlen = buf_len;
                OPENSSL_cleanse(buf, buf_len);
                return rv;
            }
        }

        CK_RV rv = tpm_rsa_decrypt(tpm_enc_data, ctext, ctextlen, buf, &buf_len);
        if (rv != CKR_OK) {
            return rv;
        }

        rv = mech_unsynthesize(
                tpm_enc_data->mdtl,
                &tpm_enc_data->mech, tpm_enc_data->tobj->attrs,
                buf, buf_len,
                ptext, ptextlen);
        OPENSSL_cleanse(buf, buf_len);
        return rv;
    }

    return do_buffered_encdec(tpm_enc_data, DECRYPT,
            ctext, ctextlen, ptext, ptextlen);
}

CK_RV tpm_final_decrypt(crypto_op_data *opdata,
        CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {

    return common_final_encrypt_decrypt(DECRYPT, opdata, last_part, last_part_len);
}

CK_RV tpm_changeauth(tpm_ctx *ctx, uint32_t parent_handle, uint32_t object_handle,
        twist oldauth, twist newauth,
        twist *newblob) {

    /* Set up the new auth value */
    TPM2B_AUTH new_tpm_auth;
    size_t newauthlen = twist_len(newauth);
    if (newauthlen > sizeof(new_tpm_auth.buffer)) {
        return CKR_PIN_LEN_RANGE;
    }

    new_tpm_auth.size = newauthlen;
    memcpy(new_tpm_auth.buffer, newauth, newauthlen);

    /* set the old auth value */
    bool result = set_esys_auth(ctx->esys_ctx, object_handle, oldauth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    /* call changeauth */
    TPM2B_PRIVATE *newprivate = NULL;
    TSS2_RC rval = Esys_ObjectChangeAuth(ctx->esys_ctx,
                        object_handle,
                        parent_handle,
                        ctx->hmac_session, ESYS_TR_NONE, ESYS_TR_NONE,
                        &new_tpm_auth, &newprivate);

    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_ObjectChangeAuth: %s", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    uint8_t serialized[sizeof(*newprivate)];

    /* serialize the new blob private */
    size_t offset = 0;
    rval = Tss2_MU_TPM2B_PRIVATE_Marshal(newprivate, serialized,
            sizeof(*newprivate), &offset);
    if (rval != TSS2_RC_SUCCESS) {
        free(newprivate);
        LOGE("Tss2_MU_TPM2B_PRIVATE_Marshal: %s", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    *newblob = twistbin_new(serialized, offset);
    free(newprivate);

    return *newblob ? CKR_OK : CKR_HOST_MEMORY;
}

static TSS2_RC create_loaded(
        tpm_ctx *tpm,
        ESYS_TR parent,
        ESYS_TR session,
        TPM2B_SENSITIVE_CREATE *in_sens,
        const TPM2B_PUBLIC *in_pub,
        ESYS_TR *out_handle,
        TPM2B_PUBLIC **out_pub,
        TPM2B_PRIVATE **out_priv
    ) {

    TSS2_RC rval;

    if (!tpm->did_check_for_createloaded) {
        /* do not free, value is cached */
        rval = tpm_supports_cc(tpm, TPM2_CC_CreateLoaded,
        		&tpm->use_createloaded);
        if (rval != TSS2_RC_SUCCESS) {
        	return rval;
        }
        tpm->did_check_for_createloaded = true;
    }

    if (out_handle && tpm->use_createloaded) {

        size_t offset = 0;
        TPM2B_TEMPLATE template = { .size = 0 };
        rval = Tss2_MU_TPMT_PUBLIC_Marshal(&in_pub->publicArea, &template.buffer[0],
                                        sizeof(TPMT_PUBLIC), &offset);
        if (rval != TSS2_RC_SUCCESS) {
            LOGE("Tss2_MU_TPMT_PUBLIC_Marshal: %s", Tss2_RC_Decode(rval));
            return rval;
        }

        template.size = offset;

        rval = Esys_CreateLoaded(
                tpm->esys_ctx,
                parent,
                session, ESYS_TR_NONE, ESYS_TR_NONE,
                in_sens,
                &template,
                out_handle,
                out_priv,
                out_pub);
        if(rval != TPM2_RC_SUCCESS) {
            LOGE("Esys_CreateLoaded: %s", Tss2_RC_Decode(rval));
            return rval;
        }
    } else {

        TPM2B_DATA outside_info = TPM2B_EMPTY_INIT;
        TPML_PCR_SELECTION creation_pcr = { .count = 0 };
        TPM2B_CREATION_DATA *creation_data = NULL;
        TPM2B_DIGEST *creation_hash = NULL;
        TPMT_TK_CREATION *creation_ticket = NULL;

        rval = Esys_Create(tpm->esys_ctx,
                parent,
                session, ESYS_TR_NONE, ESYS_TR_NONE,
                in_sens,
                in_pub,
                &outside_info,
                &creation_pcr,
                out_priv,
                out_pub,
                &creation_data,
                &creation_hash,
                &creation_ticket);
        if(rval != TPM2_RC_SUCCESS) {
            LOGE("Esys_Create: %s", Tss2_RC_Decode(rval));
            return rval;
        }

        Esys_Free(creation_data);
        Esys_Free(creation_hash);
        Esys_Free(creation_ticket);

        assert(*out_priv);
        assert(*out_pub);

        if (!out_handle)
            return TSS2_RC_SUCCESS;

        rval = Esys_Load(tpm->esys_ctx,
                parent,
                session, ESYS_TR_NONE, ESYS_TR_NONE,
                *out_priv,
                *out_pub,
                out_handle);
        if(rval != TPM2_RC_SUCCESS) {
            LOGE("Esys_Load: %s", Tss2_RC_Decode(rval));
            return rval;
        }
    }

    return TSS2_RC_SUCCESS;
}

CK_RV tpm2_create_seal_obj(tpm_ctx *ctx, twist parentauth, uint32_t parent_handle, twist objauth, twist oldpubblob, twist sealdata, twist *newpubblob, twist *newprivblob) {

    bool started_session = false;

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_RV tmp_rv = CKR_GENERAL_ERROR;

    /*
     * clone the public portion from the existing object by unmarshaling (aka unserializing) it from the
     * pub blob and converting it to a TPM2B_TEMPLATE
     */
    TPM2B_PUBLIC pub = DEFAULT_SEAL_TEMPLATE;
    if (oldpubblob) {
        pub.size = 0;
        size_t len = twist_len(oldpubblob);

        size_t offset = 0;
        TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal((uint8_t *)oldpubblob, len, &offset, &pub);
        if (rc != TSS2_RC_SUCCESS) {
            LOGE("Tss2_MU_TPM2B_PUBLIC_Unmarshal: %s", Tss2_RC_Decode(rc));
            return CKR_GENERAL_ERROR;
        }
    }
    /*
     * Set the seal data and auth value in the sensitive portion
     */
    TPM2B_SENSITIVE_CREATE sensitive = { .size = 0 };

    size_t len = twist_len(sealdata);
    if (len > sizeof(sensitive.sensitive.data.buffer)) {
        LOGE("Seal data too big");
        return CKR_GENERAL_ERROR;
    }

    memcpy(sensitive.sensitive.data.buffer, sealdata, len);
    sensitive.sensitive.data.size = len;

    len = twist_len(objauth);
    if (len > sizeof(sensitive.sensitive.userAuth.buffer)) {
        LOGE("Auth value too big");
        return CKR_GENERAL_ERROR;
    }

    memcpy(sensitive.sensitive.userAuth.buffer, objauth, len);
    sensitive.sensitive.userAuth.size = len;

    /*
     * Set the parent object auth
     */
    if (!ctx->hmac_session) {
        rv = tpm_session_start(ctx, parentauth, parent_handle);
        if (rv != CKR_OK) {
            return rv;
        }
        started_session = true;
    } else {
        bool res = set_esys_auth(ctx->esys_ctx, parent_handle, parentauth);
        if (!res) {
            return CKR_GENERAL_ERROR;
        }
    }

    TPM2B_PRIVATE *newpriv = NULL;
    TPM2B_PUBLIC *newpub = NULL;
    TSS2_RC rc = create_loaded(
            ctx,
            parent_handle,
            ctx->hmac_session,
            &sensitive,
            &pub,
            NULL,
            &newpub,
            &newpriv
    );
    if (rc != TSS2_RC_SUCCESS) {
        return CKR_GENERAL_ERROR;
    }

    uint8_t serialized[sizeof(*newpriv) > sizeof(*newpub) ?
            sizeof(*newpriv) : sizeof(*newpub)];

    /* serialize the new blob private */
    size_t offset = 0;
    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(newpriv, serialized, sizeof(*newpriv), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPM2B_PRIVATE_Marshal: %s", Tss2_RC_Decode(rc));
        goto out;
    }

    *newprivblob = twistbin_new(serialized, offset);
    if (!*newprivblob) {
        goto out;
    }

    /* serialize the new blob public */
    offset = 0;
    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(newpub, serialized, sizeof(*newpub), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        twist_free(*newprivblob);
        *newprivblob = NULL;
        LOGE("Tss2_MU_TPM2B_PUBLIC_Marshal: %s", Tss2_RC_Decode(rc));
        goto out;
    }

    *newpubblob = twistbin_new(serialized, offset);
    if (!*newpubblob) {
        twist_free(*newprivblob);
        *newprivblob = NULL;
        goto out;
    }

    rv = CKR_OK;

out:
    if (started_session) {
        tmp_rv = tpm_session_stop(ctx);
        if (tmp_rv != CKR_OK) {
            rv = tmp_rv;
        }
    }

    free(newpriv);
    free(newpub);

    return rv;
}

typedef struct tpm_key_data tpm_key_data;
/*
 * What the private key template asks of the key, for CKA_SIGN, CKA_SIGN_RECOVER, CKA_DECRYPT,
 * CKA_UNWRAP, CKA_DERIVE and CKA_DECAPSULATE, and the public key template of CKA_VERIFY_RECOVER.
 */
typedef enum usage_request usage_request;
enum usage_request {
    usage_unset = -1,
    usage_no = 0,
    usage_yes = 1,
};

struct tpm_key_data {
    tpm_ctx *ctx;
    TPM2B_PUBLIC pub;
    TPM2B_SENSITIVE_CREATE priv;
    usage_request sign;
    usage_request sign_recover;
    usage_request verify_recover;
    usage_request decrypt;
    usage_request unwrap;
    usage_request derive;
    usage_request decapsulate;
};

static CK_RV generic_bbool_check(CK_ATTRIBUTE_PTR attr, CK_BBOOL check) {

    CK_BBOOL value;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    if (value != check) {
        LOGE("Expected attr 0x%lx to be %u, got %u", attr->type, check, value);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

static CK_RV generic_bbool_false(CK_ATTRIBUTE_PTR attr, void *udata) {
    UNUSED(udata);

    return generic_bbool_check(attr, CK_FALSE);
}

static CK_RV generic_bbool_any(CK_ATTRIBUTE_PTR attr, void *udata) {
    UNUSED(udata);

    CK_BBOOL value;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    if (value != CK_TRUE && value != CK_FALSE) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

static CK_RV handle_modulus(CK_ATTRIBUTE_PTR attr, void *udata) {

    tpm_key_data *keydat = (tpm_key_data *)udata;

    CK_ULONG value;
    CK_RV rv = attr_CK_ULONG(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG min = 0;
    CK_ULONG max = 0;
    rv = tpm_find_max_rsa_keysize(keydat->ctx, &min, &max);
    if (rv != CKR_OK) {
        return rv;
    }

    if (value < min || value > max) {
        LOGE("Keysize %lu not supported.", value);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    keydat->pub.publicArea.parameters.rsaDetail.keyBits = value;

    return CKR_OK;
}

static CK_RV handle_ecparams(CK_ATTRIBUTE_PTR attr, void *udata) {

    tpm_key_data *keydat = (tpm_key_data *)udata;

    int nid = 0;
    CK_RV rv = ssl_util_params_to_nid(attr, &nid);
    if (rv != CKR_OK) {
        return rv;
    }

    TPMS_ECC_PARMS *ec = &keydat->pub.publicArea.parameters.eccDetail;

    TPMI_ECC_CURVE curve = nid_to_tpm2alg(nid);
    if (curve == TPM2_ALG_ERROR) {
        return CKR_CURVE_NOT_SUPPORTED;
    }

    ec->curveID = curve;

    return CKR_OK;
}

static CK_RV record_usage(CK_ATTRIBUTE_PTR attr, usage_request *request) {

    CK_BBOOL value;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    *request = value == CK_TRUE ? usage_yes : usage_no;
    return CKR_OK;
}

static CK_RV handle_sign(CK_ATTRIBUTE_PTR attr, void *udata) {
    return record_usage(attr, &((tpm_key_data *)udata)->sign);
}

static CK_RV handle_sign_recover(CK_ATTRIBUTE_PTR attr, void *udata) {
    return record_usage(attr, &((tpm_key_data *)udata)->sign_recover);
}

static CK_RV handle_verify_recover(CK_ATTRIBUTE_PTR attr, void *udata) {
    return record_usage(attr, &((tpm_key_data *)udata)->verify_recover);
}

static CK_RV handle_decrypt(CK_ATTRIBUTE_PTR attr, void *udata) {
    return record_usage(attr, &((tpm_key_data *)udata)->decrypt);
}

static CK_RV handle_unwrap(CK_ATTRIBUTE_PTR attr, void *udata) {
    return record_usage(attr, &((tpm_key_data *)udata)->unwrap);
}

static CK_RV handle_derive(CK_ATTRIBUTE_PTR attr, void *udata) {
    return record_usage(attr, &((tpm_key_data *)udata)->derive);
}

static CK_RV handle_decapsulate(CK_ATTRIBUTE_PTR attr, void *udata) {
    return record_usage(attr, &((tpm_key_data *)udata)->decapsulate);
}

static void set_object_attribute(TPMA_OBJECT *attrs, TPMA_OBJECT attr, bool set) {
    if (set) {
        *attrs |= attr;
    } else {
        *attrs &= ~attr;
    }
}

/*
 * Sets the TPM key's sign and decrypt attributes from what the private key template asked for, once
 * the whole template is read, so the order of its attributes doesn't matter:
 *  - CKA_SIGN is the TPM's sign attribute. For RSA, CKA_SIGN_RECOVER=true sets it too: C_SignRecover
 *    signs as C_Sign does. EC keys don't sign with recovery, and their public keys don't verify with
 *    it (CKA_VERIFY_RECOVER, which asks nothing of the TPM).
 *  - For RSA, CKA_DECRYPT, CKA_UNWRAP (C_UnwrapKey with CKM_RSA_PKCS_OAEP decrypts in the TPM),
 *    CKA_DECAPSULATE (C_DecapsulateKey unwraps) and CKA_SIGN set the TPM's decrypt attribute. RSA keys
 *    can't derive.
 *  - For EC, CKA_DERIVE is the TPM's decrypt attribute, which TPM2_ECDH_ZGen needs, and so is
 *    CKA_DECAPSULATE (C_DecapsulateKey with CKM_ECDH1_DERIVE). CKA_DECRYPT=true asks for it too, as
 *    keys asked for ECDH before CKA_DERIVE was mapped; EC keys don't decrypt.
 * The public key's CKA_VERIFY, CKA_ENCRYPT, CKA_WRAP and CKA_ENCAPSULATE ask nothing of the TPM:
 * verifying, encrypting and wrapping with the public key happen in software, and so does encapsulating
 * with an RSA key; an EC key's encapsulation loads only the public point. An EC key's CKA_WRAP and
 * CKA_UNWRAP are kept as given, as they always were: no mechanism wraps with an EC key, so C_WrapKey
 * refuses it.
 */
static CK_RV apply_usage(tpm_key_data *keydat) {

    TPMA_OBJECT *attrs = &keydat->pub.publicArea.objectAttributes;

    if (keydat->sign != usage_unset) {
        set_object_attribute(attrs, TPMA_OBJECT_SIGN_ENCRYPT, keydat->sign == usage_yes);
    }

    if (keydat->pub.publicArea.type == TPM2_ALG_ECC
            && (keydat->sign_recover == usage_yes || keydat->verify_recover == usage_yes)) {
        LOGE("EC keys can't sign or verify with recovery: "
                "CKA_SIGN_RECOVER=true or CKA_VERIFY_RECOVER=true not supported");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (keydat->sign_recover == usage_yes) {
        set_object_attribute(attrs, TPMA_OBJECT_SIGN_ENCRYPT, true);
    }

    if (keydat->pub.publicArea.type == TPM2_ALG_ECC) {
        if (keydat->derive == usage_no && keydat->decrypt == usage_yes) {
            LOGE("An EC key with CKA_DECRYPT=true can derive, but the template has CKA_DERIVE=false");
            return CKR_TEMPLATE_INCONSISTENT;
        }
        /* ECDH only when the template asks for it: a key made to sign doesn't derive too */
        set_object_attribute(attrs, TPMA_OBJECT_DECRYPT, keydat->derive == usage_yes
                || keydat->decrypt == usage_yes || keydat->decapsulate == usage_yes);
    } else {
        if (keydat->derive == usage_yes) {
            LOGE("RSA keys can't derive: CKA_DERIVE=true not supported");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        /*
         * A signing key needs the decrypt attribute too: a signature scheme the TPM doesn't do
         * natively (raw PKCS#1 v1.5, PSS with another salt length) is padded in software and
         * computed with TPM2_RSA_Decrypt. Then CKA_DECRYPT=false is enforced by C_DecryptInit
         * rather than by the TPM.
         */
        if (keydat->decrypt == usage_yes || keydat->unwrap == usage_yes
                || keydat->decapsulate == usage_yes || (*attrs & TPMA_OBJECT_SIGN_ENCRYPT)) {
            set_object_attribute(attrs, TPMA_OBJECT_DECRYPT, true);
        } else if (keydat->decrypt == usage_no) {
            set_object_attribute(attrs, TPMA_OBJECT_DECRYPT, false);
        }
    }

    /* The TPM refuses a key that can do neither. */
    if (!(*attrs & (TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT))) {
        LOGE("The private key template allows neither signing nor decrypting, unwrapping, deriving "
                "or decapsulating");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    return CKR_OK;
}

static CK_RV handle_exp(CK_ATTRIBUTE_PTR attr, void *udata) {

    tpm_key_data *keydat = (tpm_key_data *)udata;

    UINT32 *e = &keydat->pub.publicArea.parameters.rsaDetail.exponent;
    if (attr->ulValueLen > sizeof(*e)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    BIGNUM *bn = NULL;
    bn = BN_bin2bn(attr->pValue, attr->ulValueLen, NULL);
    if (!bn) {
        return CKR_HOST_MEMORY;
    }

    BN_ULONG value = BN_get_word(bn);

    *e = value;

    BN_free(bn);

    return CKR_OK;
}

static CK_RV handle_ckobject_class(CK_ATTRIBUTE_PTR attr, void *udata) {
    UNUSED(udata);

    CK_OBJECT_CLASS class[2] = {
        CKA_PRIVATE,    /* p11tool */
        CKO_PRIVATE_KEY /* pkcs11-tool */
    };

    if (attr->ulValueLen != sizeof(class[0])) {
        LOGE("Expected CK_OBJECT_CLASS length to be %zu got %lu",
                sizeof(class), attr->ulValueLen);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    CK_OBJECT_CLASS_PTR class_ptr = (CK_OBJECT_CLASS_PTR)attr->pValue;

    size_t i;
    bool found = false;
    for (i=0; i < ARRAY_LEN(class); i++) {
        if (*class_ptr == class[i]) {
            found = true;
            break;
        }
    }

    if (!found) {
        LOGE("Unexpected CK_OBJECT_CLASS got %lu", *class_ptr);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

static CK_RV handle_extractable_common(CK_ATTRIBUTE_PTR attr, bool is_extractable, void *udata) {

    tpm_key_data *keydat = (tpm_key_data *)udata;

    CK_BBOOL value;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    if (value == is_extractable ? true : false) {
        keydat->pub.publicArea.objectAttributes &= ~(TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT);
    } else {
        keydat->pub.publicArea.objectAttributes |= (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT);
    }

    return CKR_OK;
}

static CK_RV handle_extractable(CK_ATTRIBUTE_PTR attr, void *udata) {
    return handle_extractable_common(attr, true, udata);
}

static CK_RV handle_sensitive(CK_ATTRIBUTE_PTR attr, void *udata) {
    return handle_extractable_common(attr, false, udata);
}

static CK_RV handle_key_type(CK_ATTRIBUTE_PTR attr, void *udata) {

    tpm_key_data *keydat = (tpm_key_data *)udata;

    CK_ULONG value;
    CK_RV rv = attr_CK_ULONG(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    if ((value == CKK_RSA && keydat->pub.publicArea.type == TPM2_ALG_RSA) ||
        (value == CKK_EC && keydat->pub.publicArea.type == TPM2_ALG_ECC)) {
        return CKR_OK;
    }

    return CKR_ATTRIBUTE_VALUE_INVALID;
}

static CK_RV sanity_check_mech(CK_MECHANISM_PTR mechanism) {
    switch (mechanism->mechanism) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            /* falls-thru */
        case CKM_EC_KEY_PAIR_GEN:
            break;
        default:
            LOGE("Only supports mechanism \"CKM_RSA_PKCS_KEY_PAIR_GEN\" or"
                 "\"CKM_EC_KEY_PAIR_GEN\", got: 0x%lx", mechanism->mechanism);
            return CKR_MECHANISM_INVALID;
    }

    if (mechanism->ulParameterLen) {
        LOGE("Expected mechanism  with an empty parameter, got length: %lu",
                mechanism->ulParameterLen);
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (mechanism->pParameter) {
        LOGE("Expected mechanism with an empty parameter, got a parameter pointer");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return CKR_OK;
}

/* The public key template's attributes the TPM key depends on. */
static const attr_handler tpm_public_handlers[] = {
    { CKA_TOKEN,           generic_bbool_any     },
    { CKA_PRIVATE,         generic_bbool_any     },
    { CKA_MODULUS_BITS,    handle_modulus        },
    { CKA_PUBLIC_EXPONENT, handle_exp            },
    { CKA_SENSITIVE,       handle_sensitive      },
    { CKA_CLASS,           handle_ckobject_class },
    { CKA_EXTRACTABLE,     handle_extractable    },
    { CKA_EC_PARAMS,       handle_ecparams       },
    { CKA_KEY_TYPE,        handle_key_type       },
    { CKA_TRUSTED,           generic_bbool_false },
    { CKA_SIGN_RECOVER,      generic_bbool_false },
    { CKA_VERIFY_RECOVER,    handle_verify_recover },
    { CKA_DERIVE,            generic_bbool_any },
};

/* The private key template's; its usage attributes are applied by apply_usage(). */
static const attr_handler tpm_private_handlers[] = {
    { CKA_TOKEN,           generic_bbool_any     },
    { CKA_PRIVATE,         generic_bbool_any     },
    { CKA_SIGN,            handle_sign           },
    { CKA_DECRYPT,         handle_decrypt        },
    { CKA_UNWRAP,          handle_unwrap         },
    { CKA_DERIVE,          handle_derive         },
    { CKA_DECAPSULATE,     handle_decapsulate    },
    { CKA_MODULUS_BITS,    handle_modulus        },
    { CKA_PUBLIC_EXPONENT, handle_exp            },
    { CKA_SENSITIVE,       handle_sensitive      },
    { CKA_CLASS,           handle_ckobject_class },
    { CKA_EXTRACTABLE,     handle_extractable    },
    { CKA_EC_PARAMS,       handle_ecparams       },
    { CKA_KEY_TYPE,        handle_key_type       },
    { CKA_TRUSTED,           generic_bbool_false },
    { CKA_SIGN_RECOVER,      handle_sign_recover },
    { CKA_VERIFY_RECOVER,    generic_bbool_false },
};

static CK_RV tpm_data_init(
        CK_MECHANISM_PTR mechanism,
        attr_list *pubattrs,
        attr_list *privattrs,
        tpm_key_data *tpmdat) {

    memset(&tpmdat->priv, 0, sizeof(tpmdat->priv));
    memset(&tpmdat->pub,  0, sizeof(tpmdat->pub));
    tpmdat->sign = tpmdat->sign_recover = tpmdat->verify_recover = usage_unset;
    tpmdat->decrypt = tpmdat->unwrap = tpmdat->derive = tpmdat->decapsulate = usage_unset;

    switch(mechanism->mechanism) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            tpmdat->pub = rsa_template;
            break;
        case CKM_EC_KEY_PAIR_GEN:
            tpmdat->pub = ecc_template;
            break;
        default:
            /* should never happen checked at entry */
            LOGE("Unsupported key pair mechanism: 0x%lx",
                    mechanism->mechanism);
            assert(0);
            return CKR_MECHANISM_INVALID;
    }

    CK_RV rv = attr_list_invoke_handlers(pubattrs,
            tpm_public_handlers, ARRAY_LEN(tpm_public_handlers), tpmdat);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = attr_list_invoke_handlers(privattrs,
            tpm_private_handlers, ARRAY_LEN(tpm_private_handlers), tpmdat);
    if (rv != CKR_OK) {
        return rv;
    }

    return apply_usage(tpmdat);
}

static CK_RV uint32_to_BN(uint32_t value, void **bytes, CK_ULONG_PTR len) {

    CK_RV rv = CKR_GENERAL_ERROR;

    BIGNUM *b = BN_new();
    if (!b) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    int rc = BN_set_word(b, value);
    if (!rc) {
        LOGE("BN_set_word failed: %d", rc);
        goto out;
    }

    int l = BN_num_bytes(b);
    if (!l) {
        LOGE("Expected bignum to not be 0");
        return CKR_GENERAL_ERROR;
    }

    void *x = malloc(l);
    if (!x) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    rc = BN_bn2bin(b, x);
    if (!rc) {
        free(x);
        LOGE("BN_bn2bin failed: %d", rc);
        goto out;
    }

    *bytes = x;
    *len = l;

    rv = CKR_OK;

out:
    BN_free(b);
    return rv;
}

static CK_RV tpm_object_data_populate_rsa(TPM2B_PUBLIC *out_pub, tpm_object_data *objdata) {
    assert(out_pub);
    assert(objdata);

    /* MODULUS */
    bool r = attr_list_add_buf(objdata->attrs, CKA_MODULUS,
            out_pub->publicArea.unique.rsa.buffer, out_pub->publicArea.unique.rsa.size);
    if (!r) {
        return CKR_GENERAL_ERROR;
    }

    UINT32 exp = out_pub->publicArea.parameters.rsaDetail.exponent;
    if (!exp) {
        exp = 65537;
    }

    void *buf = NULL;
    CK_ULONG len = 0;
    CK_RV rv = uint32_to_BN(exp, &buf, &len);
    if (rv != CKR_OK) {
        return rv;
    }

    r = attr_list_add_buf(objdata->attrs, CKA_PUBLIC_EXPONENT, buf, len);
    free(buf);
    if (!r) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

static EC_POINT *tpm_pub_to_ossl_pub(EC_GROUP *group, TPM2B_PUBLIC *key) {

    BIGNUM *bn_x = NULL;
    BIGNUM *bn_y = NULL;

    EC_POINT *pub_key_point_tmp = NULL;
    EC_POINT *r = NULL;

    /* Create the big numbers for the coordinates of the point */
    bn_x = BN_bin2bn(&key->publicArea.unique.ecc.x.buffer[0],
                               key->publicArea.unique.ecc.x.size,
                               NULL);
    if (!bn_x) {
        LOGE("Create big num from byte buffer.");
        goto out;
    }

    bn_y = BN_bin2bn(&key->publicArea.unique.ecc.y.buffer[0],
                               key->publicArea.unique.ecc.y.size,
                               NULL);
    if (!bn_y) {
        LOGE("Create big num from byte buffer.");
        goto out;
    }

    /* Create the ec point with the affine coordinates of the TPM point */
    pub_key_point_tmp = EC_POINT_new(group);
    if (!pub_key_point_tmp) {
        LOGE("Could not create new affine point from X and Y coordinates");
        goto out;
    }

    int rc = EC_POINT_set_affine_coordinates(group,
            pub_key_point_tmp,
            bn_x,
            bn_y,
            NULL);
    if (!rc) {
        EC_POINT_free(pub_key_point_tmp);
        LOGE("Could not set affine coordinate points");
        goto out;
    }

    /* sanity check that the point created in the group is on the curve */
    rc = EC_POINT_is_on_curve(group, pub_key_point_tmp, NULL);
    if (!rc) {
        EC_POINT_free(pub_key_point_tmp);
        LOGE("The TPM point is not on the curve");
        goto out;
    }

    r = pub_key_point_tmp;

out:
    BN_free(bn_x);
    BN_free(bn_y);

    return r;
}

static CK_RV tpm_object_data_populate_ecc(TPM2B_PUBLIC *out_pub, tpm_object_data *objdata) {

    CK_RV rv = CKR_GENERAL_ERROR;

    EC_GROUP *group = NULL;               /* Group defines the used curve */
    EC_POINT *tpm_pub_key = NULL;         /* Public part of TPM key */
    int curveId;
    unsigned char *mydata = NULL;

    /* Set ossl constant for curve type and create group for curve */
    switch (out_pub->publicArea.parameters.eccDetail.curveID) {
        case TPM2_ECC_NIST_P192:
            curveId = NID_X9_62_prime192v1;
            break;
        case TPM2_ECC_NIST_P224:
            curveId = NID_secp224r1;
            break;
        case TPM2_ECC_NIST_P256:
            curveId = NID_X9_62_prime256v1;
            break;
        case TPM2_ECC_NIST_P384:
            curveId = NID_secp384r1;
            break;
        case TPM2_ECC_NIST_P521:
            curveId = NID_secp521r1;
            break;
        default:
            LOGE("ECC Curve not implemented");
            return CKR_GENERAL_ERROR;
    }

    group = EC_GROUP_new_by_curve_name(curveId);
    if (!group) {
        LOGE("EC_GROUP_new failed");
        goto out;
    }

    tpm_pub_key = tpm_pub_to_ossl_pub(group, out_pub);
    if (!tpm_pub_key){
        goto out;
    }

    ssize_t len = EC_POINT_point2buf(group, tpm_pub_key, POINT_CONVERSION_UNCOMPRESSED,
            &mydata, NULL);
    if (len <= 0) {
        LOGE("EC_POINT_point2buf failed: %zd", len);
        goto out;
    }

    if (len > 255) {
        LOGE("Length must fit within a byte, got %zd", len);
        goto out;
    }

    /*
     * Build a DER encoded uncompressed representation of the points
     * per X9.62: an OCTET STRING. A length of 128 or more (P-521's point is 133
     * bytes) takes the long form, 0x81 then the length.
     */
    size_t header = len < 128 ? 2 : 3;
    size_t tmp = 0;
    safe_add(tmp, len, header);
    char *padded_data = malloc(tmp);
    if (!padded_data) {
        LOGE("oom");
        goto out;
    }

    padded_data[0] = 4;
    if (header == 2) {
        padded_data[1] = len;
    } else {
        padded_data[1] = (char)0x81;
        padded_data[2] = len;
    }
    memcpy(&padded_data[header], mydata, len);

    safe_adde(len, header);
    bool r = attr_list_add_buf(objdata->attrs, CKA_EC_POINT,
            (CK_BYTE_PTR)padded_data, len);
    free(padded_data);
    if (!r) {
        goto out;
    }

    rv = CKR_OK;

out:
    EC_POINT_free(tpm_pub_key);
    EC_GROUP_free(group);
    OPENSSL_free(mydata);

    return rv;
}

static CK_RV serialize_pub_priv_blobs(TPM2B_PUBLIC *pub,
        TPM2B_PRIVATE *priv,
        twist *pubblob, twist *privblob) {

    twist tmppub = NULL;
    twist tmppriv = NULL;

    BYTE pubb[sizeof(*pub)];
    size_t pubb_size = 0;

    BYTE privb[sizeof(*priv)];
    size_t privb_size = 0;

    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Marshal(pub, pubb, sizeof(pubb), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPM2B_PUBLIC_Marshal: %s", Tss2_RC_Decode(rc));
        return CKR_GENERAL_ERROR;
    }

    pubb_size = offset;

    offset = 0;
    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(priv, privb, sizeof(privb), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPM2B_PRIVATE_Marshal: %s", Tss2_RC_Decode(rc));
        return CKR_GENERAL_ERROR;
    }

    privb_size = offset;

    tmppub = twistbin_new(pubb, pubb_size);
    if (!tmppub) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    tmppriv = twistbin_new(privb, privb_size);
    if (!tmppriv) {
        twist_free(tmppub);
        return CKR_HOST_MEMORY;
    }

    *pubblob = tmppub;
    *privblob = tmppriv;

    return CKR_OK;
}

CK_RV tpm2_generate_key(
        tpm_ctx *tpm,

        uint32_t parent,
        twist parentauth,

        twist newauthbin,

        CK_MECHANISM_PTR mechanism,

        attr_list *pubattrs,

        attr_list *privattrs,

        tpm_object_data *objdata) {

    twist tmppub = NULL;
    twist tmppriv = NULL;

    TPM2B_PUBLIC *out_pub = NULL;
    TPM2B_PRIVATE *out_priv = NULL;

    ESYS_TR out_handle = ESYS_TR_NONE;

    CK_RV rv = CKR_GENERAL_ERROR;

    assert(objdata);

    rv = sanity_check_mech(mechanism);
    if (rv != CKR_OK) {
        goto error;
    }

    tpm_key_data tpmdat = {
        .ctx = tpm
    };
    rv = tpm_data_init(
        mechanism,
        pubattrs,
        privattrs,
        &tpmdat);
    if (rv != CKR_OK) {
        goto error;
    }

    bool res = set_esys_auth(tpm->esys_ctx, parent, parentauth);
    if (!res) {
        rv = CKR_GENERAL_ERROR;
        goto error;
    }

    /*
     * Guaranteed to fit but throw an assert in just in case
     * utils_setup_new_object_auth() changes.
     */
    TPM2B_AUTH *auth = &tpmdat.priv.sensitive.userAuth;
    size_t len = twist_len(newauthbin);
    assert(len < sizeof(auth->buffer));
    auth->size = len;
    memcpy(auth->buffer, newauthbin, auth->size);

    TSS2_RC rc = create_loaded(
            tpm,
            parent,
            tpm->hmac_session,
            &tpmdat.priv,
            &tpmdat.pub,

            &out_handle,
            &out_pub,
            &out_priv
        );
    if (rc != TSS2_RC_SUCCESS) {
        rv = CKR_GENERAL_ERROR;
        LOGE("create_loaded %s", Tss2_RC_Decode(rc));
        goto error;
    }

    assert(out_pub);
    assert(out_priv);

    /* load the public only object portion */
    res = tpm_loadexternal(tpm, out_pub, &objdata->pubhandle);
    if (!res) {
        rv = CKR_GENERAL_ERROR;
        goto error;
    }

    /* serialize the tpm public private object portions */
    rv = serialize_pub_priv_blobs(out_pub, out_priv, &tmppub, &tmppriv);
    if (rv != CKR_OK) {
        goto error;
    }

    objdata->attrs = attr_list_new();
    if (!objdata->attrs) {
        twist_free(tmppub);
        twist_free(tmppriv);
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    /* freed with objdata on error */
    objdata->privblob = tmppriv;
    objdata->pubblob = tmppub;

    switch(mechanism->mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        rv = tpm_object_data_populate_rsa(out_pub, objdata);
        break;
    case CKM_EC_KEY_PAIR_GEN:
        rv = tpm_object_data_populate_ecc(out_pub, objdata);
        break;
    default:
        LOGE("Impossible keygen type, got: 0x%lx", mechanism->mechanism);
        rv = CKR_MECHANISM_INVALID;
        assert(rv == CKR_OK);
        goto error;
    }

    if (rv != CKR_OK) {
        goto error;
    }

    /* everything common; what goto_error_false() means is running out of memory */
    rv = CKR_HOST_MEMORY;
    TPMA_OBJECT objattrs = out_pub->publicArea.objectAttributes;

    CK_BBOOL extractable = !!!(objattrs & (TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT));
    bool r = attr_list_add_bool(objdata->attrs, CKA_EXTRACTABLE, extractable);
    goto_error_false(r);


    CK_BBOOL sensitive = !extractable;
    r = attr_list_add_bool(objdata->attrs, CKA_ALWAYS_SENSITIVE, sensitive);
    goto_error_false(r);


    CK_BBOOL never_extractable = !extractable;
    r = attr_list_add_bool(objdata->attrs, CKA_NEVER_EXTRACTABLE, never_extractable);
    goto_error_false(r);

    CK_BBOOL local = !!(objattrs & TPMA_OBJECT_SENSITIVEDATAORIGIN);
    r = attr_list_add_bool(objdata->attrs, CKA_LOCAL, local);
    goto_error_false(r);

    /*
     * conditional block: what the key pair can do, for attr_add_missing_attrs() to check against the
     * templates or fill in. The public key verifies what the private key signs, and encrypts what it
     * decrypts. An EC key's decrypt attribute is for ECDH: it derives, and doesn't encrypt.
     */
    bool is_ec = out_pub->publicArea.type == TPM2_ALG_ECC;
    /* CKA_SIGN is what the template asked for: CKA_SIGN_RECOVER=true sets the TPM's sign attribute too */
    CK_BBOOL tpm_sign = !!(objattrs & TPMA_OBJECT_SIGN_ENCRYPT);
    CK_BBOOL sign = tpmdat.sign != usage_unset ? tpmdat.sign == usage_yes : tpm_sign;
    CK_BBOOL sign_recover = tpmdat.sign_recover == usage_yes;
    CK_BBOOL tpm_decrypt = !!(objattrs & TPMA_OBJECT_DECRYPT);
    /*
     * CKA_DECRYPT is what the template asked for: an RSA signing key has the TPM's decrypt
     * attribute anyway (see apply_usage()), and an EC key's means it derives. A key asked to
     * decapsulate has it for that alone: it doesn't decrypt or derive unless the template says so.
     */
    bool for_kem = tpmdat.decapsulate == usage_yes;
    CK_BBOOL decrypt = tpmdat.decrypt != usage_unset ? tpmdat.decrypt == usage_yes
            : (is_ec || for_kem ? CK_FALSE : tpm_decrypt);
    CK_BBOOL derive = !is_ec ? CK_FALSE
            : tpmdat.derive != usage_unset ? tpmdat.derive == usage_yes
            : tpm_decrypt && (!for_kem || tpmdat.decrypt == usage_yes);

    r = attr_list_add_bool(objdata->attrs, CKA_SIGN, sign);
    goto_error_false(r);

    r = attr_list_add_bool(objdata->attrs, CKA_VERIFY, sign);
    goto_error_false(r);

    r = attr_list_add_bool(objdata->attrs, CKA_SIGN_RECOVER, sign_recover);
    goto_error_false(r);

    r = attr_list_add_bool(objdata->attrs, CKA_DECRYPT, decrypt);
    goto_error_false(r);

    r = attr_list_add_bool(objdata->attrs, CKA_ENCRYPT, is_ec ? CK_FALSE : decrypt);
    goto_error_false(r);

    r = attr_list_add_bool(objdata->attrs, CKA_DERIVE, derive);
    goto_error_false(r);

    objdata->privhandle = out_handle;

    rv = CKR_OK;
error:

    Esys_Free(out_pub);
    Esys_Free(out_priv);

    if (rv != CKR_OK) {
        /*
         * The objects stay loaded otherwise, counting against the TPM's (or resource manager's) slots.
         * A failed Esys_CreateLoaded leaves the handle ESYS_TR_NONE, not 0.
         */
        if (out_handle != ESYS_TR_NONE && out_handle) {
            tpm_flushcontext(tpm, out_handle);
        }
        if (objdata->pubhandle) {
            tpm_flushcontext(tpm, objdata->pubhandle);
            objdata->pubhandle = 0;
        }
        tpm_objdata_free(objdata);
    }

    return rv;
}

/*
 * Creates and loads a secret key under parent from pub. With value, the key is that value
 * (sensitiveDataOrigin must then be clear); without, the TPM makes it.
 */
static CK_RV create_secret_key(
        tpm_ctx *tpm,
        uint32_t parent,
        twist parentauth,
        twist newauthbin,
        const TPM2B_PUBLIC *pub,
        const CK_BYTE *value,
        CK_ULONG value_len,
        tpm_object_data *objdata) {

    assert(objdata);

    TPM2B_PUBLIC *out_pub = NULL;
    TPM2B_PRIVATE *out_priv = NULL;
    ESYS_TR out_handle = 0;

    TPM2B_SENSITIVE_CREATE priv = { 0 };
    size_t len = twist_len(newauthbin);
    if (len > sizeof(priv.sensitive.userAuth.buffer)) {
        return CKR_GENERAL_ERROR;
    }
    priv.sensitive.userAuth.size = len;
    memcpy(priv.sensitive.userAuth.buffer, newauthbin, len);

    /*
     * MAX_SYM_DATA, TPM 2.0 Part 2: the most sensitive data a TPM takes, whatever room the TSS's
     * structure has (256 bytes).
     */
    static const CK_ULONG max_sym_data = 128;

    if (value) {
        if (value_len > max_sym_data) {
            LOGE("The TPM holds at most %lu bytes of key, got %lu", max_sym_data, value_len);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        priv.sensitive.data.size = value_len;
        memcpy(priv.sensitive.data.buffer, value, value_len);
    }

    CK_RV rv = CKR_GENERAL_ERROR;

    bool res = set_esys_auth(tpm->esys_ctx, parent, parentauth);
    if (!res) {
        goto out;
    }

    TSS2_RC rc = create_loaded(tpm, parent, tpm->hmac_session, &priv, pub,
            &out_handle, &out_pub, &out_priv);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("create_loaded %s", Tss2_RC_Decode(rc));
        goto out;
    }

    rv = serialize_pub_priv_blobs(out_pub, out_priv, &objdata->pubblob, &objdata->privblob);
    if (rv != CKR_OK) {
        tpm_flushcontext(tpm, out_handle);
        goto out;
    }

    objdata->privhandle = out_handle;
    rv = CKR_OK;

out:
    /* the caller's key, copied into the TPM command */
    OPENSSL_cleanse(&priv, sizeof(priv));
    Esys_Free(out_pub);
    Esys_Free(out_priv);

    return rv;
}

/* An AES key: for a symmetric key, the sign attribute is encrypt. Its mode is TPM2_ALG_NULL, so each
 * operation names its own. */
static TPM2B_PUBLIC aes_template(CK_ULONG key_bits, bool encrypt, bool decrypt, bool imported) {

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .type = TPM2_ALG_SYMCIPHER,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                TPMA_OBJECT_FIXEDTPM
                | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_USERWITHAUTH
                | (imported ? 0 : TPMA_OBJECT_SENSITIVEDATAORIGIN)
                | (encrypt ? TPMA_OBJECT_SIGN_ENCRYPT : 0)
                | (decrypt ? TPMA_OBJECT_DECRYPT : 0),
            .parameters.symDetail.sym = {
                .algorithm = TPM2_ALG_AES,
                .keyBits.aes = key_bits,
                .mode.aes = TPM2_ALG_NULL,
            },
        },
    };

    return pub;
}

CK_RV tpm2_generate_aes_key(
        tpm_ctx *tpm,
        uint32_t parent,
        twist parentauth,
        twist newauthbin,
        CK_ULONG key_bits,
        bool encrypt,
        bool decrypt,
        tpm_object_data *objdata) {

    TPM2B_PUBLIC pub = aes_template(key_bits, encrypt, decrypt, false);
    return create_secret_key(tpm, parent, parentauth, newauthbin, &pub, NULL, 0, objdata);
}

CK_RV tpm2_import_aes_key(
        tpm_ctx *tpm,
        uint32_t parent,
        twist parentauth,
        twist newauthbin,
        const CK_BYTE *value,
        CK_ULONG value_len,
        bool encrypt,
        bool decrypt,
        tpm_object_data *objdata) {

    TPM2B_PUBLIC pub = aes_template(value_len * 8, encrypt, decrypt, true);
    return create_secret_key(tpm, parent, parentauth, newauthbin, &pub, value, value_len, objdata);
}

/*
 * An HMAC key, as tpm2_ptool makes one for any hash: a keyed hash object with sign and decrypt set and
 * a NULL scheme, so TPM2_HMAC takes the hash of each operation.
 */
CK_RV tpm2_import_hmac_key(
        tpm_ctx *tpm,
        uint32_t parent,
        twist parentauth,
        twist newauthbin,
        const CK_BYTE *value,
        CK_ULONG value_len,
        tpm_object_data *objdata) {

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                TPMA_OBJECT_FIXEDTPM
                | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_USERWITHAUTH
                | TPMA_OBJECT_SIGN_ENCRYPT
                | TPMA_OBJECT_DECRYPT,
            .parameters.keyedHashDetail.scheme = {
                .scheme = TPM2_ALG_NULL,
            },
        },
    };

    return create_secret_key(tpm, parent, parentauth, newauthbin, &pub, value, value_len, objdata);
}

void tpm_objdata_free(tpm_object_data *objdata) {

    if (!objdata) {
        return;
    }

    /* the pointers are cleared, as a caller may free it again (tpm2_generate_key(), then key_gen()) */
    attr_list_free(objdata->attrs);
    objdata->attrs = NULL;

    twist_free(objdata->privblob);
    objdata->privblob = NULL;
    twist_free(objdata->pubblob);
    objdata->pubblob = NULL;
}

CK_RV tpm_get_algorithms(tpm_ctx *ctx, TPMS_CAPABILITY_DATA **capabilityData) {

    if (ctx->tpms_alg_cache) {
        *capabilityData = ctx->tpms_alg_cache;
        return CKR_OK;
    }

    TPM2_CAP capability = TPM2_CAP_ALGS;
    UINT32 property = TPM2_ALG_FIRST;
    UINT32 propertyCount = TPM2_MAX_CAP_ALGS;
    TPMI_YES_NO moreData;

    check_pointer(ctx);
    check_pointer(capabilityData);

    TPMS_CAPABILITY_DATA *capdata = NULL;

    TSS2_RC rval = Esys_GetCapability(ctx->esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            capability,
            property, propertyCount, &moreData, &capdata);

    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_GetCapability: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    *capabilityData = ctx->tpms_alg_cache = capdata;

    return CKR_OK;
}

static CK_BBOOL is_algorithm_supported(TPMU_CAPABILITIES *capabilities, TPM2_ALG_ID algorithm){
    for (unsigned int i = 0 ; i < capabilities->algorithms.count ; i++){
        if (capabilities->algorithms.algProperties[i].alg == algorithm){
            return CK_TRUE;
        }
    }
    return CK_FALSE;
}

#define add_mech(mech) \
    if (mechanism_list) { /* Only update if not called for size*/ \
        if (*count <= supported) { \
            rv = CKR_BUFFER_TOO_SMALL; \
            goto out; \
        } \
        mechanism_list[supported] = mech; \
    } \
    supported++;

#define if_add_mech(list, test, mech) \
        if (is_algorithm_supported(list, test)) { \
           add_mech(mech); \
        }

static CK_RV tpm2_get_modes(tpm_ctx *ctx, TPMA_MODES *modes) {

    /* get the TPMA_MODES field from fixed properties */
    TPMS_CAPABILITY_DATA *fixed_props = NULL;
    CK_RV rv = tpm_get_properties(ctx, &fixed_props);
    if (rv != CKR_OK) {
        LOGE("Could not get fixed properties from TPM");
        return rv;
    }

    TPML_TAGGED_TPM_PROPERTY *plist = &fixed_props->data.tpmProperties;
    UINT32 i;
    for (i = 0; i < plist->count; i++) {
        TPM2_PT property = plist->tpmProperty[i].property;
        if (property == TPM2_PT_MODES) {
            *modes = plist->tpmProperty[i].value;
            return CKR_OK;
        }
    }

    /* if we don't find it, we just say modes is implicitly empty */
    *modes = 0;
    return CKR_OK;
}

CK_RV tpm2_getmechanisms(tpm_ctx *ctx, CK_MECHANISM_TYPE *mechanism_list, CK_ULONG_PTR count){
    check_pointer(count);
    check_pointer(ctx);

    CK_ULONG supported = 0;

    TPMS_CAPABILITY_DATA *capabilityData = NULL;
    CK_RV rv = tpm_get_algorithms(ctx, &capabilityData);
    if (rv != CKR_OK) {
        LOGE("Retrieving supported algorithms from TPM failed");
        return rv;
    }
    TPMU_CAPABILITIES *algs= &capabilityData->data;

    /* get the TPMA_MODES field from fixed properties */
    TPMA_MODES modes = 0;
    rv = tpm2_get_modes(ctx, &modes);
    if (rv != CKR_OK) {
        return rv;
    }

    /* RSA */
    if (is_algorithm_supported(algs, TPM2_ALG_RSA)) {
        /* if RSA is supported, these modes MUST be supported */
        add_mech(CKM_RSA_PKCS);
        add_mech(CKM_RSA_PKCS_OAEP);
        add_mech(CKM_RSA_PKCS_KEY_PAIR_GEN);
        add_mech(CKM_RSA_X_509);

        if_add_mech(algs, TPM2_ALG_SHA1, CKM_SHA1_RSA_PKCS)
        if_add_mech(algs, TPM2_ALG_SHA256, CKM_SHA256_RSA_PKCS);
        if_add_mech(algs, TPM2_ALG_SHA384, CKM_SHA384_RSA_PKCS);
        if_add_mech(algs, TPM2_ALG_SHA512, CKM_SHA512_RSA_PKCS);

        /*
         * RSA PSS signatures, per Anex B7 of:
         *   - https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
         *
         * States that the saltlen is the maximum permitted. However, most things, and the TLS spec
         * call out that saltlen should equal hashlength. However, in FIPS-140-2 mode, the saltlen
         * does equal hash length, so:
         *  - if fips mode is on, we can support it nativeley
         *  - if fips mode is off, we can synthesize it by applying the padding
         *    and using raw RSA.
         */
        if (modes & TPMA_MODES_FIPS_140_2) {
           add_mech(CKM_RSA_PKCS_PSS);
           if_add_mech(algs, TPM2_ALG_SHA1, CKM_SHA1_RSA_PKCS_PSS)
           if_add_mech(algs, TPM2_ALG_SHA256, CKM_SHA256_RSA_PKCS_PSS);
           if_add_mech(algs, TPM2_ALG_SHA384, CKM_SHA384_RSA_PKCS_PSS);
           if_add_mech(algs, TPM2_ALG_SHA512, CKM_SHA512_RSA_PKCS_PSS);
        }
    }

    /* ECC */
    if (is_algorithm_supported(algs, TPM2_ALG_ECC)) {
        add_mech(CKM_EC_KEY_PAIR_GEN);
        if_add_mech(algs, TPM2_ALG_ECDSA, CKM_ECDSA);
        if_add_mech(algs, TPM2_ALG_ECDSA, CKM_ECDSA_SHA1);
        if_add_mech(algs, TPM2_ALG_ECDSA, CKM_ECDSA_SHA256);
        if_add_mech(algs, TPM2_ALG_ECDSA, CKM_ECDSA_SHA384);
        if_add_mech(algs, TPM2_ALG_ECDSA, CKM_ECDSA_SHA512);

        if_add_mech(algs, TPM2_ALG_ECDH, CKM_ECDH1_DERIVE);
    }

    /* AES */
    if (is_algorithm_supported(algs, TPM2_ALG_AES)) {
        add_mech(CKM_AES_KEY_GEN);

        if_add_mech(algs, TPM2_ALG_CBC, CKM_AES_CBC);
        if_add_mech(algs, TPM2_ALG_CBC, CKM_AES_CBC_PAD);
        if_add_mech(algs, TPM2_ALG_CFB, CKM_AES_CFB128);
        if_add_mech(algs, TPM2_ALG_ECB, CKM_AES_ECB);
        if_add_mech(algs, TPM2_ALG_CTR, CKM_AES_CTR);
    }

    /* HMAC */
    if (is_algorithm_supported(algs, TPM2_ALG_KEYEDHASH)) {
        if_add_mech(algs, TPM2_ALG_SHA1, CKM_SHA_1_HMAC);
        if_add_mech(algs, TPM2_ALG_SHA256, CKM_SHA256_HMAC);
        if_add_mech(algs, TPM2_ALG_SHA384, CKM_SHA384_HMAC);
        if_add_mech(algs, TPM2_ALG_SHA512, CKM_SHA512_HMAC);
    }

out:
    *count = supported;

    return rv;
}

void tpm_init(void) {
    /* pass nothing to do */
}

void tpm_destroy(void) {
    /* pass nothing to do */
}

CK_RV tpm_serialize_handle(ESYS_CONTEXT *esys, ESYS_TR handle, twist *buf) {
    assert(buf);

    uint8_t *buffer = NULL;
    size_t size = 0;
    TSS2_RC rval = Esys_TR_Serialize(esys,
                        handle,
                        &buffer, &size);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_Serialize: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    twist t = twistbin_new(buffer, size);
    Esys_Free(buffer);
    if (!t) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    *buf = t;
    return CKR_OK;
}

#define PARAM_1_HANDLE_IS_INVALID 0x0000018b

CK_RV tpm_get_existing_primary(tpm_ctx *tpm, uint32_t *primary_handle, twist *primary_blob) {
    assert(tpm);
    assert(tpm->esys_ctx);
    assert(primary_blob);

    ESYS_TR handle = ESYS_TR_NONE;
    TPMI_YES_NO more_data = TPM2_NO;
    TPMS_CAPABILITY_DATA *capdata = NULL;

    /* Check for the handle here to avoid causing TPM2_ReadPublic to fail loudly */
    TSS2_RC rval = Esys_GetCapability(
            tpm->esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            TPM2_CAP_HANDLES,
            TPM2_PERSISTENT_FIRST,
            TPM2_MAX_CAP_HANDLES,
            &more_data,
            &capdata);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_GetCapability: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    TPM2_HANDLE find_handle = DEFAULT_SRK_HANDLE;

    bool found = false;
    UINT32 i;
    TPM2_HANDLE *found_handles = capdata->data.handles.handle;
    for (i=0; i < capdata->data.handles.count; i++) {
        if (find_handle == found_handles[i]) {
            found = true;
            break;
        }
    }

    Esys_Free(capdata);

    if (!found) {
        *primary_handle = 0;
        LOGV("No Provisioning Guide Spec Key Handle");
        return CKR_OK;
    }

    rval = Esys_TR_FromTPMPublic(
        tpm->esys_ctx,
        find_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_FromTPMPublic: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    CK_RV rv = tpm_serialize_handle(tpm->esys_ctx, handle, primary_blob);
    if (rv != CKR_OK) {
        return rv;
    }

    *primary_handle = handle;

    return CKR_OK;
}

typedef CK_RV (*pfn_populate)(tpm_ctx *tpm, TPM2B_PUBLIC *pub);

typedef struct key_template key_template;
struct key_template {
    const char *template_name;
    pfn_populate fn;
};

static CK_RV tss2_engine_pub_populator(tpm_ctx *tpm, TPM2B_PUBLIC *pub) {
    assert(tpm);

    static const TPM2B_PUBLIC primary_ecc_template = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH
                    |TPMA_OBJECT_RESTRICTED
                    |TPMA_OBJECT_DECRYPT
                    |TPMA_OBJECT_NODA
                    |TPMA_OBJECT_FIXEDTPM
                    |TPMA_OBJECT_FIXEDPARENT
                    |TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = { 0 },
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB,
                 },
                 .scheme = {
                      .scheme = TPM2_ALG_NULL,
                  },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {
                      .scheme = TPM2_ALG_NULL,
                      .details = {}}
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {}},
                 .y = {.size = 0,.buffer = {}},
             },
        } /* end TPMT */
    };

    static const TPM2B_PUBLIC primary_rsa_template = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH
                    |TPMA_OBJECT_RESTRICTED
                    |TPMA_OBJECT_DECRYPT
                    |TPMA_OBJECT_NODA
                    |TPMA_OBJECT_FIXEDTPM
                    |TPMA_OBJECT_FIXEDPARENT
                    |TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = { 0 },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB,
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                },
                .keyBits = 2048,
                .exponent = 0,
            }
        }, /* end TPMT */
    };

    TPMS_CAPABILITY_DATA *cap_data = NULL;
    CK_RV rv = tpm_get_algorithms(tpm, &cap_data);
    if (rv != CKR_OK) {
        return rv;
    }

    bool supports_ecc = false;
    bool supports_rsa = false;

    TPML_ALG_PROPERTY *algs = &cap_data->data.algorithms;
    UINT32 i;
    for (i=0; i < algs->count; i++) {
        TPMS_ALG_PROPERTY *p = &algs->algProperties[i];
        if (p->alg == TPM2_ALG_ECC) {
            supports_ecc = true;
        } else if (p->alg == TPM2_ALG_RSA) {
            supports_rsa = true;
        }

        /* nothing left to examine, exit loop */
        if (supports_ecc && supports_rsa) {
            break;
        }
    }

    if (!supports_rsa && !supports_ecc) {
        LOGE("TPM Supports niether ECC nor RSA?");
        return CKR_GENERAL_ERROR;
    }

    *pub = supports_ecc ?
            primary_ecc_template : primary_rsa_template;

    return CKR_OK;
}

static CK_RV tpm2_tools_default_pub_populator(tpm_ctx *tpm, TPM2B_PUBLIC *pub) {
    UNUSED(tpm);

    /* fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt */
    static const TPM2B_PUBLIC primary_rsa_template = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                      TPMA_OBJECT_FIXEDTPM
                    | TPMA_OBJECT_FIXEDPARENT
                    | TPMA_OBJECT_SENSITIVEDATAORIGIN
                    | TPMA_OBJECT_USERWITHAUTH
                    | TPMA_OBJECT_RESTRICTED
                    | TPMA_OBJECT_DECRYPT
                    ,
            .authPolicy = { 0 },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB,
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                },
                .keyBits = 2048,
                .exponent = 0,
            }
        }, /* end TPMT */
    };


    *pub = primary_rsa_template;

    return CKR_OK;
}


static CK_RV tpm2_tools_default_ecc_pub_populator(tpm_ctx *tpm, TPM2B_PUBLIC *pub) {
    UNUSED(tpm);

    /* fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt */
    static const TPM2B_PUBLIC primary_ecc_template = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                      TPMA_OBJECT_FIXEDTPM
                    | TPMA_OBJECT_FIXEDPARENT
                    | TPMA_OBJECT_SENSITIVEDATAORIGIN
                    | TPMA_OBJECT_USERWITHAUTH
                    | TPMA_OBJECT_RESTRICTED
                    | TPMA_OBJECT_DECRYPT
                    ,
            .authPolicy = { 0 },
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB,
                 },
                 .scheme = {
                      .scheme = TPM2_ALG_NULL,
                  },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {
                      .scheme = TPM2_ALG_NULL,
                      .details = {}}
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {}},
                 .y = {.size = 0,.buffer = {}},
             },
        }, /* end TPMT */
    };


    *pub = primary_ecc_template;

    return CKR_OK;
}

/*
 * Mapping friendly string names to primary objects templates
 */
static const key_template TEMPLATES[] = {
    {
        .template_name = "tss2-engine-key",
        .fn = tss2_engine_pub_populator,
    },
    {
        .template_name= "tpm2-tools-default",
        .fn = tpm2_tools_default_pub_populator,
    },
    {
        .template_name= "tpm2-tools-ecc-default",
        .fn = tpm2_tools_default_ecc_pub_populator,
    }
};

WEAK CK_RV tpm_create_transient_primary_from_template(tpm_ctx *tpm,
        const char *template_name, twist pobj_auth,
        uint32_t *primary_handle) {

    const key_template *templ = NULL;
    size_t i;
    for(i=0; i < ARRAY_LEN(TEMPLATES); i++) {
        const key_template *t = &TEMPLATES[i];

        if (!strcmp(template_name, t->template_name)) {
            templ = t;
            break;
        }
    }

    if (!templ) {
        LOGE("No match for template with name: \"%s\"", template_name);
        return CKR_GENERAL_ERROR;
    }

    /* TODO make configurable ? */
    ESYS_TR hierarchy = ESYS_TR_RH_OWNER;

    /*
     * Hierarchy is currently fixed to owner auth, but eventually
     * this could be:
     * TPM2_PKCS11_<hierarchy>_AUTH where <hierarchy> is one of:
     * OWNER
     * PLATFORM
     * ENDORSEMENT
     * NULL
     */
    const char *auth = getenv("TPM2_PKCS11_OWNER_AUTH");
    bool res = set_esys_auth_string(tpm->esys_ctx, hierarchy, auth);
    if (!res) {
	    return CKR_GENERAL_ERROR;
    }

    TPM2B_DATA outside_info = { 0 };
    TPML_PCR_SELECTION pcrs = { 0 };
    TPM2B_SENSITIVE_CREATE in_sens = { 0 };

    if (pobj_auth) {
        size_t len = twist_len(pobj_auth);
        TPM2B_AUTH *a = &in_sens.sensitive.userAuth;
        if (len > sizeof(a->buffer)) {
            LOGE("pobject auth too large");
            return CKR_GENERAL_ERROR;
        }
        a->size = (UINT16)len;
        memcpy(a->buffer, pobj_auth, len);
    }

    TPM2B_PUBLIC in_pub = { 0 };
    CK_RV rv = templ->fn(tpm, &in_pub);
    if (rv != CKR_OK) {
        LOGE("Template population routine failed: 0x%lx", rv);
        return rv;
    }

    TPM2B_PUBLIC *out_pub = NULL;
    TPM2B_CREATION_DATA *data = NULL;
    TPM2B_DIGEST *hash = NULL;
    TPMT_TK_CREATION *ticket = NULL;

    ESYS_TR handle = ESYS_TR_NONE;
    TSS2_RC rval = Esys_CreatePrimary(tpm->esys_ctx,
            hierarchy,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &in_sens,
            &in_pub,
            &outside_info,
            &pcrs,
            &handle,
            &out_pub,
            &data,
            &hash,
            &ticket);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_CreatePrimary: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    Esys_Free(data);
    Esys_Free(hash);
    Esys_Free(ticket);
    Esys_Free(out_pub);

    *primary_handle = handle;

    return CKR_OK;
}

CK_RV tpm_create_persistent_primary(tpm_ctx *tpm, uint32_t *primary_handle, twist *primary_blob) {
    assert(tpm);
    assert(primary_blob);
    assert(tpm->esys_ctx);

    /* TODO make configurable ? */
    ESYS_TR hierarchy = ESYS_TR_RH_OWNER;

    TPM2B_SENSITIVE_CREATE sens = { 0 };

    /* TODO use proper template ? */
    // https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG_PC_Client_Platform_TPM_Profile_PTP_2.0_r1.03_v22.pdf
    TPM2B_PUBLIC pub_template = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB,
                 },
                 .scheme = {
                      .scheme = TPM2_ALG_NULL,
                  },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {
                      .scheme = TPM2_ALG_NULL,
                      .details = {}}
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {}},
                 .y = {.size = 0,.buffer = {}},
             },
        },
    };

    TPM2B_DATA outside_info = { 0 };
    TPML_PCR_SELECTION pcrs = { 0 };

    const char *auth = getenv("TPM2_PKCS11_OWNER_AUTH");
    bool res = set_esys_auth_string(tpm->esys_ctx, hierarchy, auth);
    if (!res) {
	    return CKR_GENERAL_ERROR;
    }

    TPM2B_PUBLIC *out_pub = NULL;
    TPM2B_CREATION_DATA *data = NULL;
    TPM2B_DIGEST *hash = NULL;
    TPMT_TK_CREATION *ticket = NULL;

    ESYS_TR handle = ESYS_TR_NONE;
    TSS2_RC rval = Esys_CreatePrimary(tpm->esys_ctx,
            hierarchy,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &sens,
            &pub_template,
            &outside_info,
            &pcrs,
            &handle,
            &out_pub,
            &data,
            &hash,
            &ticket);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_CreatePrimary: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    Esys_Free(data);
    Esys_Free(hash);
    Esys_Free(ticket);
    Esys_Free(out_pub);

    // XXX should we be creating this here, if so it should probably
    // match provisioning spec
    ESYS_TR new_handle = ESYS_TR_NONE;
    rval = Esys_EvictControl(tpm->esys_ctx,
            ESYS_TR_RH_OWNER,
            handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            DEFAULT_SRK_HANDLE,
            &new_handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_EvictControl: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    CK_RV rv = tpm_serialize_handle(tpm->esys_ctx, new_handle, primary_blob);
    if (rv != CKR_OK) {
        return rv;
    }

    *primary_handle = new_handle;

    return CKR_OK;
}

CK_RV tpm_get_pss_sig_state(tpm_ctx *tctx, tobject *tobj,
        bool *pss_sigs_good) {

    CK_RV rv = CKR_GENERAL_ERROR;

    TPM2B_PRIVATE *out_priv = NULL;
    TPM2B_PUBLIC *out_pub = NULL;
    TPMT_SIGNATURE *signature = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    /*
     * do the fastest operation to figure this out front by checking,
     * the hopefully cached, FIPS_140_2 mode bit
     */
    TPMA_MODES modes = 0;
    rv = tpm2_get_modes(tctx, &modes);
    if (rv != CKR_OK) {
        return rv;
    }

    if (modes & TPMA_MODES_FIPS_140_2) {
        *pss_sigs_good = true;
        return CKR_OK;
    }

    /* Sign something using RSA PSS SHA256 */
    static const TPM2B_DIGEST dgst = {
        .size = 32,
        .buffer = {
            0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7,
            0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12,
            0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c
        }
    };

    TPMT_SIG_SCHEME scheme = { 0 };
    scheme.scheme = TPM2_ALG_RSAPSS;
    scheme.details.rsapss.hashAlg = TPM2_ALG_SHA256;

    TPMT_TK_HASHCHECK validation = {
            .tag = TPM2_ST_HASHCHECK,
            .hierarchy = TPM2_RH_NULL,
            .digest = { 0 }
    };

    bool res = set_esys_auth(tctx->esys_ctx, tobj->tpm_esys_tr,
            tobj->unsealed_auth);
    if (!res) {
        return CKR_GENERAL_ERROR;
    }

    TSS2_RC rval = Esys_Sign(
            tctx->esys_ctx,
            tobj->tpm_esys_tr,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &dgst,
            &scheme,
            &validation,
            &signature);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_Sign: %s", Tss2_RC_Decode(rval));
        goto out;
    }

    rv = ssl_util_attrs_to_evp(tobj->attrs, &pkey);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = ssl_util_setup_evp_pkey_ctx(pkey, RSA_PKCS1_PSS_PADDING, EVP_sha256(),
            EVP_PKEY_verify_init, &pkey_ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    int rc = EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
    if (!rc) {
        SSL_UTIL_LOGE("EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen"
                " RSA_PSS_SALTLEN_DIGEST failed");
        goto out;
    }

    TPM2B_PUBLIC_KEY_RSA *sig = &signature->signature.rsapss.sig;

    rc = EVP_PKEY_verify(pkey_ctx, sig->buffer, sig->size, dgst.buffer, dgst.size);
    if (rc < 0) {
        SSL_UTIL_LOGE("EVP_PKEY_verify failed");
        goto out;
    }

    if (rc == 1) {
        *pss_sigs_good = true;
    } else {
        *pss_sigs_good = false;
    }

    rv = CKR_OK;

out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(pkey);
    Esys_Free(out_priv);
    Esys_Free(out_pub);
    Esys_Free(signature);

    return rv;
}

/* What an ECDH command's refusal of the other party's point means: the point isn't on the curve */
static CK_RV ecdh_refusal(const char *cmd, TSS2_RC rval) {

    LOGE("%s: %s", cmd, Tss2_RC_Decode(rval));

    TSS2_RC code = utils_format_one_code(rval);
    if (code == TPM2_RC_ECC_POINT || code == TPM2_RC_NO_RESULT) {
        return CKR_DATA_INVALID;
    }

    return rval == TPM2_RC_LOCKOUT ? CKR_PIN_LOCKED : CKR_GENERAL_ERROR;
}

/* A field element of a field_size-byte field, with the zero bytes a TPM may leave out put back */
static twist ecc_parameter_to_twist(const TPM2B_ECC_PARAMETER *p, size_t field_size) {

    if (p->size > field_size) {
        LOGE("A %u-byte coordinate in a %zu-byte field", p->size, field_size);
        return NULL;
    }

    twist t = twist_calloc(field_size);
    if (!t) {
        LOGE("oom");
        return NULL;
    }

    memcpy((char *)t + field_size - p->size, p->buffer, p->size);
    return t;
}

CK_RV tpm_ec_ecdh1_derive(tpm_ctx *tctx, tobject *tobj, uint8_t *ecc_point,
                          size_t ecc_point_len, uint8_t **secret,
                          size_t *secret_len)
{
    TPM2B_ECC_POINT *out_point = NULL;
    TPM2B_ECC_POINT in_point = { };
    CK_RV rv = CKR_GENERAL_ERROR;

    if (!tobj || !tctx || !ecc_point || !ecc_point_len || !secret_len) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = utils_uncompressed_ecpoint_to_tpm2b(ecc_point, &in_point, ecc_point_len);
    if (rv != CKR_OK) {
        return rv;
    }

    bool res = set_esys_auth(tctx->esys_ctx, tobj->tpm_esys_tr, tobj->unsealed_auth);
    if (!res) {
        return CKR_GENERAL_ERROR;
    }

    TSS2_RC rval = Esys_ECDH_ZGen(tctx->esys_ctx, tobj->tpm_esys_tr, ESYS_TR_PASSWORD,
                        ESYS_TR_NONE, ESYS_TR_NONE, &in_point, &out_point);
    if (rval != TSS2_RC_SUCCESS) {
        return ecdh_refusal("Esys_ECDH_ZGen", rval);
    }

    *secret = calloc(1, out_point->point.x.size);
    if (!*secret) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    *secret_len = out_point->point.x.size;
    memcpy(*secret, out_point->point.x.buffer, *secret_len);

out:
    /* Z, the shared secret */
    OPENSSL_cleanse(out_point, sizeof(*out_point));
    free(out_point);

    return rv;
}

CK_RV tpm_ec_ecdh_keygen(tpm_ctx *tctx, tobject *pubkey, twist *z, twist *ephemeral_point) {

    if (!tctx || !pubkey || !z || !ephemeral_point) {
        return CKR_ARGUMENTS_BAD;
    }

    CK_ATTRIBUTE_PTR params = attr_get_attribute_by_type(pubkey->attrs, CKA_EC_PARAMS);
    CK_ATTRIBUTE_PTR ecpoint = attr_get_attribute_by_type(pubkey->attrs, CKA_EC_POINT);
    if (!params || !ecpoint) {
        LOGE("Expected the EC key to have CKA_EC_PARAMS and CKA_EC_POINT");
        return CKR_GENERAL_ERROR;
    }

    int nid = 0;
    CK_RV rv = ssl_util_params_to_nid(params, &nid);
    if (rv != CKR_OK) {
        return rv;
    }

    TPMI_ECC_CURVE curve = nid_to_tpm2alg(nid);
    CK_ULONG field_size = 0;
    if (curve == TPM2_ALG_ERROR || ssl_util_ec_field_size(params, &field_size) != CKR_OK) {
        return CKR_CURVE_NOT_SUPPORTED;
    }

    CK_BYTE_PTR raw = NULL;
    CK_ULONG raw_len = 0;
    if (!utils_ec_point_unwrap(ecpoint->pValue, ecpoint->ulValueLen, field_size, &raw, &raw_len)) {
        LOGE("The key's CKA_EC_POINT isn't an uncompressed point on its curve");
        return CKR_GENERAL_ERROR;
    }

    TPM2B_ECC_POINT point = { 0 };
    rv = utils_uncompressed_ecpoint_to_tpm2b(raw, &point, raw_len);
    if (rv != CKR_OK) {
        LOGE("The key's CKA_EC_POINT isn't an uncompressed point on its curve");
        return CKR_GENERAL_ERROR;
    }

    /* the public key alone, with no hierarchy: TPM2_ECDH_KeyGen uses only its public point */
    TPM2B_PUBLIC pub = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_DECRYPT | TPMA_OBJECT_USERWITHAUTH,
            .parameters.eccDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .scheme = { .scheme = TPM2_ALG_NULL },
                .curveID = curve,
                .kdf = { .scheme = TPM2_ALG_NULL },
            },
            .unique.ecc = point.point,
        },
    };

    uint32_t handle = ESYS_TR_NONE;
    if (!tpm_loadexternal(tctx, &pub, &handle)) {
        return CKR_GENERAL_ERROR;
    }

    TPM2B_ECC_POINT *zpoint = NULL;
    TPM2B_ECC_POINT *qpoint = NULL;
    TSS2_RC rval = Esys_ECDH_KeyGen(tctx->esys_ctx, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            &zpoint, &qpoint);
    tpm_flushcontext(tctx, handle);
    if (rval != TSS2_RC_SUCCESS) {
        return ecdh_refusal("Esys_ECDH_KeyGen", rval);
    }

    twist x = NULL, y = NULL;
    twist secret = ecc_parameter_to_twist(&zpoint->point.x, field_size);
    if (!secret) {
        rv = CKR_GENERAL_ERROR;
        goto out;
    }

    /* the ephemeral point as CKA_EC_POINT has it: 04 || x || y in a DER OCTET STRING */
    x = ecc_parameter_to_twist(&qpoint->point.x, field_size);
    y = ecc_parameter_to_twist(&qpoint->point.y, field_size);
    if (!x || !y) {
        rv = CKR_GENERAL_ERROR;
        goto out;
    }

    CK_ULONG content = 2 * field_size + 1;
    CK_ULONG der_len = utils_ec_point_der_len(field_size);
    CK_BYTE header[4] = { 0x04 };
    CK_ULONG header_len = der_len - content;
    if (header_len == 2) {
        header[1] = (CK_BYTE)content;
    } else {
        header[1] = 0x81;
        header[2] = (CK_BYTE)content;
    }
    header[header_len] = 0x04;

    binarybuffer parts[] = {
        { .data = header, .size = header_len + 1 },
        { .data = x, .size = field_size },
        { .data = y, .size = field_size },
    };
    twist q = twistbin_create(parts, ARRAY_LEN(parts));
    if (!q) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    *z = secret;
    secret = NULL;
    *ephemeral_point = q;
    rv = CKR_OK;

out:
    if (secret) {
        OPENSSL_cleanse((void *)secret, twist_len(secret));
        twist_free(secret);
    }
    twist_free(x);
    twist_free(y);
    /* Z, the shared secret */
    OPENSSL_cleanse(zpoint, sizeof(*zpoint));
    Esys_Free(zpoint);
    Esys_Free(qpoint);

    return rv;
}
