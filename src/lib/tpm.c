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
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
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

#define TPM2_ERROR_TSS2_RC_ERROR_MASK 0xFFFF

static inline UINT16 tpm2_error_get(TSS2_RC rc) {
    return ((rc & TPM2_ERROR_TSS2_RC_ERROR_MASK));
}

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
            TPMI_ALG_SYM_MODE mode;
            TPM2B_IV iv;
            twist prev_data;
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
    Tss2_TctiLdr_Finalize(&ctx->tcti_ctx);

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
    t->tcti_ctx = tcti;

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

    return tpm_ctx_new_fromtcti(tcti, tctx);
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
            if ((rval & (TPM2_RC_P | TPM2_RC_1)) == (TPM2_RC_P | TPM2_RC_1)) {
                rval &= ~(TPM2_RC_P | TPM2_RC_1);
                if (rval == TPM2_RC_KEY_SIZE || rval == TPM2_RC_VALUE) {
                    continue;
                } else {
                    return CKR_MECHANISM_INVALID;
                }
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
        if ((rval & (TPM2_RC_P | TPM2_RC_1)) == (TPM2_RC_P | TPM2_RC_1)) {
            rval &= ~(TPM2_RC_P | TPM2_RC_1);
            if (rval == TPM2_RC_KEY_SIZE || rval == TPM2_RC_VALUE) {
                return CKR_MECHANISM_INVALID;
            }
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
        if ((rval & (TPM2_RC_P | TPM2_RC_1)) == (TPM2_RC_P | TPM2_RC_1)) {
            rval &= ~(TPM2_RC_P | TPM2_RC_1);
            if (rval == TPM2_RC_CURVE || rval == TPM2_RC_VALUE) {
                return CKR_MECHANISM_INVALID;
            }
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
            if ((rval & (TPM2_RC_P | TPM2_RC_1)) == (TPM2_RC_P | TPM2_RC_1)) {
                rval &= ~(TPM2_RC_P | TPM2_RC_1);
                if (rval == TPM2_RC_CURVE) {
                    continue;
                } else {
                    return CKR_MECHANISM_INVALID;
                }
            }
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
    if (rv != CKR_OK) {
        return rv;
    }

    /* if it's supported 128bits is min by spec IIUC */
    /* convert to bytes for return values */
    *min = _min/8;
    *max = _max/8;

    return CKR_OK;
}

CK_RV tpm_get_token_info (tpm_ctx *ctx, CK_TOKEN_INFO *info) {

    check_pointer(ctx);
    check_pointer(info);

    TPMS_CAPABILITY_DATA *capabilityData = NULL;

    CK_RV rv = tpm_get_properties(ctx, &capabilityData);
    if (rv !=CKR_OK) {
        return rv;
    }

    TPMS_TAGGED_PROPERTY *tpmProperties = capabilityData->data.tpmProperties.tpmProperty;

    // Use Spec revision as HW Version
    UINT32 revision = tpmProperties[TPM2_PT_REVISION - TPM2_PT_FIXED].value;
    info->hardwareVersion.major = revision / 100;
    info->hardwareVersion.minor = revision % 100;

    // Use Firmware Version as FW Version
    UINT32 version = tpmProperties[TPM2_PT_FIRMWARE_VERSION_1 - TPM2_PT_FIXED].value;
    // Most vendors seem to use 00MM.00mm as format for TPM2_PT_FIRMWARE_VERSION_1
    // Unfortunately we only have 1 byte for major and minor each.
    info->firmwareVersion.major = (version >> 16) & 0xFF;
    info->firmwareVersion.minor = version  & 0xFF;

    // Use Vendor ID as Manufacturer ID
    unsigned char manufacturerID[sizeof(UINT32)+1] = {0}; // 4 bytes + '\0' as temp storage
    UINT32 manufacturer = ntohl(tpmProperties[TPM2_PT_MANUFACTURER - TPM2_PT_FIXED].value);
    memcpy(manufacturerID, (unsigned char*) &manufacturer, sizeof(uint32_t));
    str_padded_copy(info->manufacturerID, manufacturerID, sizeof(info->manufacturerID));

    // Map human readable Manufacturer String, if available,
    // otherwise 4 byte ID was already padded and will be used.
    for (unsigned int i=0; i < ARRAY_LEN(TPM2_MANUFACTURER_MAP); i++){
        if (!strncasecmp((char *)info->manufacturerID, TPM2_MANUFACTURER_MAP[i][0], 4)) {
            str_padded_copy(info->manufacturerID,
                            (unsigned char *)TPM2_MANUFACTURER_MAP[i][1],
                            sizeof(info->manufacturerID));
        }
    }

    // Use Vendor String as Model description
    UINT32 vendor[4];
    vendor[0] = ntohl(tpmProperties[TPM2_PT_VENDOR_STRING_1 - TPM2_PT_FIXED].value);
    vendor[1] = ntohl(tpmProperties[TPM2_PT_VENDOR_STRING_2 - TPM2_PT_FIXED].value);
    vendor[2] = ntohl(tpmProperties[TPM2_PT_VENDOR_STRING_3 - TPM2_PT_FIXED].value);
    vendor[3] = ntohl(tpmProperties[TPM2_PT_VENDOR_STRING_4 - TPM2_PT_FIXED].value);
    str_padded_copy(info->model, (unsigned char*) &vendor, sizeof(info->model));

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
            goto out;
        }

        memcpy(&data[offset], rand_bytes->buffer, rand_bytes->size);

        offset += rand_bytes->size;
        size -= rand_bytes->size;
    }

    result = true;

out:
    free(rand_bytes);

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

#ifdef ESYS_2_4
/* Esys_TR_GetTpmHandle() was only added to tss2-esys in v2.4. Its
 * functionality is merely used in optional backends. Splice out into a
 * dedicated function, so the main codebase can keep a more lenient versioned
 * dependency on tss2-esys.
 */
bool tpm_get_tpmhandle(tpm_ctx *ctx, uint32_t handle, uint32_t *tpm_handle) {

    TSS2_RC rval = Esys_TR_GetTpmHandle(ctx->esys_ctx, handle, tpm_handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_GetTpmHandle: %s:", Tss2_RC_Decode(rval));
        return false;
    }

    return true;
}
#endif

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
        return false;
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
    *siglen = rs;

    if (!sig) {
        return CKR_OK;
    }

    if (rs > *siglen) {
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(sig, R->buffer, R->size);
    memcpy(sig + R->size, S->buffer, S->size);
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
        /* no default */
    }

    return CKR_GENERAL_ERROR;
}

static TPMI_ALG_HASH guess_hash_by_size(CK_ULONG len) {
    switch(len) {
    case 20:
        return TPM2_ALG_SHA1;
    case 32:
        return TPM2_ALG_SHA256;
    case 48:
        return TPM2_ALG_SHA384;
    case 64:
        return TPM2_ALG_SHA512;
        /* no default */
    }

    return TPM2_ALG_ERROR;
}

static CK_RV ecc_fixup_halg(TPMT_SIG_SCHEME *sig, CK_ULONG datalen) {
    if (sig->details.any.hashAlg == TPM2_ALG_ERROR) {
        TPMI_ALG_HASH halg = guess_hash_by_size(datalen);
        if (halg == TPM2_ALG_ERROR) {
            LOGE("Cannot figure out hashing algorithm for signature of len: %lu", datalen);
            return CKR_GENERAL_ERROR;
        }
        sig->details.any.hashAlg = halg;
    }
    return CKR_OK;
}

CK_RV tpm_sign(tpm_op_data *opdata, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {
    assert(opdata);

    tobject *tobj = opdata->tobj;
    assert(tobj);

    tpm_ctx *tctx = opdata->ctx;
    assert(tctx);

    twist auth = tobj->unsealed_auth;
    TPMI_DH_OBJECT handle = tobj->tpm_handle;
    ESYS_CONTEXT *ectx = tctx->esys_ctx;
    ESYS_TR session = tctx->hmac_session;
    TPMT_SIG_SCHEME *scheme = opdata->op_type == CKK_RSA ? &opdata->rsa.sig :
            &opdata->ecc.sig;

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

    if (opdata->op_type == CKK_EC) {
        CK_RV rv = ecc_fixup_halg(&opdata->ecc.sig, datalen);
        if (rv != CKR_OK) {
            return rv;
        }
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

    free(signature);

    return rv;
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
    CK_RV rv = get_oaep_mgf1_alg(tctx, tobj->tpm_handle, &supported_mgf);
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
     * So we need to detect this case and guess the algorithm based on hash size.
     */
    opdata->ecc.sig.details.any.hashAlg = TPM2_ALG_ERROR;

    set_common_opdata(opdata, tctx, tobj, CKK_EC);

    *outdata = opdata;

    return CKR_OK;
}

CK_RV tpm_ec_ecdsa_sha1_get_opdata(mdetail *mdtl,
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
    opdata->ecc.sig.details.any.hashAlg = TPM2_ALG_SHA1;

    set_common_opdata(opdata, tctx, tobj, CKK_EC);

    *outdata = opdata;

    return CKR_OK;
}

static CK_RV aes_common_opdata(tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data *opdata) {

    if (mech->ulParameterLen > sizeof(opdata->sym.iv.buffer) ||
            mech->ulParameterLen % 8) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    opdata->sym.iv.size = mech->ulParameterLen;
    memcpy(opdata->sym.iv.buffer, mech->pParameter, mech->ulParameterLen);
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

void tpm_opdata_free(tpm_op_data **opdata) {

    if (opdata) {
        twist_free((*opdata)->sym.prev_data);
        free(*opdata);
        *opdata = NULL;
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
    ESYS_TR handle = tpm_enc_data->tobj->tpm_handle;
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
        return CKR_GENERAL_ERROR;
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

    CK_ULONG offset = 0;

    while (offset < data_in_len) {

        TPM2B_MAX_BUFFER tpm_data_in = { 0 };

        assert(offset <= data_in_len);

        CK_ULONG data_left = data_in_len - offset;
        assert(data_left != 0);

        /* How much can we encrypt in this part, bounded by TPM data structure sizes */
        CK_ULONG part_len = data_left > sizeof(tpm_data_in.buffer) ?
                sizeof(tpm_data_in.buffer) : data_left;

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
            return CKR_GENERAL_ERROR;
        }

        /* shuffle IVs */
        current_iv = *tpm_iv_out;
        Esys_Free(tpm_iv_out);
        tpm_iv_out = NULL;

        /* shuffle to output buffer */
        assert(tpm_data_out->size == part_len);
        memcpy(&data_out[offset], tpm_data_out->buffer, part_len);
        Esys_Free(tpm_data_out);
        tpm_data_out = NULL;

        /* update the offset for the next go around */
        offset += part_len;
    }

    assert(offset == data_in_len);

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
    ESYS_TR handle = tpm_enc_data->tobj->tpm_handle;

    /*
     * if the application doesn't ask for a block boundary,
     * buffer the extra till later when you can make a block.
     * Manipulate the input to the TPM to be on a boundary.
     */
    twist full_buffer = twistbin_append(tpm_enc_data->sym.prev_data, in, inlen);
    if (!full_buffer) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }
    /* done with this buffer, transfered to full_buffer */
    tpm_enc_data->sym.prev_data = NULL;

    /* pass only the "good blocks here */
    size_t full_buffer_len = twist_len(full_buffer);
    CK_ULONG extra = full_buffer_len % 16;
    CK_ULONG blocks = full_buffer_len / 16;
    CK_ULONG modified_full_buffer_len = full_buffer_len - extra;

    if (blocks) {
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
    if (extra) {
        tpm_enc_data->sym.prev_data = NULL;
        tpm_enc_data->sym.prev_data = twistbin_new(
                &full_buffer[modified_full_buffer_len],
                extra);
        if (!tpm_enc_data->sym.prev_data) {
            LOGE("oom");
            rv = CKR_HOST_MEMORY;
            goto error;
        }
    }

    rv = CKR_OK;

error:
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

CK_RV tpm_final_encrypt(crypto_op_data *opdata,
        CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {

    UNUSED(last_part);

    /* non-aes things don't matter */
    if (opdata->tpm_opdata->op_type != CKK_AES) {
        if (last_part_len) {
            *last_part_len = 0;
        }
        return CKR_OK;
    }

    size_t extra = opdata->tpm_opdata->sym.prev_data ?
            twist_len(opdata->tpm_opdata->sym.prev_data) : 0;

    /*
     * For padding modes, this is where you would apply the pad  or error
     * for non-padding modes
     */
    if (extra) {
        return CKR_DATA_LEN_RANGE;
    }

    if (last_part_len) {
        *last_part_len = 0;
    }

    return CKR_OK;
}

CK_RV tpm_decrypt(crypto_op_data *opdata,
        CK_BYTE_PTR ctext, CK_ULONG ctextlen,
        CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen) {

    tpm_op_data *tpm_enc_data = opdata->tpm_opdata;

    if (tpm_enc_data->op_type == CKK_RSA) {
        CK_BYTE buf[4096];
        CK_ULONG buf_len = sizeof(buf);

        CK_RV rv = tpm_rsa_decrypt(tpm_enc_data, ctext, ctextlen, buf, &buf_len);
        if (rv != CKR_OK) {
            return rv;
        }

        return mech_unsynthesize(
                tpm_enc_data->mdtl,
                &tpm_enc_data->mech, tpm_enc_data->tobj->attrs,
                buf, buf_len,
                ptext, ptextlen);
    }

    return do_buffered_encdec(tpm_enc_data, DECRYPT,
            ctext, ctextlen, ptext, ptextlen);
}

CK_RV tpm_final_decrypt(crypto_op_data *opdata,
        CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {

    UNUSED(last_part);

    /* non-aes things don't matter */
    if (opdata->tpm_opdata->op_type != CKK_AES) {
        if (last_part_len) {
            *last_part_len = 0;
        }
        return CKR_OK;
    }

    size_t extra = opdata->tpm_opdata->sym.prev_data ?
            twist_len(opdata->tpm_opdata->sym.prev_data) : 0;

    /*
     * For padding modes, this is where you would remove the pad  or error
     * for non-padding modes
     */
    if (extra) {
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

    if (last_part_len) {
        *last_part_len = 0;
    }

    return CKR_OK;
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
        		&tpm->did_check_for_createloaded);
        if (rval != TSS2_RC_SUCCESS) {
        	return rval;
        }
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
struct tpm_key_data {
    TPM2B_PUBLIC pub;
    TPM2B_SENSITIVE_CREATE priv;
};

static CK_RV generic_bbool_check(CK_ATTRIBUTE_PTR attr, CK_BBOOL check) {

    CK_BBOOL value;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    if (value != check) {
        LOGE("Expected attr 0x%lx to be %u, got %u", attr->type, value, check);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

static CK_RV generic_bbool_true(CK_ATTRIBUTE_PTR attr, void *udata) {
    UNUSED(udata);

    return generic_bbool_check(attr, CK_TRUE);
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

    // TODO get known bit sizes from TPM on init and check
    if (value != 1024 && value != 2048) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    keydat->pub.publicArea.parameters.rsaDetail.keyBits = value;

    return CKR_OK;
}

static CK_RV handle_ecparams(CK_ATTRIBUTE_PTR attr, void *udata) {

    tpm_key_data *keydat = (tpm_key_data *)udata;

    int nid = 0;
    CK_RV rv = ec_params_to_nid(attr, &nid);
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

static CK_RV handle_encrypt(CK_ATTRIBUTE_PTR attr, void *udata) {

    tpm_key_data *keydat = (tpm_key_data *)udata;

    CK_BBOOL value;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    if (value == CK_TRUE) {
        keydat->pub.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    } else {
        keydat->pub.publicArea.objectAttributes &= ~TPMA_OBJECT_SIGN_ENCRYPT;
    }

    return CKR_OK;
}

static CK_RV handle_decrypt(CK_ATTRIBUTE_PTR attr, void *udata) {

    tpm_key_data *keydat = (tpm_key_data *)udata;

    CK_BBOOL value;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    if (value == CK_TRUE) {
        keydat->pub.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    } else {
        keydat->pub.publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
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

static const attr_handler tpm_handlers[] = {
    { CKA_TOKEN,           generic_bbool_true    },
    { CKA_PRIVATE,         generic_bbool_any     },
    { CKA_VERIFY,          handle_decrypt        }, // Verify is same as decrypt
    { CKA_ENCRYPT,         handle_encrypt        },
    { CKA_DECRYPT,         handle_decrypt        },
    { CKA_SIGN,            handle_encrypt        }, // SIGN_ENCRYPT are same in TPM, depends on SCHEME
    { CKA_MODULUS_BITS,    handle_modulus        },
    { CKA_PUBLIC_EXPONENT, handle_exp            },
    { CKA_SENSITIVE,       handle_sensitive      },
    { CKA_CLASS,           handle_ckobject_class },
    { CKA_EXTRACTABLE,     handle_extractable    },
    { CKA_EC_PARAMS,       handle_ecparams       },
    { CKA_KEY_TYPE,        handle_key_type       },
    { CKA_TRUSTED,           generic_bbool_false },
    { CKA_SIGN_RECOVER,      generic_bbool_false },
    { CKA_VERIFY_RECOVER,    generic_bbool_false },
    { CKA_DERIVE,            generic_bbool_any },
};

static CK_RV tpm_data_init(CK_MECHANISM_PTR mechanism,
        attr_list *pubattrs,
        attr_list *privattrs,
        tpm_key_data *tpmdat) {

    memset(&tpmdat->priv, 0, sizeof(tpmdat->priv));
    memset(&tpmdat->pub,  0, sizeof(tpmdat->pub));

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
            tpm_handlers, ARRAY_LEN(tpm_handlers), tpmdat);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = attr_list_invoke_handlers(privattrs,
            tpm_handlers, ARRAY_LEN(tpm_handlers), tpmdat);
    if (rv != CKR_OK) {
        return rv;
    }

    return CKR_OK;
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

    int rc = EC_POINT_set_affine_coordinates_GFp(group,
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
     * per X9.62.
     *
     * TODO get better link to documentation around this or build
     * with OSSL.
     */
    size_t tmp = 0;
    safe_add(tmp, len, 2);
    char *padded_data = malloc(tmp);
    if (!padded_data) {
        LOGE("oom");
        goto out;
    }

    padded_data[0] = 4;
    padded_data[1] = len;
    memcpy(&padded_data[2], mydata, len);

    safe_adde(len, 2);
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

    ESYS_TR out_handle = 0;

    CK_RV rv = CKR_GENERAL_ERROR;

    assert(objdata);

    rv = sanity_check_mech(mechanism);
    if (rv != CKR_OK) {
        goto error;
    }

    tpm_key_data tpmdat;
    rv = tpm_data_init(mechanism,
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

    /* everything common*/
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

    /* conditional block */
    CK_BBOOL decrypt = !!(objattrs & TPMA_OBJECT_DECRYPT);
    r = attr_list_add_bool(objdata->attrs, CKA_DECRYPT, decrypt);
    goto_error_false(r);

    /* decrypt and verify are the same */
    r = attr_list_add_bool(objdata->attrs, CKA_VERIFY, decrypt);
    goto_error_false(r);

    CK_BBOOL sign = !!(objattrs & TPMA_OBJECT_SIGN_ENCRYPT);
    r = attr_list_add_bool(objdata->attrs, CKA_SIGN, sign);
    goto_error_false(r);

    /* sign and encrypt are same */
    r = attr_list_add_bool(objdata->attrs, CKA_ENCRYPT, sign);
    goto_error_false(r);

    objdata->privblob = tmppriv;
    objdata->pubblob = tmppub;
    objdata->privhandle = out_handle;

    rv = CKR_OK;
error:

    Esys_Free(out_pub);
    Esys_Free(out_priv);

    if (rv != CKR_OK) {
        tpm_objdata_free(objdata);
    }

    return rv;
}

void tpm_objdata_free(tpm_object_data *objdata) {

    if (!objdata) {
        return;
    }

    attr_list_free(objdata->attrs);

    twist_free(objdata->privblob);
    twist_free(objdata->pubblob);
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
    }

    /* AES */
    if (is_algorithm_supported(algs, TPM2_ALG_AES)) {
        add_mech(CKM_AES_KEY_GEN);

        if_add_mech(algs, TPM2_ALG_CBC, CKM_AES_CBC);
        if_add_mech(algs, TPM2_ALG_CFB, CKM_AES_CFB128);
        if_add_mech(algs, TPM2_ALG_ECB, CKM_AES_ECB);
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
    TPM2B_AUTH hieararchy_auth = { 0 };

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
    if (auth && auth[0]) {
        size_t len = strlen(auth);
        if (len > sizeof(hieararchy_auth.buffer)) {
            LOGE("TPM2_PKCS11_HIERARCHY_AUTH is too big. Max size is: %zu",
                    sizeof(hieararchy_auth.buffer));
            return CKR_GENERAL_ERROR;
        }
        hieararchy_auth.size = (typeof(hieararchy_auth.size))len;
        memcpy(hieararchy_auth.buffer, auth, len);
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

    TSS2_RC rval = Esys_TR_SetAuth(tpm->esys_ctx, hierarchy, &hieararchy_auth);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_SetAuth: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
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
    rval = Esys_CreatePrimary(tpm->esys_ctx,
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

    *primary_handle = handle;

    return CKR_OK;
}

CK_RV tpm_create_persistent_primary(tpm_ctx *tpm, uint32_t *primary_handle, twist *primary_blob) {
    assert(tpm);
    assert(primary_blob);
    assert(tpm->esys_ctx);

    /* TODO make configurable ? */
    ESYS_TR hierarchy = ESYS_TR_RH_OWNER;
    TPM2B_AUTH hieararchy_auth = { 0 };

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

    TSS2_RC rval = Esys_TR_SetAuth(tpm->esys_ctx, hierarchy, &hieararchy_auth);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_SetAuth: %s:", Tss2_RC_Decode(rval));
        return CKR_GENERAL_ERROR;
    }

    TPM2B_PUBLIC *out_pub = NULL;
    TPM2B_CREATION_DATA *data = NULL;
    TPM2B_DIGEST *hash = NULL;
    TPMT_TK_CREATION *ticket = NULL;

    ESYS_TR handle = ESYS_TR_NONE;
    rval = Esys_CreatePrimary(tpm->esys_ctx,
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

    bool res = set_esys_auth(tctx->esys_ctx, tobj->tpm_handle,
            tobj->unsealed_auth);
    if (!res) {
        return CKR_GENERAL_ERROR;
    }

    TSS2_RC rval = Esys_Sign(
            tctx->esys_ctx,
            tobj->tpm_handle,
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

    rv = ssl_util_tobject_to_evp(&pkey, tobj);
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

