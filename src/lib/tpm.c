/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include <openssl/asn1.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <openssl/sha.h>

#include "pkcs11.h"
#include "log.h"
#include "mutex.h"
#include "tcti_ldr.h"
#include "tpm.h"

struct tpm_ctx {
    TSS2_TCTI_CONTEXT *tcti_ctx;
    ESYS_CONTEXT *esys_ctx;
    ESYS_TR hmac_session;
    TPMA_SESSION old_flags;
    TPMA_SESSION original_flags;
};

#define TPM2B_INIT(xsize) { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)

#define TPM2_ERROR_TSS2_RC_ERROR_MASK 0xFFFF

static inline UINT16 tpm2_error_get(TSS2_RC rc) {
    return ((rc & TPM2_ERROR_TSS2_RC_ERROR_MASK));
}

#define TSS2_RETRY_EXP(expression)                         \
    ({                                                     \
        TSS2_RC __result = 0;                              \
        do {                                               \
            __result = (expression);                       \
        } while (tpm2_error_get(__result) == TPM2_RC_RETRY); \
        __result;                                          \
    })

#define TSS2L_SYS_AUTH_COMMAND_INIT(cnt, array) { \
        .count = cnt, \
        .auths = array, \
    }

#define TPMS_AUTH_COMMAND_INIT(session_handle) \
        TPMS_AUTH_COMMAND_INIT_ATTRS(session_handle, TPMA_SESSION_CONTINUESESSION)

#define TPMS_AUTH_COMMAND_INIT_ATTRS(session_handle, attrs) { \
        .sessionHandle = session_handle,\
        .nonce = TPM2B_EMPTY_INIT, \
        .sessionAttributes = attrs, \
        .hmac = TPM2B_EMPTY_INIT \
    }

typedef struct tpm2_hierarchy_pdata tpm2_hierarchy_pdata;
struct tpm2_hierarchy_pdata {
    struct {
        TPMI_RH_HIERARCHY hierarchy;
        TPM2B_SENSITIVE_CREATE sensitive;
        TPM2B_PUBLIC public;
        TPM2B_DATA outside_info;
        TPML_PCR_SELECTION creation_pcr;
        TPM2_HANDLE object_handle;
    } in;
    struct {
        TPM2_HANDLE handle;
        TPM2B_PUBLIC public;
        TPM2B_DIGEST hash;
        struct {
            TPM2B_CREATION_DATA data;
            TPMT_TK_CREATION ticket;
        } creation;
        TPM2B_NAME name;
    } out;
};

//|decrypt|sign"
#define _PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT { \
    .publicArea = { \
        .nameAlg = TPM2_ALG_SHA256, \
        .type = TPM2_ALG_RSA, \
        .objectAttributes = \
              TPMA_OBJECT_FIXEDTPM \
            | TPMA_OBJECT_FIXEDPARENT \
            | TPMA_OBJECT_SENSITIVEDATAORIGIN \
            | TPMA_OBJECT_USERWITHAUTH \
            | TPMA_OBJECT_DECRYPT \
            | TPMA_OBJECT_SIGN_ENCRYPT, \
        .parameters = { \
            .rsaDetail = { \
                .exponent = 0, \
                .symmetric = { \
                    .algorithm = TPM2_ALG_NULL, \
                 }, \
            .scheme = { .scheme = TPM2_ALG_NULL }, \
            .keyBits = 2048 \
            }, \
        }, \
            .unique = { .rsa = { .size = 0 } } \
    }, \
}

#define TPM2B_SENSITIVE_CREATE_EMPTY_INIT { \
           .sensitive = { \
                .data = {   \
                    .size = 0 \
                }, \
                .userAuth = {   \
                    .size = 0 \
                } \
            } \
    }

#define TPM2_HIERARCHY_DATA_INIT { \
    .in = { \
        .public = _PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT, \
        .sensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT, \
        .hierarchy = TPM2_RH_OWNER \
    }, \
}

#define SUPPORTED_ABI_VERSION \
{ \
    .tssCreator = 1, \
    .tssFamily = 2, \
    .tssLevel = 1, \
    .tssVersion = 108, \
}

static ESYS_CONTEXT* esys_ctx_init(TSS2_TCTI_CONTEXT *tcti_ctx) {

    TSS2_ABI_VERSION abi_version = SUPPORTED_ABI_VERSION;

    ESYS_CONTEXT *esys_ctx = NULL;
    TSS2_RC rval = Esys_Initialize(&esys_ctx, tcti_ctx, &abi_version);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_Initialize: 0x%x", rval);
        return NULL;
    }

    return esys_ctx;
}

static void flags_turndown(tpm_ctx *ctx, TPMA_SESSION flags) {

    TSS2_RC rc = Esys_TRSess_GetAttributes(ctx->esys_ctx, ctx->hmac_session, &ctx->old_flags);
    assert(rc == TPM2_RC_SUCCESS);

    assert(ctx->old_flags == ctx->original_flags);

    TPMA_SESSION new_flags = (ctx->old_flags & (~flags));
    rc = Esys_TRSess_SetAttributes(ctx->esys_ctx, ctx->hmac_session, new_flags, 0xff);
    assert(rc == TPM2_RC_SUCCESS);
}

static void flags_restore(tpm_ctx *ctx) {

    assert(ctx->old_flags == ctx->original_flags);

    TSS2_RC rc = Esys_TRSess_SetAttributes(ctx->esys_ctx, ctx->hmac_session, ctx->old_flags, 0xff);
    assert(rc == TPM2_RC_SUCCESS);
}

void tpm_ctx_free(tpm_ctx *ctx) {

    if (!ctx) {
        return;
    }

    Esys_Finalize(&ctx->esys_ctx);
    Tss2_Tcti_Finalize(ctx->tcti_ctx);
    free(ctx->tcti_ctx);
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

CK_RV tpm_sesion_start(tpm_ctx *ctx, twist auth, uint32_t handle) {

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
        LOGE("Esys_StartAuthSession: 0x%x", rc);
        return CKR_GENERAL_ERROR;
    }

    rc = Esys_TRSess_SetAttributes(ctx->esys_ctx, session, session_attrs,
                                      0xff);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_TRSess_SetAttributes: 0x%x", rc);
        rc = Esys_FlushContext(ctx->esys_ctx,
                session);
        if (rc != TSS2_RC_SUCCESS) {
            LOGW("Esys_FlushContext: 0x%x", rc);
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
        LOGE("Esys_FlushContext: 0x%x", rc);
        return CKR_GENERAL_ERROR;
    }

    ctx->hmac_session = 0;

    return CKR_OK;
}


CK_RV tpm_ctx_new(tpm_ctx **tctx) {

    ESYS_CONTEXT *esys = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;

    tpm_ctx *t = calloc(1, sizeof(*t));
    if (!t) {
        return CKR_HOST_MEMORY;
    }

    tcti = tcti_ldr_load();
    if (!tcti) {
        goto error;
    }

    esys = esys_ctx_init(tcti);
    if (!esys) {
        goto error;
    }

    /* populate */
    t->esys_ctx = esys;
    t->tcti_ctx = tcti;

    /* assign back (return via pointer) */
    *tctx = t;

    return CKR_OK;

error:
    tpm_ctx_free(t);
    return CKR_GENERAL_ERROR;
}

bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path) {

    long current = ftell(fp);
    if (current < 0) {
        if (path) {
            LOGE("Error getting current file offset for file \"%s\" error: %s", path, strerror(errno));
        }
        return false;
    }

    int rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        if (path) {
            LOGE("Error seeking to end of file \"%s\" error: %s", path, strerror(errno));
        }
        return false;
    }

    long size = ftell(fp);
    if (size < 0) {
        if (path) {
            LOGE("ftell on file \"%s\" failed: %s", path, strerror(errno));
        }
        return false;
    }

    rc = fseek(fp, current, SEEK_SET);
    if (rc < 0) {
        if (path) {
            LOGE("Could not restore initial stream position for file \"%s\" failed: %s", path, strerror(errno));
        }
        return false;
    }

    /* size cannot be negative at this point */
    *file_size = (unsigned long)size;
    return true;
}

static bool readx(FILE *f, UINT8 *data, size_t size) {

    size_t bread = 0;
    size_t index = 0;
    do {
        bread = fread(&data[index], 1, size, f);
        if (bread != size) {
            if (feof(f) || (errno != EINTR)) {
                return false;
            }
            /* continue on EINTR */
        }
        size -= bread;
        index += bread;
    } while (size > 0);

    return true;
}

bool files_read_bytes(FILE *out, UINT8 bytes[], size_t len) {

    if (!out || !bytes) {
        return false;
    }

    return readx(out, bytes, len);
}

static bool read_bytes_from_file(FILE *f, UINT8 *buf, UINT16 *size,
                                 const char *path) {
    unsigned long file_size;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        /* get_file_size() logs errors */
        return false;
    }

    /* max is bounded on UINT16 */
    if (file_size > *size) {
        if (path) {
            LOGE(
                    "File \"%s\" size is larger than buffer, got %lu expected less than %u",
                    path, file_size, *size);
        }
        return false;
    }

    result = files_read_bytes(f, buf, file_size);
    if (!result) {
        if (path) {
            LOGE("Could not read data from file \"%s\"", path);
        }
        return false;
    }

    *size = file_size;

    return true;
}

bool files_load_bytes_from_path(const char *path, UINT8 *buf, UINT16 *size) {
    if (!buf || !size || !path) {
        return false;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOGE("Could not open file \"%s\" error %s", path, strerror(errno));
        return false;
    }

    bool result = read_bytes_from_file(f, buf, size, path);

    fclose(f);
    return result;
}

#define LOAD_TYPE(type, name) \
    bool files_load_##name(const char *path, type *name) { \
    \
        UINT8 buffer[sizeof(*name)]; \
        UINT16 size = sizeof(buffer); \
        bool res = files_load_bytes_from_path(path, buffer, &size); \
        if (!res) { \
            return false; \
        } \
        \
        size_t offset = 0; \
        TSS2_RC rc = Tss2_MU_##type##_Unmarshal(buffer, size, &offset, name); \
        if (rc != TSS2_RC_SUCCESS) { \
            LOGE("Error serializing "str(name)" structure: 0x%x", rc); \
            LOGE("The input file needs to be a valid "xstr(type)" data structure"); \
            return false; \
        } \
        \
        return rc == TPM2_RC_SUCCESS; \
    }

LOAD_TYPE(TPM2B_PUBLIC, public)
LOAD_TYPE(TPM2B_PRIVATE, private)

bool tpm_getrandom(tpm_ctx *ctx, BYTE *data, size_t size) {

    size_t offset = 0;

    bool result = false;

    /*
     * This will get re-used once allocated by esys
     */
    TPM2B_DIGEST *rand_bytes = NULL;

    while (size) {

        UINT16 requested_size = size > sizeof(rand_bytes->buffer) ?
                sizeof(rand_bytes->buffer) : size;

        TSS2_RC rval = Esys_GetRandom(
            ctx->esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            size,
            &rand_bytes);
        if (rval != TSS2_RC_SUCCESS) {
            LOGE("Esys_GetRandom: 0x%x:", rval);
            goto out;
        }

        memcpy(&data[offset], rand_bytes->buffer, requested_size);

        offset += requested_size;
        size -= requested_size;
    }

    result = true;

out:
    free(rand_bytes);

    return result;
}

CK_RV tpm_stirrandom(tpm_ctx *ctx, unsigned char *seed, unsigned long seed_len) {

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
            LOGE("Esys_StirRandom: 0x%x:", rc);
            return CKR_GENERAL_ERROR;
        }

        offset += seed_len;
    }

    return CKR_OK;
}

bool tpm_register_handle(tpm_ctx *ctx, uint32_t *handle) {

    ESYS_TR object;

    TSS2_RC rval =
        Esys_TR_FromTPMPublic(
            ctx->esys_ctx,
            *handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &object);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_FromTPMPublic: 0x%x", rval);
        return false;
    }
    *handle = object;

    return true;
}

bool tpm_loadobj(
        tpm_ctx *ctx,
        uint32_t phandle, twist auth,
        twist pub_data, twist priv_data,
        uint32_t *handle) {

    TPM2B_PRIVATE priv = { .size = 0 };
    size_t len = twist_len(priv_data);

    size_t offset = 0;
    TSS2_RC rval = Tss2_MU_TPM2B_PRIVATE_Unmarshal((uint8_t *)priv_data, len, &offset, &priv);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPM2B_PRIVATE_Unmarshal: 0x%x:", rval);
        return false;
    }

    TPM2B_PUBLIC pub = { .size = 0 };
    len = twist_len(pub_data);

    offset = 0;
    rval = Tss2_MU_TPM2B_PUBLIC_Unmarshal((uint8_t *)pub_data, len, &offset, &pub);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPM2B_PRIVATE_Unmarshal: 0x%x:", rval);
        return false;
    }

    bool tmp_rc = set_esys_auth(ctx->esys_ctx, phandle, auth);
    if (!tmp_rc) {
        return false;
    }

    rval = Esys_Load(
           ctx->esys_ctx,
           phandle,
           ctx->hmac_session,
           ESYS_TR_NONE,
           ESYS_TR_NONE,
           &priv,
           &pub,
           handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_Load: 0x%x:", rval);
        return false;
    }

    return true;
}

bool tpm_flushcontext(tpm_ctx *ctx, uint32_t handle) {

    TSS2_RC rval = Esys_FlushContext(
                ctx->esys_ctx,
                handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_FlushContext: 0x%x", rval);
        return false;
    }

    return true;
}

TPMI_ALG_HASH mech_to_hash_alg(CK_MECHANISM_TYPE mode) {

    switch (mode) {
    case CKM_RSA_PKCS:
        return TPM2_ALG_NULL;

    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256:
        return TPM2_ALG_SHA256;

    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384:
        return TPM2_ALG_SHA384;

    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512:
        return TPM2_ALG_SHA512;

    case CKM_ECDSA_SHA1:
        return TPM2_ALG_SHA1;

    default:
        return TPM2_ALG_ERROR;
    }
}

TPM2_ALG_ID mech_to_sig_scheme(CK_MECHANISM_TYPE mode) {

    switch (mode) {
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
        return TPM2_ALG_RSASSA;
    case CKM_ECDSA_SHA1:
        return TPM2_ALG_ECDSA;
    default:
        return TPM2_ALG_ERROR;
    }
}

bool get_signature_scheme(CK_MECHANISM_TYPE mech, TPMT_SIG_SCHEME *scheme) {

    TPM2_ALG_ID sig_scheme = mech_to_sig_scheme(mech);
    if (sig_scheme == TPM2_ALG_ERROR) {
        return false;
    }

    TPMI_ALG_HASH halg = mech_to_hash_alg(mech);
    if (halg == TPM2_ALG_ERROR) {
        return false;
    }

    scheme->scheme = sig_scheme;
    scheme->details.rsassa.hashAlg = halg;

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
        LOGE("Tss2_Sys_Unseal: 0x%X", rc);
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

static CK_RV flatten_ecdsa(TPMS_SIGNATURE_ECDSA *ecdsa, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    /*
     * This code is a bit of hack for converting from a TPM ECDSA
     * signature, to an ASN1 encoded one for things like OSSL.
     *
     * The problem here, is that it is unclear the proper OSSL
     * calls to make the SEQUENCE HEADER populate.
     *
     * AN ECDSA Signature is an ASN1 sequence of 2 ASNI Integers,
     * the R and the S portions of the signature.
     */
    static const unsigned SEQ_HDR_SIZE = 2;

    unsigned char *buf_r = NULL;
    unsigned char *buf_s = NULL;

    TPM2B_ECC_PARAMETER *R = &ecdsa->signatureR;
    TPM2B_ECC_PARAMETER *S = &ecdsa->signatureS;

    /*
     * 1. Calculate the sizes of the ASN1 INTEGERS
     *    DER encoded.
     * 2. Allocate an array big enough for them and
     *    the SEQUENCE header.
     * 3. Set the header 0x30 and length
     * 4. Copy in R then S
     */
    ASN1_INTEGER *asn1_r = ASN1_INTEGER_new();
    ASN1_INTEGER *asn1_s = ASN1_INTEGER_new();
    if (!asn1_r || !asn1_s) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    /*
     * I wanted to calc the total size with i2d_ASN1_INTEGER
     * using a NULL output buffer, per the man page this should
     * work, however the code was dereferencing the pointer.
     *
     * I'll just let is alloc the buffers
     */
    ASN1_STRING_set(asn1_r, R->buffer, R->size);
    int size_r = i2d_ASN1_INTEGER(asn1_r, &buf_r);
    if (size_r < 0) {
        LOGE("Error converting R to ASN1");
        goto out;
    }

    ASN1_STRING_set(asn1_s, S->buffer, S->size);
    int size_s = i2d_ASN1_INTEGER(asn1_s, &buf_s);
    if (size_s < 0) {
        LOGE("Error converting R to ASN1");
        goto out;
    }

    /*
     * If the size doesn't fit in a byte my
     * encoding hack for ASN1 Sequence won't
     * work, so fail...loudly.
     */
    if (size_s + size_r > 0xFF) {
        LOGE("Cannot encode ASN1 Sequence, too big!");
        goto out;
    }

    if (!sig) {
        *siglen = size_r + size_s + SEQ_HDR_SIZE;
        rv = CKR_OK;
        goto out;
    }

    if (size_s + size_r + SEQ_HDR_SIZE > *siglen) {
        *siglen = size_r + size_s + SEQ_HDR_SIZE;
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    unsigned char *p = sig;

    /* populate header and skip */
    p[0] = 0x30;
    p[1] = size_r + size_s;
    p += 2;

    memcpy(p, buf_r, size_r);
    p += size_r;
    memcpy(p, buf_s, size_s);

    *siglen = size_r + size_s + SEQ_HDR_SIZE;

    rv = CKR_OK;

out:
    if (asn1_r) {
        ASN1_INTEGER_free(asn1_r);
    }

    if (asn1_s) {
        ASN1_INTEGER_free(asn1_s);
    }

    free(buf_r);
    free(buf_s);

    return rv;
}

static CK_RV sig_flatten(TPMT_SIGNATURE *signature, TPMT_SIG_SCHEME *scheme, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    switch(scheme->scheme) {
    case TPM2_ALG_RSASSA:
        return flatten_rsassa(&signature->signature.rsassa, sig, siglen);
    case TPM2_ALG_ECDSA:
        return flatten_ecdsa(&signature->signature.ecdsa, sig, siglen);
        /* no default */
    }

    return false;
}

CK_RV tpm_sign(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    twist auth = tobj->unsealed_auth;
    TPMI_DH_OBJECT handle = tobj->handle;

    TPM2B_DIGEST tdigest;
    if (sizeof(tdigest.buffer) < datalen) {
        return CKR_DATA_LEN_RANGE;
    }
    memcpy(tdigest.buffer, data, datalen);
    tdigest.size = datalen;

    bool result = set_esys_auth(ctx->esys_ctx, handle, auth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    TPMT_SIG_SCHEME in_scheme;
    result = get_signature_scheme(mech, &in_scheme);
    assert(result);
    if (!result) {
        /*
         * do not return unsupported here
         * this should be done in C_SignInit()
         * In theory this cannot fail
         */
        return CKR_GENERAL_ERROR;
    }

    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = TPM2B_EMPTY_INIT
    };

    flags_turndown(ctx, TPMA_SESSION_ENCRYPT);

    TPMT_SIGNATURE *signature = NULL;
    TSS2_RC rval = Esys_Sign(
            ctx->esys_ctx,
            handle,
            ctx->hmac_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &tdigest,
            &in_scheme,
            &validation,
            &signature);
    flags_restore(ctx);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_Sign: 0x%0x", rval);
        return false;
    }

    CK_RV rv = sig_flatten(signature, &in_scheme, sig, siglen);

    free(signature);

    return rv;
}

static CK_RV init_rsassa_sig(CK_BYTE_PTR sig, CK_ULONG siglen, TPMS_SIGNATURE_RSASSA *rsassa) {

    if (siglen > sizeof(rsassa->sig.buffer)) {
        return CKR_SIGNATURE_LEN_RANGE;
    }

    rsassa->sig.size = siglen;
    memcpy(rsassa->sig.buffer, sig, siglen);

    return CKR_OK;
}

static CK_RV init_ecdsa_sig(CK_BYTE_PTR sig, CK_ULONG siglen, TPMS_SIGNATURE_ECDSA *ecdsa) {

    int tag;
    int class;
    long len;
    const unsigned char *p = sig;

    int j = ASN1_get_object(&p, &len, &tag, &class, siglen);
    if (!(j & V_ASN1_CONSTRUCTED)) {
        LOGE("Expected ECDSA signature to start as ASN1 Constructed object");
        return CKR_GENERAL_ERROR;
    }

    if (tag != V_ASN1_SEQUENCE) {
        LOGE("Expected ECDSA signature to be an ASN1 sequence");
        return CKR_GENERAL_ERROR;
    }

    /*
     * Get R
     */
    TPM2B_ECC_PARAMETER *R = &ecdsa->signatureR;
    ASN1_INTEGER *r = d2i_ASN1_INTEGER(NULL, &p, len);
    if (!r) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }
    memcpy(R->buffer, r->data, r->length);
    R->size = r->length;
    ASN1_INTEGER_free(r);

    /*
     * Get S
     */
    TPM2B_ECC_PARAMETER *S = &ecdsa->signatureS;
    ASN1_INTEGER *s = d2i_ASN1_INTEGER(NULL, &p, len);
    if (!s) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }
    memcpy(S->buffer, s->data, s->length);
    S->size = s->length;
    ASN1_INTEGER_free(s);

    return CKR_OK;
}

static CK_RV init_sig_from_mech(CK_MECHANISM_TYPE mech, CK_BYTE_PTR sig, CK_ULONG siglen, TPMT_SIGNATURE *tpmsig) {

    /*
     * VerifyInit should be verifying that the mech and sig is supported, so
     * we can't return that error code here as PKCS11 doesn't support it,
     * so just return general error.
     */
    tpmsig->sigAlg = mech_to_sig_scheme(mech);
    if (tpmsig->sigAlg == TPM2_ALG_ERROR) {
        return CKR_GENERAL_ERROR;
    }

    tpmsig->signature.any.hashAlg = mech_to_hash_alg(mech);
    if (tpmsig->signature.any.hashAlg == TPM2_ALG_ERROR) {
        return CKR_GENERAL_ERROR;
    }

    switch(tpmsig->sigAlg) {
    case TPM2_ALG_RSASSA:
        return init_rsassa_sig(sig, siglen, &tpmsig->signature.rsassa);
    case TPM2_ALG_ECDSA:
        return init_ecdsa_sig(sig, siglen, &tpmsig->signature.ecdsa);
    default:
        LOGE("Unsupported verification algorithm, got: 0x%x", mech);
        return CKR_GENERAL_ERROR;
    }
}

CK_RV tpm_verify(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG siglen) {

    TPMI_DH_OBJECT handle = tobj->handle;

    // Copy the data into the digest block
    TPM2B_DIGEST msgdigest;
    if (sizeof(msgdigest.buffer) < datalen) {
        return CKR_DATA_LEN_RANGE;
    }
    memcpy(msgdigest.buffer, data, datalen);
    msgdigest.size = datalen;

    TPMT_SIGNATURE tpmsig;
    CK_RV rv = init_sig_from_mech(mech, sig, siglen, &tpmsig);
    if (rv != CKR_OK) {
        return rv;
    }

    TPMT_TK_VERIFIED *validation = NULL;
    TSS2_RC rval = Esys_VerifySignature(
            ctx->esys_ctx,
            handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &msgdigest,
            &tpmsig,
            &validation);
    if (rval != TPM2_RC_SUCCESS) {
        if (rval != TPM2_RC_SIGNATURE) {
            LOGE("Esys_VerifySignature: 0x%x", rval);
            return CKR_GENERAL_ERROR;
        }
        return CKR_SIGNATURE_INVALID;
    }

    free(validation);
    return CKR_OK;
}

#define P2_RC_HASH (TPM2_RC_HASH + TPM2_RC_P + TPM2_RC_2)

CK_RV tpm_hash_init(tpm_ctx *ctx, CK_MECHANISM_TYPE mode, uint32_t *sequence_handle) {

    TPM2B_AUTH null_auth = TPM2B_EMPTY_INIT;

    TPMI_ALG_HASH halg = mech_to_hash_alg(mode);
    if (halg == TPM2_ALG_ERROR) {
        return CKR_MECHANISM_INVALID;
    }

    if (halg == TPM2_ALG_NULL) {
        return CKR_OK;
    }

    TSS2_RC rval = Esys_HashSequenceStart(
            ctx->esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &null_auth,
            halg,
            sequence_handle);
    rval = tpm2_error_get(rval);
    if (rval != TPM2_RC_SUCCESS) {
        if (rval == P2_RC_HASH) {
            return CKR_MECHANISM_INVALID;
        }
        LOGE("Esys_HashSequenceStart: 0x%x", rval);
        return CKR_GENERAL_ERROR;
    }

    rval = Esys_TR_SetAuth(ctx->esys_ctx, *sequence_handle, &null_auth);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_TR_SetAuth: 0x%x", rval);
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV tpm_hash_update(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG data_len) {

    size_t offset = 0;
    while(offset < data_len) {

        TPM2B_MAX_BUFFER buffer;

        size_t send = data_len > sizeof(buffer.buffer) ? sizeof(buffer.buffer) : data_len;

        buffer.size = send;
        memcpy(buffer.buffer, &data[offset], send);

        flags_turndown(ctx, TPMA_SESSION_ENCRYPT);

        TSS2_RC rval = Esys_SequenceUpdate(
                    ctx->esys_ctx,
                    sequence_handle,
                    ctx->hmac_session,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &buffer);
        flags_restore(ctx);
        if (rval != TPM2_RC_SUCCESS) {
            LOGE("Esys_SequenceUpdate: 0x%x", rval);
            return CKR_GENERAL_ERROR;
        }

        offset += send;
    }

    return CKR_OK;
}

CK_RV tpm_readpub(tpm_ctx *ctx,
        uint32_t handle,

        TPM2B_PUBLIC **public,
        TPM2B_NAME **name,
        TPM2B_NAME **qualified_name) {

    TSS2_RC rval = TSS2_RETRY_EXP(Esys_ReadPublic(ctx->esys_ctx, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            public, name, qualified_name));
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_ReadPublic: 0x%x", rval);
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV tpm_hash_final(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {

    TPM2B_MAX_BUFFER no_data = { .size = 0 };

    TPMT_TK_HASHCHECK *validation = NULL;
    TPM2B_DIGEST *result = NULL;

    TSS2_RC rval = Esys_SequenceComplete(
            ctx->esys_ctx,
            sequence_handle,
            ctx->hmac_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &no_data,
            TPM2_RH_OWNER,
            &result,
            &validation);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_SequenceComplete: 0x%x", rval);
        return CKR_GENERAL_ERROR;
    }

    if (*data_len < result->size) {
        return CKR_BUFFER_TOO_SMALL;
    }

    *data_len = result->size;
    memcpy(data, result->buffer, result->size);

    free(result);
    free(validation);

    return CKR_OK;
}

struct tpm_encrypt_data {
    tpm_ctx *ctx;

    uint32_t handle;
    twist auth;

    bool is_rsa;

    union {
        struct {
            TPMT_RSA_DECRYPT scheme;
            TPM2B_DATA label;
        } rsa;
        struct {
            TPMI_ALG_SYM_MODE mode;
            TPM2B_IV iv;
        } sym;
    };
};

static CK_RV mech_to_sym(CK_MECHANISM_PTR mech, tpm_encrypt_data *tpm_enc_data) {

    switch(mech->mechanism) {
    case CKM_AES_CBC:
        tpm_enc_data->sym.mode = TPM2_ALG_CBC;
        break;
    case CKM_AES_ECB:
        tpm_enc_data->sym.mode = TPM2_ALG_ECB;
        break;
    case CKM_AES_CFB1:
        tpm_enc_data->sym.mode = TPM2_ALG_CFB;
        break;
    default:
        LOGE("Unsupported mechanism: 0x%x", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (mech->ulParameterLen > 0) {

        if (mech->ulParameterLen > sizeof(tpm_enc_data->sym.iv.buffer)) {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        tpm_enc_data->sym.iv.size = mech->ulParameterLen;
        memcpy(tpm_enc_data->sym.iv.buffer, mech->pParameter, mech->ulParameterLen);
    } else {
        /* initialize to 16 zeros if IV not specified */
        tpm_enc_data->sym.iv.size = sizeof(tpm_enc_data->sym.iv.buffer);
        memset(tpm_enc_data->sym.iv.buffer, 0, sizeof(tpm_enc_data->sym.iv.buffer));
    }

    return CKR_OK;
}

static CK_RV mech_to_rsa_raw(CK_MECHANISM_PTR mech, tpm_encrypt_data *encdata) {
    UNUSED(mech);

    encdata->rsa.scheme.scheme = TPM2_ALG_NULL;

    encdata->rsa.label.size = 0;

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

static CK_RV mech_to_rsa_oaep(tpm_ctx *tpm, CK_MECHANISM_PTR mech, tpm_encrypt_data *encdata) {

    encdata->rsa.scheme.scheme = TPM2_ALG_OAEP;

    if (mech->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)mech->pParameter;

    if (params->source != CKZ_DATA_SPECIFIED
            && params->pSourceData != NULL
            && params->ulSourceDataLen != 0) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /*
     * TPM is hardcoded to MGF1 + <name alg> in the TPM, make sure what is requested is supported
     */
    CK_RSA_PKCS_MGF_TYPE supported_mgf;
    CK_RV rv = get_oaep_mgf1_alg(tpm, encdata->handle, &supported_mgf);
    if (rv != CKR_OK) {
        return rv;
    }

    if (params->mgf != supported_mgf) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    encdata->rsa.scheme.details.oaep.hashAlg = mech_to_hash_alg(params->hashAlg);
    if (encdata->rsa.scheme.details.oaep.hashAlg == TPM2_ALG_ERROR) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (params->ulSourceDataLen > sizeof(encdata->rsa.label.buffer)) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    encdata->rsa.label.size = params->ulSourceDataLen;
    if (params->ulSourceDataLen) {
        if (!params->pSourceData) {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        memcpy(encdata->rsa.label.buffer, params->pSourceData, params->ulSourceDataLen);
    }

    return CKR_OK;
}

CK_RV tpm_encrypt_data_init(tpm_ctx *ctx, uint32_t handle, twist auth, CK_MECHANISM_PTR mech, tpm_encrypt_data **encdata) {

    CK_RV rv = CKR_MECHANISM_INVALID;

    tpm_encrypt_data *tpm_enc_data = calloc(1, sizeof(*tpm_enc_data));
    if (!tpm_enc_data) {
        return CKR_HOST_MEMORY;
    }

    tpm_enc_data->ctx = ctx;
    tpm_enc_data->handle = handle;
    tpm_enc_data->auth = auth;

    switch(mech->mechanism) {
        case CKM_RSA_X_509:
        case CKM_RSA_PKCS:
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            tpm_enc_data->is_rsa = true;
            rv = mech_to_rsa_raw(mech, tpm_enc_data);
            break;

        case CKM_RSA_PKCS_OAEP:
            tpm_enc_data->is_rsa = true;
            rv = mech_to_rsa_oaep(ctx, mech, tpm_enc_data);
            break;

        case CKM_AES_CBC:
        case CKM_AES_ECB:
        case CKM_AES_CFB1:
            rv = mech_to_sym(mech, tpm_enc_data);
            break;
        /* no default */
    }

    if (rv == CKR_OK) {
        *encdata = tpm_enc_data;
    } else {
        free(tpm_enc_data);
    }

    return rv;
}

void tpm_encrypt_data_free(tpm_encrypt_data *encdata) {

    free(encdata);
}

CK_RV tpm_rsa_decrypt(tpm_encrypt_data *tpm_enc_data,
        CK_BYTE_PTR ctext, CK_ULONG ctextlen,
        CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    tpm_ctx *ctx = tpm_enc_data->ctx;

    TPMT_RSA_DECRYPT *scheme = &tpm_enc_data->rsa.scheme;
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

    twist auth = tpm_enc_data->auth;
    ESYS_TR handle = tpm_enc_data->handle;
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
        LOGE("Esys_RSA_Decrypt: 0x%x", rc);
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

CK_RV tpm_rsa_encrypt(tpm_encrypt_data *tpm_enc_data,
        CK_BYTE_PTR pptext, CK_ULONG pptextlen,
        CK_BYTE_PTR cctext, CK_ULONG_PTR cctextlen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    tpm_ctx *ctx = tpm_enc_data->ctx;

    TPMT_RSA_DECRYPT *scheme = &tpm_enc_data->rsa.scheme;
    TPM2B_DATA *label = &tpm_enc_data->rsa.label;

    /*
     * Validate that plaintext data fits in a message buffer.
     * Do this first since it requires no trip to the TPM
     * to verify or memory allocation.
     */
    TPM2B_PUBLIC_KEY_RSA message = { .size = pptextlen };
    if (pptextlen > sizeof(message.buffer)) {
        return CKR_ARGUMENTS_BAD;
    }
    memcpy(message.buffer, pptext, pptextlen);

    ESYS_TR handle = tpm_enc_data->handle;

    TPM2B_PUBLIC_KEY_RSA *ctext;

    TSS2_RC rc = Esys_RSA_Encrypt(
            ctx->esys_ctx,
            handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &message,
            scheme,
            label,
            &ctext);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("Esys_RSA_Encrypt: 0x%x", rc);
        return CKR_GENERAL_ERROR;
    }

    if (!ctext) {
        *cctextlen = ctext->size;
        rv = CKR_OK;
        goto out;
    }

    if (*cctextlen < ctext->size) {
        *cctextlen = ctext->size;
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    *cctextlen = ctext->size;
    memcpy(cctext, ctext->buffer, ctext->size);

    rv = CKR_OK;

out:
    free(ctext);

    return rv;
}

static CK_RV encrypt_decrypt(tpm_ctx *ctx, uint32_t handle, twist objauth, TPMI_ALG_SYM_MODE mode, TPMI_YES_NO is_decrypt,
        TPM2B_IV *iv, CK_BYTE_PTR data_in, CK_ULONG data_in_len, CK_BYTE_PTR data_out, CK_ULONG_PTR data_out_len) {

    CK_RV rv = CKR_GENERAL_ERROR;

    bool result = set_esys_auth(ctx->esys_ctx, handle, objauth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    /*
     * Copy the data into TPM structures
     */
    TPM2B_MAX_BUFFER tpm_data_in = {
         .size = data_in_len,
    };

    if (data_in_len > sizeof(tpm_data_in.buffer)) {
        return false;
    }

    memcpy(tpm_data_in.buffer, data_in, tpm_data_in.size);

    assert(iv);

    if (!iv) {
        TPM2B_IV empty_iv_in = { .size = sizeof(empty_iv_in.buffer), .buffer = { 0 } };
        iv = &empty_iv_in;
    }

    /* setup the output structures */
    TPM2B_MAX_BUFFER *tpm_data_out = NULL;
    TPM2B_IV *tpm_iv_out = NULL;

    unsigned version = 2;

    TSS2_RC rval =
        Esys_EncryptDecrypt2(
            ctx->esys_ctx,
            handle,
            ctx->hmac_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &tpm_data_in,
            is_decrypt,
            mode,
            iv,
            &tpm_data_out,
            &tpm_iv_out);

    if (tpm2_error_get(rval) == TPM2_RC_COMMAND_CODE) {
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
            iv,
            &tpm_data_in,
            &tpm_data_out,
            &tpm_iv_out);
        flags_restore(ctx);
    }

    if(rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_EncryptDecrypt%u: 0x%x", version, rval);
        return CKR_GENERAL_ERROR;
    }

    if (!data_out) {
        *data_out_len = tpm_data_out->size;
        rv = CKR_OK;
        goto out;
    }

    if (tpm_data_out->size > *data_out_len) {
        *data_out_len = tpm_data_out->size;
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    *data_out_len = tpm_data_out->size;
    memcpy(data_out, tpm_data_out->buffer, tpm_data_out->size);

    /* swap iv's */
    memcpy(iv, tpm_iv_out, sizeof(*tpm_iv_out));

    rv = CKR_OK;

out:
    free(tpm_data_out);
    free(tpm_iv_out);

    return rv;
}

/*
 * These align with the specifications TPMI_YES_NO values as understood for encryptdecrypt routines.
 */
#define ENCRYPT 0
#define DECRYPT 1

CK_RV tpm_encrypt(tpm_encrypt_data *tpm_enc_data,
        CK_BYTE_PTR ptext, CK_ULONG ptextlen,
        CK_BYTE_PTR ctext, CK_ULONG_PTR ctextlen) {

    if (tpm_enc_data->is_rsa) {
        return tpm_rsa_encrypt(tpm_enc_data, ptext, ptextlen, ctext, ctextlen);
    }

    tpm_ctx *ctx = tpm_enc_data->ctx;
    TPMI_ALG_SYM_MODE mode = tpm_enc_data->sym.mode;
    TPM2B_IV *iv = &tpm_enc_data->sym.iv;

    twist auth = tpm_enc_data->auth;
    ESYS_TR handle = tpm_enc_data->handle;

    return encrypt_decrypt(ctx, handle, auth, mode, ENCRYPT,
            iv, ptext, ptextlen, ctext, ctextlen);
}

CK_RV tpm_decrypt(tpm_encrypt_data *tpm_enc_data,
        CK_BYTE_PTR ctext, CK_ULONG ctextlen,
        CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen) {

    if (tpm_enc_data->is_rsa) {
        return tpm_rsa_decrypt(tpm_enc_data, ctext, ctextlen, ptext, ptextlen);
    }

    tpm_ctx *ctx = tpm_enc_data->ctx;
    TPMI_ALG_SYM_MODE mode = tpm_enc_data->sym.mode;
    TPM2B_IV *iv = &tpm_enc_data->sym.iv;

    twist auth = tpm_enc_data->auth;
    ESYS_TR handle = tpm_enc_data->handle;

    return encrypt_decrypt(ctx, handle, auth, mode, DECRYPT,
            iv, ctext, ctextlen, ptext, ptextlen);
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
        LOGE("Esys_ObjectChangeAuth: 0x%x", rval);
        return CKR_GENERAL_ERROR;
    }

    uint8_t serialized[sizeof(*newprivate)];

    /* serialize the new blob private */
    size_t offset = 0;
    rval = Tss2_MU_TPM2B_PRIVATE_Marshal(newprivate, serialized, sizeof(*newprivate), &offset);
    if (rval != TSS2_RC_SUCCESS) {
        free(newprivate);
        LOGE("Tss2_MU_TPM2B_PRIVATE_Marshal: 0x%x", rval);
        return CKR_GENERAL_ERROR;
    }

    *newblob = twistbin_new(serialized, offset);
    free(newprivate);

    return *newblob ? CKR_OK : CKR_HOST_MEMORY;
}
/*
 * Esys_CreateLoaded(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_TEMPLATE *inPublic,
    ESYS_TR *objectHandle,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic);
 */

CK_RV tpm2_create_seal_obj(tpm_ctx *ctx, twist parentauth, uint32_t parent_handle, twist objauth, twist oldpubblob, twist sealdata, twist *newpubblob, twist *newprivblob, uint32_t *handle) {

    CK_RV rv = CKR_GENERAL_ERROR;

    /*
     * clone the public portion from the existing object by unmarshaling (aka unserializing) it from the
     * pub blob and converting it to a TPM2B_TEMPLATE
     */
    TPM2B_PUBLIC pub = { .size = 0 };
    size_t len = twist_len(oldpubblob);

    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal((uint8_t *)oldpubblob, len, &offset, &pub);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPM2B_PUBLIC_Unmarshal: 0x%x", rc);
        return CKR_GENERAL_ERROR;
    }

    offset = 0;
    TPM2B_TEMPLATE template = { .size = 0 };
    rc = Tss2_MU_TPMT_PUBLIC_Marshal(&pub.publicArea, &template.buffer[0],
                                    sizeof(TPMT_PUBLIC), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPMT_PUBLIC_Marshal: 0x%x:", rc);
        return CKR_GENERAL_ERROR;
    }

    template.size = offset;

    /*
     * Set the seal data and auth value in the sensitive portion
     */
    TPM2B_SENSITIVE_CREATE sensitive = { .size = 0 };

    len = twist_len(sealdata);
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
    bool res = set_esys_auth(ctx->esys_ctx, parent_handle, parentauth);
    if (!res) {
        return CKR_GENERAL_ERROR;
    }

    TPM2B_PRIVATE *newpriv = NULL;
    TPM2B_PUBLIC *newpub = NULL;
    rc = Esys_CreateLoaded(
            ctx->esys_ctx,
            parent_handle,
            ctx->hmac_session, ESYS_TR_NONE, ESYS_TR_NONE,
            &sensitive,
            &template,
            handle,
            &newpriv,
            &newpub
    );
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_CreateLoaded: 0x%x:", rc);
        return CKR_GENERAL_ERROR;
    }

    uint8_t serialized[sizeof(*newpriv) > sizeof(*newpub) ? sizeof(*newpriv) : sizeof(*newpub)];

    /* serialize the new blob private */
    offset = 0;
    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(newpriv, serialized, sizeof(*newpriv), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Tss2_MU_TPM2B_PRIVATE_Marshal: 0x%x", rc);
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
        LOGE("Tss2_MU_TPM2B_PUBLIC_Marshal: 0x%x", rc);
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
    free(newpriv);
    free(newpub);

    return rv;
}
