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

void tpm_ctx_free(tpm_ctx *ctx) {

    if (!ctx) {
        return;
    }

    Esys_Finalize(&ctx->esys_ctx);
    Tss2_Tcti_Finalize(ctx->tcti_ctx);
    free(ctx->tcti_ctx);
    free(ctx);
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

#define xstr(s) str(s)
#define str(s) #s

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

bool tpm_loadobj(
        tpm_ctx *ctx,
        uint32_t phandle, twist auth,
        twist pub_path, twist priv_path,
        uint32_t *handle) {

    TPM2B_PRIVATE priv = { .size = 0 };
    bool res = files_load_private(priv_path, &priv);
    if (!res) {
        return false;
    }

    TPM2B_PUBLIC pub = { .size = 0 };
    res = files_load_public(pub_path, &pub);
    if (!res) {
        return false;
    }

    bool tmp_rc = set_esys_auth(ctx->esys_ctx, phandle, auth);
    if (!tmp_rc) {
        return false;
    }

    TSS2_RC rval = Esys_Load(
               ctx->esys_ctx,
               phandle,
               ESYS_TR_PASSWORD,
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

    TSS2_RC rval = Esys_Unseal(
            ctx->esys_ctx,
            handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &unsealed_data);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Tss2_Sys_Unseal: 0x%X", rval);
        return NULL;
    }

    t = twistbin_new(unsealed_data->buffer, unsealed_data->size);

    free(unsealed_data);

    return t;
}

bool flatten_rsassa(TPMS_SIGNATURE_RSASSA *rsassa, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    if (*siglen <  sizeof(rsassa->sig.size)) {
        return false;
    }

    *siglen = rsassa->sig.size;
    memcpy(sig, rsassa->sig.buffer, *siglen);

    return true;
}

bool flatten_ecdsa(TPMS_SIGNATURE_ECDSA *ecdsa, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

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

    if (size_s + size_r + SEQ_HDR_SIZE > *siglen) {
        return false;
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

out:
    if (asn1_r) {
        ASN1_INTEGER_free(asn1_r);
    }

    if (asn1_s) {
        ASN1_INTEGER_free(asn1_s);
    }

    free(buf_r);
    free(buf_s);

    return true;
}

bool sig_flatten(TPMT_SIGNATURE *signature, TPMT_SIG_SCHEME *scheme, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    switch(scheme->scheme) {
    case TPM2_ALG_RSASSA:
        return flatten_rsassa(&signature->signature.rsassa, sig, siglen);
    case TPM2_ALG_ECDSA:
        return flatten_ecdsa(&signature->signature.ecdsa, sig, siglen);
        /* no default */
    }

    return false;
}

bool tpm_sign(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    twist auth = tobj->unsealed_auth;
    TPMI_DH_OBJECT handle = tobj->handle;

    bool result = set_esys_auth(ctx->esys_ctx, handle, auth);
    if (!result) {
        return false;
    }

    TPMT_SIG_SCHEME in_scheme;
    result = get_signature_scheme(mech, &in_scheme);
    if (!result) {
        return false;
    }

    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = TPM2B_EMPTY_INIT
    };

    TPM2B_DIGEST tdigest;
    if (sizeof(tdigest.buffer) < datalen) {
        return false;
    }

    memcpy(tdigest.buffer, data, datalen);
    tdigest.size = datalen;

    TPMT_SIGNATURE *signature = NULL;
    TSS2_RC rval = Esys_Sign(
            ctx->esys_ctx,
            handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &tdigest,
            &in_scheme,
            &validation,
            &signature);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_Sign: 0x%0x", rval);
        return false;
    }

    result = sig_flatten(signature, &in_scheme, sig, siglen);
    if (!result) {
        goto out;
    }

out:
    free(signature);

    return result;
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

    return CKR_OK;
}

CK_RV tpm_hash_update(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG data_len) {

    size_t offset = 0;
    while(offset < data_len) {

        TPM2B_MAX_BUFFER buffer;

        size_t send = data_len > sizeof(buffer.buffer) ? sizeof(buffer.buffer) : data_len;

        buffer.size = send;
        memcpy(buffer.buffer, &data[offset], send);

        TSS2_RC rval = Esys_SequenceUpdate(
                    ctx->esys_ctx,
                    sequence_handle,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &buffer);
        if (rval != TPM2_RC_SUCCESS) {
            LOGE("Esys_SequenceUpdate: 0x%x", rval);
            return CKR_GENERAL_ERROR;
        }

        offset += send;
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
            ESYS_TR_PASSWORD,
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

TPM2_ALG_ID mech_to_rsa_dec_alg(CK_MECHANISM_TYPE mech) {

    switch(mech) {
    case CKM_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
        /* RSA Decrypt expects padded data */
        return TPM2_ALG_NULL;
    default:
        LOGE("Unsupported RSA cipher mechanism, got: %lu", mech);
        return TPM2_ALG_ERROR;
    }
}

CK_RV tpm_rsa_decrypt(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech,
        CK_BYTE_PTR ctext, CK_ULONG ctextlen,
        CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen) {

    TPM2_ALG_ID alg = mech_to_rsa_dec_alg(mech);
    if (alg == TPM2_ALG_ERROR) {
        return CKR_ARGUMENTS_BAD;
    }

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

    twist auth = tobj->unsealed_auth;
    ESYS_TR handle = tobj->handle;
    bool result = set_esys_auth(ctx->esys_ctx, handle, auth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    TPMT_RSA_DECRYPT scheme  = { .scheme = alg };

    TPM2B_DATA label = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC_KEY_RSA *tpm_ptext;

    TSS2_RC rval = Esys_RSA_Decrypt(
            ctx->esys_ctx,
            handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &tpm_ctext,
            &scheme,
            &label,
            &tpm_ptext);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_RSA_Decrypt: 0x%x", rval);
        return CKR_GENERAL_ERROR;
    }

    if (*ptextlen < tpm_ctext.size) {
        return CKR_BUFFER_TOO_SMALL;
    }

    *ptextlen = tpm_ptext->size;
    memcpy(ptext, tpm_ptext->buffer, tpm_ptext->size);

    free(tpm_ptext);

    return CKR_OK;
}

static CK_RV encrypt_decrypt(tpm_ctx *ctx, uint32_t handle, twist objauth, CK_MECHANISM_TYPE mode, TPMI_YES_NO is_decrypt,
        twist iv_in, twist data_in, twist *data_out, twist *iv_out) {

    TPMI_ALG_SYM_MODE tpm_mode;
    switch(mode) {
    case CKM_AES_CBC:
        tpm_mode = TPM2_ALG_CBC;
        break;
    case CKM_AES_ECB:
        tpm_mode = TPM2_ALG_ECB;
        break;
    case CKM_AES_NULL:
        tpm_mode = TPM2_ALG_NULL;
        break;
    default:
        LOGE("Unsupported mode, got: %lu", mode);
        return CKR_ARGUMENTS_BAD;
    }

    bool result = set_esys_auth(ctx->esys_ctx, handle, objauth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    /*
     * Copy the data into TPM structures
     */
    TPM2B_MAX_BUFFER tpm_data_in = {
         .size = twist_len(data_in),
    };

    if (tpm_data_in.size > sizeof(tpm_data_in.buffer)) {
        return false;
    }

    memcpy(tpm_data_in.buffer, data_in, tpm_data_in.size);

    TPM2B_IV tpm_iv_in = {
        .size = iv_in ? twist_len(iv_in) : sizeof(tpm_iv_in.buffer),
    };

    if (iv_in) {
        if (tpm_iv_in.size > sizeof(tpm_iv_in.buffer)) {
            return false;
        }
        memcpy(tpm_iv_in.buffer, iv_in, tpm_iv_in.size);
    } else {
        memset(tpm_iv_in.buffer, 0, sizeof(tpm_iv_in.buffer));
    }

    /* setup the output structures */
    TPM2B_MAX_BUFFER *tpm_data_out = NULL;
    TPM2B_IV *tpm_iv_out = NULL;

    unsigned version = 2;

    TSS2_RC rval =
        Esys_EncryptDecrypt2(
            ctx->esys_ctx,
            handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &tpm_data_in,
            is_decrypt,
            tpm_mode,
            &tpm_iv_in,
            &tpm_data_out,
            &tpm_iv_out);

    if (tpm2_error_get(rval) == TPM2_RC_COMMAND_CODE) {
        version = 1;
        rval = Esys_EncryptDecrypt(
            ctx->esys_ctx,
            handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            is_decrypt,
            tpm_mode,
            &tpm_iv_in,
            &tpm_data_in,
            &tpm_data_out,
            &tpm_iv_out);
    }

    if(rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_EncryptDecrypt%u: 0x%x", version, rval);
        return CKR_GENERAL_ERROR;
    }

    /* copy output data from tpm into twist types */
    if (iv_out) {
        *iv_out = twistbin_new(tpm_iv_out->buffer, tpm_iv_out->size);
        if (!*iv_out) {
            return CKR_HOST_MEMORY;
        }
    }

    *data_out = twistbin_new(tpm_data_out->buffer, tpm_data_out->size);
    if (!*data_out) {
        if (iv_out) {
            twist_free(*iv_out);
        }
        return CKR_HOST_MEMORY;
    }

    free(tpm_data_out);
    free(tpm_iv_out);

    return CKR_OK;
}

/*
 * These align with the specifications TPMI_YES_NO values as understood for encryptdecrypt routines.
 */
#define ENCRYPT 0
#define DECRYPT 1

CK_RV tpm_encrypt(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mode, twist iv, twist plaintext, twist *ciphertext, twist *iv_out) {

    return encrypt_decrypt(ctx, tobj->handle, tobj->unsealed_auth, mode, ENCRYPT,
            iv, plaintext, ciphertext, iv_out);
}

CK_RV tpm_decrypt_handle(tpm_ctx *ctx, uint32_t handle, twist objauth, CK_MECHANISM_TYPE mode, twist iv, twist ciphertext, twist *plaintext, twist *iv_out) {

    return encrypt_decrypt(ctx, handle, objauth, mode, DECRYPT,
            iv, ciphertext, plaintext, iv_out);
}

CK_RV tpm_decrypt(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mode, twist iv, twist ciphertext, twist *plaintext, twist *iv_out) {

    return encrypt_decrypt(ctx, tobj->handle, tobj->unsealed_auth, mode, DECRYPT,
            iv, ciphertext, plaintext, iv_out);
}
