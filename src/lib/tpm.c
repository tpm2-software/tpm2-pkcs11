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

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <openssl/sha.h>

#include "pkcs11.h"
#include "log.h"
#include "mutex.h"
#include "tcti_ldr.h"
#include "tpm.h"

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

static inline ESYS_CONTEXT *from_ctx(tpm_ctx *ctx) {
    return (ESYS_CONTEXT *)ctx;
}

static inline tpm_ctx *to_ctx(ESYS_CONTEXT *sys) {
    return (tpm_ctx *)sys;
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

static void tcti_teardown (TSS2_TCTI_CONTEXT *tcti_context) {

    Tss2_Tcti_Finalize(tcti_context);
    free(tcti_context);
}

static void esys_teardown (ESYS_CONTEXT *esys_ctx) {

    Esys_Finalize(&esys_ctx);
}

static struct {
    unsigned long tcti_cnt;
    void *tcti_mutex;
    TSS2_TCTI_CONTEXT *tcti;
    TPM2_HANDLE phandle;
} global;

static void lock_tcti(void) {
    mutex_lock_fatal(global.tcti_mutex);
}

static void unlock_tcti(void) {
    mutex_unlock_fatal(global.tcti_mutex);
}

CK_RV tpm_init(void) {

    return mutex_create(&global.tcti_mutex);
}

void tpm_destroy(void) {

    mutex_destroy(global.tcti_mutex);
    global.tcti_mutex = NULL;
}

static void tpm_tcti_free_unlocked(void) {

    assert(global.tcti_cnt);

    global.tcti_cnt--;
    if (!global.tcti_cnt) {
        tcti_teardown (global.tcti);
        global.tcti = NULL;
    }
}

static bool tpm_ctx_new_unlocked(void) {

    if (!global.tcti) {
        global.tcti = tcti_ldr_load();
    }

    global.tcti_cnt++;

    return global.tcti ? true : false;
}

void tpm_ctx_free(tpm_ctx *ctx) {

    esys_teardown (from_ctx(ctx));
    tpm_tcti_free_unlocked();
}

tpm_ctx *tpm_ctx_new(void) {

    ESYS_CONTEXT *sys = NULL;

    lock_tcti();
    bool res = tpm_ctx_new_unlocked();
    if (!res) {
        goto unlock;
    }

    sys = esys_ctx_init(global.tcti);
    if (!sys) {
        tpm_tcti_free_unlocked();
        goto unlock;
    }

unlock:
    unlock_tcti();
    return to_ctx(sys);
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

    lock_tcti();

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    /*
     * This will get re-used once allocated by esys
     */
    TPM2B_DIGEST *rand_bytes = NULL;

    while (size) {

        UINT16 requested_size = size > sizeof(rand_bytes->buffer) ?
                sizeof(rand_bytes->buffer) : size;

        TSS2_RC rval = Esys_GetRandom(
            esys_ctx,
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
    unlock_tcti();

    return result;
}

CK_RV tpm_stirrandom(tpm_ctx *ctx, unsigned char *seed, unsigned long seed_len) {

    TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;;

    lock_tcti();

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    size_t offset = 0;
    while(offset < seed_len) {
        TPM2B_SENSITIVE_DATA stir;

        size_t left = seed_len - offset;
        size_t chunk = left > sizeof(stir.buffer) ? sizeof(stir.buffer) : left;

        stir.size = chunk;
        memcpy(stir.buffer, &seed[offset], chunk);

        rc = Esys_StirRandom(
            esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &stir);
        if (rc != TSS2_RC_SUCCESS) {
            LOGE("Esys_StirRandom: 0x%x:", rc);
            goto out;
        }

        offset += seed_len;
    }

out:
    unlock_tcti();
    return rc == TSS2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

bool tpm_register_handle(tpm_ctx *ctx, uint32_t *handle) {

    ESYS_TR object;

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    TSS2_RC rval =
        Esys_TR_FromTPMPublic(
            esys_ctx,
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

    bool rc = false;

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

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    bool tmp_rc = set_esys_auth(esys_ctx, phandle, auth);
    if (!tmp_rc) {
        return false;
    }

    lock_tcti();

    TSS2_RC rval = Esys_Load(
               esys_ctx,
               phandle,
               ESYS_TR_PASSWORD,
               ESYS_TR_NONE,
               ESYS_TR_NONE,
               &priv,
               &pub,
               handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_Load: 0x%x:", rval);
        goto out;
    }

    rc = true;

out:
    unlock_tcti();
    return rc;
}

bool tpm_flushcontext(tpm_ctx *ctx, uint32_t handle) {

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    lock_tcti();

    TSS2_RC rval = Esys_FlushContext(
                esys_ctx,
                handle);
    unlock_tcti();
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
        return CKR_MECHANISM_INVALID;
    }

    scheme->scheme = sig_scheme;
    scheme->details.rsassa.hashAlg = halg;

    return true;
}

twist tpm_unseal(tpm_ctx *ctx, uint32_t handle, twist objauth) {

    twist t = NULL;

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    bool result = set_esys_auth(esys_ctx, handle, objauth);
    if (!result) {
        return false;
    }

    TPM2B_SENSITIVE_DATA *unsealed_data = NULL;

    lock_tcti();

    TSS2_RC rval = Esys_Unseal(
            esys_ctx,
            handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &unsealed_data);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Tss2_Sys_Unseal: 0x%X", rval);
        goto out;
    }

    t = twistbin_new(unsealed_data->buffer, unsealed_data->size);
out:
    unlock_tcti();
    free(unsealed_data);

    return t;
}

bool tpm_sign(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    bool rv = false;

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    twist auth = tobj->unsealed_auth;
    TPMI_DH_OBJECT handle = tobj->handle;

    bool result = set_esys_auth(esys_ctx, handle, auth);
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
            esys_ctx,
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

    if (*siglen <  sizeof(signature->signature.rsassa.sig.size)) {
        goto out;
    }

    assert(signature->sigAlg == TPM2_ALG_RSASSA);

    *siglen = signature->signature.rsassa.sig.size;
    memcpy(sig, signature->signature.rsassa.sig.buffer, *siglen);

    rv = true;

out:
    unlock_tcti();
    free(signature);

    return rv;
}

bool tpm_verify(tpm_ctx *ctx, tobject *tobj, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG siglen) {

    bool rc = false;

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    twist auth = tobj->unsealed_auth;
    TPMI_DH_OBJECT handle = tobj->handle;

    bool tmp_rc = set_esys_auth(esys_ctx, handle, auth);
    if (tmp_rc) {
        return false;
    }

    // Copy the data into the digest block
    TPM2B_DIGEST msgdigest;
    if (sizeof(msgdigest.buffer) < datalen) {
        return false;
    }
    memcpy(msgdigest.buffer, data, datalen);
    msgdigest.size = datalen;

    // Copy the signature into the signature block
    // For now we have sign hardcoded to RSASSA + SHA256, so just replicate that here.
    TPMT_SIGNATURE signature;

    assert(siglen < sizeof(signature.signature.rsassa.sig.buffer));

    signature.sigAlg = TPM2_ALG_RSASSA;
    signature.signature.rsassa.hash = TPM2_ALG_SHA256;
    signature.signature.rsassa.sig.size = siglen;
    memcpy(signature.signature.rsassa.sig.buffer, sig, siglen);

    TPMT_TK_VERIFIED *validation = NULL;

    lock_tcti();

    TSS2_RC rval = Esys_VerifySignature(
            esys_ctx,
            handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &msgdigest,
            &signature,
            &validation);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_VerifySignature: 0x%x", rval);
        goto out;
    }

    rc = true;

out:
    unlock_tcti();
    free(validation);
    return rc;
}

CK_RV tpm_hash_init(tpm_ctx *ctx, CK_MECHANISM_TYPE mode, uint32_t *sequence_handle) {

    CK_RV rv = CKR_GENERAL_ERROR;

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    TPM2B_AUTH null_auth = TPM2B_EMPTY_INIT;

    TPMI_ALG_HASH halg = mech_to_hash_alg(mode);
    if (halg == TPM2_ALG_ERROR) {
        return CKR_MECHANISM_INVALID;
    }

    if (halg == TPM2_ALG_NULL) {
        return CKR_OK;
    }

    lock_tcti();

    TSS2_RC rval = Esys_HashSequenceStart(
            esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &null_auth,
            halg,
            sequence_handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_HashSequenceStart: 0x%x", rval);
        goto out;
    }

    rv = CKR_OK;

out:
    unlock_tcti();
    return rv;
}

CK_RV tpm_hash_update(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG data_len) {

    CK_RV rc = CKR_GENERAL_ERROR;

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    lock_tcti();

    size_t offset = 0;
    while(offset < data_len) {

        TPM2B_MAX_BUFFER buffer;

        size_t send = data_len > sizeof(buffer.buffer) ? sizeof(buffer.buffer) : data_len;

        buffer.size = send;
        memcpy(buffer.buffer, &data[offset], send);

        TSS2_RC rval = Esys_SequenceUpdate(
                    esys_ctx,
                    sequence_handle,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &buffer);
        if (rval != TPM2_RC_SUCCESS) {
            LOGE("Esys_SequenceUpdate: 0x%x", rval);
            goto out;
        }

        offset += send;
    }

    rc = CKR_OK;

out:
    unlock_tcti();
    return rc;
}

CK_RV tpm_hash_final(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {

    CK_RV rc = CKR_GENERAL_ERROR;

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    TPM2B_MAX_BUFFER no_data = { .size = 0 };

    TPMT_TK_HASHCHECK *validation = NULL;
    TPM2B_DIGEST *result = NULL;

    lock_tcti();

    TSS2_RC rval = Esys_SequenceComplete(
            esys_ctx,
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
        goto out;
    }

    if (*data_len < result->size) {
        rc = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    *data_len = result->size;
    memcpy(data, result->buffer, result->size);

    rc = CKR_OK;

out:
    unlock_tcti();
    free(result);
    free(validation);

    return rc;
}

TPM2_ALG_ID mech_to_rsa_dec_alg(CK_MECHANISM_TYPE mech) {

    switch(mech) {
    case CKM_RSA_PKCS:
        /* RSA Decrypt expects padded data */
        return TPM2_ALG_NULL;
    default:
        LOGE("Unsupported RSA cipher mechansim, got: %lu", mech);
        return TPM2_ALG_ERROR;
    }
}

CK_RV tpm_rsa_decrypt(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech,
        CK_BYTE_PTR ctext, CK_ULONG ctextlen,
        CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen) {

    CK_RV rc = CKR_GENERAL_ERROR;

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

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);

    twist auth = tobj->unsealed_auth;
    ESYS_TR handle = tobj->handle;
    bool result = set_esys_auth(esys_ctx, handle, auth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    TPMT_RSA_DECRYPT scheme  = { .scheme = alg };


    TPM2B_DATA label = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC_KEY_RSA *tpm_ptext;

    lock_tcti();

    TSS2_RC rval = Esys_RSA_Decrypt(
            esys_ctx,
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
        goto out;
    }

    if (*ptextlen < tpm_ctext.size) {
        rc = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    *ptextlen = tpm_ptext->size;
    memcpy(ptext, tpm_ptext->buffer, tpm_ptext->size);

    rc = CKR_OK;

out:
    unlock_tcti();
    free(tpm_ptext);

    return rc;
}

static CK_RV encrypt_decrypt(tpm_ctx *ctx, uint32_t handle, twist objauth, CK_MECHANISM_TYPE mode, TPMI_YES_NO is_decrypt,
        twist iv_in, twist data_in, twist *data_out, twist *iv_out) {

    CK_RV rc = CKR_GENERAL_ERROR;

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

    ESYS_CONTEXT *esys_ctx = from_ctx(ctx);
    bool result = set_esys_auth(esys_ctx, handle, objauth);
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

    lock_tcti();

    unsigned version = 2;

    TSS2_RC rval =
        Esys_EncryptDecrypt2(
            esys_ctx,
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
            esys_ctx,
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
        goto out;
    }

    /* copy output data from tpm into twist types */
    if (iv_out) {
        *iv_out = twistbin_new(tpm_iv_out->buffer, tpm_iv_out->size);
        if (!*iv_out) {
            goto out;
        }
    }

    *data_out = twistbin_new(tpm_data_out->buffer, tpm_data_out->size);
    if (!*data_out) {
        if (iv_out) {
            twist_free(*iv_out);
        }
        goto out;
    }

    rc = CKR_OK;

out:
    unlock_tcti();
    free(tpm_data_out);
    free(tpm_iv_out);

    return rc;
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
