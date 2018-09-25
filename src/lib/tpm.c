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
#include <tss2/tss2_sys.h>
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

static inline TSS2_SYS_CONTEXT *from_ctx(tpm_ctx *ctx) {
    return (TSS2_SYS_CONTEXT *)ctx;
}

static inline tpm_ctx *to_ctx(TSS2_SYS_CONTEXT *sys) {
    return (tpm_ctx *)sys;
}


#define SUPPORTED_ABI_VERSION \
{ \
    .tssCreator = 1, \
    .tssFamily = 2, \
    .tssLevel = 1, \
    .tssVersion = 108, \
}

static TSS2_SYS_CONTEXT* sapi_ctx_init(TSS2_TCTI_CONTEXT *tcti_ctx) {

    TSS2_ABI_VERSION abi_version = SUPPORTED_ABI_VERSION;

    size_t size = Tss2_Sys_GetContextSize(0);
    TSS2_SYS_CONTEXT *sapi_ctx = (TSS2_SYS_CONTEXT*) calloc(1, size);
    if (sapi_ctx == NULL) {
        LOGE("Failed to allocate 0x%zx bytes for the SAPI context\n",
                size);
        return NULL;
    }

    TSS2_RC rval = Tss2_Sys_Initialize(sapi_ctx, size, tcti_ctx, &abi_version);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Tss2_Sys_Initialize: 0x%x", rval);
        free(sapi_ctx);
        return NULL;
    }

    return sapi_ctx;
}

static void tcti_teardown (TSS2_TCTI_CONTEXT *tcti_context) {

    Tss2_Tcti_Finalize (tcti_context);
    free (tcti_context);
}

static void sapi_teardown (TSS2_SYS_CONTEXT *sapi_context) {

    Tss2_Sys_Finalize (sapi_context);
    free (sapi_context);
}

static struct {
    unsigned long tcti_cnt;
    void *tcti_mutex;
    TSS2_TCTI_CONTEXT *tcti;
    TPM2_HANDLE phandle;
} global;

static void lock_tcti(void) {
    mutex_lock_fatal(&global.tcti_mutex);
}

static void unlock_tcti(void) {
    mutex_unlock_fatal(&global.tcti_mutex);
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

    sapi_teardown (from_ctx(ctx));
    tpm_tcti_free_unlocked();
}

tpm_ctx *tpm_ctx_new(void) {

    TSS2_SYS_CONTEXT *sys = NULL;

    lock_tcti();
    bool res = tpm_ctx_new_unlocked();
    if (!res) {
        goto unlock;
    }

    sys = sapi_ctx_init(global.tcti);
    if (!sys) {
        tpm_tcti_free_unlocked();
        goto unlock;
    }

unlock:
    unlock_tcti();
    return to_ctx(sys);
}

bool tpm_getrandom(tpm_ctx *ctx, BYTE *data, size_t size) {

    size_t offset = 0;

    bool result = false;

    lock_tcti();

    while (size) {
        TPM2B_DIGEST rand_bytes = {
            .size = sizeof(((TPM2B_DIGEST *)NULL)->buffer)
        };

        TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_GetRandom(from_ctx(ctx), NULL, size,
                &rand_bytes, NULL));
        if (rval != TSS2_RC_SUCCESS) {
            goto out;
        }

        memcpy(&data[offset], rand_bytes.buffer, rand_bytes.size);

        offset += rand_bytes.size;
        size -= rand_bytes.size;
    }

    result = true;

out:
    unlock_tcti();

    return result;
}

CK_RV tpm_stirrandom(tpm_ctx *ctx, unsigned char *seed, unsigned long seed_len) {

    TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;;

    lock_tcti();

    size_t offset = 0;
    while(offset < seed_len) {
        TPM2B_SENSITIVE_DATA stir;

        size_t left = seed_len - offset;
        size_t chunk = left > sizeof(stir.buffer) ? sizeof(stir.buffer) : left;

        stir.size = chunk;
        memcpy(stir.buffer, &seed[offset], chunk);

        rc = Tss2_Sys_StirRandom(from_ctx(ctx), NULL, &stir, NULL);
        if (rc != TSS2_RC_SUCCESS) {
            goto out;
        }
        offset += seed_len;
    }

out:
    unlock_tcti();
    return rc == TSS2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
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

bool tpm_loadobj(
        tpm_ctx *ctx,
        uint32_t phandle, twist auth,
        twist pub_path, twist priv_path,
        uint32_t *handle) {

    TSS2L_SYS_AUTH_COMMAND sessionsData = { 0 };
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    if (twist_len(auth) > sizeof(sessionsData.auths[0].hmac.buffer)) {
        return false;
    }

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

    sessionsData.count = 1;
    memcpy(sessionsData.auths[0].hmac.buffer, auth, twist_len(auth));
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].hmac.size = twist_len(auth);

    TPM2B_NAME name = { .size = sizeof(name.name) };

    TSS2_SYS_CONTEXT *sysctx = from_ctx(ctx);
    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Load(sysctx,
                         phandle,
                         &sessionsData,
                         &priv,
                         &pub,
                         handle,
                         &name,
                         &sessionsDataOut));
    if(rval != TPM2_RC_SUCCESS) {
        LOGE("Load Object Failed ! ErrorCode: 0x%0x\n",rval);
        return false;
    }

    return true;
}

bool tpm_flushcontext(tpm_ctx *ctx, uint32_t handle) {

    TSS2_SYS_CONTEXT *sysctx = from_ctx(ctx);
    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sysctx, handle));
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Tss2_Sys_FlushContext: 0x%x", rval);
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

    TSS2_SYS_CONTEXT *sysctx = from_ctx(ctx);

    TSS2L_SYS_AUTH_COMMAND sessionsData = { 0 };
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    if (twist_len(objauth) > sizeof(sessionsData.auths[0].hmac.buffer)) {
        return false;
    }

    sessionsData.count = 1;
    memcpy(sessionsData.auths[0].hmac.buffer, objauth, twist_len(objauth));
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].hmac.size = twist_len(objauth);

    TPM2B_SENSITIVE_DATA unsealed_data = { .size = sizeof(unsealed_data.buffer) };

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Unseal(sysctx, handle,
            &sessionsData, &unsealed_data, &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Tss2_Sys_Unseal: 0x%X", rval);
        return NULL;
    }

    return twistbin_new(unsealed_data.buffer, unsealed_data.size);
}

bool tpm_sign(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    TSS2_SYS_CONTEXT *sysctx = from_ctx(ctx);

    TSS2L_SYS_AUTH_COMMAND sessionsData = { 0 };
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    twist auth = tobj->unsealed_auth;
    TPMI_DH_OBJECT handle = tobj->handle;

    if (twist_len(auth) > sizeof(sessionsData.auths[0].hmac.buffer)) {
        return false;
    }

    TPMT_SIG_SCHEME in_scheme;
    bool result = get_signature_scheme(mech, &in_scheme);
    if (!result) {
        return false;
    }

    TPMT_TK_HASHCHECK validation;
    validation.tag = TPM2_ST_HASHCHECK;
    validation.hierarchy = TPM2_RH_NULL;
    memset(&validation.digest, 0, sizeof(validation.digest));

    sessionsData.count = 1;
    memcpy(sessionsData.auths[0].hmac.buffer, auth, twist_len(auth));
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].hmac.size = twist_len(auth);

    TPM2B_DIGEST tdigest;
    if (sizeof(tdigest.buffer) < datalen) {
        return false;
    }

    memcpy(tdigest.buffer, data, datalen);
    tdigest.size = datalen;

    LOGV("CALLING SIGN -- START CARING");

    TPMT_SIGNATURE signature;
    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Sign(sysctx, handle,
            &sessionsData, &tdigest, &in_scheme, &validation, &signature,
            &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Sign Failed! ErrorCode: 0x%0x\n",rval);
        return false;
    }

    if (*siglen <  sizeof(signature.signature.rsassa.sig.size)) {
        return false;
    }

    assert(signature.sigAlg == TPM2_ALG_RSASSA);

    *siglen = signature.signature.rsassa.sig.size;
    memcpy(sig, signature.signature.rsassa.sig.buffer, *siglen);

    return true;
}

bool tpm_verify(tpm_ctx *ctx, tobject *tobj, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG siglen) {

    TSS2_SYS_CONTEXT *sysctx = from_ctx(ctx);

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

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

    TPMT_TK_VERIFIED validation;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_VerifySignature(sysctx, tobj->handle, NULL,
            &msgdigest, &signature, &validation, &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Tss2_Sys_VerifySignature: 0x%x", rval);
        return false;
    }

    return true;
}

CK_RV tpm_hash_init(tpm_ctx *ctx, CK_MECHANISM_TYPE mode, uint32_t *sequence_handle) {

    TSS2_SYS_CONTEXT *sysctx = from_ctx(ctx);

    TPM2B_AUTH nullAuth = TPM2B_EMPTY_INIT;

    TPMI_ALG_HASH halg = mech_to_hash_alg(mode);
    if (halg == TPM2_ALG_ERROR) {
        return CKR_MECHANISM_INVALID;
    }

    if (halg == TPM2_ALG_NULL) {
        return CKR_OK;
    }

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_HashSequenceStart(sysctx, NULL, &nullAuth,
            halg, sequence_handle, NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Tss2_Sys_HashSequenceStart: 0x%x", rval);
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV tpm_hash_update(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG data_len) {

    TSS2L_SYS_AUTH_COMMAND cmdAuthArray = {
        .count = 1,
        .auths = {{
            .sessionHandle = TPM2_RS_PW,
            .nonce = TPM2B_EMPTY_INIT,
            .hmac = TPM2B_EMPTY_INIT,
            .sessionAttributes = 0,
        }},
    };

    TSS2_SYS_CONTEXT *sysctx = from_ctx(ctx);

    TPM2B_MAX_BUFFER buffer;

    size_t offset = 0;
    while(offset < data_len) {

        size_t send = data_len > sizeof(buffer.buffer) ? sizeof(buffer.buffer) : data_len;

        buffer.size = send;
        memcpy(buffer.buffer, &data[offset], send);

        TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sysctx, sequence_handle,
                &cmdAuthArray, &buffer, NULL));
        if (rval != TPM2_RC_SUCCESS) {
            LOGE("Tss2_Sys_SequenceUpdate: 0x%x", rval);
            return CKR_GENERAL_ERROR;
        }

        offset += send;
    }

    return CKR_OK;
}

CK_RV tpm_hash_final(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {

    TSS2L_SYS_AUTH_COMMAND cmdAuthArray = {
        .count = 1,
        .auths = {{
            .sessionHandle = TPM2_RS_PW,
            .nonce = TPM2B_EMPTY_INIT,
            .hmac = TPM2B_EMPTY_INIT,
            .sessionAttributes = 0,
        }},
    };

    TSS2_SYS_CONTEXT *sysctx = from_ctx(ctx);

    TPM2B_MAX_BUFFER no_data = { .size = 0 };

    TPMT_TK_HASHCHECK validation;
    TPM2B_DIGEST result = { .size = sizeof(result.buffer) };

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_SequenceComplete(sysctx, sequence_handle,
            &cmdAuthArray, &no_data, TPM2_RH_OWNER, &result, &validation,
            NULL));
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Tss2_Sys_SequenceComplete: 0x%x", rval);
        return CKR_GENERAL_ERROR;
    }

    if (*data_len < result.size) {
        return CKR_BUFFER_TOO_SMALL;
    }

    *data_len = result.size;
    memcpy(data, result.buffer, result.size);

    return CKR_OK;
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

    TPM2_ALG_ID alg = mech_to_rsa_dec_alg(mech);
    if (alg == TPM2_ALG_ERROR) {
        return false;
    }

    /*
     * Validate that the data to perform the operation on, typically
     * ciphertext on RSA decrypt, fits in the buffer for the TPM and
     * populate it.
     */
    TPM2B_PUBLIC_KEY_RSA c = { .size = ctextlen };
    if (ctextlen > sizeof(c.buffer)) {
        return CKR_GENERAL_ERROR;
    }
    memcpy(c.buffer, ctext, ctextlen);

    TPMT_RSA_DECRYPT scheme  = { .scheme = alg };

    TSS2L_SYS_AUTH_COMMAND sessionsData = { 0 };

    if (twist_len(tobj->unsealed_auth) > sizeof(sessionsData.auths[0].hmac.buffer)) {
        return CKR_GENERAL_ERROR;
    }

    sessionsData.count = 1;
    memcpy(sessionsData.auths[0].hmac.buffer, tobj->unsealed_auth, twist_len(tobj->unsealed_auth));
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].hmac.size = twist_len(tobj->unsealed_auth);

    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    TPM2B_DATA label = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC_KEY_RSA m = { .size = sizeof(m.buffer) };

    TSS2_SYS_CONTEXT *sysctx = from_ctx(ctx);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_RSA_Decrypt(sysctx, tobj->handle,
            &sessionsData, &c, &scheme, &label, &m,
            &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Tss2_Sys_RSA_Decrypt: 0x%x", rval);
        return CKR_GENERAL_ERROR;
    }

    if (*ptextlen < m.size) {
        return CKR_BUFFER_TOO_SMALL;
    }

    *ptextlen = m.size;
    memcpy(ptext, m.buffer, m.size);

    return CKR_OK;
}

static bool encrypt_decrypt(tpm_ctx *ctx, uint32_t handle, twist objauth, CK_MECHANISM_TYPE mode, TPMI_YES_NO is_decrypt,
        twist iv_in, twist data_in, twist *data_out, twist *iv_out) {

    TSS2_SYS_CONTEXT *sysctx = from_ctx(ctx);

    TSS2L_SYS_AUTH_COMMAND sessionsData = { 0 };
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    if (twist_len(objauth) > sizeof(sessionsData.auths[0].hmac.buffer)) {
        return false;
    }

    sessionsData.count = 1;
    memcpy(sessionsData.auths[0].hmac.buffer, objauth, twist_len(objauth));
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].hmac.size = twist_len(objauth);

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
        return false;
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
    TPM2B_MAX_BUFFER tpm_data_out = {
        .size = sizeof(tpm_data_out.buffer)
    };

    TPM2B_IV tpm_iv_out = {
            .size = sizeof(tpm_iv_out.buffer)
    };

    /*
     * try EncryptDecrypt2 first, and if the command is not supported by the TPM, fall back to
     * EncryptDecrypt. Keep track of which version you ran, for error reporting.
     */
    unsigned version = 2;
    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_EncryptDecrypt2(sysctx,
            handle, &sessionsData, &tpm_data_in,
            is_decrypt, tpm_mode, &tpm_iv_in, &tpm_data_out, &tpm_iv_out,
            &sessionsDataOut));
    if (tpm2_error_get(rval) == TPM2_RC_COMMAND_CODE) {
        version = 1;
        rval = TSS2_RETRY_EXP(Tss2_Sys_EncryptDecrypt(sysctx,
                handle, &sessionsData, is_decrypt,
                tpm_mode, &tpm_iv_in, &tpm_data_in, &tpm_data_out, &tpm_iv_out,
                &sessionsDataOut));
    }
    if (rval != TPM2_RC_SUCCESS) {
        if (version == 2) {
            LOGE("Tss2_Sys_EncryptDecrypt2: 0x%x", rval);
        } else {
            LOGE("Tss2_Sys_EncryptDecrypt: 0x%x", rval);
        }
        return false;
    }

    /* copy output data from tpm into twist types */
    if (iv_out) {
        *iv_out = twistbin_new(tpm_iv_out.buffer, tpm_iv_out.size);
        if (!*iv_out) {
            return false;
        }
    }

    *data_out = twistbin_new(tpm_data_out.buffer, tpm_data_out.size);
    if (!*data_out) {
        if (iv_out) {
            twist_free(*iv_out);
        }
        return false;
    }

    return true;
}

/*
 * These align with the specifications TPMI_YES_NO values as understood for encryptdecrypt routines.
 */
#define ENCRYPT 0
#define DECRYPT 1

bool tpm_encrypt(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mode, twist iv, twist plaintext, twist *ciphertext, twist *iv_out) {

    return encrypt_decrypt(ctx, tobj->handle, tobj->unsealed_auth, mode, ENCRYPT,
            iv, plaintext, ciphertext, iv_out);
}

bool tpm_decrypt_handle(tpm_ctx *ctx, uint32_t handle, twist objauth, CK_MECHANISM_TYPE mode, twist iv, twist ciphertext, twist *plaintext, twist *iv_out) {

    return encrypt_decrypt(ctx, handle, objauth, mode, DECRYPT,
            iv, ciphertext, plaintext, iv_out);
}

bool tpm_decrypt(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mode, twist iv, twist ciphertext, twist *plaintext, twist *iv_out) {

    return encrypt_decrypt(ctx, tobj->handle, tobj->unsealed_auth, mode, DECRYPT,
            iv, ciphertext, plaintext, iv_out);
}
