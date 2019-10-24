/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
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

#include <tss2/tss2_fapi.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "checks.h"
#include "openssl_compat.h"
#include "pkcs11.h"
#include "log.h"
#include "mutex.h"
#include "tpm.h"

TSS2_RC tss_get_esys(FAPI_CONTEXT *fctx, ESYS_CONTEXT **esys) {
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti;

    rc = Fapi_GetTcti(fctx, &tcti);
    check_tssrc(rc, return rc);

    rc = Esys_Initialize(esys, tcti, NULL);
    check_tssrc(rc, return rc);

    return rc;
}

TSS2_RC auth_cb (FAPI_CONTEXT *context, char const *description,
                       char **auth, void *userData) {
    (void)(context);
    (void)(description);
    *auth = userData;
    return TSS2_RC_SUCCESS;
}

CK_RV tss_get_card_ids(CK_SLOT_ID *slot_list, CK_ULONG_PTR count) {
    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    char *pathlist, *path, *strtokr_save = NULL;
    size_t numPaths = 0;
    CK_SLOT_ID tmp;

    LOGV("Calling TSS to retrieve tokens.");
    /* Let's check if everything is up and working.*/
    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    rc = Fapi_List(fctx, "/HS/SRK", &pathlist);
    /* We immediately close FAPI because we have nowhere to put the context,
       no global variables desired */
    Fapi_Finalize(&fctx);
    if (rc == 0x0006000a) {
        numPaths = 0;
        rc = TSS2_RC_SUCCESS;
    }
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    LOGV("Processing TSS token results. keystore items found: %s", pathlist);
    while ((path = strtok_r( (strtokr_save == NULL)? pathlist : NULL, ":", &strtokr_save))) {
        if (sscanf(path, PREFIX "so-%08lx", &tmp) != 1) {
            LOGV("%s is not a token, ignoring", path);
            continue;
        }

        numPaths += 1;
        LOGV("%s is token number %zi", path, numPaths);

        if (!slot_list)
            continue;

        if (numPaths > *count) {
            LOGE("buffer too small, count = %u, required=%u", *count, numPaths);
            *count = numPaths;
            Fapi_Free(pathlist);
            return CKR_BUFFER_TOO_SMALL;
        }

        LOGV("Slot %zi: %s", numPaths - 1, path);
        sscanf(path, PREFIX "so-%08lx", &slot_list[numPaths - 1]);
    }

    *count = numPaths;
    Fapi_Free(pathlist);

    return CKR_OK;
}

CK_RV tss_get_object_ids(CK_SLOT_ID slot_id, CK_OBJECT_HANDLE_PTR *phObject, CK_ULONG_PTR count) {
    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    char *pathlist, *path, *strtokr_save = NULL, pattern[100/*PREFIX*/ + 3 + 1 + 8 + 1 + 6 + 1];
    CK_SLOT_ID tmp;

    sprintf(&pattern[0], PREFIX "key-%08lx-%%08lx", slot_id);

    LOGV("Calling TSS to retrieve tokens.");
    /* Let's check if everything is up and working.*/
    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    rc = Fapi_List(fctx, "/HS/SRK", &pathlist);
    /* We immediately close FAPI because we have nowhere to put the context,
       no global variables desired */
    Fapi_Finalize(&fctx);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    *count = 0;
    *phObject = calloc(10, sizeof(**phObject));

    LOGV("Processing TSS object results. keystore items found: %s", pathlist);
    while ((path = strtok_r( (strtokr_save == NULL)? pathlist : NULL, ":", &strtokr_save))) {
        if (sscanf(path, &pattern[0], &tmp) != 1) {
            LOGV("%s is not a key, ignoring", path);
            continue;
        }
        *count += 2;

        if (*count % 10 == 9)
            *phObject = calloc(*count + 10, sizeof(**phObject));

        LOGV("key %zi: %s", *count - 2, path);
        sscanf(path, &pattern[0], &((*phObject)[*count - 1]));
        LOGV("key %zi: %s", *count - 1, path);
        (*phObject)[*count - 2] = (*phObject)[*count - 1] | 0x10000000;
    }

    Fapi_Free(pathlist);

    return CKR_OK;
}

char * tss_path_from_id(CK_SLOT_ID slot_id) {
    char *path = malloc(strlen(PREFIX) + 2 + 1 + 8 + 1);
    if (!path)
        return NULL;

    sprintf(&path[0], "%sso-%08x", PREFIX, (unsigned int) slot_id & ~EMPTY_TOKEN_BIT);

    return path;
}

char * tss_userpath_from_id(CK_SLOT_ID slot_id) {
    char *path = malloc(strlen(PREFIX) + 4 + 1 + 8 + 1);
    if (!path)
        return NULL;

    sprintf(&path[0], "%suser-%08x", PREFIX, (unsigned int) slot_id & ~EMPTY_TOKEN_BIT);

    return path;
}

char * tss_keypath_from_id(CK_SLOT_ID slot_id, CK_OBJECT_HANDLE object) {
    char *path = malloc(strlen(PREFIX) + 3 + 1 + 8 + 1 + 8 + 1);
    if (!path)
        return NULL;

    sprintf(&path[0], "%skey-%08x-%08x", PREFIX, (unsigned int) slot_id & ~EMPTY_TOKEN_BIT,
            (unsigned int) object & 0x0FFFFFFF);

    return path;
}

CK_RV tss_data_from_id(CK_SLOT_ID slot_id, CK_OBJECT_HANDLE object,
                        TPM2B_PUBLIC *public, TPM2B_PRIVATE *private,
                        char **description,
                        uint8_t **appData, size_t *appDataSize) {
    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    uint8_t *tpm2bPublic, *tpm2bPrivate;
    size_t tpm2bPublicSize, tpm2bPrivateSize;
    char *path, *d;

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    path = tss_keypath_from_id(slot_id, object);

    rc = Fapi_GetTpmBlobs(fctx, path, &tpm2bPublic, &tpm2bPublicSize,
                          &tpm2bPrivate, &tpm2bPrivateSize, NULL /* policy */);
    check_tssrc(rc, free(path); Fapi_Finalize(&fctx); return CKR_GENERAL_ERROR);

    rc = Fapi_GetDescription(fctx, path, &d);
    if (rc == 0x00060007) {
        if (description) *description = NULL;
    } else {
        check_tssrc(rc, Fapi_Free(tpm2bPublic); Fapi_Free(tpm2bPrivate); return CKR_GENERAL_ERROR);
        if (description) *description = d;
    }

    rc = Fapi_GetAppData(fctx, path, appData, appDataSize);
    free(path);
    Fapi_Finalize(&fctx);
    if (rc == 0x00060007) {
        if (appData) *appData = NULL;
        if (appDataSize) *appDataSize = 0;
    } else
        check_tssrc(rc, Fapi_Free(tpm2bPublic); Fapi_Free(tpm2bPrivate); return CKR_GENERAL_ERROR);

    if (public) {
        public->size = 0;
        rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(tpm2bPublic, tpm2bPublicSize, NULL, public);
        check_tssrc(rc, Fapi_Free(tpm2bPrivate); Fapi_Free(tpm2bPublic); return CKR_GENERAL_ERROR);
    }
    Fapi_Free(tpm2bPublic);

    if (private) {
        private->size = 0;
        rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(tpm2bPrivate, tpm2bPrivateSize, NULL, private);
        check_tssrc(rc, Fapi_Free(tpm2bPrivate); return CKR_GENERAL_ERROR);
    }
    Fapi_Free(tpm2bPrivate);

    return CKR_OK;
}

#if 0
static const char *TPM2_MANUFACTURER_MAP[][2] = {
    {"ATML", "Atmel"},
    {"INTC", "Intel"},
    {"IFX ", "Infineon"},
    {"IBM ", "IBM"},
    {"NTC ", "Nuvoton"},
    {"STM ", "STMicro"}
};

CK_RV tpm_get_token_info (tpm_ctx *ctx, CK_TOKEN_INFO *info) {

    CK_RV rv = CKR_OK;
    check_pointer(ctx);
    check_pointer(info);

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
        LOGE("Esys_GetCapability: 0x%x:", rval);
        return CKR_GENERAL_ERROR;
    }

    if (!capabilityData ||
        capabilityData->data.tpmProperties.count < TPM2_PT_VENDOR_STRING_4 - TPM2_PT_FIXED + 1) {
        LOGE("TPM did not reply with correct amount of capabilities");
        rv = CKR_GENERAL_ERROR;
        goto out;
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

out:
    free (capabilityData);
    return rv;
}
#endif /*0*/

bool tpm_getrandom(BYTE *data, size_t size) {

    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    uint8_t *rand_bytes;

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, return false);

    rc = Fapi_GetRandom(fctx, size, &rand_bytes);
    Fapi_Finalize(&fctx);
    check_tssrc(rc, return false);

    memcpy(data, rand_bytes, size);
    Fapi_Free(rand_bytes);
    return true;
}

TPMI_ALG_HASH hashlen_to_alg_guess(CK_ULONG datalen) {
    switch (datalen) {
        case SHA_DIGEST_LENGTH:
            return TPM2_ALG_SHA1;
        case SHA256_DIGEST_LENGTH:
            return TPM2_ALG_SHA256;
        case SHA384_DIGEST_LENGTH:
            return TPM2_ALG_SHA384;
        case SHA512_DIGEST_LENGTH:
            return TPM2_ALG_SHA512;
        default:
            LOGE("unkown digest length");
            return TPM2_ALG_ERROR;
    }
}

TPMI_ALG_HASH mech_to_hash_alg_ex(CK_MECHANISM_TYPE mode, CK_ULONG datalen) {

    switch (mode) {
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA_1:
        return TPM2_ALG_SHA1;

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

    case CKM_RSA_PKCS:
    case CKM_ECDSA:
	// ECDSA is NOT using a hash.
	// It needs a length (determined by the name of an hash alg) anyway.
	// The length/hash_alg with correct length will be specified later.
	return datalen ? hashlen_to_alg_guess(datalen) : TPM2_ALG_ERROR;

    default:
        return TPM2_ALG_ERROR;
    }
}

TPMI_ALG_HASH mech_to_hash_alg(CK_MECHANISM_TYPE mode) {

    return mech_to_hash_alg_ex(mode, 0);
}


CK_RV tpm_sign(CK_SLOT_ID slot_id, CK_OBJECT_HANDLE key, uint8_t *auth, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {

    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    uint8_t *signature;
    size_t signatureSize;
    char *sigscheme;

//TODO: remove
    char *pubkey;

    /* FAPI will guess the hashAlg. For SSA that's merely used for digest buffer sizes
       at the TPM anyways. For PSS, this is TODO. */
    switch (mech) {
        case CKM_SHA1_RSA_PKCS:
            LOGV("Using scheme RSA_SSA for SHA1");
            sigscheme = "RSA_SSA";
            break;
        case CKM_SHA256_RSA_PKCS:
            LOGV("Using scheme RSA_SSA for SHA256");
            sigscheme = "RSA_SSA";
            break;
        case CKM_SHA384_RSA_PKCS:
            LOGV("Using scheme RSA_SSA for SHA384");
            sigscheme = "RSA_SSA";
            break;
        case CKM_SHA1_RSA_PKCS_PSS:
            LOGV("Using scheme RSA_PSS for SHA1");
            sigscheme = "RSA_PSS";
            break;
        case CKM_SHA256_RSA_PKCS_PSS:
            LOGV("Using scheme RSA_PSS for SHA256");
            sigscheme = "RSA_PSS";
            break;
        default:
            LOGE("Mechanism not supported: %li", mech);
            return CKR_GENERAL_ERROR;
    }

    char *keypath = tss_keypath_from_id(slot_id, key);
    check_pointer(keypath);

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, free(keypath); return CKR_GENERAL_ERROR);

    rc = Fapi_SetAuthCB(fctx, auth_cb, auth);
    check_tssrc(rc, free(keypath); Fapi_Finalize(&fctx); return CKR_GENERAL_ERROR);

    rc = Fapi_Sign(fctx, keypath, sigscheme, data, datalen,
                   &signature, &signatureSize, &pubkey/*NULL pubkey*/, NULL /*cert*/);
    free(keypath);
//    Fapi_Finalize(&fctx);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    if (mech == CKM_ECDSA && mech == CKM_ECDSA_SHA1) {
        //TODO: Flatten ecdsa
    } else {
        *siglen = signatureSize;
        if (sig)
            memcpy(sig, signature, *siglen);
    }

//TODO: Remove these dumps
fprintf(stderr, "PubkeyPEM: %s", pubkey);
    rc = Fapi_Import(fctx, "pubkey", pubkey);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    rc = Fapi_VerifySignature(fctx, "/ext/pubkey", data, datalen,
                   signature, signatureSize);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

fprintf(stderr, "data:");
    for (size_t i = 0; i < datalen; i++)
        fprintf(stderr, "%02x", (uint8_t)data[i]);
fprintf(stderr, "\n\n");

fprintf(stderr, "Signature:");
    for (size_t i = 0; i < signatureSize; i++)
        fprintf(stderr, "%02x", (uint8_t)signature[i]);
fprintf(stderr, "\n\n");

TPM2B_PUBLIC public;
tss_data_from_id(slot_id, key, &public, NULL, NULL, NULL, NULL);
fprintf(stderr, "key:");
    for (size_t i = 0; i < public.publicArea.unique.rsa.size; i++)
        fprintf(stderr, "%02x", public.publicArea.unique.rsa.buffer[i]);
fprintf(stderr, "\n\n");

    Fapi_Finalize(&fctx);
//TODO: End of remove

    Fapi_Free(signature);
    return CKR_OK;
}

CK_RV tpm_verify(CK_SLOT_ID slot_id, CK_OBJECT_HANDLE key, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG siglen) {
    /* Fapi attempts signature verifications with all known paddings */
    (void)(mech);

    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    uint8_t signature[1024];

    if (siglen > sizeof(signature))
        return CKR_SIGNATURE_INVALID;

    char *keypath = tss_keypath_from_id(slot_id, key);
    check_pointer(keypath);

    if (mech == CKM_ECDSA && mech == CKM_ECDSA_SHA1) {
        //TODO: unflatten ecdsa
    } else {
        memcpy(&signature[0], sig, siglen);
    }

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, free(keypath); return CKR_GENERAL_ERROR);

    rc = Fapi_VerifySignature(fctx, keypath, data, datalen,
                              &signature[0], siglen);
    free(keypath);
    Fapi_Finalize(&fctx);
    check_tssrc(rc, return CKR_SIGNATURE_INVALID);

    return CKR_OK;
}

static CK_RV tpm_get_algorithms (ESYS_CONTEXT *esys_ctx, TPMS_CAPABILITY_DATA **capabilityData) {

    TPM2_CAP capability = TPM2_CAP_ALGS;
    UINT32 property = TPM2_ALG_FIRST;
    UINT32 propertyCount = TPM2_MAX_CAP_ALGS;
    TPMI_YES_NO moreData;

    check_pointer(esys_ctx);
    check_pointer(capabilityData);

    TSS2_RC rval = Esys_GetCapability(esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            capability,
            property, propertyCount, &moreData, capabilityData);

    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_GetCapability: 0x%x:", rval);
        return CKR_GENERAL_ERROR;
    }

    if (!capabilityData) {
        LOGE("TPM did not reply with correct amount of capabilities");
        return CKR_GENERAL_ERROR;
    }

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

CK_RV tpm2_getmechanisms(CK_MECHANISM_TYPE *mechanism_list, CK_ULONG_PTR count){
    check_pointer(count);

    CK_ULONG supported = 0;
    CK_RV rv;
    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    ESYS_CONTEXT *esys;

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    rc = tss_get_esys(fctx, &esys);
    check_tssrc(rc, Fapi_Finalize(&fctx); return CKR_GENERAL_ERROR);

    TPMS_CAPABILITY_DATA *capabilityData = NULL;
    rv = tpm_get_algorithms(esys, &capabilityData);
    Esys_Finalize(&esys); Fapi_Finalize(&fctx);
    if (rv != CKR_OK) {
        LOGE("Retrieving supported algorithms from TPM failed");
        return rv;
    }
    TPMU_CAPABILITIES *algs= &capabilityData->data;

    if (is_algorithm_supported(algs, TPM2_ALG_RSA)) {
        add_mech(CKM_RSA_PKCS);
        add_mech(CKM_RSA_PKCS_KEY_PAIR_GEN);
        add_mech(CKM_RSA_X_509);
        if (is_algorithm_supported(algs, TPM2_ALG_SHA1)) {
           add_mech(CKM_SHA1_RSA_PKCS);
        }
        if (is_algorithm_supported(algs, TPM2_ALG_SHA256)) {
           add_mech(CKM_SHA256_RSA_PKCS);
        }
        if (is_algorithm_supported(algs, TPM2_ALG_SHA384)) {
           add_mech(CKM_SHA384_RSA_PKCS);
        }
        if (is_algorithm_supported(algs, TPM2_ALG_SHA512)) {
           add_mech(CKM_SHA512_RSA_PKCS);
        }
    }

    if (is_algorithm_supported(algs, TPM2_ALG_OAEP)) {
        add_mech(CKM_RSA_PKCS_OAEP);
    }
    if (is_algorithm_supported(algs, TPM2_ALG_ECDSA)) {
        add_mech(CKM_ECDSA);
        if (is_algorithm_supported(algs, TPM2_ALG_SHA1)) {
            add_mech(CKM_ECDSA_SHA1);
        }
    }
    if (is_algorithm_supported(algs, TPM2_ALG_ECC)) {
        add_mech(CKM_EC_KEY_PAIR_GEN);
    }

out:
    *count = supported;
    free(capabilityData);

    return rv;

}

TPMI_ALG_HASH mgftype2tpm(CK_RSA_PKCS_MGF_TYPE mgf) {
    switch(mgf) {
    case CKG_MGF1_SHA1:
        return TPM2_ALG_SHA1;
    case CKG_MGF1_SHA256:
        return TPM2_ALG_SHA256;
    case CKG_MGF1_SHA384:
        return TPM2_ALG_SHA384;
    case CKG_MGF1_SHA512:
        return TPM2_ALG_SHA512;
    case CKG_MGF1_SHA224:
        return TPM2_ALG_ERROR;
    default:
        return TPM2_ALG_ERROR;
    }
}

CK_RV tss_rsa_decrypt(CK_SLOT_ID slot_id, CK_OBJECT_HANDLE key, uint8_t *auth, CK_MECHANISM_TYPE mtype, oaepparams *params, CK_BYTE_PTR cipher, CK_ULONG cipherlen, CK_BYTE_PTR part, CK_ULONG_PTR partlen) {

    CK_RV rv;
    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    ESYS_CONTEXT *esys;
    TPM2B_PUBLIC public;
    TPM2B_PRIVATE private;
    ESYS_TR parent, handle;
    TPMT_RSA_DECRYPT scheme;
    TPM2B_DATA label;
    TPM2B_AUTH auth2b = { .size = 64 };
    memcpy(&auth2b.buffer[0], auth, 64);

    TPM2B_PUBLIC_KEY_RSA *plain2b, cipher2b = { .size = cipherlen };
    if (cipherlen > sizeof(cipher2b.buffer)) {
        LOGE("Cipher is too long. Got %li max %zi", cipherlen, sizeof(cipher2b.buffer));
        return CKR_ARGUMENTS_BAD;
    }
    memcpy(cipher2b.buffer, cipher, cipherlen);

    rv = tss_data_from_id(slot_id, key, &public, &private, NULL, NULL, NULL);
    check_tssrc(rv, return rv);

    switch(mtype) {
    case CKM_RSA_X_509:
        LOGE("Mechanism is RSA_X_509 aka raw");
        scheme.scheme = TPM2_ALG_NULL;
        label.size = 0;
        break;
    case CKM_RSA_PKCS:
        LOGE("Mechanism is RSA_PKCS");
        scheme.scheme = TPM2_ALG_RSAES;
        label.size = 0;
        break;
    case CKM_RSA_PKCS_OAEP:
        LOGE("Mechanism is RSA_PKCS_OAEP");
        scheme.scheme = TPM2_ALG_OAEP;
        if (mgftype2tpm(params->mgf) != public.publicArea.nameAlg) {
            LOGE("MGF mode does not match TPM's nameAlg, that's used for MGF.");
            /*  TODO revisit - why does it return not supported here. It works though
            return CKR_MECHANISM_PARAM_INVALID; */
        }
        scheme.details.oaep.hashAlg = mech_to_hash_alg(params->hashAlg);
        if (scheme.details.oaep.hashAlg == TPM2_ALG_ERROR) {
            LOGE("hashAlg invalid: 0x%lx", params->hashAlg);
            return CKR_MECHANISM_PARAM_INVALID;
        }
        if (params->ulSourceDataLen > sizeof(label.buffer)) {
            LOGE("ulSourceDataLen to large: %li", params->ulSourceDataLen);
            return CKR_MECHANISM_PARAM_INVALID;
        }
        label.size = params->ulSourceDataLen;
        if (params->ulSourceDataLen) {
            if (!params->pSourceData) {
                LOGE("no label source provided.");
                return CKR_MECHANISM_PARAM_INVALID;
            }
            memcpy(&label.buffer[0], params->pSourceData, label.size);
        }
        break;
    default:
        LOGE("Mechanism not supported. Got 0x%lx", mtype);
        return CKR_MECHANISM_INVALID;
    }

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    rc = tss_get_esys(fctx, &esys);
    check_tssrc(rc, Fapi_Finalize(&fctx); return CKR_GENERAL_ERROR);

    rc = Esys_TR_FromTPMPublic(esys, 0x81000000,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &parent);
    check_tssrc(rc, Esys_Finalize(&esys); Fapi_Finalize(&fctx); return CKR_GENERAL_ERROR);

    rc = Esys_Load(esys, parent,
                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &private, &public, &handle);
    Esys_TR_Close(esys, &parent);
    check_tssrc(rc, Esys_Finalize(&esys); Fapi_Finalize(&fctx); return CKR_GENERAL_ERROR);

    rc = Esys_TR_SetAuth(esys, handle, &auth2b);
    check_tssrc(rc, Esys_FlushContext(esys, handle); Esys_Finalize(&esys);
                    Fapi_Finalize(&fctx); return CKR_GENERAL_ERROR);

    rc = Esys_RSA_Decrypt(esys, handle,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          &cipher2b, &scheme, &label, &plain2b);
    Esys_FlushContext(esys, handle); Esys_Finalize(&esys); Fapi_Finalize(&fctx);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    *partlen = plain2b->size;
    memcpy(part, &plain2b->buffer[0], *partlen);
    Esys_Free(plain2b);

    return CKR_OK;
}
