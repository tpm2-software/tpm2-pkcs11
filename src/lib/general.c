/* SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "checks.h"
#include "config.h"
#include "backend.h"
#include "general.h"
#include "log.h"
#include "mutex.h"
#include "pkcs11.h"
#include "session.h"
#include "utils.h"

#ifndef VERSION
  #warning "VERSION Not known at compile time, not embedding..."
  #define VERSION "UNKNOWN"
#endif

static const CK_UTF8CHAR LIBRARY_DESCRIPTION[] = "TPM2.0 Cryptoki";
static const CK_UTF8CHAR LIBRARY_MANUFACTURER[] = "tpm2-software.github.io";

/*
 * The highest Cryptoki version the library implements, which C_GetInfo reports. The function lists
 * carry the version of their own layout: C_GetFunctionList hands out the v2.40 list, and
 * C_GetInterface/C_GetInterfaceList offer the v3.2, v3.1, v3.0 and v2.40 ones.
 */
#define CRYPTOKI_VERSION { \
           .major = 3, \
           .minor = 2 \
         }

CK_RV general_get_info(CK_INFO *info) {
    check_pointer(info);

    /* we only need one copy and we only need to initialize it on first call */
    static CK_INFO _info_ = {
        .cryptokiVersion = CRYPTOKI_VERSION,
    };

    static CK_INFO *_info = NULL;
    if (!_info) {
        str_padded_copy(_info_.manufacturerID, LIBRARY_MANUFACTURER);
        str_padded_copy(_info_.libraryDescription, LIBRARY_DESCRIPTION);

        parse_lib_version(PACKAGE_VERSION, &_info_.libraryVersion.major,
                &_info_.libraryVersion.minor);

        _info = &_info_;
    }

    *info = *_info;

    return CKR_OK;
}

/* The v2.40 functions, shared by every list. */
#define FUNCTION_LIST_2_40 \
    .C_Initialize = C_Initialize, \
    .C_Finalize = C_Finalize, \
    .C_GetInfo = C_GetInfo, \
    .C_GetFunctionList = C_GetFunctionList, \
    .C_GetSlotList = C_GetSlotList, \
    .C_GetSlotInfo = C_GetSlotInfo, \
    .C_GetTokenInfo = C_GetTokenInfo, \
    .C_GetMechanismList = C_GetMechanismList, \
    .C_GetMechanismInfo = C_GetMechanismInfo, \
    .C_InitToken = C_InitToken, \
    .C_InitPIN = C_InitPIN, \
    .C_SetPIN = C_SetPIN, \
    .C_OpenSession = C_OpenSession, \
    .C_CloseSession = C_CloseSession, \
    .C_CloseAllSessions = C_CloseAllSessions, \
    .C_GetSessionInfo = C_GetSessionInfo, \
    .C_GetOperationState = C_GetOperationState, \
    .C_SetOperationState = C_SetOperationState, \
    .C_Login = C_Login, \
    .C_Logout = C_Logout, \
    .C_CreateObject = C_CreateObject, \
    .C_CopyObject = C_CopyObject, \
    .C_DestroyObject = C_DestroyObject, \
    .C_GetObjectSize = C_GetObjectSize, \
    .C_GetAttributeValue = C_GetAttributeValue, \
    .C_SetAttributeValue = C_SetAttributeValue, \
    .C_FindObjectsInit = C_FindObjectsInit, \
    .C_FindObjects = C_FindObjects, \
    .C_FindObjectsFinal = C_FindObjectsFinal, \
    .C_EncryptInit = C_EncryptInit, \
    .C_Encrypt = C_Encrypt, \
    .C_EncryptUpdate = C_EncryptUpdate, \
    .C_EncryptFinal = C_EncryptFinal, \
    .C_DecryptInit = C_DecryptInit, \
    .C_Decrypt = C_Decrypt, \
    .C_DecryptUpdate = C_DecryptUpdate, \
    .C_DecryptFinal = C_DecryptFinal, \
    .C_DigestInit = C_DigestInit, \
    .C_Digest = C_Digest, \
    .C_DigestUpdate = C_DigestUpdate, \
    .C_DigestKey = C_DigestKey, \
    .C_DigestFinal = C_DigestFinal, \
    .C_SignInit = C_SignInit, \
    .C_Sign = C_Sign, \
    .C_SignUpdate = C_SignUpdate, \
    .C_SignFinal = C_SignFinal, \
    .C_SignRecoverInit = C_SignRecoverInit, \
    .C_SignRecover = C_SignRecover, \
    .C_VerifyInit = C_VerifyInit, \
    .C_Verify = C_Verify, \
    .C_VerifyUpdate = C_VerifyUpdate, \
    .C_VerifyFinal = C_VerifyFinal, \
    .C_VerifyRecoverInit = C_VerifyRecoverInit, \
    .C_VerifyRecover = C_VerifyRecover, \
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate, \
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate, \
    .C_SignEncryptUpdate = C_SignEncryptUpdate, \
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate, \
    .C_GenerateKey = C_GenerateKey, \
    .C_GenerateKeyPair = C_GenerateKeyPair, \
    .C_WrapKey = C_WrapKey, \
    .C_UnwrapKey = C_UnwrapKey, \
    .C_DeriveKey = C_DeriveKey, \
    .C_SeedRandom = C_SeedRandom, \
    .C_GenerateRandom = C_GenerateRandom, \
    .C_GetFunctionStatus = C_GetFunctionStatus, \
    .C_CancelFunction = C_CancelFunction, \
    .C_WaitForSlotEvent = C_WaitForSlotEvent

/* The functions v3.0 added; v3.1 added none. */
#define FUNCTION_LIST_3_0 \
    .C_GetInterfaceList = C_GetInterfaceList, \
    .C_GetInterface = C_GetInterface, \
    .C_LoginUser = C_LoginUser, \
    .C_SessionCancel = C_SessionCancel, \
    .C_MessageEncryptInit = C_MessageEncryptInit, \
    .C_EncryptMessage = C_EncryptMessage, \
    .C_EncryptMessageBegin = C_EncryptMessageBegin, \
    .C_EncryptMessageNext = C_EncryptMessageNext, \
    .C_MessageEncryptFinal = C_MessageEncryptFinal, \
    .C_MessageDecryptInit = C_MessageDecryptInit, \
    .C_DecryptMessage = C_DecryptMessage, \
    .C_DecryptMessageBegin = C_DecryptMessageBegin, \
    .C_DecryptMessageNext = C_DecryptMessageNext, \
    .C_MessageDecryptFinal = C_MessageDecryptFinal, \
    .C_MessageSignInit = C_MessageSignInit, \
    .C_SignMessage = C_SignMessage, \
    .C_SignMessageBegin = C_SignMessageBegin, \
    .C_SignMessageNext = C_SignMessageNext, \
    .C_MessageSignFinal = C_MessageSignFinal, \
    .C_MessageVerifyInit = C_MessageVerifyInit, \
    .C_VerifyMessage = C_VerifyMessage, \
    .C_VerifyMessageBegin = C_VerifyMessageBegin, \
    .C_VerifyMessageNext = C_VerifyMessageNext, \
    .C_MessageVerifyFinal = C_MessageVerifyFinal

/* The functions v3.2 added. */
#define FUNCTION_LIST_3_2 \
    .C_EncapsulateKey = C_EncapsulateKey, \
    .C_DecapsulateKey = C_DecapsulateKey, \
    .C_VerifySignatureInit = C_VerifySignatureInit, \
    .C_VerifySignature = C_VerifySignature, \
    .C_VerifySignatureUpdate = C_VerifySignatureUpdate, \
    .C_VerifySignatureFinal = C_VerifySignatureFinal, \
    .C_GetSessionValidationFlags = C_GetSessionValidationFlags, \
    .C_AsyncComplete = C_AsyncComplete, \
    .C_AsyncGetID = C_AsyncGetID, \
    .C_AsyncJoin = C_AsyncJoin, \
    .C_WrapKeyAuthenticated = C_WrapKeyAuthenticated, \
    .C_UnwrapKeyAuthenticated = C_UnwrapKeyAuthenticated

static CK_FUNCTION_LIST function_list_2_40 = {
    .version = { .major = 2, .minor = 40 },
    FUNCTION_LIST_2_40,
};

static CK_FUNCTION_LIST_3_0 function_list_3_0 = {
    .version = { .major = 3, .minor = 0 },
    FUNCTION_LIST_2_40,
    FUNCTION_LIST_3_0,
};

/* v3.1 has the v3.0 layout. */
static CK_FUNCTION_LIST_3_0 function_list_3_1 = {
    .version = { .major = 3, .minor = 1 },
    FUNCTION_LIST_2_40,
    FUNCTION_LIST_3_0,
};

static CK_FUNCTION_LIST_3_2 function_list_3_2 = {
    .version = { .major = 3, .minor = 2 },
    FUNCTION_LIST_2_40,
    FUNCTION_LIST_3_0,
    FUNCTION_LIST_3_2,
};

#define INTERFACE_NAME "PKCS 11"

/*
 * Newest first: C_GetInterface without a name or a version returns the first, the default. None is
 * CKF_INTERFACE_FORK_SAFE: a child process can't use the TPM connection and token state it inherits.
 */
static CK_INTERFACE interfaces[] = {
    { .pInterfaceName = (char *)INTERFACE_NAME, .pFunctionList = &function_list_3_2, .flags = 0 },
    { .pInterfaceName = (char *)INTERFACE_NAME, .pFunctionList = &function_list_3_1, .flags = 0 },
    { .pInterfaceName = (char *)INTERFACE_NAME, .pFunctionList = &function_list_3_0, .flags = 0 },
    { .pInterfaceName = (char *)INTERFACE_NAME, .pFunctionList = &function_list_2_40, .flags = 0 },
};

CK_RV general_get_func_list(CK_FUNCTION_LIST **function_list) {

    if (function_list == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    *function_list = &function_list_2_40;

    return CKR_OK;
}

CK_RV general_get_interface_list(CK_INTERFACE *interface_list, CK_ULONG_PTR count) {

    check_pointer(count);

    CK_ULONG n = ARRAY_LEN(interfaces);
    if (!interface_list) {
        *count = n;
        return CKR_OK;
    }

    CK_RV rv = CKR_OK;
    if (*count < n) {
        rv = CKR_BUFFER_TOO_SMALL;
    } else {
        memcpy(interface_list, interfaces, sizeof(interfaces));
    }

    *count = n;
    return rv;
}

CK_RV general_get_interface(CK_UTF8CHAR_PTR interface_name, CK_VERSION_PTR version,
        CK_INTERFACE_PTR_PTR interface, CK_FLAGS flags) {

    check_pointer(interface);

    for (size_t i = 0; i < ARRAY_LEN(interfaces); i++) {
        CK_INTERFACE *candidate = &interfaces[i];

        if (interface_name
                && strcmp((const char *)interface_name, (const char *)candidate->pInterfaceName)) {
            continue;
        }

        /* Every function list starts with its CK_VERSION. */
        const CK_VERSION *list_version = (const CK_VERSION *)candidate->pFunctionList;
        if (version
                && (version->major != list_version->major || version->minor != list_version->minor)) {
            continue;
        }

        if ((candidate->flags & flags) != flags) {
            continue;
        }

        *interface = candidate;
        return CKR_OK;
    }

    /* The standard names no return value for an interface it doesn't have; this is the usual one. */
    return CKR_ARGUMENTS_BAD;
}

static bool _g_is_init;
bool general_is_init(void) {
    return _g_is_init;
}

CK_RV general_init(void *init_args) {

    CK_RV rv = CKR_GENERAL_ERROR;

    if (init_args) {
        CK_C_INITIALIZE_ARGS *args = (CK_C_INITIALIZE_ARGS *)init_args;
        if(args->pReserved) {
            return CKR_ARGUMENTS_BAD;
        }

        /*
         * If their is CKF_OS_LOCKING_OK flag:
         * 1. No function pointers, Use native OS support (default in mutex.h).
         * 2. Supplied function pointers, optional use them (we won't).
         * 3. Partial supplied function pointers is CKR_ARGUMENTS_BAD
         *
         * If their is no CKF_OS_LOCKING_OK flag:
         * A. No callbacks means no need for locks
         * B. All callbacks means use theirs
         * C. A mix is CKR_ARGUMENTS_BAD
         */
        if (!args->CreateMutex
            && !args->DestroyMutex
            && !args->LockMutex
            && !args->UnlockMutex) {
            /* no function pointers, options 1 and A */
                if(args->flags & CKF_OS_LOCKING_OK) {
                    /* pass as it's default */
                } else {
                    /* no need for locks */
                    mutex_set_handlers(NULL, NULL, NULL, NULL);
                }
        } else if (args->CreateMutex
            && args->DestroyMutex
            && args->LockMutex
            && args->UnlockMutex) {
            /* all function pointers, options 2 and B */
            if(args->flags & CKF_OS_LOCKING_OK) {
                /* optional, we won't use theirs, use default */
            } else {
                mutex_set_handlers(args->CreateMutex,
                        args->DestroyMutex,
                        args->LockMutex,
                        args->UnlockMutex);
            }
        } else {
            /* mixed function pointers, bad */
            return CKR_ARGUMENTS_BAD;
        }
    } else {
        /* No init arguments means no multi-thread access */
        mutex_set_handlers(NULL, NULL, NULL, NULL);
    }

    /*
     * Initialize the various sub-systems.
     *
     * THESE MUST GO AFTER MUTEX INIT above!!
     */
    rv = backend_init();
    if (rv != CKR_OK) {
        goto err;
    }

    rv = slot_init();
    if (rv != CKR_OK) {
        (void)backend_destroy();
        goto err;
    }

    _g_is_init = true;

    return CKR_OK;
err:
    return rv;
}

CK_RV general_finalize(void *reserved) {

    if (reserved) {
        return CKR_ARGUMENTS_BAD;
    }

    _g_is_init = false;

    slot_destroy();
    backend_destroy();

    return CKR_OK;
}
