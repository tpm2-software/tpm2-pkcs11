/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <config.h>

#include <stdbool.h>
#include <stdlib.h>

#include "checks.h"
#include "db.h"
#include "general.h"
#include "log.h"
#include "mutex.h"
#include "pkcs11.h"
#include "session.h"

#ifndef VERSION
  #warning "VERSION Not known at compile time, not embedding..."
  #define VERSION "UNKNOWN"
#endif

/* TODO These should probably emanate from the fixed properties
 * via get capability.
 */
#define LIBRARY_DESCRIPTION "TPM2.0 Cryptoki"

#define CRYPTOKI_VERSION { \
           .major = CRYPTOKI_VERSION_MAJOR, \
           .minor = CRYPTOKI_VERSION_MINOR \
         }

CK_RV general_get_info(CK_INFO *info) {

    static CK_INFO _info = {
        .cryptokiVersion = CRYPTOKI_VERSION,
        .manufacturerID = " "TPM2_TOKEN_MANUFACTURER,
        .flags = 0,
        .libraryDescription = " "LIBRARY_DESCRIPTION,
        .libraryVersion = {
            /* TODO get from build VERSION */
            .major = 42,
            .minor = 42
        },
    };

    *info = _info;

    return CKR_OK;
}

CK_RV general_get_func_list(CK_FUNCTION_LIST **function_list) {

    if (function_list == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    static CK_FUNCTION_LIST list = {
         .version = CRYPTOKI_VERSION,
        .C_Initialize = C_Initialize,
        .C_Finalize = C_Finalize,
        .C_GetInfo = C_GetInfo,
        .C_GetFunctionList = C_GetFunctionList,
        .C_GetSlotList = C_GetSlotList,
        .C_GetSlotInfo = C_GetSlotInfo,
        .C_GetTokenInfo = C_GetTokenInfo,
        .C_GetMechanismList = C_GetMechanismList,
        .C_GetMechanismInfo = C_GetMechanismInfo,
        .C_InitToken = C_InitToken,
        .C_InitPIN = C_InitPIN,
        .C_SetPIN = C_SetPIN,
        .C_OpenSession = C_OpenSession,
        .C_CloseSession = C_CloseSession,
        .C_CloseAllSessions = C_CloseAllSessions,
        .C_GetSessionInfo = C_GetSessionInfo,
        .C_GetOperationState = C_GetOperationState,
        .C_SetOperationState = C_SetOperationState,
        .C_Login = C_Login,
        .C_Logout = C_Logout,
        .C_CreateObject = C_CreateObject,
        .C_CopyObject = C_CopyObject,
        .C_DestroyObject = C_DestroyObject,
        .C_GetObjectSize = C_GetObjectSize,
        .C_GetAttributeValue = C_GetAttributeValue,
        .C_SetAttributeValue = C_SetAttributeValue,
        .C_FindObjectsInit = C_FindObjectsInit,
        .C_FindObjects = C_FindObjects,
        .C_FindObjectsFinal = C_FindObjectsFinal,
        .C_EncryptInit = C_EncryptInit,
        .C_Encrypt = C_Encrypt,
        .C_EncryptUpdate = C_EncryptUpdate,
        .C_EncryptFinal = C_EncryptFinal,
        .C_DecryptInit = C_DecryptInit,
        .C_Decrypt = C_Decrypt,
        .C_DecryptUpdate = C_DecryptUpdate,
        .C_DecryptFinal = C_DecryptFinal,
        .C_DigestInit = C_DigestInit,
        .C_Digest = C_Digest,
        .C_DigestUpdate = C_DigestUpdate,
        .C_DigestKey = C_DigestKey,
        .C_DigestFinal = C_DigestFinal,
        .C_SignInit = C_SignInit,
        .C_Sign = C_Sign,
        .C_SignUpdate = C_SignUpdate,
        .C_SignFinal = C_SignFinal,
        .C_SignRecoverInit = C_SignRecoverInit,
        .C_SignRecover = C_SignRecover,
        .C_VerifyInit = C_VerifyInit,
        .C_Verify = C_Verify,
        .C_VerifyUpdate = C_VerifyUpdate,
        .C_VerifyFinal = C_VerifyFinal,
        .C_VerifyRecoverInit = C_VerifyRecoverInit,
        .C_VerifyRecover = C_VerifyRecover,
        .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
        .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
        .C_SignEncryptUpdate = C_SignEncryptUpdate,
        .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
        .C_GenerateKey = C_GenerateKey,
        .C_GenerateKeyPair = C_GenerateKeyPair,
        .C_WrapKey = C_WrapKey,
        .C_UnwrapKey = C_UnwrapKey,
        .C_DeriveKey = C_DeriveKey,
        .C_SeedRandom = C_SeedRandom,
        .C_GenerateRandom = C_GenerateRandom,
        .C_GetFunctionStatus = C_GetFunctionStatus,
        .C_CancelFunction = C_CancelFunction,
        .C_WaitForSlotEvent = C_WaitForSlotEvent,
    };

    *function_list = &list;

    return CKR_OK;
}

static bool _g_is_init;
bool general_is_init(void) {
    return _g_is_init;
}

CK_RV general_init(void *init_args) {

    CK_RV rv = CKR_GENERAL_ERROR;

    if (_g_is_init) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

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
    rv  = tpm_init();
    if (rv != CKR_OK) {
        goto err;
    }

    rv = db_init();
    if (rv != CKR_OK) {
        goto err;
    }

    rv = slot_init();
    if (rv != CKR_OK) {
        goto err;
    }

    _g_is_init = true;

    return CKR_OK;
err:
    tpm_destroy();
    return rv;
}

CK_RV general_finalize(void *reserved) {

    check_is_init();
    if (reserved) {
        return CKR_ARGUMENTS_BAD;
    }

    _g_is_init = false;

    tpm_destroy();
    db_destroy();
    slot_destroy();

    return CKR_OK;
}
