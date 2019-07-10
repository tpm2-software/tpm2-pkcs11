/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */

#include <tss2/tss2_fapi.h>

#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "checks.h"
#include "list.h"
#include "session.h"
#include "mutex.h"
#include "pkcs11.h"
#include "slot.h"
#include "tpm.h"
#include "token.h"
#include "utils.h"

CK_RV token_get_info (CK_SLOT_ID slot_id, CK_TOKEN_INFO *info) {
    TSS2_RC rc;
    FAPI_CONTEXT *fctx;

    char *label, *path;
    check_pointer(info);

    //TODO: get token infos from tpm

    memset(info, 0, sizeof(*info));

    strcpy((char *)&info->manufacturerID[0], "TODO TPM");
    strcpy((char *)&info->model[0], "TODO");
    strcpy((char *)&info->serialNumber[0], "TODO");

    info->flags = CKF_RNG;

    // Counts
    info->ulMaxSessionCount = info->ulMaxRwSessionCount = 1;
    info->ulSessionCount = info->ulRwSessionCount = 0; //TODO if a session is open
    info->ulMaxPinLen = 20;
    info->ulMinPinLen = 4;

    // Memory: TODO not sure what memory values should go here; just 1 meg for now
    info->ulTotalPublicMemory = 1048576;
    info->ulFreePublicMemory = 1048575;
    info->ulTotalPrivateMemory = 1048576;
    info->ulFreePrivateMemory = 1048575;

    // Hardware information from the TPM
    info->hardwareVersion.major = 0; //TODO tpm values
    info->hardwareVersion.minor = 0;
    info->firmwareVersion.major = 0;
    info->firmwareVersion.minor = 0;

    // Time
    info->utcTime[0] = 0; // We don't set CKF_CLOCK_ON_TOKEN

    if (slot_id == emptyTokenSlot) {
        strcpy((char *)&info->label[0], "Uninitialized");
    } else if ((slot_id & EMPTY_TOKEN_BIT) != 0) {
        LOGE("This should not happen, a bit-set slot_id; emptyTokenSlot is %x", emptyTokenSlot);
        return CKR_GENERAL_ERROR;
    } else {
        path = tss_path_from_id(slot_id);
        check_pointer(path);

        rc = Fapi_Initialize(&fctx, NULL);
        check_tssrc(rc, return CKR_GENERAL_ERROR);

        rc = Fapi_GetDescription(fctx, path, &label);
        Fapi_Finalize(&fctx);
        check_tssrc(rc, return CKR_GENERAL_ERROR);

        memset(&info->label[0], ' ', 32);
        strncpy((char *)&info->label[0], label, 32);
        free(label);
        info->flags |= CKF_LOGIN_REQUIRED;
        info->flags |= CKF_TOKEN_INITIALIZED;

        //TODO: Check for noda-counter
        info->flags |= CKF_USER_PIN_LOCKED;

        //TODO: Check for user seal token info->flags |= CKF_USER_PIN_INITIALIZED;
        info->flags |= CKF_USER_PIN_TO_BE_CHANGED;

        //TODO: Check for noda-counter
        //info->flags |= CKF_SO_PIN_LOCKED;
    }

    return CKR_OK;
}

CK_RV token_init(CK_SLOT_ID slot_id, CK_BYTE_PTR pin, CK_ULONG pin_len,
                 CK_BYTE_PTR label) {
    char *path, *tmppin;
    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    char labelstr[33];

    check_pointer(pin);
    check_pointer(label);

    LOGV("slotid=%x", slot_id);
    if (slot_id != emptyTokenSlot || emptyTokenSlot == 0) {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    path = tss_path_from_id(slot_id & ~EMPTY_TOKEN_BIT);
    check_pointer(path);

    tmppin = malloc(pin_len + 1);
    check_pointer(tmppin);
    memcpy(&tmppin[0], pin, pin_len);
    tmppin[pin_len] = '\0';

    memcpy(&labelstr[0], label, 32);
    labelstr[32] = '\0';

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, goto cleanup);

    rc = Fapi_CreateSeal(fctx, path, NULL /*type*/, 64, NULL /*policy*/, tmppin, NULL /*data*/);
    check_tssrc(rc, goto cleanup);

    rc = Fapi_SetDescription(fctx, path, &labelstr[0]);
    check_tssrc(rc, goto cleanup);

    emptyTokenSlot = 0;
cleanup:
    Fapi_Finalize(&fctx);
    free(path);
    free(tmppin);
    return (rc == TSS2_RC_SUCCESS)? CKR_OK : CKR_GENERAL_ERROR;
}


/*
CK_RV token_get_info (token *t, CK_TOKEN_INFO *info) {
    check_pointer(t);
    check_pointer(info);
    int rval;
    time_t rawtime;
    struct tm tminfo;

    memset(info, 0, sizeof(*info));

    rval = tpm_get_token_info(t->tctx, info);
    if (rval != CKR_OK) {
        return CKR_GENERAL_ERROR;
    }

    // Support Flags
    info->flags = CKF_RNG
        | CKF_LOGIN_REQUIRED;

    if (t->config.is_initialized) {
        info->flags |= CKF_TOKEN_INITIALIZED;
        info->flags |= CKF_USER_PIN_INITIALIZED;
    }

    // Identification
    str_padded_copy(info->label, t->label, sizeof(info->label));
    str_padded_copy(info->serialNumber, (unsigned char*) TPM2_TOKEN_SERIAL_NUMBER, sizeof(info->serialNumber));


    // Memory: TODO not sure what memory values should go here, the platform?
    info->ulFreePrivateMemory = ~0;
    info->ulFreePublicMemory = ~0;
    info->ulTotalPrivateMemory = ~0;
    info->ulTotalPublicMemory = ~0;

    // Maximums and Minimums
    info->ulMaxPinLen = 128;
    info->ulMinPinLen = 5;
    info->ulMaxSessionCount = MAX_NUM_OF_SESSIONS;
    info->ulMaxRwSessionCount = MAX_NUM_OF_SESSIONS;

    // Session
    session_table_get_cnt(t->s_table, &info->ulSessionCount, &info->ulRwSessionCount, NULL);

    // Time
    time (&rawtime);
    gmtime_r(&rawtime, &tminfo);
    strftime ((char *)info->utcTime, sizeof(info->utcTime), "%Y%m%d%H%M%S", &tminfo);
    // The last two bytes must be '0', not NULL/'\0' terminated.
    info->utcTime[14] = '0';
    info->utcTime[15] = '0';

    return CKR_OK;
}
*/

void token_lock(token *t) {
    mutex_lock_fatal(t->mutex);
}

void token_unlock(token *t) {
    mutex_unlock_fatal(t->mutex);
}

CK_RV token_setpin(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR oldpin, CK_ULONG oldlen,
                   CK_UTF8CHAR_PTR newpin, CK_ULONG newlen) {

    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    char *path, *pinstring;
    (void)(newlen);

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    // TODO Handle CKU_CONTEXT_SPECIFIC
    // TODO Support CKA_ALWAYS_AUTHENTICATE
    switch(session_tab[session].user_type) {
        case CKU_SO:
            path = tss_path_from_id(session_tab[session].slot_id);
            break;
        case CKU_USER:
            path = tss_userpath_from_id(session_tab[session].slot_id);
            break;
        case CKU_CONTEXT_SPECIFIC:
            return CKR_USER_TYPE_INVALID;
            break;
        default:
            return CKR_USER_TYPE_INVALID;
    }

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    pinstring = malloc(oldlen + 1);
    memcpy(pinstring, oldpin, oldlen);
    pinstring[oldlen] = '\0';

    rc = Fapi_SetAuthCB(fctx, auth_cb, pinstring);
    check_tssrc(rc, Fapi_Finalize(&fctx); free(pinstring); return CKR_GENERAL_ERROR);

    rc = Fapi_ChangeAuth(fctx, path, (const char *) newpin);
    free(pinstring);
    Fapi_Finalize(&fctx);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    return CKR_OK;
}

CK_RV token_initpin(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR newpin, CK_ULONG newlen) {
    CK_RV r;
    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    const uint8_t *seal;
    char *path = NULL;
    CK_SLOT_ID slot_id;
    (void)(newlen);

    check_pointer(newpin);

    r = session_getseal(session, &seal);
    if (r != CKR_OK) {
        LOGE("Session error");
        return r;
    }

    r = session_getslot(session, &slot_id);
    if (r != CKR_OK) {
        LOGE("Session error");
        return r;
    }

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    path = tss_userpath_from_id(slot_id);
    rc = Fapi_CreateSeal(fctx, path, NULL /*type*/, 64, NULL /*policy*/,
                         (const char *)newpin, seal);
    check_tssrc(rc, goto cleanup);

    rc = Fapi_SetDescription(fctx, path, "User token");
    check_tssrc(rc, goto cleanup);

cleanup:
    Fapi_Finalize(&fctx);
    if (path) free(path);
    return (rc == TSS2_RC_SUCCESS)? CKR_OK : CKR_GENERAL_ERROR;
}
