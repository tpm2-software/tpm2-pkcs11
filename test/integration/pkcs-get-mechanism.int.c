/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
/* SPDX-License-Identifier: BSD-2 */

#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <assert.h>

#include <tss2/tss2_sys.h>

#define LOGMODULE test
#include "log.h"
#include "pkcs11.h"
#include "db.h"

/**
 * C_GetMechanismList is used to obtain a list of mechanism types supported by a token.
 * SlotID is the ID of the token’s slot; pulCount points to the location that receives the number of mechanisms.
 * There are two ways for an application to call C_GetMechanismList:
 * 1. If pMechanismList is NULL_PTR, then all that C_GetMechanismList does is return (in *pulCount) the number of mechanisms,
 *  without actually returning a list of mechanisms.  The contents of *pulCount on entry to C_GetMechanismList has no meaning
 *  in this case, and the call returns the value CKR_OK.
 * 2. If pMechanismList is not NULL_PTR, then *pulCount MUST contain the size (in terms of CK_MECHANISM_TYPE elements) of the
 *  buffer pointed to by pMechanismList.  If that buffer is large enough to hold the list of mechanisms, then the list is returned in it,
 *  and CKR_OK is returned.  If not, then the call to C_GetMechanismList returns the value CKR_BUFFER_TOO_SMALL.
 *  In either case, the value *pulCount is set to hold the number of mechanisms.
 * Because C_GetMechanismList does not allocate any space of its own, an application will often call C_GetMechanismList twice.
 * However, this behavior is by no means required.
 */
void test_get_mechanism_list_good(CK_SLOT_ID slot_id) {

    unsigned long mech_cnt;

    // Only return the number of mechanisms
    CK_RV rv = C_GetMechanismList(slot_id, NULL, &mech_cnt);
    if ( rv != CKR_OK)
    {
        LOGE("C_GetMechanismList failed! Response Code %x", rv);
        exit(1);
    }

    CK_MECHANISM_TYPE_PTR mechs = malloc(mech_cnt * sizeof(CK_MECHANISM_TYPE));

    // Return List of mechanisms
    rv = C_GetMechanismList(slot_id, mechs, &mech_cnt);
    if ( rv != CKR_OK)
    {
        LOGE("C_GetMechanismList failed! Response Code %x", rv);
        free(mechs);
        exit(1);
    }

    free(mechs);
    LOGV("test_get_mechanism_list_good Test Passed!");
}

void test_get_mechanism_list_bad(CK_SLOT_ID slot_id) {

    unsigned long mech_cnt;

    // Invalid Slot
    CK_RV rv = C_GetMechanismList((CK_ULONG)-10, NULL, &mech_cnt);
    if ( rv != CKR_SLOT_ID_INVALID)
    {
        LOGE("C_GetMechanismList failed for Invalid Slot id! Response Code %x", rv);
        exit(1);
    }
    LOGV("Invalid slot passed");
    // NULL Arguments
    rv = C_GetMechanismList(slot_id, NULL, NULL);
    if ( rv != CKR_ARGUMENTS_BAD)
    {
        LOGE("C_GetMechanismList failed for Invalid Arguments! Response Code %x", rv);
        exit(1);
    }

    // No buffer
    rv = C_GetMechanismList(slot_id, NULL, &mech_cnt);
    if ( rv != CKR_OK)
    {
        LOGE("C_GetMechanismList failed for No buffer! Response Code %x", rv);
        exit(1);
    }

    CK_MECHANISM_TYPE_PTR mechs = malloc(mech_cnt * sizeof(CK_MECHANISM_TYPE));

    // Zero count but buffer present
    unsigned long value = 0;
    rv = C_GetMechanismList(slot_id, mechs, &value);
    if ( rv != CKR_BUFFER_TOO_SMALL)
    {
        LOGE("C_GetMechanismList failed for Zero count! Response Code %x", rv);
        free(mechs);
        exit(1);
    }

    // Low count but buffer present
    value = 1;
    rv = C_GetMechanismList(slot_id, mechs, &value);
    if ( rv != CKR_BUFFER_TOO_SMALL)
    {
        LOGE("C_GetMechanismList failed for Low count! Response Code %x", rv);
        free(mechs);
        exit(1);
    }

    free(mechs);
    LOGV("test_get_mechanism_list_bad Test Passed!");
}

/**
 * C_GetMechanismInfo obtains information about a particular mechanism possibly supported by a token.
 * slotID is the ID of the token’s slot; type is the type of mechanism; pInfo points to the location that receives the mechanism
 * information.
 */
void test_get_mechanism_info_good(CK_SLOT_ID slot_id) {

    CK_MECHANISM_INFO mech_info;

    CK_RV rv = C_GetMechanismInfo(slot_id, CKM_AES_KEY_GEN, &mech_info);
    if ( rv != CKR_OK){
        LOGE("C_GetMechanismInfo failed! Response Code %x", rv);
        exit(1);
    }

    if ( mech_info.ulMaxKeySize != 512){
        LOGE("C_GetMechanismInfo failed, Mechanism max key size is wrong! Response Code %x", rv);
        exit(1);
    }

    if ( mech_info.ulMinKeySize != 128){
        LOGE("C_GetMechanismInfo failed, Mechanism min key size is wrong! Response Code %x", rv);
        exit(1);
    }

    if ( mech_info.flags != 0){
        LOGE("C_GetMechanismInfo failed, Mechanism flags are wrong! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_get_mechanism_info_good Test Passed!");
}

void test_get_mechanism_info_bad(CK_SLOT_ID slot_id) {

    CK_MECHANISM_INFO mech_info;

    // Invalid mechanism
    CK_RV rv = C_GetMechanismInfo(slot_id, (CK_ULONG)-10, &mech_info);
    if ( rv != CKR_MECHANISM_INVALID ){
        LOGE("C_GetMechanismInfo failed for Invalid Mechanism! Response Code %x", rv);
        exit(1);
    }

    // NULL Arguments
    rv = C_GetMechanismInfo(slot_id, CKM_AES_KEY_GEN, NULL);
    if ( rv != CKR_ARGUMENTS_BAD ){
        LOGE("C_GetMechanismInfo failed for NULL Arguments! Response Code %x", rv);
        exit(1);
    }

    // Invalid slot ID
    rv = C_GetMechanismInfo((CK_ULONG)-10, CKM_AES_KEY_GEN, &mech_info);
    if ( rv != CKR_SLOT_ID_INVALID ){
        LOGE("C_GetMechanismInfo failed for Invalid Slot ID! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_get_mechanism_info_bad Test Passed!");
}

int main() {

    CK_RV rv = C_Initialize(NULL);
    if (rv == CKR_OK)
	LOGV("Initialize was successful");
    else
	LOGE("Initialize was unsuccessful");

    CK_SLOT_ID slots[6];
    unsigned long count = ARRAY_LEN(slots);
    rv = C_GetSlotList(true, slots, &count);
    if (rv == CKR_OK)
	LOGV("C_GetSlotList was successful");
    else
	LOGE("C_GetSlotList was unsuccessful");

    CK_SESSION_HANDLE handle;

    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL , NULL, &handle);
    if (rv == CKR_OK)
	LOGV("C_OpenSession was successful");
    else
	LOGE("C_OpenSession was unsuccessful");

    test_get_mechanism_list_good(slots[0]);
    test_get_mechanism_list_bad(slots[0]);

    rv = C_CloseSession(handle);
    if (rv == CKR_OK)
	LOGV("C_CloseSession was successful");
    else
	LOGE("C_CloseSession was unsuccessful");

    rv = C_Finalize(NULL);
    if (rv == CKR_OK)
	LOGV("C_Finalize was successful");
    else
	LOGE("C_Finalize was unsuccessful");

    return 0;
}
