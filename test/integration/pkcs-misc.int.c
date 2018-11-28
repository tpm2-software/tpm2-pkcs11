/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <assert.h>

#include <tss2/tss2_sys.h>

#define LOGMODULE test
#include "log.h"
#include "pkcs11.h"
#include "db.h"

void test_c_getfunctionlist() {

    //Case 1: Successfully obtain function list
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_RV rv = C_GetFunctionList(&pFunctionList);
    if (rv != CKR_OK) {
        LOGE("C_GetFunctionList failed for Case 1! Response Code %x", rv);
        exit(1);
    }

    //Case 2: Null to obtain gunction list
    rv = C_GetFunctionList(NULL);
    if (rv != CKR_ARGUMENTS_BAD) {
        LOGE("C_GetFunctionList failed for Case 2! Response Code %x", rv);
        exit(1);
    }
    LOGV("test_c_getfunctionlist Test Passed!");
}

void test_get_slot_list() {

    CK_SLOT_ID slots[6];
    unsigned long count;
    // Case 1: Good test to get the count of slots
    CK_RV rv = C_GetSlotList(true, NULL, &count);
    if (rv != CKR_OK) {
        LOGE("C_GetSlotList failed for Case 1! Response Code %x", rv);
        exit(1);
    }

    // Case 2: Good test to get the slots in buffer
    rv = C_GetSlotList(true, slots, &count);
    if (rv != CKR_OK) {
        LOGE("C_GetSlotList failed for Case 2! Response Code %x", rv);
        exit(1);
    }
    CK_SLOT_INFO sinfo;
    rv = C_GetSlotInfo(slots[0], &sinfo);
    if (rv != CKR_OK) {
        LOGE("C_GetSlotInfo failed for Case 2! Response Code %x", rv);
        exit(1);
    }
    if (!(sinfo.flags & CKF_TOKEN_PRESENT)){
        LOGE("C_GetSlotInfo failed for Case 2! CKF_TOKEN_PRESENT flag is missing");
        exit(1);
    }
    if (!(sinfo.flags & CKF_HW_SLOT)){
        LOGE("C_GetSlotInfo failed for Case 2! CKF_HW_SLOT flag is missing");
        exit(1);
    }

    CK_TOKEN_INFO tinfo;
    rv = C_GetTokenInfo(slots[0], &tinfo);
    if (rv != CKR_OK) {
        LOGE("C_GetTokenInfo failed for Case 2! Response Code %x", rv);
        exit(1);
    }
    if (!(tinfo.flags & CKF_RNG)){
        LOGE("C_GetTokenInfo failed for Case 2! CKF_RING flag is missing");
        exit(1);
    }
    if (!(tinfo.flags & CKF_TOKEN_INITIALIZED)){
        LOGE("C_GetTokenInfo failed for Case 2! CKF_TOKEN_INITIALIZED flag is missing");
        exit(1);
    }

    LOGV("test_get_slot_list test Passed!");
}

void test_random(CK_SESSION_HANDLE hSession) {

    unsigned char buf[4];

    // Case 1: Good test
    CK_RV rv = C_GenerateRandom(hSession++, buf, 4);
    if(rv != CKR_OK){
        LOGE("C_GenerateRandom failed for Case 1! Response Code %x", rv);
        exit(1);
    }

    // Case 2: Test bad session
    rv = C_GenerateRandom(hSession, buf, 4);
    if(rv != CKR_SESSION_HANDLE_INVALID){
        LOGE("C_GenerateRandom failed for Case 2! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_random test Passed!");
}

void test_seed(CK_SESSION_HANDLE hSession) {

    unsigned char buf[]="ksadjfhjkhfsiudgfkjewsdjbkfcoidugshbvfewug";

    CK_RV rv = C_SeedRandom(hSession, buf, sizeof(buf));
    if(rv != CKR_OK){
        LOGE("C_GenerateRandom failed for Case 1! Response Code %x", rv);
        exit(1);
    }
    LOGV("test_seed test Passed!");
}

void test_get_session_info (CK_SESSION_HANDLE session) {

    CK_SESSION_INFO info;
    CK_RV rv = C_GetSessionInfo(session, &info);

    if (rv != CKR_OK){
        LOGE("C_GetSessionInfo failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_get_session_info test Passed!");
}

void test_digest_good(CK_SESSION_HANDLE session) {

    /* now that we have an object, login */
    unsigned char upin[] = "myuserpin";
    CK_RV rv = C_Login(session, CKU_USER, upin, sizeof(upin) - 1);
    if (rv != CKR_OK){
        LOGE("C_Login failed! Response Code %x", rv);
        exit(1);
    }

    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    rv = C_DigestInit(session, &smech);
    if (rv != CKR_OK){
        LOGE("C_DigestInit failed! Response Code %x", rv);
        exit(1);
    }

    // sizeof a sha256 hash
    unsigned char data[] = "Hello World This is My First Digest Message";

    unsigned char hash[32];
    unsigned long hashlen = sizeof(hash);

    rv = C_DigestUpdate(session, data, sizeof(data) - 1);
    if (rv != CKR_OK){
        LOGE("C_DigestUpdate failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_DigestFinal(session, hash, &hashlen);
    if (rv != CKR_OK){
        LOGE("C_DigestFinal failed! Response Code %x", rv);
        exit(1);
    }

    unsigned char hash2[32];
    unsigned long hash2len = sizeof(hash);

    rv = C_DigestInit(session, &smech);
    if (rv != CKR_OK){
        LOGE("C_DigestInit failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Digest(session, data, sizeof(data) - 1, hash2, &hash2len);
    if (rv != CKR_OK){
        LOGE("C_Digest failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Logout(session);
    if (rv != CKR_OK){
        LOGE("C_Logout failed! Response Code %x", rv);
        exit(1);
    }
    LOGV("test_digest_good test Passed!");
}

static void test_session_cnt(CK_SLOT_ID slot) {

    size_t i;
    CK_RV rv;
    CK_TOKEN_INFO info;

    CK_ULONG cnt = 0;
    CK_ULONG rw_cnt = 0;

    CK_SESSION_HANDLE handles[6];

    /*
     * Test incrementing
     */
    for (i=0; i < ARRAY_LEN(handles); i++) {
        CK_SESSION_HANDLE *handle = &handles[i];
        /*
         * Every odd open up a RW session, every even open up a RO session
         */
        CK_FLAGS flags = CKF_SERIAL_SESSION;
        flags |= (i & 1) ? CKF_RW_SESSION : 0;

        rv = C_OpenSession(slot, flags, NULL , NULL, handle);
        if (rv != CKR_OK) {
            LOGE("C_OpenSession was unsuccessful: 0x%x", rv);
            exit(1);
        }

        /*
         * For clarity, just track the sessions here rather than
         * doing computing it off of i.
         */
        if (i & 1) {
            rw_cnt++;
        }

        cnt++;

        rv = C_GetTokenInfo(slot, &info);
        if (rv != CKR_OK) {
            LOGE("C_GetTokenInfo was unsuccessful: 0x%x", rv);
            exit(1);
        }

        if (info.ulSessionCount != cnt) {
            LOGE("ulSessionCount %lu != expected %lu",
                    info.ulSessionCount, cnt);
            exit (1);
        }

        if (info.ulRwSessionCount != rw_cnt) {
            LOGE("ulRwSessionCount %lu != expected %lu",
                    info.ulRwSessionCount, rw_cnt);
            exit (1);
        }
    }

    /*
     * Test decrementing, but only decrement all but 2, so we can test
     * closeall.
     *
     * rw_cnt and cnt are properly in the state of current open handles, so
     * just use them from above.
     */
    for (i=0; i < (ARRAY_LEN(handles) - 2); i++) {
        CK_SESSION_HANDLE handle = handles[i];

        rv = C_CloseSession(handle);
        if (rv != CKR_OK) {
            LOGE("C_OpenSession was unsuccessful: 0x%x", rv);
            exit(1);
        }

        /*
         * For clarity, just track the sessions here rather than
         * doing computing it off of i. Remember that odd indexed
         * handles are R/W.
         */
        if (i & 1) {
            rw_cnt--;
        }

        cnt--;

        rv = C_GetTokenInfo(slot, &info);
        if (rv != CKR_OK) {
            LOGE("C_GetTokenInfo was unsuccessful: 0x%x", rv);
            exit(1);
        }

        if (info.ulSessionCount != cnt) {
            LOGE("ulSessionCount %lu != expected %lu");
            exit (1);
        }

        if (info.ulRwSessionCount != rw_cnt) {
            LOGE("ulRwSessionCount %lu != expected %lu");
            exit (1);
        }
    }

    /*
     * test closeall brings it 0
     */
    rv = C_CloseAllSessions(slot);
    if (rv != CKR_OK) {
        LOGE("C_CloseAllSessions was unsuccessful: 0x%x", rv);
        exit(1);
    }

    rv = C_GetTokenInfo(slot, &info);
    if (rv != CKR_OK) {
        LOGE("C_GetTokenInfo was unsuccessful: 0x%x", rv);
        exit(1);
    }

    if (info.ulSessionCount != 0) {
        LOGE("ulSessionCount %lu != expected %lu");
        exit (1);
    }

    if (info.ulRwSessionCount != 0) {
        LOGE("ulRwSessionCount %lu != expected %lu");
        exit (1);
    }
}

int main() {

    CK_RV rv = C_Initialize(NULL);
    if (rv == CKR_OK)
        LOGV("Initialize was successful");
    else
        LOGV("Initialize was unsuccessful");

    CK_SLOT_ID slots[6];
    unsigned long count = ARRAY_LEN(slots);
    rv = C_GetSlotList(true, slots, &count);
    if (rv == CKR_OK)
        LOGV("C_GetSlotList was successful");
    else
        LOGV("C_GetSlotList was unsuccessful");

    CK_SESSION_HANDLE handle;

    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL , NULL, &handle);
    if (rv == CKR_OK)
        LOGV("C_OpenSession was successful");
    else
        LOGV("C_OpenSession was unsuccessful");

    test_c_getfunctionlist();
    test_get_slot_list();
    test_seed(handle);
    test_random(handle);
    test_get_session_info(handle);
    test_digest_good(handle);

    rv = C_CloseSession(handle);
    if (rv == CKR_OK)
        LOGV("C_CloseSession was successful");
    else
        LOGV("C_CloseSession was unsuccessful");

    /*
     * Test session handle count
     */
    test_session_cnt(slots[0]);

    rv = C_Finalize(NULL);
    if (rv == CKR_OK)
        LOGV("C_Finalize was successful");
    else
        LOGV("C_Finalize was unsuccessful");

    return 0;
}
