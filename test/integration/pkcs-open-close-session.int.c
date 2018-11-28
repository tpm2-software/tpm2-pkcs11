/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include <tss2/tss2_sys.h>

#define LOGMODULE test
#include "log.h"
#include "pkcs11.h"
#include "db.h"

/*
 * Test that a C_OpenSession and C_CloseSession work as expected (ie return code CKR_OK).
 */
static void test_session_open_close(CK_SLOT_ID slotid) {

    CK_SESSION_HANDLE handle;
    CK_RV rv = C_OpenSession(slotid, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL , NULL, &handle);
    if(rv != CKR_OK){
        LOGE("C_OpenSession failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_CloseSession(handle);
    if(rv != CKR_OK){
        LOGE("C_CloseSession failed! Response Code %x", rv);
        exit(1);
    }
}

/*
 * Make sure that a C_CloseAllSessions() only closes sessions on the token in the
 * slot.
 */
static void test_session_open_close_all(CK_SLOT_ID *slots, unsigned long count) {

    CK_RV rv;
    CK_SESSION_INFO info;

    if (count < 2) {
        LOGE("test_session_open_close_all expects at least 2 slots configured, found %lu", count);
        exit(1);
    }

    CK_SESSION_HANDLE handle[2];

    unsigned i;
    for (i = 0; i < ARRAY_LEN(handle); i++) {

        rv = C_OpenSession(slots[i], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL , NULL, &handle[i]);
        if(rv != CKR_OK){
            LOGE("C_OpenSession failed! Response Code %x", rv);
            exit(1);
        }
    }

    /*
     * Verify *BOTH* sessions work
     */
    for (i = 0; i < ARRAY_LEN(handle); i++) {

        rv = C_GetSessionInfo(handle[i], &info);
        if(rv != CKR_OK){
            LOGE("C_GetSessionInfo failed! Response Code %x", rv);
            exit(1);
        }
    }

    /*
     * Close ALL session handles on slots[0] (handle[0]) and verify it doesn't work
     */
    rv = C_CloseAllSessions(slots[0]);
    if(rv != CKR_OK){
        LOGE("C_CloseSession failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_GetSessionInfo(handle[0], &info);
    if(rv != CKR_SESSION_HANDLE_INVALID){
        LOGE("C_GetSessionInfo expected to fail with"
                " CKR_SESSION_HANDLE_INVALID"
                ", got response Code %x", rv);
        exit(1);
    }

    /*
     * Verify that session handle[1] from slot[1] works still
     */
    rv = C_GetSessionInfo(handle[1], &info);
    if(rv != CKR_OK){
        LOGE("C_GetSessionInfo failed! Response Code %x", rv);
        exit(1);
    }

    /*
     * Close sessions on slots[1]
     */
    rv = C_CloseAllSessions(slots[1]);
    if(rv != CKR_OK){
        LOGE("C_CloseSession failed! Response Code %x", rv);
        exit(1);
    }

    /*
     * verify it doesn't work
     */
    rv = C_GetSessionInfo(handle[1], &info);
    if(rv != CKR_SESSION_HANDLE_INVALID){
        LOGE("C_GetSessionInfo expected to fail with"
                " CKR_SESSION_HANDLE_INVALID"
                ", got response Code %x", rv);
        exit(1);
    }
}


int main() {

    CK_RV rv = C_Initialize(NULL);
    if(rv != CKR_OK){
        LOGE("C_Initialize failed! Response Code %x", rv);
        exit(1);
    }

    CK_SLOT_ID slots[6];
    unsigned long count = ARRAY_LEN(slots);
    rv = C_GetSlotList(true, slots, &count);
    if(rv != CKR_OK){
        LOGE("C_GetSlotList failed! Response Code %x", rv);
        exit(1);
    }

    test_session_open_close(slots[0]);

    test_session_open_close_all(slots, count);

    rv = C_Finalize(NULL);
    if(rv != CKR_OK){
        LOGE("C_Finalize failed! Response Code %x", rv);
        exit(1);
    }

    return 0;
}


