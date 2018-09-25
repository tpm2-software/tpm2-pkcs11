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

#include <tss2/tss2_sys.h>

#define LOGMODULE test
#include "log.h"
#include "pkcs11.h"
#include "db.h"
#include "test.h"

/**
 * This program contains integration test for SAPI Tss2_Sys_GetRandom.
 * First, this test is checking the return code to make sure the
 * SAPI is executed correctly(return code should return TPM2_RC_SUCCESS).
 * Second, the SAPI is called twice to make sure the return randomBytes
 * are different by comparing the two randomBytes through memcmp.
 * It might not be the best test for random bytes generator but
 * at least this test shows the return randomBytes are different.
 */
/*
int
test_invoke ()
{
	//(void) state;
    unsigned char buf[4];
    CK_SESSION_HANDLE session = 0;
    CK_RV rv = C_GenerateRandom(session++, buf, 4);
    if (rv == CKR_OK)
        LOGV("GetRandom Test Passed!");
    else
        LOGV("GetRandom Test Failed");
    return 0;
}
*/

int test_invoke() {

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

    CK_SESSION_HANDLE handle;

    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL , NULL, &handle);
    if(rv != CKR_OK){
        LOGE("C_OpenSession failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_CloseSession(handle);
    if(rv != CKR_OK){
        LOGE("C_CloseSession failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Finalize(NULL);
    if(rv != CKR_OK){
        LOGE("C_Finalize failed! Response Code %x", rv);
        exit(1);
    }

    return 0;
}


