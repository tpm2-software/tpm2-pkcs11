/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */

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
#include "test.h"

/**
 * C_Login logs a user into a token.
 * hSession is a session handle; userType is the user type; pPin points to the user’s PIN; ulPinLen is the length of the PIN.
 * If the application calling C_Login has a R/O session open with the token, then it will be unable to log the SO into a session
 * An attempt to do this will result in the error code CKR_SESSION_READ_ONLY_EXISTS.
 * C_Login may be called repeatedly, without intervening C_Logout calls, if (and only if) a key with the CKA_ALWAYS_AUTHENTICATE attribute
 * set to CK_TRUE exists, and the user needs to do cryptographic operation on this key.
 */
//Normal SO Login and Logout
void test_so_login_logout_good(CK_SESSION_HANDLE hSession) {

    unsigned char sopin[] = "mysopin";

    CK_RV rv = C_Login(hSession, CKU_SO, sopin, sizeof(sopin) - 1);
    if(rv != CKR_OK){
        LOGE("C_Login failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Logout(hSession);
    if(rv != CKR_OK){
        LOGE("C_Logout failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_so_login_logout_good Test Passed!");
}

// Normal user login and logout
void test_user_login_logout_good(CK_SESSION_HANDLE hSession) {

    unsigned char upin[] = "myuserpin";

    CK_RV rv = C_Login(hSession, CKU_USER, upin, sizeof(upin) - 1);
    if(rv != CKR_OK){
        LOGE("C_Login failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Logout(hSession);
    if(rv != CKR_OK){
        LOGE("C_Logout failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_user_login_logout_good Test Passed!");
}

// Login with Incorrect user PIN
void test_user_login_incorrect_pin(CK_SESSION_HANDLE hSession) {

    unsigned char upin[] = "myBADuserpin";

    CK_RV rv = C_Login(hSession, CKU_USER, upin, sizeof(upin) - 1);
    if(rv != CKR_PIN_INCORRECT){
        LOGE("C_Login with Incorrect User PIN failed! Response Code %x", rv);
        exit(1);
    }
    LOGV("test_user_login_incorrect_pin Test Passed!");

}

//Login with incorrect SO PIN
void test_so_login_incorrect_pin(CK_SESSION_HANDLE hSession) {

    unsigned char sopin[] = "myBADsopin";

    CK_RV rv = C_Login(hSession, CKU_SO, sopin, sizeof(sopin) - 1);
    if(rv != CKR_PIN_INCORRECT){
        LOGE("C_Login with Incorrect SO PIN failed! Response Code %x", rv);
        exit(1);
    }
    LOGV("test_so_login_incorrect_pin Test Passed!");
}

// Invalid Logout tests
void test_logout_bad(CK_SESSION_HANDLE hSession) {

    // Logout without Login
    CK_RV rv = C_Logout(hSession);
    if(rv != CKR_USER_NOT_LOGGED_IN){
        LOGE("C_Logout without Login failed! Response Code %x", rv);
        exit(1);
    }

    // Logout with an Invalid Session
    rv = C_Logout((CK_ULONG)-10);
    if (rv != CKR_SESSION_HANDLE_INVALID){
        LOGE("C_Logout with Invalid Session failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_logout_bad Test Passed!");
}

// Other invalid Login tests
void test_login_bad(CK_SESSION_HANDLE hSession){

    unsigned char upin[] = "myuserpin";

    // Invalid Session
    CK_RV rv = C_Login((CK_ULONG)-10, CKU_USER, upin, sizeof(upin) - 1);
    if(rv != CKR_SESSION_HANDLE_INVALID){
        LOGE("C_Login with Invalid Session failed! Response Code %x", rv);
        exit(1);
    }

    //Invalid User Type
    rv = C_Login(hSession, (CK_ULONG)-10, upin, sizeof(upin) - 1);
    if (rv != CKR_USER_TYPE_INVALID){
        LOGE("C_Login with Invalid User Type failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_login_bad Test Passed!");
}

// Login when user is already logged in
void test_so_login_already_logged_in(CK_SESSION_HANDLE hSession) {

    unsigned char sopin[] = "mysopin";

    CK_RV rv = C_Login(hSession, CKU_SO, sopin, sizeof(sopin) - 1);
    if(rv != CKR_OK){
        LOGE("C_Login failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Login(hSession, CKU_SO, sopin, sizeof(sopin) - 1);
    if(rv != CKR_USER_ALREADY_LOGGED_IN){
        LOGE("C_Login when already logged in failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Logout(hSession);
    if(rv != CKR_OK){
        LOGE("C_Logout failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_so_login_logout_good Test Passed!");
}

int test_invoke() {

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

    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL , NULL, &handle);
//    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL , NULL, &handle);

    if (rv == CKR_OK)
	LOGV("C_OpenSession was successful");
    else
	LOGE("C_OpenSession was unsuccessful");

    test_so_login_logout_good(handle);
    test_user_login_logout_good(handle);
    test_user_login_incorrect_pin(handle);
    test_so_login_incorrect_pin(handle);
    test_login_bad(handle);
    test_logout_bad(handle);
    test_so_login_already_logged_in(handle);

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
