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

void test_so_on_ro_session(CK_SESSION_HANDLE hSession) {

    unsigned char sopin[] = "mysopin";

    CK_RV rv = C_Login(hSession, CKU_SO, sopin, sizeof(sopin) - 1);
    if(rv != CKR_SESSION_READ_ONLY_EXISTS){
        LOGE("C_Login failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_so_on_ro_session Test Passed!");
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

// SO global login and logout
// Tests whether user is automatically logged in to other sessions for the same slot/token
void test_so_global_login_logout_good(CK_SESSION_HANDLE slot0_session0, CK_SESSION_HANDLE slot0_session1, CK_SESSION_HANDLE slot1_session0) {

    unsigned char sopin[] = "mysopin";

    CK_RV rv = C_Login(slot0_session0, CKU_SO, sopin, sizeof(sopin) - 1);
    if (rv != CKR_OK){
        LOGE("C_Login failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Login(slot0_session1, CKU_SO, sopin, sizeof(sopin) - 1);
    if (rv != CKR_USER_ALREADY_LOGGED_IN) {
        LOGE("C_Login when already logged in failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Logout(slot1_session0);
    if(rv != CKR_USER_NOT_LOGGED_IN){
        LOGE("C_Logout when not logged in failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Logout(slot0_session0);
    if(rv != CKR_OK){
        LOGE("C_Logout failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Logout(slot0_session1);
    if(rv != CKR_USER_NOT_LOGGED_IN){
        LOGE("C_Logout when not logged in failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_user_global_login_logout_good Test Passed!");
}

// Normal user global login and logout
// Tests whether user is automatically logged in to other sessions for the same slot/token
void test_user_global_login_logout_good(CK_SESSION_HANDLE slot0_session0, CK_SESSION_HANDLE slot0_session1, CK_SESSION_HANDLE slot1_session0) {

    unsigned char upin[] = "myuserpin";

    CK_RV rv = C_Login(slot0_session0, CKU_USER, upin, sizeof(upin) - 1);
    if (rv != CKR_OK){
        LOGE("C_Login failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Login(slot0_session1, CKU_USER, upin, sizeof(upin) - 1);
    if (rv != CKR_USER_ALREADY_LOGGED_IN) {
        LOGE("C_Login when already logged in failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Logout(slot1_session0);
    if(rv != CKR_USER_NOT_LOGGED_IN){
        LOGE("C_Logout when not logged in failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Logout(slot0_session0);
    if(rv != CKR_OK){
        LOGE("C_Logout failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_Logout(slot0_session1);
    if(rv != CKR_USER_NOT_LOGGED_IN){
        LOGE("C_Logout when not logged in failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_user_global_login_logout_good Test Passed!");
}

/*
 * Replicate issue https://github.com/tpm2-software/tpm2-pkcs11/issues/81
 *
 * Where a C_OpenSession, C_Login, C_OpenSession, C_Login fails
 */
void test_user_login_logout_time_two(CK_SLOT_ID slotid) {

    /*
     * Open a session
     */
    CK_SESSION_HANDLE handle[3];
    CK_RV rv = C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL , NULL, &handle[0]);
    if (rv != CKR_OK) {
        LOGE("C_OpenSession was unsuccessful");
        exit(1);
    }

    /*
     * State should be CKS_RO_PUBLIC_SESSION
     */
    CK_SESSION_INFO info;
    rv = C_GetSessionInfo(handle[0], &info);
    if(rv != CKR_OK){
        LOGE("C_GetSessionInfo failed! Response Code %x", rv);
        exit(1);
    }

    if (info.state != CKS_RO_PUBLIC_SESSION) {
        LOGE("Expected session state to be %lu, got: %lu!", CKS_RO_PUBLIC_SESSION, info.state);
        exit(1);
    }

    /*
     * Login should cause state to change from:
     * CKS_RO_PUBLIC_SESSION
     * to
     * CKS_RO_USER_FUNCTIONS
     */

    unsigned char upin[] = "myuserpin";

    rv = C_Login(handle[0], CKU_USER, upin, sizeof(upin) - 1);
    if(rv != CKR_OK){
        LOGE("C_Login failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_GetSessionInfo(handle[0], &info);
    if(rv != CKR_OK){
        LOGE("C_GetSessionInfo failed! Response Code %x", rv);
        exit(1);
    }

    if (info.state != CKS_RO_USER_FUNCTIONS) {
        LOGE("Expected session state to be %lu, got: %lu!", CKS_RO_USER_FUNCTIONS, info.state);
        exit(1);
    }

    /*
     * Start another session, state should be CKS_RO_USER_FUNCTIONS
     */
    rv = C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL , NULL, &handle[1]);
    if (rv != CKR_OK) {
        LOGE("C_OpenSession was unsuccessful");
        exit(1);
    }

    rv = C_GetSessionInfo(handle[1], &info);
    if(rv != CKR_OK){
        LOGE("C_GetSessionInfo failed! Response Code %x", rv);
        exit(1);
    }

    if (info.state != CKS_RO_USER_FUNCTIONS) {
        LOGE("Expected session state to be %lu, got: %lu!", CKS_RO_USER_FUNCTIONS, info.state);
        exit(1);
    }

    /*
     * Start another session but R/W, and state should be CKS_RW_USER_FUNCTIONS
     */
    rv = C_OpenSession(slotid, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL , NULL, &handle[2]);
    if (rv != CKR_OK) {
        LOGE("C_OpenSession was unsuccessful");
        exit(1);
    }

    rv = C_GetSessionInfo(handle[2], &info);
    if(rv != CKR_OK){
        LOGE("C_GetSessionInfo failed! Response Code %x", rv);
        exit(1);
    }

    if (info.state != CKS_RW_USER_FUNCTIONS) {
        LOGE("Expected session state to be %lu, got: %lu!", CKS_RW_USER_FUNCTIONS, info.state);
        exit(1);
    }

    /*
     * C_Logout, states should return to CKS_RO_PUBLIC_SESSION
     */
    rv = C_Logout(handle[0]);
    if(rv != CKR_OK){
        LOGE("C_Logout failed! Response Code %x", rv);
        exit(1);
    }

    unsigned i;
    for (i=0; i < ARRAY_LEN(handle); i++) {

        rv = C_GetSessionInfo(handle[i], &info);
        if(rv != CKR_OK){
            LOGE("C_GetSessionInfo failed! Response Code %x", rv);
            exit(1);
        }

        CK_STATE expected = i < 2 ? CKS_RO_PUBLIC_SESSION : CKS_RW_PUBLIC_SESSION;
        if (info.state != expected) {
            LOGE("Expected session state to be %lu, got: %lu!", expected, info.state);
            exit(1);
        }
    }

    rv = C_CloseAllSessions(slotid);
    if (rv != CKR_OK) {
        LOGE("C_CloseAllSessions was unsuccessful");
        exit(1);
    }

    LOGV("test_user_login_logout_time_two Test Passed!");
}

int test_invoke() {

    /*
     * Run these tests with locking enabled
     */
    CK_C_INITIALIZE_ARGS args = {
        .CreateMutex = NULL,
        .DestroyMutex = NULL,
        .LockMutex = NULL,
        .UnlockMutex = NULL,
        .flags = CKF_OS_LOCKING_OK
    };

    CK_RV rv = C_Initialize(&args);
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

    CK_SESSION_HANDLE slot0_session0;
    CK_SESSION_HANDLE slot0_session1;
    CK_SESSION_HANDLE slot1_session0;

    /*
     * Test user R/O sessions
     */
    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL , NULL, &slot0_session0);
    rv += C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL , NULL, &slot0_session1);
    rv += C_OpenSession(slots[1], CKF_SERIAL_SESSION, NULL , NULL, &slot1_session0);
    if (rv == CKR_OK) {
	    LOGV("C_OpenSession was successful");
    } else {
	    LOGE("C_OpenSession was unsuccessful");
    }

    test_user_login_logout_good(slot0_session0);
    test_user_login_incorrect_pin(slot0_session0);

    test_login_bad(slot0_session0);
    test_logout_bad(slot0_session0);

    /*
     * This so test requires an R/O session
     */
    test_so_on_ro_session(slot0_session0);

    /*
     * Test that a C_Login() call propagates to ALL sessions.
     */
    test_user_global_login_logout_good(slot0_session0, slot0_session1, slot1_session0);

    /*
     * Close the RO sessions so we can open a RW session
     * and allow SO login
     */
    rv += C_CloseSession(slot0_session0);
    rv += C_CloseSession(slot0_session1);
    rv += C_CloseSession(slot1_session0);
    if (rv == CKR_OK) {
        LOGV("C_CloseSession was successful");
    } else {
        LOGE("C_CloseSession was unsuccessful");
    }

    /*
     * test SO which requires an R/W session
     */
    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION  | CKF_RW_SESSION,
            NULL , NULL, &slot0_session0);
    rv += C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL , NULL, &slot0_session1);
    rv += C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL , NULL, &slot1_session0);
    if (rv == CKR_OK) {
        LOGV("C_OpenSession was successful");
    } else {
        LOGE("C_OpenSession was unsuccessful");
    }    if (rv == CKR_OK) {
        LOGV("C_OpenSession was successful");
    } else {
        LOGE("C_OpenSession was unsuccessful");
    }

    test_so_login_already_logged_in(slot0_session0);
    test_so_login_logout_good(slot0_session0);
    test_so_login_incorrect_pin(slot0_session0);
    test_so_global_login_logout_good(slot0_session0, slot0_session1, slot1_session0);

    rv += C_CloseSession(slot0_session0);
    rv += C_CloseSession(slot0_session1);
    rv += C_CloseSession(slot1_session0);
    if (rv == CKR_OK) {
        LOGV("C_CloseSession was successful");
    } else {
        LOGE("C_CloseSession was unsuccessful");
    }

    /*
     * Session Slot tests
     */
    test_user_login_logout_time_two(slots[0]);

    rv = C_Finalize(NULL);
    if (rv == CKR_OK)
	LOGV("C_Finalize was successful");
    else
	LOGE("C_Finalize was unsuccessful");

    return 0;
}
