/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#ifndef TEST_INTEGRATION_TEST_H_
#define TEST_INTEGRATION_TEST_H_

/* Set up ALL the headers needed so tests can just use #include "test.h" */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>
#include <tss2/tss2_sys.h>

#include "pkcs11.h"
#include "utils.h"

#define GOOD_USERPIN "myuserpin"
#define GOOD_SOPIN   "mysopin"

#define BAD_USERPIN "myBADuserpin"
#define BAD_SOPIN   "myBADsopin"

typedef struct test_info test_info;

static inline test_info *test_info_from_state(void **state) {
    return (test_info *)*state;
}

static inline int group_setup(void **state) {
    UNUSED(state);

    /* Initialize the library */
    CK_RV rv = C_Initialize(NULL);
    assert_int_equal(rv, CKR_OK);

    return 0;
}

static inline int group_setup_locking(void **state) {
    UNUSED(state);

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
    assert_int_equal(rv, CKR_OK);

    return 0;
}

static inline int group_teardown(void **state) {
    UNUSED(state);

    /* Finalize the library */
    CK_RV rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    return 0;
}

static inline void logout_expects(CK_SESSION_HANDLE handle, CK_RV expected) {

    CK_RV rv = C_Logout(handle);
    assert_int_equal(rv, expected);
}

static inline void logout(CK_SESSION_HANDLE handle) {

    logout_expects(handle, CKR_OK);
}

static inline void user_login_expects(CK_SESSION_HANDLE handle, CK_RV expected) {

    unsigned char upin[] = GOOD_USERPIN;
    CK_RV rv = C_Login(handle, CKU_USER, upin, sizeof(upin) - 1);
    assert_int_equal(rv, expected);
}

static inline void user_login_bad_pin(CK_SESSION_HANDLE handle) {

    unsigned char upin[] = BAD_USERPIN;
    CK_RV rv = C_Login(handle, CKU_SO, upin, sizeof(upin) - 1);
    assert_int_equal(rv, CKR_PIN_INCORRECT);
}

static inline void user_login(CK_SESSION_HANDLE handle) {

    user_login_expects(handle, CKR_OK);
}

static inline void so_login_expects(CK_SESSION_HANDLE handle, CK_RV expected) {

    unsigned char sopin[] = GOOD_SOPIN;
    CK_RV rv = C_Login(handle, CKU_SO, sopin, sizeof(sopin) - 1);
    assert_int_equal(rv, expected);
}

static inline void so_login(CK_SESSION_HANDLE handle) {

    so_login_expects(handle, CKR_OK);
}

static inline void so_login_bad_pin(CK_SESSION_HANDLE handle) {

    unsigned char sopin[] = BAD_SOPIN;
    CK_RV rv = C_Login(handle, CKU_SO, sopin, sizeof(sopin) - 1);
    assert_int_equal(rv, CKR_PIN_INCORRECT);
}

#endif /* TEST_INTEGRATION_TEST_H_ */
