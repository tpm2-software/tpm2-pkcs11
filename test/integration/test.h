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

static inline void login_expects(CK_SESSION_HANDLE handle, CK_USER_TYPE user_type, CK_RV expected, unsigned char *pin, CK_ULONG len) {

    CK_RV rv = C_Login(handle, user_type, pin, len);
    assert_int_equal(rv, expected);
}

static inline void user_login_expects(CK_SESSION_HANDLE handle, CK_RV expected) {

    unsigned char upin[] = GOOD_USERPIN;
    login_expects(handle, CKU_USER, expected, upin, sizeof(upin) - 1);
}

static inline void user_login_bad_pin(CK_SESSION_HANDLE handle) {

    unsigned char upin[] = BAD_USERPIN;
    login_expects(handle, CKU_USER, CKR_PIN_INCORRECT, upin, sizeof(upin) - 1);
}

static inline void user_login(CK_SESSION_HANDLE handle) {

    user_login_expects(handle, CKR_OK);
}

static inline void so_login_expects(CK_SESSION_HANDLE handle, CK_RV expected) {

    unsigned char sopin[] = GOOD_SOPIN;
    login_expects(handle, CKU_SO, expected, sopin, sizeof(sopin) - 1);
}

static inline void so_login(CK_SESSION_HANDLE handle) {

    so_login_expects(handle, CKR_OK);
}

static inline void so_login_bad_pin(CK_SESSION_HANDLE handle) {

    unsigned char sopin[] = BAD_SOPIN;
    login_expects(handle, CKU_SO, CKR_PIN_INCORRECT, sopin, sizeof(sopin) - 1);
}

#define GENERIC_ATTR_TYPE_CONVERT(T) \
    static CK_RV generic_##T(CK_ATTRIBUTE_PTR attr, T *x) { \
    \
        if (attr->ulValueLen != sizeof(*x)) { \
            return CKR_ATTRIBUTE_VALUE_INVALID; \
        } \
    \
        *x = *(T *)attr->pValue; \
    \
        return CKR_OK; \
    }

static void get_keypair(CK_SESSION_HANDLE session, CK_KEY_TYPE key_type, CK_OBJECT_HANDLE_PTR pub_handle, CK_OBJECT_HANDLE_PTR priv_handle) {

    assert_non_null(pub_handle);
    assert_non_null(priv_handle);

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_CLASS, &key_class, sizeof(key_class)  },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
    };

    CK_RV rv = C_FindObjectsInit(session, priv_tmpl, ARRAY_LEN(priv_tmpl));
    assert_int_equal(rv, CKR_OK);

    /* Find an RSA key priv at index 0 pub at index 1 */
    CK_ULONG count;
    rv = C_FindObjects(session, priv_handle, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* got private now fnd public based on CKA_ID */
    key_class = CKO_PUBLIC_KEY;
    CK_BYTE _tmp_buf[1024];
    CK_ATTRIBUTE pub_tmpl[] = {
        { .type = CKA_ID, .ulValueLen = sizeof(_tmp_buf), .pValue = _tmp_buf },
        { CKA_CLASS, &key_class, sizeof(key_class)  },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
    };

    /* populate the CKA_ID field for the public object template */
    rv = C_GetAttributeValue(session, *priv_handle, pub_tmpl, 1);
    assert_int_equal(rv, CKR_OK);

    /* use public template + CKA_ID to find proper public object */
    rv = C_FindObjectsInit(session, pub_tmpl, ARRAY_LEN(pub_tmpl));
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjects(session, pub_handle, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /*
     * whitebox test handle identifier link sanity
     * Turning down the high bit in the public handle should
     * result in the same handle id as the private portion of
     * the object.
     */
    CK_OBJECT_HANDLE x = *pub_handle;
    /* clear high bit, no sign extension as unsigned type */
    x = x << 1;
    x = x >> 1;

    assert_int_equal(x, *priv_handle);
}

#endif /* TEST_INTEGRATION_TEST_H_ */
