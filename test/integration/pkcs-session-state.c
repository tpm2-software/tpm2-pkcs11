/* SPDX-License-Identifier: BSD-2-Clause */

#include "test.h"

struct test_info {
    CK_SLOT_ID slot;
    CK_OBJECT_HANDLE key;
    CK_SESSION_HANDLE session[2];
};

static test_info *test_info_new(void) {

    test_info *ti = calloc(1, sizeof(*ti));
    assert_non_null(ti);

    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &ti->session[0]);
    assert_int_equal(rv, CKR_OK);

    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &ti->session[1]);
    assert_int_equal(rv, CKR_OK);

    ti->slot = slots[0];

    user_login(ti->session[0]);

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
    };

    rv = C_FindObjectsInit(ti->session[0], tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    count = 1;
    rv = C_FindObjects(ti->session[0], &ti->key, count, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(ti->session[0]);
    assert_int_equal(rv, CKR_OK);

    return ti;
}

static int test_setup(void **state) {

    /* get the slots */
    test_info *ti = test_info_new();

    *state = ti;

    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_CloseAllSessions(ti->slot);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

static void test_session_operation_state(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_MECHANISM dmech = {
        .mechanism = CKM_SHA256,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256_RSA_PKCS,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_BYTE iv[16] = {0};

    CK_MECHANISM emech = {
        .mechanism = CKM_AES_CBC,
        .pParameter = &iv,
        .ulParameterLen = sizeof(iv)
    };


    CK_RV rv = C_DigestInit(ti->session[0], &dmech);
    assert_int_equal(rv, CKR_OK);

    rv = C_DigestInit(ti->session[0], &dmech);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);

    rv = C_SignInit(ti->session[0], &smech, ti->key);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);

    rv = C_SignInit(ti->session[1], &smech, ti->key);
    assert_int_equal(rv, CKR_OK);

    rv = C_DigestInit(ti->session[1], &dmech);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);

    rv = C_EncryptInit(ti->session[1], &emech, ti->key);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);
}

static void test_session_exhastion(void **state) {
    UNUSED(state);

    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);

    CK_SESSION_HANDLE session;

    while ((rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL_PTR, NULL_PTR, &session)) != CKR_SESSION_COUNT) {
        assert_int_equal(rv, CKR_OK);
    }

    rv = C_CloseAllSessions(slots[0]);
    assert_int_equal(rv, CKR_OK);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_session_operation_state,
                test_setup, test_teardown),
        /* this must go last to get C_Finalize from group_teardown called */
        cmocka_unit_test(test_session_exhastion),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
