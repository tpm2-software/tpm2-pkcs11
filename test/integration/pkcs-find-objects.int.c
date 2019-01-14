/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#include "test.h"

struct test_info {
    CK_SESSION_HANDLE session;
};

static int test_setup(void **state) {

    test_info *info = calloc(1, sizeof(*info));
    assert_non_null(info);

    /* get the slots */
    CK_SLOT_ID slots[6];
    unsigned long count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, TEST_TOKEN_COUNT);

    /* open a session on slot 1 */
    CK_SESSION_HANDLE session;
    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
            NULL, &session);
    assert_int_equal(rv, CKR_OK);

    /* assign to state */
    info->session = session;

    *state = info;

    /* success */
    return 0;
}

static int test_setup_by_label(void **state) {

    test_info *info = calloc(1, sizeof(*info));
    assert_non_null(info);

    /* get the slots */
    CK_SLOT_ID slots[6];
    unsigned long count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, TEST_TOKEN_COUNT);

    unsigned i;
    CK_SLOT_ID slot = ~0;
    for (i=0; i < count; i++) {
        CK_TOKEN_INFO info;
        rv = C_GetTokenInfo(slots[i], &info);
        assert_int_equal(rv, CKR_OK);

        int eq = !memcmp((char *)info.label, "import-keys                     ", sizeof(info.label));
        if (eq) {
            slot = slots[i];
            break;
        }
    }

    assert_in_range(i, 0, count - 1);

    /* open a session on foudn slot */
    CK_SESSION_HANDLE session;
    rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
            NULL, &session);
    assert_int_equal(rv, CKR_OK);

    /* assign to state */
    info->session = session;

    *state = info;

    /* success */
    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_CloseSession(ti->session);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

static void test_find_objects_aes_good(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->session;

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    /*
     * We know there are 2 private key objects in the first item, so break up the calls
     * so we test state tracking across C_FindObject(). You can think of
     * C_FindObject like read, where it keeps moving the file pointer ahead,
     * and eventually returns EOF, in our case, count == 0.
     */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 0);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);
}

static void do_test_find_objects_by_label(void **state, const char *key_label, unsigned expected) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->session;

    CK_ATTRIBUTE tmpl[] = {
      {CKA_LABEL, (void *)key_label, strlen(key_label)},
    };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    /*
     * There is only one key in the test db with the label "mykeylabel"
     */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1024];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, expected);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);
}

static void test_find_objects_by_label(void **state) {

    do_test_find_objects_by_label(state, "mykeylabel", 1);
}

static void test_find_imprted_objects_by_label(void **state) {

    do_test_find_objects_by_label(state, "imported_key", 1);
}

static void test_find_objects_via_empty_template(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->session;

    CK_RV rv = C_FindObjectsInit(session, NULL, 0);
    assert_int_equal(rv, CKR_OK);

    /*
     * There are 4 keys in the test db with
     */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[6];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, ARRAY_LEN(objhandles));

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_find_objects_aes_good,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_find_objects_by_label,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_find_objects_via_empty_template,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_find_imprted_objects_by_label,
                test_setup_by_label, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

