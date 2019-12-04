/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#include "test.h"

/*
 * config *MUST* go after test.h or cmocka includes cause some
 * odd memory issues.
 */
#include "config.h"

struct test_info {
    CK_SESSION_HANDLE handles[6];
    CK_SLOT_ID slot_id;
};

static test_info *test_info_new(void) {

    test_info *ti = calloc(1, sizeof(*ti));
    assert_non_null(ti);

    /* get the slots and verify that count is updated
     * when buffer is null or count is too small */
    CK_SLOT_ID slots[TOKEN_COUNT];
    CK_ULONG count = 0;
    CK_RV rv = C_GetSlotList(true, NULL, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, TOKEN_COUNT);

    CK_ULONG count2 = count - 1;
    rv = C_GetSlotList(true, slots, &count2);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(count2, count);

    rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, TOKEN_COUNT);

    ti->slot_id = slots[0];

    return ti;
}

static int test_setup(void **state) {

    test_info *ti = test_info_new();

    CK_RV rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL,
            NULL, &ti->handles[0]);
    assert_int_equal(rv, CKR_OK);

    *state = ti;

    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_CloseAllSessions(ti->slot_id);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

static void test_c_getfunctionlist_good(void **state) {

    UNUSED(state);

    //Case 1: Successfully obtain function list
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_RV rv = C_GetFunctionList(&pFunctionList);
    assert_int_equal(rv, CKR_OK);
}

static void test_c_getfunctionlist_bad(void **state) {

    UNUSED(state);

    //Case 2: Null PTR fails
    CK_RV rv = C_GetFunctionList(NULL);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);
}

static void test_get_slot_list(void **state) {

    UNUSED(state);

    CK_SLOT_ID slots[6];
    CK_ULONG count;
    // Case 1: Good test to get the count of slots
    CK_RV rv = C_GetSlotList(true, NULL, &count);
    assert_int_equal(rv, CKR_OK);

    // Case 2: Good test to get the slots in buffer
    rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);

    CK_SLOT_INFO sinfo;
    rv = C_GetSlotInfo(slots[0], &sinfo);
    assert_int_equal(rv, CKR_OK);

    assert_true(sinfo.flags & CKF_TOKEN_PRESENT);
    assert_true(sinfo.flags & CKF_HW_SLOT);

    CK_TOKEN_INFO tinfo;
    rv = C_GetTokenInfo(slots[0], &tinfo);
    assert_int_equal(rv, CKR_OK);

    assert_true(tinfo.flags & CKF_RNG);
    assert_true(tinfo.flags & CKF_TOKEN_INITIALIZED);
}

static void parse_lib_version(CK_BYTE *major, CK_BYTE *minor) {

    char buf[] = PACKAGE_VERSION;

    char *minor_str = NULL;
    char *major_str = &buf[0];

    char *split = strchr(buf, '.');
    if (split) {
        split[0] = '\0';
        minor_str = split + 1;
    } else {
        minor_str = "0";
    }

    if (!major_str || !major_str[0] || !minor_str[0]) {
        *major = *minor = 0;
        return;
    }

    char *endptr = NULL;
    unsigned long val;
    errno = 0;
    val = strtoul(major_str, &endptr, 10);
    if (errno != 0 || endptr[0] || val > UINT8_MAX) {
        *major = *minor = 0;
        return;
    }

    *major = val;

    endptr = NULL;
    val = strtoul(minor_str, &endptr, 10);
    if (errno != 0 || endptr[0] || val > UINT8_MAX) {
        *major = *minor = 0;
        return;
    }

    *minor = val;
}

static void test_get_info(void **state) {

    UNUSED(state);
    CK_INFO info;
    CK_RV rv;

    // check if null pointer is handled correctly
    rv = C_GetInfo(NULL);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    // check for successful invocation
    rv = C_GetInfo(&info);
    assert_int_equal(rv, CKR_OK);

    // check whether cryptoki version is correct
    assert_int_equal(info.cryptokiVersion.major, 2);
    assert_int_equal(info.cryptokiVersion.minor, 40);


    CK_BYTE major;
    CK_BYTE minor;
    parse_lib_version(&major, &minor);
    assert_int_equal(info.libraryVersion.major, major);
    assert_int_equal(info.libraryVersion.minor, minor);
}

static void test_random_good(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE handle = ti->handles[0];

    user_login(ti->handles[0]);

    CK_BYTE buf[4];

    // Case 1: Good test
    CK_RV rv = C_GenerateRandom(handle++, buf, sizeof(buf));
    assert_int_equal(rv, CKR_OK);
}

static void test_random_bad_session_handle(void **state) {

    test_info *ti = test_info_from_state(state);
    /* make the handle bad */
    CK_SESSION_HANDLE handle = ~ti->handles[0];

    CK_BYTE buf[4];

    // Case 2: Test bad session
    CK_RV rv = C_GenerateRandom(handle, buf, sizeof(buf));
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_seed(void **state) {

    static CK_BYTE buf[]="ksadjfhjkhfsiudgfkjewsdjbkfcoidugshbvfewug";

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE handle = ti->handles[0];

    user_login(ti->handles[0]);

    CK_RV rv = C_SeedRandom(handle, buf, sizeof(buf));
    assert_int_equal(rv, CKR_OK);
}

static void test_get_session_info (void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE handle = ti->handles[0];

    CK_SESSION_INFO info;
    CK_RV rv = C_GetSessionInfo(handle, &info);
    assert_int_equal(rv, CKR_OK);
}

static void test_digest_good(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE handle = ti->handles[0];

    user_login(handle);

    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_RV rv = C_DigestInit(handle, &smech);
    assert_int_equal(rv, CKR_OK);

    // sizeof a sha256 hash
    CK_BYTE data[] = "Hello World This is My First Digest Message";

    CK_BYTE hash[32];
    CK_ULONG hashlen = sizeof(hash);

    rv = C_DigestUpdate(handle, data, sizeof(data) - 1);
    assert_int_equal(rv, CKR_OK);

    rv = C_DigestFinal(handle, hash, &hashlen);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE hash2[32];
    CK_ULONG hash2len = sizeof(hash);

    rv = C_DigestInit(handle, &smech);
    assert_int_equal(rv, CKR_OK);

    rv = C_Digest(handle, data, sizeof(data) - 1, hash2, &hash2len);
    assert_int_equal(rv, CKR_OK);

    rv = C_Logout(handle);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(hash2len, hashlen);
    assert_memory_equal(hash, hash2, hash2len);

    /*
     * expected hash of data
     */
    CK_BYTE expected_digest[] = {
      0xce, 0x89, 0xe6, 0x32, 0xe2, 0x56, 0x4c, 0x7b, 0xdb, 0x3c, 0x01, 0xca,
      0x28, 0x20, 0x9b, 0x02, 0x9b, 0x80, 0x05, 0x99, 0x65, 0xb2, 0x8e, 0x58,
      0xe0, 0xb3, 0xec, 0x88, 0x16, 0xe0, 0x77, 0x77
    };

    assert_int_equal(hashlen, sizeof(expected_digest));
    assert_memory_equal(hash, expected_digest, sizeof(expected_digest));
}

static void test_session_cnt(void **state) {

    /* we populate state in this test */
    assert_null(*state);

    test_info *ti = test_info_new();
    *state = ti;

    CK_SESSION_HANDLE slot = ti->slot_id;

    size_t i;
    CK_RV rv;
    CK_TOKEN_INFO info;

    CK_ULONG cnt = 0;
    CK_ULONG rw_cnt = 0;

    /*
     * Test incrementing
     */
    for (i=0; i < ARRAY_LEN(ti->handles); i++) {
        CK_SESSION_HANDLE_PTR handle = &ti->handles[i];
        /*
         * Every odd open up a RW session, every even open up a RO session
         */
        CK_FLAGS flags = CKF_SERIAL_SESSION;
        flags |= (i & 1) ? CKF_RW_SESSION : 0;

        rv = C_OpenSession(slot, flags, NULL , NULL, handle);
        assert_int_equal(rv, CKR_OK);

        /*
         * For clarity, just track the sessions here rather than
         * doing computing it off of i.
         */
        if (i & 1) {
            rw_cnt++;
        }

        cnt++;

        rv = C_GetTokenInfo(slot, &info);
        assert_int_equal(rv, CKR_OK);

        assert_int_equal(info.ulSessionCount, cnt);
        assert_int_equal(info.ulRwSessionCount, rw_cnt);
    }

    /*
     * Test decrementing, but only decrement all but 2, so we can test
     * closeall.
     *
     * rw_cnt and cnt are properly in the state of current open handles, so
     * just use them from above.
     */
    for (i=0; i < (ARRAY_LEN(ti->handles) - 2); i++) {
        CK_SESSION_HANDLE handle = ti->handles[i];

        rv = C_CloseSession(handle);
        assert_int_equal(rv, CKR_OK);


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
        assert_int_equal(rv, CKR_OK);

        assert_int_equal(info.ulSessionCount, cnt);
        assert_int_equal(info.ulRwSessionCount, rw_cnt);
    }

    /*
     * test closeall brings it 0
     */
    rv = C_CloseAllSessions(slot);
    assert_int_equal(rv, CKR_OK);


    rv = C_GetTokenInfo(slot, &info);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(info.ulSessionCount, 0);
    assert_int_equal(info.ulRwSessionCount, 0);
}

int main() {

    const struct CMUnitTest tests[] = {
        /*
         * No Session tests
         */
        cmocka_unit_test_setup_teardown(test_c_getfunctionlist_good,
                NULL, NULL),
        cmocka_unit_test_setup_teardown(test_c_getfunctionlist_bad,
                NULL, NULL),
        cmocka_unit_test_setup_teardown(test_get_slot_list,
                NULL, NULL),
        cmocka_unit_test_setup_teardown(test_get_info,
                NULL, NULL),

        /*
         * R/O Session Tests
         */
        cmocka_unit_test_setup_teardown(test_seed,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_random_good,
                test_setup, test_teardown),
                cmocka_unit_test_setup_teardown(test_random_bad_session_handle,
                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_session_info,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_digest_good,
                test_setup, test_teardown),
        /*
         * manages it's own sessions
         */
        cmocka_unit_test_setup_teardown(test_session_cnt,
                NULL, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup_locking, group_teardown);
}
