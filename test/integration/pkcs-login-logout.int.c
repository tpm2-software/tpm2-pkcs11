/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#include "test.h"

typedef struct test_session_handle test_session_handle;
struct test_session_handle {
    CK_SESSION_HANDLE handle; /* the session handle */
    bool is_rw;               /* true if the session is R/W false if R/O */
};

/*
 *  The maximum number of sessions any test expects to use
 *  Note: The test_setup() routine only populates 2 session
 *  handles as most tests ONLY need 2. The one test that
 *  needs more than 2 is test_user_login_logout_time_two(),
 *  and it manages the sessions itself.
 */
#define MAX_TEST_SESSIONS 3

typedef struct test_slot test_slot;
struct test_slot {
    CK_SLOT_ID slot_id; /* slot id */
    test_session_handle sessions[MAX_TEST_SESSIONS]; /* session on that slot */
};

struct test_info {
    test_slot slots[2]; /* slots with sessions for use */
};

/**
 * Opens a session on a slot
 * @param slot
 *  The slot id to open the session on
 * @param is_rw
 *  True if it should open the session as R/W via CKF_RW_SESSION, else it's just R/O.
 * @param tsh
 *  The test_session_handle to populate
 */
static void open_session(CK_SLOT_ID slot, bool is_rw, test_session_handle *tsh) {

    CK_FLAGS flags = CKF_SERIAL_SESSION;
    if (is_rw) {
        flags |= CKF_RW_SESSION;
    }

    CK_RV rv = C_OpenSession(slot, CKF_SERIAL_SESSION | flags, NULL,
            NULL, &tsh->handle);
    assert_int_equal(rv, CKR_OK);
    tsh->is_rw = is_rw;
}

/**
 * Creates and populates a test_info structure but
 * DOESNT open ANY sessions.
 * @return
 *  test_info *, asserts on ENOMEM.
 */
static test_info *_test_info_new(void) {

    test_info *ti = calloc(1, sizeof(*ti));
    assert_non_null(ti);

    /* get the slots */
    CK_SLOT_ID slots[6];
    unsigned long count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 3);

    ti->slots[0].slot_id = slots[0];
    ti->slots[1].slot_id = slots[1];

    return ti;
}

/**
 * Creates a new test_info structure populating:
 * slot[0]:
 *   - slot_id    --> slot_id of the token
 *   - session[0] --> a valid session
 *   - session[1] --> a valid session
 * slot[1]:
 *   - slot_id    --> slot_id of the token
 *   - session[0] --> a valid session
 *
 * @param is_rw
 *  True if the sessions should be R/W false for R/O
 * @return
 *  test_info on success.
 */
static test_info *test_info_new(bool is_rw) {

    test_info *ti = _test_info_new();

    CK_SLOT_ID slot_id = ti->slots[0].slot_id;
    test_session_handle *tsh = &ti->slots[0].sessions[0];
    /* open two RO sessions on slot 0, and one on slot 1 */
    open_session(slot_id, is_rw, tsh);

    tsh = &ti->slots[0].sessions[1];
    open_session(slot_id, is_rw, tsh);

    slot_id = ti->slots[1].slot_id;
    tsh = &ti->slots[1].sessions[0];
    open_session(slot_id, is_rw, tsh);

    return ti;
}

/**
 * Sets up a test run with read/write sessions
 * @param state
 *  The CMOCKA state to populate
 * @return
 *  0 on success or asserts on error.
 */
static int test_setup_rw(void **state) {

    *state = test_info_new(true);
    return 0;
}

/**
 * Sets up a test run with read-only sessions
 * @param state
 *  The CMOCKA state to populate
 * @return
 *  0 on success or asserts on error.
 */
static int test_setup_ro(void **state) {

    *state = test_info_new(false);
    return 0;
}

/**
 * Closes all sessions for slots and frees the test_info
 * structure.
 * @param state
 *  Expects *state to be a valid test_info pointer.
 * @return
 */
static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    unsigned i;
    for (i=0; i < ARRAY_LEN(ti->slots); i++) {
        CK_SLOT_ID slot_id = ti->slots[i].slot_id;
        CK_RV rv = C_CloseAllSessions(slot_id);
        assert_int_equal(rv, CKR_OK);
    }

    free(ti);

    return 0;
}

/**
 * Performs an SO login test
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
static void test_so_login_logout_good(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE handle = ti->slots[0].sessions[0].handle;

    so_login(handle);
    logout(handle);
}

/**
 * Performs a USER login test
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
static void test_user_login_logout_good(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->slots[0].sessions[0].handle;

    user_login(session);
}

/**
 * Performs a USER login test with a bad pin
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
static void test_user_login_incorrect_pin(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->slots[0].sessions[0].handle;

    unsigned char upin[] = BAD_USERPIN;

    CK_RV rv = C_Login(session, CKU_USER, upin, sizeof(upin) - 1);
    assert_int_equal(rv, CKR_PIN_INCORRECT);
}

/**
 * Performs a SO login test with a bad pin
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
void test_so_login_incorrect_pin(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->slots[0].sessions[0].handle;

    so_login_bad_pin(session);
}

/**
 * Tests C_Logout without C_Login fails with CKR_USER_NOT_LOGGED_IN
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
static void test_logout_bad_not_logged_in(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->slots[0].sessions[0].handle;

    // Logout without Login
    CK_RV rv = C_Logout(session);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);
}

/**
 * Tests C_Logout with an invalid session handle fails with CKR_SESSION_HANDLE_INVALID
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
static void test_logout_bad_invalid_session_handle(void **state) {

    UNUSED(state);

    // Logout with an Invalid Session
    CK_RV rv = C_Logout((CK_ULONG)-10);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

/**
 * Tests C_Login with an R/O session for a SO user fails with CKR_SESSION_READ_ONLY_EXISTS
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
static void test_so_on_ro_session(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->slots[0].sessions[0].handle;

    so_login_expects(session, CKR_SESSION_READ_ONLY_EXISTS);
}

/**
 * Tests C_Login when SO is already logged in fails with CKR_USER_ALREADY_LOGGED_IN
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
static void test_so_login_already_logged_in(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->slots[0].sessions[0].handle;

    so_login(session);
    so_login_expects(session, CKR_USER_ALREADY_LOGGED_IN);

    CK_RV rv = C_Logout(session);
    assert_int_equal(rv, CKR_OK);
}

/**
 * Validates that *EXISTING* session state changes on SO logins. Ie all sessions
 * are logged in.
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
static void test_so_global_login_logout_good(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE slot0_session0 = ti->slots[0].sessions[0].handle;
    CK_SESSION_HANDLE slot0_session1 = ti->slots[0].sessions[1].handle;
    CK_SESSION_HANDLE slot1_session0 = ti->slots[1].sessions[0].handle;

    so_login(slot0_session0);
    so_login_expects(slot0_session1, CKR_USER_ALREADY_LOGGED_IN);

    logout_expects(slot1_session0, CKR_USER_NOT_LOGGED_IN);

    logout(slot0_session1);
    logout_expects(slot0_session1, CKR_USER_NOT_LOGGED_IN);
}

/**
 * Validates that *EXISTING* session state changes on USER logins. Ie all sessions
 * are logged in.
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
static void test_user_global_login_logout_good(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE slot0_session0 = ti->slots[0].sessions[0].handle;
    CK_SESSION_HANDLE slot0_session1 = ti->slots[0].sessions[1].handle;
    CK_SESSION_HANDLE slot1_session0 = ti->slots[1].sessions[0].handle;;

    /*
     * login on slot 0 session 0, and verify that it is logged in on the other session
     */
    user_login(slot0_session0);
    user_login_expects(slot0_session1, CKR_USER_ALREADY_LOGGED_IN);

    /*
     * logging out of slot 1 session 0 should yeild not logged in (different slot)
     */
    logout_expects(slot1_session0, CKR_USER_NOT_LOGGED_IN);

    /*
     * logging out of slot 0 should yeild a logout and no other sessions should
     * be logged in. Try cross session login/logout. Ie DONT login and logout from
     * the same session
     */
    logout(slot0_session1);
    logout_expects(slot0_session0, CKR_USER_NOT_LOGGED_IN);
}

/**
 * Replicate issue https://github.com/tpm2-software/tpm2-pkcs11/issues/81
 *
 * Where a C_OpenSession, C_Login, C_OpenSession, C_Login fails
 * @param state
 *  Cmocka state where *state is a valid test_info *.
 */
static void test_user_login_logout_time_two(void **state) {

    /*
     * We don't use the common init as this needs to manage session
     * state on it's own
     */
    test_info *ti = _test_info_new();
    *state = ti;

    CK_SLOT_ID slot_id = ti->slots[0].slot_id;
    test_session_handle *tsh[3] = {
        &ti->slots[0].sessions[0],
        &ti->slots[0].sessions[1],
        &ti->slots[0].sessions[2]
    };

    /*
     * Open an R/O session, state should be initally at
     * CKS_RO_PUBLIC_SESSION
     */
    open_session(slot_id, false, tsh[0]);

    CK_SESSION_INFO info;
    CK_RV rv = C_GetSessionInfo(tsh[0]->handle, &info);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(info.state, CKS_RO_PUBLIC_SESSION);

    /*
     * Login should cause state to change from:
     * CKS_RO_PUBLIC_SESSION
     * to
     * CKS_RO_USER_FUNCTIONS
     */
    user_login(tsh[0]->handle);

    rv = C_GetSessionInfo(tsh[0]->handle, &info);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(info.state, CKS_RO_USER_FUNCTIONS);

    /*
     * Now that we're logged in, new R/0 sessions should start in the
     * state: CKS_RO_USER_FUNCTIONS
     */
    open_session(slot_id, false, tsh[1]);

    rv = C_GetSessionInfo(tsh[1]->handle, &info);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(info.state, CKS_RO_USER_FUNCTIONS);

    /*
     * Start another session but R/W, and state should be CKS_RW_USER_FUNCTIONS
     */
    open_session(slot_id, true, tsh[2]);

    rv = C_GetSessionInfo(tsh[2]->handle, &info);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(info.state, CKS_RW_USER_FUNCTIONS);

    /*
     * C_Logout, ALL states should return to CKS_RO_PUBLIC_SESSION or CKS_RW_PUBLIC_SESSION
     * depending on flags
     */
    logout(tsh[1]->handle);

    unsigned i;
    for (i=0; i < ARRAY_LEN(tsh); i++) {

        test_session_handle *t = tsh[i];

        rv = C_GetSessionInfo(t->handle, &info);
        assert_int_equal(rv, CKR_OK);

        CK_STATE expected = t->is_rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
        assert_int_equal(info.state, expected);
    }

    rv = C_CloseAllSessions(slot_id);
    assert_int_equal(rv, CKR_OK);
}

int main() {

    const struct CMUnitTest tests[] = {
        /*
         * No Session tests
         */
            cmocka_unit_test_setup_teardown(test_logout_bad_invalid_session_handle,
                    NULL, NULL),
        /*
         * R/O Session Tests
         */
        cmocka_unit_test_setup_teardown(test_user_login_logout_good,
                test_setup_ro, test_teardown),
        cmocka_unit_test_setup_teardown(test_user_login_incorrect_pin,
                test_setup_ro, test_teardown),
        cmocka_unit_test_setup_teardown(test_logout_bad_not_logged_in,
                test_setup_ro, test_teardown),
        cmocka_unit_test_setup_teardown(test_so_on_ro_session,
                test_setup_ro, test_teardown),
        cmocka_unit_test_setup_teardown(test_user_global_login_logout_good,
                test_setup_ro, test_teardown),
        cmocka_unit_test_setup_teardown(test_user_login_logout_time_two,
                NULL, test_teardown),
                /*
             * R/W Session Tests
             */
        cmocka_unit_test_setup_teardown(test_so_login_already_logged_in,
                test_setup_rw, test_teardown),
        cmocka_unit_test_setup_teardown(test_so_login_logout_good,
                test_setup_rw, test_teardown),
        cmocka_unit_test_setup_teardown(test_so_login_incorrect_pin,
                test_setup_rw, test_teardown),
        cmocka_unit_test_setup_teardown(test_so_global_login_logout_good,
                test_setup_rw, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup_locking, group_teardown);
}
