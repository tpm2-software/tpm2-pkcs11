/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include <tss2/tss2_sys.h>

#include "pkcs11.h"
#include "test.h"

/**
 * This program contains integration test for C_Initialize and C_Finalize.
 * C_Initialize initializes the Cryptoki library.
 * C_Finalize is called to indicate that an application is finished with the Cryptoki library.
 */

static CK_RV create(void **mutex) {
    (void) mutex;
    return CKR_OK;
}

static CK_RV lock(void *mutex) {
    (void) mutex;
    return CKR_OK;
}

static CK_RV unlock(void *mutex) {
    (void) mutex;
    return CKR_OK;
}

static CK_RV destroy(void *mutex) {
    (void) mutex;
    return CKR_OK;
}

static void state_setup(void **state) {

	bool *do_teardown = malloc(sizeof(bool));
	assert_non_null(do_teardown);
	*do_teardown = true;
	*state = do_teardown;
}

static int test_setup(void **state) {

	state_setup(state);
	return group_setup(NULL);
}

static int test_teardown(void **state) {

	bool *p_do_teardown = (bool *)(*state);
	bool do_teardown = *p_do_teardown;
	free(p_do_teardown);
	if (do_teardown) {
		return group_teardown(NULL);
	}

	return 0;
}

// Test the 4 states and additional error case of:
//   http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
// Section 5.4
void test_c_init_args(void **state) {

	/* No setup routine called */
	state_setup(state);

    bool *do_teardown = (bool *)(*state);

    // Case 1 - flags and fn ptr's clear. No threaded access.
    CK_C_INITIALIZE_ARGS args = {
        .flags = 0,
        .CreateMutex = NULL,
        .DestroyMutex = NULL,
        .LockMutex = NULL,
        .pReserved = NULL,
    };

    CK_RV rv = C_Initialize(&args);
    assert_int_equal(rv, CKR_OK);

    *do_teardown = true;

    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    *do_teardown = false;

    // Case 2 locking flag specified but no fn pointers. Threaded access and use
    // library lock defaults.
    args.flags = CKF_OS_LOCKING_OK;

    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_OK);

    *do_teardown = true;

    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    *do_teardown = false;

    // Case 3, no locking flag set, and set fn pointers. Threaded access and
    // use my call backs
    args.flags = 0;
    args.CreateMutex = create;
    args.DestroyMutex = destroy;
    args.LockMutex = lock;
    args.UnlockMutex = unlock;

    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_OK);

    *do_teardown = true;

    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    *do_teardown = false;

    // Case 4, locking flag set, and set fn pointers. Threaded access and
    // optionally use my callbacks
    args.flags = CKF_OS_LOCKING_OK;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_OK);

    *do_teardown = true;

    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    /* State is finalized, all other checks are negative tests below this */
    *do_teardown = false;

    // Clear args for negative test
    // Case 5: If some, but not all, of the supplied function pointers to C_Initialize are non-NULL_PTR,
    // then C_Initialize should return with the value CKR_ARGUMENTS_BAD.
    memset(&args, 0, sizeof(args));
    args.CreateMutex = create;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    args.DestroyMutex = destroy;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    args.LockMutex = lock;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    memset(&args, 0, sizeof(args));
    // Case 6: flag is set but only some function pointers are provided,
    // then C_Initialize should return with the value CKR_ARGUMENTS_BAD
    args.flags = CKF_OS_LOCKING_OK;
    args.DestroyMutex = destroy;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    args.LockMutex = lock;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    args.UnlockMutex = unlock;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    // Case 7: the value of pReserved MUST be NULL_PTR; if it’s not,
    // then C_Initialize should return with the value CKR_ARGUMENTS_BAD.
    memset(&args, 0, sizeof(args));
    args.pReserved = (void *)0xDEADBEEF;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    // If negative test cases, successfully run C_Initialize
    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_CRYPTOKI_NOT_INITIALIZED);
}

void test_c_double_init(void **state) {
	UNUSED(state);

    CK_RV rv = C_Initialize (NULL);
    assert_int_equal(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED);
}

static void test_c_finalize_bad(void **state) {
	UNUSED(state);

    // Give it a pointer and make sure we don't try and dereference it.
    CK_RV rv = C_Finalize((void *)0xDEADBEEF);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);
}

static void test_double_calls(void **state) {

    bool *do_teardown = (bool *)(*state);

	/* already initialized by test setup */
    CK_RV rv = C_Initialize(NULL);
    assert_int_equal(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED);

    CK_TOKEN_INFO info = { 0 };
    rv = C_GetTokenInfo(1, &info);
    assert_int_equal(rv, CKR_OK);

    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    *do_teardown = false;

    rv = C_Initialize(NULL);
    assert_int_equal(rv, CKR_OK);

    *do_teardown = true;
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_double_calls,
            test_setup, test_teardown),
        cmocka_unit_test_teardown(test_c_init_args,
            test_teardown),
        cmocka_unit_test_setup_teardown(test_c_double_init,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_c_finalize_bad,
            test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
