/* SPDX-License-Identifier: BSD-2-Clause */

#include "tpm.h"
#include "test.h"

/* we need to manage lockout counter for testing bad auths */
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tctildr.h>

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

#define C(x) ((CK_UTF8CHAR_PTR)x)

typedef struct test_slot test_slot;
struct test_slot {
    CK_SLOT_ID slot_id; /* slot id */
    test_session_handle sessions[MAX_TEST_SESSIONS]; /* session on that slot */
};

struct test_info {
    test_slot slots[2]; /* slots with sessions for use */
};

ESYS_CONTEXT *_g_ectx = NULL;
TSS2_TCTI_CONTEXT *_g_tcti = NULL;

//TPM2_PT_MAX_AUTH_FAIL
static void get_prop(TPM2_PT needle, UINT32 *value) {

    TPMS_CAPABILITY_DATA *cap_data = NULL;
    TPMI_YES_NO more_data = TPM2_NO;
    TSS2_RC rc = Esys_GetCapability(_g_ectx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        TPM2_CAP_TPM_PROPERTIES,
        TPM2_PT_VAR,
        TPM2_MAX_TPM_PROPERTIES,
        &more_data, &cap_data);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    UINT32 count = cap_data->data.tpmProperties.count;
    TPMS_TAGGED_PROPERTY *props = cap_data->data.tpmProperties.tpmProperty;

    UINT32 i;
    for(i=0; i < count; i++) {
        TPM2_PT p = props[i].property;
        UINT32 v =props[i].value;
        if (p == needle) {
            *value = v;
            Esys_Free(cap_data);
            return;
        }
    }

    Esys_Free(cap_data);
    fail_msg("No property: %" PRIu32, needle);
}

static int _group_setup_locking(void **state) {

    const char *config = getenv(TPM2_PKCS11_TCTI);

    TSS2_RC rc = Tss2_TctiLdr_Initialize(config, &_g_tcti);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    rc = Esys_Initialize(&_g_ectx, _g_tcti, NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    return group_setup_locking(state);
}

static int _group_teardown(void **state) {

    Esys_Finalize(&_g_ectx);
    Tss2_TctiLdr_Finalize(&_g_tcti);
    free(_g_tcti);
    return group_teardown(state);
}

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
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, TOKEN_COUNT);

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

static void test_user_lockout(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE handle = ti->slots[0].sessions[0].handle;

    /* tpm's are generally configured for 3 attempts you can check
     * tpm2_getcap properties-variable
     *   - TPM2_PT_MAX_AUTH_FAIL: 0x3
     */

    UINT32 max_fail = 0;
    get_prop(TPM2_PT_MAX_AUTH_FAIL, &max_fail);

    UINT32 count = 0;
    get_prop(TPM2_PT_LOCKOUT_COUNTER, &count);
    assert_int_equal(count, 0);

    UINT32 i;
    for(i=0; i < max_fail; i++) {
        login_expects(handle, CKU_USER, CKR_PIN_INCORRECT, C(BAD_USERPIN), sizeof(BAD_USERPIN) - 1);
        get_prop(TPM2_PT_LOCKOUT_COUNTER, &count);
        assert_int_equal(count, i + 1);
    }

    get_prop(TPM2_PT_LOCKOUT_COUNTER, &count);
    assert_int_equal(count, max_fail);

    login_expects(handle, CKU_USER, CKR_PIN_LOCKED, C(GOOD_USERPIN), sizeof(GOOD_USERPIN) - 1);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_user_lockout,
                test_setup_ro, test_teardown),
    };

    return cmocka_run_group_tests(tests, _group_setup_locking, _group_teardown);
}
