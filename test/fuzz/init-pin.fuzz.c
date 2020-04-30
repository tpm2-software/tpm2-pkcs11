/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"

#include <stdbool.h>
#include <stdlib.h>

#include "attrs.h"
#include "log.h"
#include "parser.h"
#include "pkcs11.h"

#include "wrap_tpm.h"

static const uint8_t *_data;
static size_t _size;
static CK_SESSION_HANDLE _session;

static int setup(void **state) {
    UNUSED(state);

    /*
     * we just use an in memory db so we don't need to fake sqlite or deal
     *
     * with temp file cleanup
     */
    setenv("TPM2_PKCS11_STORE", ":memory:", 1);
    set_default_tpm();

    CK_RV rv = C_Initialize(NULL);
    assert_int_equal(rv, CKR_OK);

    CK_SLOT_ID slot_list;
    CK_ULONG count = 1;

    rv = C_GetSlotList(0, &slot_list, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_not_equal(count, 0);

    CK_BYTE label[32] = "                        my label";
    rv = C_InitToken(slot_list, (CK_BYTE_PTR)"mysopin", 7, label);
    assert_int_equal(rv, CKR_OK);

    rv = C_OpenSession(slot_list, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &_session);
    assert_int_equal(rv, CKR_OK);

    rv = C_Login(_session, CKU_SO, (CK_BYTE_PTR)"mysopin", 7);
    assert_int_equal(rv, CKR_OK);

    return 0;
}

static int teardown(void **state) {
    UNUSED(state);

    set_default_tpm();

    CK_RV rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    return 0;
}

static void test(void **state) {
    UNUSED(state);

    set_default_tpm();

    /* FUZZ TARGET C_InitPIN pin */
    CK_RV rv = C_InitPIN(_session, (CK_BYTE_PTR)_data, _size);
    /* it should never fail, all pins are ok */
    assert_int_equal(rv, CKR_OK);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    _size = size;
    _data = data;

    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(test, setup, teardown),
    };

    cmocka_run_group_tests(tests, NULL, NULL);
    return 0;
}
