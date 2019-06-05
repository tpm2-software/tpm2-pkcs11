#include "test.h"

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
};

static test_info *test_info_new(void) {

    test_info *ti = calloc(1, sizeof(*ti));
    assert_non_null(ti);

    /* get the slots */
    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);

    ti->slot_id = slots[0];

    return ti;
}

static int test_setup(void **state) {

    test_info *ti = test_info_new();

    CK_RV rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION,
              NULL, NULL, &ti->handle);
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

static void test_tpm_ecc_support_check(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";

    CK_ATTRIBUTE pub[] = {
        ADD_ATTR_BASE(CKA_TOKEN, ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_VERIFY, ck_true),
        {.type = CKA_EC_PARAMS, .ulValueLen = 0, .pValue =0}, /*.ulValueLen and .pValue will be populated later*/
        ADD_ATTR_STR(CKA_LABEL, label)
    };

    CK_ATTRIBUTE priv[] = {
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_SIGN, ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_TOKEN, ck_true),
        ADD_ATTR_STR(CKA_LABEL, label),
        ADD_ATTR_BASE(CKA_SENSITIVE, ck_false)
    };

     /*
     * Check the return values for supported and not supported curve.
     * The first rv_ecc should be CKR_OK for supported P256 curve
     * The second rv_ecc should be CKR_ARGUMENTS_BAD for unsupported P521 curve
     */
    CK_BYTE ec_params_P256[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07
    };

    CK_BYTE ec_params_P521[] = {
        0x06, 0x05, 0x2b, 0x81, 0x04,
        0x00, 0x23
    };

    CK_BYTE_PTR ec_params[2] = {ec_params_P256, ec_params_P521}; /*P256 is supported, P521 is not supported by simulator*/

    for (size_t i = 0; i < ARRAY_LEN(ec_params); i++) {

        pub[4].ulValueLen = ec_params[i][1]+2;       /*[1]+2 = Size of curve array*/
        pub[4].pValue = ec_params[i];

        CK_OBJECT_HANDLE pubkey;
        CK_OBJECT_HANDLE privkey;
        CK_MECHANISM mech = {
            .mechanism = CKM_EC_KEY_PAIR_GEN,
            .pParameter = NULL,
            .ulParameterLen = 0
        };

        CK_RV rv = C_GenerateKeyPair (session, &mech,
            pub, ARRAY_LEN(pub),
            priv, ARRAY_LEN(priv),
            &pubkey, &privkey);

        if (i == 0) {
            /*P256 is supported*/
            assert_int_equal(rv, CKR_OK);
        } else if (i == 1) {
            /*P521 is not supported*/
            assert_int_equal(rv, CKR_ARGUMENTS_BAD);;
        }
    }
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_tpm_ecc_support_check,
            test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
