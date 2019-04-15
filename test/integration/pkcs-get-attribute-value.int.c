/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2019, Infineon Technologies AG
 *
 * All rights reserved.
 ***********************************************************************/

#include "test.h"

struct test_info {
    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hObject;
};

static int test_setup(void **state) {

    test_info *info = calloc(1, sizeof(*info));
    assert_non_null(info);

    /* get the slots */
    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 3);

    /* open a session on slot 1 */
    CK_SESSION_HANDLE hSession;
    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
            NULL, &hSession);
    assert_int_equal(rv, CKR_OK);

    /* assign to state */
    info->hSession = hSession;

    /* find a suitable object to work with */
    const char *key_label = "mykeylabel";
    CK_ATTRIBUTE tmpl[] = {
      {CKA_LABEL, (void *)key_label, strlen(key_label)},
    };

    rv = C_FindObjectsInit(hSession, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE objhandles[1024];
    rv = C_FindObjects(hSession, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(hSession);
    assert_int_equal(rv, CKR_OK);

    /* store handle for tests*/
    info->hObject = objhandles[0];

    *state = info;

    /* success */
    return 0;
}


static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_CloseSession(ti->hSession);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}


static void test_get_attribute_value_single_okay(void **state) {
    CK_RV rv;
    CK_UTF8CHAR *pLabel = NULL;
    CK_LONG exactsize = 0;
    CK_ATTRIBUTE template[] = {
      {CKA_LABEL, NULL_PTR, 0},
    };

    test_info *ti = test_info_from_state(state);

    // Call for Size
    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 1);
    assert_int_equal(rv, CKR_OK);

    pLabel = malloc(template[0].ulValueLen+1); //+1 for \0
    memset(pLabel, '\0', template[0].ulValueLen+1);
    exactsize = template[0].ulValueLen; //for comparison

    template[0].pValue = pLabel;
    template[0].ulValueLen++; //must be reset to 'exactsize'

    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(template[0].ulValueLen, exactsize);
    assert_string_equal(template[0].pValue, "mykeylabel");
    free(pLabel);
}

static void test_get_attribute_value_multiple_okay(void **state) {
    CK_RV rv;
    CK_UTF8CHAR *pLabel = NULL;
    CK_BYTE_PTR *pId = NULL;
    CK_ATTRIBUTE template[] = {
      {CKA_LABEL, NULL_PTR, 0},
      {CKA_ID, NULL_PTR, 0},
    };

    test_info *ti = test_info_from_state(state);

    // Call for Size
    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 2);
    assert_int_equal(rv, CKR_OK);

    pLabel = malloc(template[0].ulValueLen+1); //+1 for \0
    memset(pLabel, '\0', template[0].ulValueLen+1);
    template[0].pValue = pLabel;
    
    pId = malloc(template[1].ulValueLen);
    template[1].pValue = pId;

    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 2);
    assert_int_equal(rv, CKR_OK);
    assert_string_equal(template[0].pValue, "mykeylabel");
    free(pLabel);
    free(pId);
}

static void test_get_attribute_value_buffer_too_small(void **state) {
    CK_RV rv;
    CK_UTF8CHAR *pLabel = NULL;
    CK_ATTRIBUTE template[] = {
      {CKA_LABEL, NULL_PTR, 0},
    };

    test_info *ti = test_info_from_state(state);

    // Call for Size
    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 1);
    assert_int_equal(rv, CKR_OK);

    pLabel = malloc(template[0].ulValueLen+1); //+1 for \0
    memset(pLabel, '\0', template[0].ulValueLen+1);
    template[0].pValue = pLabel;

    //make buffer length too small
    template[0].ulValueLen--;
    
    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 1);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    free(pLabel);
}

static void test_get_attribute_value_invalid_attribute(void **state) {
    test_info *ti = test_info_from_state(state);
    CK_ATTRIBUTE template[] = {
      {0x0000FFFFUL, NULL_PTR, 0}, //Invalid
    };

    CK_RV rv;

    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 1);

    assert_int_equal(rv, CKR_ATTRIBUTE_TYPE_INVALID);
    assert_int_equal(template[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);
    assert_null(template[0].pValue);
}

/*
 * C_GetAttributeValue must process every attribute in the template,
 * even if CKR_ATTRIBUTE_TYPE_INVALID or CKR_BUFFER_TOO_SMALL is returned.
 * The return value can be any one of the failures.
 * */
static void test_get_attribute_value_multiple_fail(void **state) {
    CK_RV rv;
    CK_UTF8CHAR *pLabel = NULL;
    CK_BYTE_PTR *pId = NULL;
    CK_BYTE_PTR *pInvalid = NULL;
    CK_ATTRIBUTE template[] = {
      {CKA_ID, NULL_PTR, 0},
      {CKA_LABEL, NULL_PTR, 0},
      {0x0000FFFFUL, NULL_PTR, 0}, //Invalid
    };
    LargestIntegralType expected_returns[] = {CKR_BUFFER_TOO_SMALL, CKR_ATTRIBUTE_TYPE_INVALID};

    test_info *ti = test_info_from_state(state);

    // Call for Size, without invalid
    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 2);
    assert_int_equal(rv, CKR_OK);

    // too small
    pId = malloc(template[0].ulValueLen);
    template[0].pValue = pId;
    template[0].ulValueLen--; // make buffer too small
    
    // this one will be okay
    pLabel = malloc(template[1].ulValueLen+1); //+1 for \0
    memset(pLabel, '\0', template[1].ulValueLen+1);
    template[1].pValue = pLabel;
   
    // invalid 
    pInvalid = malloc(10);
    template[2].pValue = pInvalid;
    template[2].ulValueLen = 10;

    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 3);
    // Return should be CKR_ATTRIBUTE_TYPE_INVALID or CKR_BUFFER_TOO_SMALL
    assert_in_set(rv, expected_returns, 2);
    assert_int_equal(template[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);
    assert_string_equal(template[1].pValue, "mykeylabel");
    assert_int_equal(template[2].ulValueLen, CK_UNAVAILABLE_INFORMATION);
    free(pLabel);
    free(pId);
    free(pInvalid);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_attribute_value_single_okay,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_attribute_value_multiple_okay,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_attribute_value_buffer_too_small,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_attribute_value_invalid_attribute,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_attribute_value_multiple_fail,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

