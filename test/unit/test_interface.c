/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>

#include "general.h"
#include "pkcs11.h"

/*
 * The interfaces the library offers: PKCS#11 v3.2, v3.1, v3.0 and v2.40, newest first. None of
 * this needs C_Initialize, or a TPM.
 */

static const CK_VERSION expected_versions[] = {
    { .major = 3, .minor = 2 },
    { .major = 3, .minor = 1 },
    { .major = 3, .minor = 0 },
    { .major = 2, .minor = 40 },
};

static const CK_VERSION *list_version(const CK_INTERFACE *interface) {
    return (const CK_VERSION *)interface->pFunctionList;
}

static void test_interface_list(void **state) {
    (void) state;

    CK_ULONG count = 0;
    assert_int_equal(C_GetInterfaceList(NULL, &count), CKR_OK);
    assert_int_equal(count, 4);

    CK_INTERFACE interfaces[4] = { 0 };
    count = 4;
    assert_int_equal(C_GetInterfaceList(interfaces, &count), CKR_OK);
    assert_int_equal(count, 4);

    for (size_t i = 0; i < 4; i++) {
        assert_string_equal(interfaces[i].pInterfaceName, "PKCS 11");
        assert_int_equal(interfaces[i].flags, 0);
        assert_int_equal(list_version(&interfaces[i])->major, expected_versions[i].major);
        assert_int_equal(list_version(&interfaces[i])->minor, expected_versions[i].minor);
    }
}

static void test_interface_list_buffer_too_small(void **state) {
    (void) state;

    CK_INTERFACE interfaces[3] = { 0 };
    CK_ULONG count = 3;
    assert_int_equal(C_GetInterfaceList(interfaces, &count), CKR_BUFFER_TOO_SMALL);
    assert_int_equal(count, 4);

    assert_int_equal(C_GetInterfaceList(interfaces, NULL), CKR_ARGUMENTS_BAD);
}

static void test_default_interface_is_newest(void **state) {
    (void) state;

    CK_INTERFACE_PTR interface = NULL;
    assert_int_equal(C_GetInterface(NULL, NULL, &interface, 0), CKR_OK);
    assert_non_null(interface);
    assert_int_equal(list_version(interface)->major, 3);
    assert_int_equal(list_version(interface)->minor, 2);

    interface = NULL;
    assert_int_equal(C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11", NULL, &interface, 0), CKR_OK);
    assert_int_equal(list_version(interface)->minor, 2);
}

static void test_interface_by_version(void **state) {
    (void) state;

    for (size_t i = 0; i < 4; i++) {
        CK_VERSION version = expected_versions[i];
        CK_INTERFACE_PTR interface = NULL;
        assert_int_equal(C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11", &version, &interface, 0), CKR_OK);
        assert_int_equal(list_version(interface)->major, version.major);
        assert_int_equal(list_version(interface)->minor, version.minor);
    }
}

static void test_interface_not_offered(void **state) {
    (void) state;

    CK_INTERFACE_PTR interface = NULL;
    CK_VERSION v2_20 = { .major = 2, .minor = 20 };
    assert_int_equal(C_GetInterface(NULL, &v2_20, &interface, 0), CKR_ARGUMENTS_BAD);
    assert_int_equal(C_GetInterface((CK_UTF8CHAR_PTR)"Vendor X", NULL, &interface, 0), CKR_ARGUMENTS_BAD);
    /* No interface is fork safe. */
    assert_int_equal(C_GetInterface(NULL, NULL, &interface, CKF_INTERFACE_FORK_SAFE), CKR_ARGUMENTS_BAD);
    assert_null(interface);

    assert_int_equal(C_GetInterface(NULL, NULL, NULL, 0), CKR_ARGUMENTS_BAD);
}

static void test_function_list_is_v2_40(void **state) {
    (void) state;

    CK_FUNCTION_LIST_PTR list = NULL;
    assert_int_equal(C_GetFunctionList(&list), CKR_OK);
    assert_int_equal(list->version.major, 2);
    assert_int_equal(list->version.minor, 40);
    assert_ptr_equal(list->C_GetFunctionList, C_GetFunctionList);

    CK_VERSION v2_40 = { .major = 2, .minor = 40 };
    CK_INTERFACE_PTR interface = NULL;
    assert_int_equal(C_GetInterface(NULL, &v2_40, &interface, 0), CKR_OK);
    assert_ptr_equal(interface->pFunctionList, list);
}

static void test_v3_lists_carry_v3_functions(void **state) {
    (void) state;

    for (size_t i = 0; i < 3; i++) {
        CK_VERSION version = expected_versions[i];
        CK_INTERFACE_PTR interface = NULL;
        assert_int_equal(C_GetInterface(NULL, &version, &interface, 0), CKR_OK);

        CK_FUNCTION_LIST_3_0_PTR list = interface->pFunctionList;
        assert_ptr_equal(list->C_Initialize, C_Initialize);
        assert_ptr_equal(list->C_GetInterface, C_GetInterface);
        assert_ptr_equal(list->C_GetInterfaceList, C_GetInterfaceList);
        assert_ptr_equal(list->C_LoginUser, C_LoginUser);
        assert_ptr_equal(list->C_SessionCancel, C_SessionCancel);
        assert_ptr_equal(list->C_MessageVerifyFinal, C_MessageVerifyFinal);
    }

    CK_INTERFACE_PTR interface = NULL;
    assert_int_equal(C_GetInterface(NULL, NULL, &interface, 0), CKR_OK);
    CK_FUNCTION_LIST_3_2_PTR list = interface->pFunctionList;
    assert_ptr_equal(list->C_VerifySignatureInit, C_VerifySignatureInit);
    assert_ptr_equal(list->C_VerifySignatureFinal, C_VerifySignatureFinal);
    assert_ptr_equal(list->C_GetSessionValidationFlags, C_GetSessionValidationFlags);
    assert_ptr_equal(list->C_UnwrapKeyAuthenticated, C_UnwrapKeyAuthenticated);
    assert_ptr_equal(list->C_EncapsulateKey, C_EncapsulateKey);
    assert_ptr_equal(list->C_DecapsulateKey, C_DecapsulateKey);
}

static void test_info_reports_v3_2(void **state) {
    (void) state;

    CK_INFO info = { 0 };
    assert_int_equal(general_get_info(&info), CKR_OK);
    assert_int_equal(info.cryptokiVersion.major, 3);
    assert_int_equal(info.cryptokiVersion.minor, 2);
}

/* The v3.x functions the token refuses still check the library is initialized first. */
static void test_refusals_need_init(void **state) {
    (void) state;

    assert_int_equal(C_MessageEncryptInit(1, NULL, 1), CKR_CRYPTOKI_NOT_INITIALIZED);
    assert_int_equal(C_AsyncGetID(1, NULL, NULL), CKR_CRYPTOKI_NOT_INITIALIZED);
    assert_int_equal(C_WaitForSlotEvent(CKF_DONT_BLOCK, NULL, NULL), CKR_CRYPTOKI_NOT_INITIALIZED);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_interface_list),
        cmocka_unit_test(test_interface_list_buffer_too_small),
        cmocka_unit_test(test_default_interface_is_newest),
        cmocka_unit_test(test_interface_by_version),
        cmocka_unit_test(test_interface_not_offered),
        cmocka_unit_test(test_function_list_is_v2_40),
        cmocka_unit_test(test_v3_lists_carry_v3_functions),
        cmocka_unit_test(test_info_reports_v3_2),
        cmocka_unit_test(test_refusals_need_init),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
