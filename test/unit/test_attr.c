/* SPDX-License-Identifier: BSD-2-Clause */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>

#include "attrs.h"

static void test_config_parser_empty_seq(void **state) {
    (void) state;

    attr_list *attrs = attr_list_new();
    assert_non_null(attrs);

    bool r = attr_list_add_int(attrs, CKA_CLASS, CKO_CERTIFICATE);
    assert_true(r);

    r = attr_list_add_buf(attrs, CKA_ID, (CK_BYTE_PTR)"2132333435", 10);
    assert_true(r);

    r = attr_list_add_bool(attrs, CKA_DECRYPT, CK_TRUE);
    assert_true(r);

    /* test class */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, CKA_CLASS);
    assert_non_null(a);
    CK_OBJECT_CLASS got_class = CKO_DATA;
    CK_RV rv = attr_CK_OBJECT_CLASS(a, &got_class);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(got_class, CKO_CERTIFICATE);

    /* test id */
    a = attr_get_attribute_by_type(attrs, CKA_ID);
    assert_non_null(a);
    assert_int_equal(a->ulValueLen, 10);
    assert_memory_equal(a->pValue, "2132333435", 10);

    /* test decrypt */
    a = attr_get_attribute_by_type(attrs, CKA_DECRYPT);
    assert_non_null(a);
    CK_BBOOL got_bool = CK_FALSE;
    rv = attr_CK_BBOOL(a, &got_bool);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(got_bool, CK_TRUE);

    /* test shouldn't be there */
    a = attr_get_attribute_by_type(attrs, CKA_SIGN);
    assert_null(a);

    attr_list_free(attrs);
}

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_config_parser_empty_seq),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
