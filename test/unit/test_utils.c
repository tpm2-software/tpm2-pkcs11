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

#include "utils.h"

static void test_parse_lib_version(void **state) {
    (void) state;

    CK_BYTE major  = 0xFF;
    CK_BYTE minor = 0xFF;
    parse_lib_version("1", &major, &minor);
    assert_int_equal(major, 1);
    assert_int_equal(minor, 0);

    major  = 0xFF;
    minor = 0xFF;
    parse_lib_version("5.2", &major, &minor);
    assert_int_equal(major, 5);
    assert_int_equal(minor, 2);

    major  = 0xFF;
    minor = 0xFF;
    parse_lib_version("9.8.7", &major, &minor);
    assert_int_equal(major, 9);
    assert_int_equal(minor, 8);

    major  = 0xFF;
    minor = 0xFF;
    parse_lib_version("1.6.0-42-gb462a23778ea-dirty", &major, &minor);
    assert_int_equal(major, 0);
    assert_int_equal(minor, 0);

    major  = 0xFF;
    minor = 0xFF;
    parse_lib_version("1.6.0-", &major, &minor);
    assert_int_equal(major, 0);
    assert_int_equal(minor, 0);

    major  = 0xFF;
    minor = 0xFF;
    parse_lib_version("", &major, &minor);
    assert_int_equal(major, 0);
    assert_int_equal(minor, 0);

    major  = 0xFF;
    minor = 0xFF;
    parse_lib_version(NULL, &major, &minor);
    assert_int_equal(major, 0);
    assert_int_equal(minor, 0);
}

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_lib_version),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
