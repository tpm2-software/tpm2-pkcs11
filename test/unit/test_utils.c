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

/* A block of data ending in PKCS#7 padding of pad bytes. */
static void padded_block(CK_BYTE block[32], CK_BYTE pad) {
    memset(block, 0x41, 32);
    memset(&block[32 - pad], pad, pad);
}

static void test_remove_pkcs7_pad_valid(void **state) {
    (void) state;

    for (CK_BYTE pad = 1; pad <= 16; pad++) {
        CK_BYTE block[32];
        padded_block(block, pad);

        CK_BYTE out[32];
        CK_ULONG outlen = sizeof(out);
        assert_int_equal(remove_pkcs7_pad(block, sizeof(block), out, &outlen), CKR_OK);
        assert_int_equal(outlen, 32 - pad);
        assert_memory_equal(out, block, outlen);
    }
}

/* Every padding byte must be the pad value, not only the last. */
static void test_remove_pkcs7_pad_inconsistent(void **state) {
    (void) state;

    for (CK_BYTE pad = 2; pad <= 16; pad++) {
        for (CK_BYTE bad = 1; bad < pad; bad++) {
            CK_BYTE block[32];
            padded_block(block, pad);
            block[32 - 1 - bad] ^= 0x01;

            CK_BYTE out[32];
            CK_ULONG outlen = sizeof(out);
            assert_int_equal(remove_pkcs7_pad(block, sizeof(block), out, &outlen), CKR_ENCRYPTED_DATA_INVALID);
        }
    }
}

static void test_remove_pkcs7_pad_out_of_range(void **state) {
    (void) state;

    CK_BYTE block[16];
    CK_BYTE out[16];
    CK_ULONG outlen = sizeof(out);

    memset(block, 0, sizeof(block));
    assert_int_equal(remove_pkcs7_pad(block, sizeof(block), out, &outlen), CKR_ENCRYPTED_DATA_INVALID);

    memset(block, 17, sizeof(block));
    assert_int_equal(remove_pkcs7_pad(block, sizeof(block), out, &outlen), CKR_ENCRYPTED_DATA_INVALID);
}

static void test_remove_pkcs7_pad_length(void **state) {
    (void) state;

    CK_BYTE block[32];
    padded_block(block, 4);
    CK_BYTE out[32];

    /* empty, or not a whole number of blocks */
    CK_ULONG outlen = sizeof(out);
    assert_int_equal(remove_pkcs7_pad(block, 0, out, &outlen), CKR_ENCRYPTED_DATA_LEN_RANGE);
    assert_int_equal(remove_pkcs7_pad(block, 31, out, &outlen), CKR_ENCRYPTED_DATA_LEN_RANGE);

    /* a buffer too small for what remains */
    outlen = 27;
    assert_int_equal(remove_pkcs7_pad(block, sizeof(block), out, &outlen), CKR_BUFFER_TOO_SMALL);
}

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_lib_version),
        cmocka_unit_test(test_remove_pkcs7_pad_valid),
        cmocka_unit_test(test_remove_pkcs7_pad_inconsistent),
        cmocka_unit_test(test_remove_pkcs7_pad_out_of_range),
        cmocka_unit_test(test_remove_pkcs7_pad_length),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
