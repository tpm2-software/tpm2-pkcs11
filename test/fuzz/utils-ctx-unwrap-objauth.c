/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"
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

#include "token.h"
#include "twist.h"
#include "utils.h"

static const uint8_t *_data = NULL;
static size_t _size = 0;

/*
 * We want to target malicious DB injection. If someone points us to a store,
 * where data is malformed, we want to tolerate that.
 *
 * Generally 3 things come from the db in wild formats:
 * 1. attributes in yaml
 * 2. wrapped object auths (immediately handed to twistbin_new())
 * 3. Public and Private TPM blobs
 *
 * This test aims to check issue 2.
 *
 * Sample Good Corpus with key below:
 * 05271d7286bfb46667a6ed2c:aa1f228f9925ac9694663d0b20dc5526:a8b8b5487e1abe7585458e88c8c7e82dc8c1f40d7bb0c6776a3895ecf75d240b
 *
 * Define CORPUS_TEST to test it.
 */
static void test(void **state) {
    UNUSED(state);
#ifdef CORPUS_TEST
    char *e = "05271d7286bfb46667a6ed2c:aa1f228f9925ac9694663d0b20dc5526:a8b8b5487e1abe7585458e88c8c7e82dc8c1f40d7bb0c6776a3895ecf75d240b";
    _data = (uint8_t *)e;
    _size = strlen(e);
#endif

    /* we just need an AES key, any key will work */
    twist wrappingkey = twistbin_unhexlify("6ef4c48c59793d6f004dbf4de399e643b627031a4bfd352b660fadaced95c9b4");
    assert_non_null(wrappingkey);

    twist wrapped = twistbin_new(_data, _size);
    assert_non_null(wrapped);

    twist unwrapped = NULL;
    /*
     * under the hood this expects very specifically formated hex data, make sure that code
     * doesn't blow up
     */
    CK_RV rv = utils_ctx_unwrap_objauth(wrappingkey, wrapped, &unwrapped);
#ifdef CORPUS_TEST
    assert_int_equal(rv, CKR_OK);
#else
    UNUSED(rv);
#endif

    twist_free(wrappingkey);
    twist_free(wrapped);
    twist_free(unwrapped);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    _data = data;
    _size = size;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test),
    };

    cmocka_run_group_tests(tests, NULL, NULL);
    return 0;
}
