/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>

#include <linux/limits.h>

#include "db.h"

static const uint8_t *_data;
static size_t _size;

typedef struct test_state test_state;
struct test_state {
    char *random_string;
    char *tmp_dir;
    FILE *file;
};

static inline test_state *test_state_cast(void **state) {
    return (test_state *)*state;
}

static void test_state_free(test_state **test) {

    if (test && *test) {
        test_state *t = *test;
        free(t->random_string);
        if (t->file) {
            fclose(t->file);
        }
        free(t);
        *test = NULL;
    }
}

static test_state *test_state_new(const uint8_t *data, size_t len) {

    /* require a null terminated string */
    char *null_term_data = calloc(1, len + 1);
    if (!null_term_data) {
        return NULL;
    }
    memcpy(null_term_data, data, len);

    char tmp_key[] = "pkcs11_fuzztest_db_take_lock_XXXXXX";
    char *tmp_dir = mkdtemp(tmp_key);
    if (!tmp_dir) {
        free(null_term_data);
        return NULL;
    }

    test_state *t = calloc(1, sizeof(test_state));
    if (!t) {
        free(null_term_data);
        return NULL;
    }

    t->random_string = null_term_data;
    t->tmp_dir = tmp_dir;

    return t;
}

static int setup(void **state) {

    /* assign to state */
    *state = test_state_new(_data, _size);

    return *state == NULL;
}

static int teardown(void **state) {

    test_state *s = test_state_cast(state);
    test_state_free(&s);

    return 0;
}

static void test(void **state) {

    test_state *t = test_state_cast(state);
    assert_non_null(t);

    setenv("PKCS11_SQL_LOCK", t->random_string, true);

    char lockpath[PATH_MAX];
    t->file = take_lock(t->tmp_dir, lockpath);
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
