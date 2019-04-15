/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
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

#include "log.h"
#include "utils.h"

void test_log_levels(void **state) {
    (void) state;

    char *levels[] = {"abc", "-1", "0", "1", "2", "3", "4"}; 
    for (int i = 0; i < 7; i++) {
        setenv("TPM2_PKCS11_LOG_LEVEL", levels[i], 1);
        LOGV("Test %i", i);
        LOGW("Test %i", i);
        LOGE("Test %i", i);
    }
}

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_log_levels),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
