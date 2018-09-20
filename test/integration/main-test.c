/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#include <stdbool.h>
#include <stdlib.h>

#define LOGMODULE test
#include "log.h"
#include "test.h"


int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    int ret = test_invoke();

    return ret;
}
