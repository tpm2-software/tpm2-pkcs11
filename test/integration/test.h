/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
/* SPDX-License-Identifier: BSD-2 */

#define YES 1
#define NO  0

/*
 * This is the prototype for all integration tests in the tpm2-tss
 * project. Integration tests are intended to exercise the combined
 * components in the software stack. This typically means executing some
 * SAPI function using the socket TCTI to communicate with a software
 * TPM2 simulator.
 * Return values:
 * A successful test will return 0, any other value indicates failure.
 */
int test_invoke();
