/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include "checks.h"
#include "pkcs11.h"
#include "random.h"
#include "token.h"
#include "tpm.h"

CK_RV random_get(CK_BYTE_PTR random_data, CK_ULONG random_len) {

    check_pointer(random_data);

    bool res = tpm_getrandom(random_data, random_len);

    return res ? CKR_OK: CKR_GENERAL_ERROR;
}
