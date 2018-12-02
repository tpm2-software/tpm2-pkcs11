/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include "checks.h"
#include "pkcs11.h"
#include "random.h"
#include "session_ctx.h"
#include "token.h"
#include "tpm.h"

CK_RV random_get(token *tok, unsigned char *random_data, unsigned long random_len) {

    check_pointer(random_data);

    tpm_ctx *tpm = tok->tctx;

    bool res = tpm_getrandom(tpm, random_data, random_len);

    return res ? CKR_OK: CKR_GENERAL_ERROR;
}

CK_RV seed_random(token *tok, unsigned char *seed, unsigned long seed_len) {

    check_pointer(seed);

    tpm_ctx *tpm = tok->tctx;
    CK_RV rv = tpm_stirrandom(tpm, seed, seed_len);

    return rv;
}
