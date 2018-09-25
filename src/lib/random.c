/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <string.h>

#include "general.h"
#include "pkcs11.h"
#include "random.h"
#include "session.h"
#include "tpm.h"

CK_RV random_get(CK_SESSION_HANDLE session, unsigned char *random_data, unsigned long random_len) {

    session_ctx *ctx = session_lookup(session);
    if (!ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    tpm_ctx *sys = session_ctx_get_tpm_ctx(ctx);

    bool res = tpm_getrandom(sys, random_data, random_len);
    session_ctx_unlock(ctx);

    return res ? CKR_OK: CKR_GENERAL_ERROR;
}

CK_RV seed_random (CK_SESSION_HANDLE session, unsigned char *seed, unsigned long seed_len) {

    session_ctx *ctx = session_lookup(session);
    if (!ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);

    CK_RV rv = tpm_stirrandom(tpm, seed, seed_len);
    session_ctx_unlock(ctx);

    return rv;
}
