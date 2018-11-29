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
#include "token.h"
#include "tpm.h"

CK_RV random_get(CK_SESSION_HANDLE session, unsigned char *random_data, unsigned long random_len) {

    session_ctx *ctx = NULL;
    CK_RV rv = session_lookup(session, &ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    token *tok = session_ctx_get_tok(ctx);
    tpm_ctx *tpm = tok->tctx;

    bool res = tpm_getrandom(tpm, random_data, random_len);
    session_ctx_unlock(ctx);

    return res ? CKR_OK: CKR_GENERAL_ERROR;
}

CK_RV seed_random (CK_SESSION_HANDLE session, unsigned char *seed, unsigned long seed_len) {

    session_ctx *ctx = NULL;
    CK_RV rv = session_lookup(session, &ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    token *tok = session_ctx_get_tok(ctx);
    tpm_ctx *tpm = tok->tctx;

    rv = tpm_stirrandom(tpm, seed, seed_len);
    session_ctx_unlock(ctx);

    return rv;
}
