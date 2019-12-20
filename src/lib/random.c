/* SPDX-License-Identifier: BSD-2-Clause */

#include "checks.h"
#include "pkcs11.h"
#include "random.h"
#include "session_ctx.h"
#include "token.h"
#include "tpm.h"

CK_RV random_get(session_ctx *ctx, CK_BYTE_PTR random_data, CK_ULONG random_len) {

    check_pointer(random_data);

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tpm_ctx *tpm = tok->tctx;

    bool res = tpm_getrandom(tpm, random_data, random_len);

    return res ? CKR_OK: CKR_GENERAL_ERROR;
}

CK_RV seed_random(session_ctx *ctx, CK_BYTE_PTR seed, CK_ULONG seed_len) {

    check_pointer(seed);

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tpm_ctx *tpm = tok->tctx;
    CK_RV rv = tpm_stirrandom(tpm, seed, seed_len);

    return rv;
}
