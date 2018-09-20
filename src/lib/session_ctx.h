/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_SESSION_CTX_H_
#define SRC_PKCS11_SESSION_CTX_H_

/*
 * XXX This session_ctx provides minimal abstractions, perhaps roll into session.h
 */

#include "object.h"
#include "pkcs11.h"
#include "token.h"
#include "tpm.h"
#include "utils.h"

typedef enum session_ctx_state session_ctx_state;
enum session_ctx_state {
    session_ctx_state_none = 0,
    // bits 0..2 so/user ro/rw state
    session_ctx_state_so_rw   = 1 << 0,
    session_ctx_state_user_ro = 1 << 1,
    session_ctx_state_user_rw = 1 << 2,

    // bit 3..4 user/so is logged in
    session_ctx_state_user_loggedin = 1 << 3,
    session_ctx_state_so_loggedin   = 1 << 4,
};

typedef enum operation operation;
enum operation {
    operation_find,
    operation_sign,
    operation_verify,
    operation_encrypt,
    operation_decrypt,
    operation_digest,
    operation_count
};

typedef struct session_ctx session_ctx;

void session_ctx_free(session_ctx *ctx);
CK_RV session_ctx_new(session_ctx **ctx, token *tok, bool is_rw);

void session_ctx_lock(session_ctx *ctx);
void session_ctx_unlock(session_ctx *ctx);

void session_ctx_opdata_set(session_ctx *ctx, operation op, void *opdata);
void *session_ctx_opdata_get(session_ctx *ctx, operation op);

tpm_ctx *session_ctx_get_tpm_ctx(session_ctx *ctx);

token *session_ctx_get_token(session_ctx *ctx);

session_ctx_state session_ctx_state_get(session_ctx *ctx);

static inline bool session_is_rw(session_ctx *ctx) {

    session_ctx_state state = session_ctx_state_get(ctx);
    return !!((state & session_ctx_state_so_rw)
            | (state & session_ctx_state_user_rw));
}

static inline CK_STATE session_ctx_get_CKS_flags(session_ctx *ctx) {

    // TODO deal with public sessions
    // Maybe we should get state bitwise segmented, ie CKS_ flags at
    // bits 0-4, CKF_ flags at 5-8, and so forth, then mask them out.
    session_ctx_state state = session_ctx_state_get(ctx);
    if (state & session_ctx_state_so_rw) {
        return CKS_RW_SO_FUNCTIONS;
    } else if (state & session_ctx_state_user_rw) {
        return CKS_RW_USER_FUNCTIONS;
    }

    return CKS_RO_USER_FUNCTIONS;
}

bool session_ctx_is_user_logged_in(session_ctx *ctx);

CK_RV session_ctx_login(session_ctx *ctx, twist pin, int usertype);

CK_RV session_ctx_logout(session_ctx *ctx);

CK_RV session_ctx_load_object(session_ctx *ctx, CK_OBJECT_HANDLE key, tobject **loaded_tobj);

#endif /* SRC_PKCS11_SESSION_CTX_H_ */
