/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_TOKEN_H_
#define SRC_TOKEN_H_

#include "checks.h"
#include "object.h"
#include "pkcs11.h"
#include "session_ctx.h"
#include "tpm.h"
#include "twist.h"
#include "utils.h"

typedef struct session_table session_table;
typedef struct session_ctx session_ctx;

typedef enum operation operation;
enum operation {
    operation_none = 0,
    operation_find,
    operation_sign,
    operation_verify,
    operation_encrypt,
    operation_decrypt,
    operation_digest,
    operation_count
};

typedef enum token_login_state token_login_state;
enum token_login_state {
    token_no_one_logged_in = 0,
    token_user_logged_in   = 1 << 0,
    token_so_logged_in     = 1 << 1,
};

typedef struct generic_opdata generic_opdata;
struct generic_opdata {
    operation op;
    void *data;
};

typedef struct token token;
struct token {

    unsigned id;
    unsigned pid;
    unsigned char label[32];

    twist userpobjauthkeysalt;
    unsigned userpobjauthkeyiters;
    twist userpobjauth;

    twist sopobjauthkeysalt;
    unsigned sopobjauthkeyiters;
    twist sopobjauth;

    pobject pobject;

    sealobject sealobject;
    wrappingobject wrappingobject;

    sobject sobject;

    tobject *tobjects;

    struct {
        bool sym_support; /* use TPM for unwrapping if true else use software */
        bool is_initialized; /* token initialization state */
    } config;

    session_table *s_table;

    token_login_state login_state;

    tpm_ctx *tctx;

    generic_opdata opdata;

    void *mutex;
};

/**
 * Frees a token
 * @param t
 *  The token to free
 */
void token_free(token *t);

/**
 * Free's a list of tokens
 * @param t
 *  The token list to free
 * @param len
 *  The number of elements to free
 */
void token_free_list(token *t, size_t len);

CK_RV token_get_info(token *t, CK_TOKEN_INFO *info);

/**
 * Causes a login event to be propagated through the token
 * associated with the session context. A login event is
 * Propagated by:
 *   1. setting the token level who is logged in state with whom is logged in.
 *   2. updating all open session states in the session table
 * @param ctx
 *  The session context to update
 * @param pin
 *  The pin
 * @param user
 *  The user
 * @return
 *  CKR_OK on success, anything else is a failure.
 */
CK_RV token_login(token *tok, twist pin, CK_USER_TYPE user);

/**
 * Generates a logout event to be propagated through the token.
 * A logout event is propagated by:
 *   1. setting the token level "who is logged in state" to no one is logged in.
 *   2. setting all existing sessions back to their original state.
 *
 * @param tok
 *  The token to propagate the login event
 * @return
 *  CKR_OK on success, anything else is a failure.
 */
CK_RV token_logout(token *tok);

/**
 * Determines if the opdata is in use
 * @param ctx
 *  The token
 * @return
 */
bool token_opdata_is_active(token *tok);

/**
 * Sets operational specific data. Callers should take care to ensure
 * no other users are using it by calling token_opdata_is_active()
 * before setting the data.
 *
 * @param tok
 *  The token to set operational data on
 * @param op
 *  The operation setting the data
 * @param data
 *  The data to set
 */
void token_opdata_set(token *tok, operation op, void *data);

/**
 * Clears the token opdata state. NOTE that callers
 * are required to perfrom memory managment on what
 * is stored in the void pointer.
 * @param tok
 *  The token to clear operational data from.
 */
void token_opdata_clear(token *tok);

/**
 * Sets the operation specific state data
 * @param tok
 *  The token to set the operation state data
 * @param op
 *  The operation setting it
 * @param data
 *  The data to set
 * @return
 *  CKR_OK on success.
 */
#define token_opdata_get(ctx, op, data) _token_opdata_get(ctx, op, (void **)data)
CK_RV _token_opdata_get(token *tok, operation op, void **data);

void token_lock(token *t);
void token_unlock(token *t);

#endif /* SRC_TOKEN_H_ */
