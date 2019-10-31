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

typedef enum token_login_state token_login_state;
enum token_login_state {
    token_no_one_logged_in = 0,
    token_user_logged_in   = 1 << 0,
    token_so_logged_in     = 1 << 1,
};

typedef struct token token;
struct token {

    unsigned id;
    unsigned pid;
    unsigned char label[32];

    pobject pobject;

    twist wappingkey;

    sealobject sealobject;

    tobject *tobjects;

    struct {
        bool is_initialized; /* token initialization state */
    } config;

    session_table *s_table;

    token_login_state login_state;

    tpm_ctx *tctx;

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
 * TODO
 * @param tok
 * @param old_pin
 * @param old_len
 * @param new_pin
 * @param new_len
 * @return
 */
CK_RV token_setpin(token *tok, CK_UTF8CHAR_PTR old_pin, CK_ULONG old_len, CK_UTF8CHAR_PTR new_pin, CK_ULONG new_len);

CK_RV token_initpin(token *tok, CK_UTF8CHAR_PTR new_pin, CK_ULONG new_len);

void token_lock(token *t);
void token_unlock(token *t);

/**
 * Look up and possibly load an unloaded tobject.
 * @param tok
 *  The token to look up the object on.
 * @param key
 *  The object handle to look for.
 * @param loaded_tobj
 *  The pointer to the backing tobject
 * @return
 *   CKR_OK - everything is good.
 *   CKR_INVALID_KEY_HANDLE - not found
 *   CKR_KEY_HANDLE_INVALID - invalid key handle
 *   Others like: CKR_GENERAL_ERROR and CKR_HOST_MEMORY
 */
CK_RV token_load_object(token *tok, CK_OBJECT_HANDLE key, tobject **loaded_tobj);

#endif /* SRC_TOKEN_H_ */
