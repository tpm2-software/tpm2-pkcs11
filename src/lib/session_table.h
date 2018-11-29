/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_SESSION_TABLE_H_
#define SRC_PKCS11_SESSION_TABLE_H_

#include "session.h"
#include "session_ctx.h"
#include "session_table.h"

typedef struct token token;

typedef struct session_table session_table;

CK_RV session_table_new(session_table **t);
void session_table_free(session_table *t);

void session_table_unlock(session_table *t);
void session_table_lock(session_table *t);

void session_table_get_cnt(session_table *t, unsigned long *all, unsigned long *rw, unsigned long *ro);
void session_table_get_cnt_unlocked(session_table *t, unsigned long *all, unsigned long *rw, unsigned long *ro);

CK_RV session_table_new_ctx_unlocked(session_table *t,
        CK_SESSION_HANDLE *handle, token *tok, CK_FLAGS flags);

session_ctx *session_table_lookup(session_table *t, CK_SESSION_HANDLE handle);

CK_RV session_table_free_ctx_unlocked_by_handle(token *t, CK_SESSION_HANDLE handle);
CK_RV session_table_free_ctx(token *t, CK_SESSION_HANDLE handle);
void session_table_free_ctx_all(token *t);

/**
 * performs a session_ctx_login_event() call for each item in the table
 * with the session table lock held.
 * @param s_table
 *  The session table
 * @param user
 *  The user triggering the login event.
 */
void session_table_login_event(session_table *s_table, CK_USER_TYPE user);

/**
 * performs a session_ctx_logout_event() call for each item in the table
 * with the session table lock held.
 * @param s_table
 *  The session table
 * @param called_session
 *  The session context that the logout event occured on.
 */
void token_logout_all_sessions(token *tok);


#endif /* SRC_PKCS11_SESSION_TABLE_H_ */
