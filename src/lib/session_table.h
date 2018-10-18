/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_SESSION_TABLE_H_
#define SRC_PKCS11_SESSION_TABLE_H_

#include "session.h"
#include "session_ctx.h"

typedef struct session_table session_table;

CK_RV session_table_new(session_table **t);
void session_table_free(session_table *t);

void session_table_unlock(session_table *t);
void session_table_lock(session_table *t);

unsigned long session_table_get_cnt(session_table *t, bool is_rw);
unsigned long session_table_get_cnt_unlocked(session_table *t, bool is_rw);

CK_RV session_table_new_ctx_unlocked(session_table *t,
        CK_SESSION_HANDLE *handle, token *tok, bool is_rw);

session_ctx *session_table_lookup(session_table *t, CK_SESSION_HANDLE handle);

CK_RV session_table_free_ctx_unlocked(session_table *t, CK_SESSION_HANDLE handle);
CK_RV session_table_free_ctx(session_table *t, CK_SESSION_HANDLE handle);
void session_table_free_ctx_all(session_table *t);
void session_table_update_ctx_state(session_table *t, token *tok, session_ctx_state state);

#endif /* SRC_PKCS11_SESSION_TABLE_H_ */
