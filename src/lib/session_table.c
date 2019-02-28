/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include "config.h"
#include <assert.h>
#include <stdlib.h>

#include "mutex.h"
#include "pkcs11.h"
#include "session_ctx.h"
#include "session_table.h"
#include "token.h"
#include "utils.h"

struct session_table {
    CK_ULONG cnt;
    CK_ULONG rw_cnt;
    CK_SESSION_HANDLE free_handle;
    session_ctx *table[MAX_NUM_OF_SESSIONS];
};

CK_RV session_table_new(session_table **t) {

    session_table *x = calloc(1, sizeof(session_table));
    if (!x) {
        return CKR_HOST_MEMORY;
    }

    *t = x;

    return CKR_OK;
}

void session_table_free(session_table *t) {

    if (!t) {
        return;
    }

    free(t);
}

void session_table_get_cnt(session_table *t, CK_ULONG_PTR all, CK_ULONG_PTR rw, CK_ULONG_PTR ro) {

    /* All counts should always be greater than or equal to rw count */
    assert(t->cnt >= t->rw_cnt);

    if (all) {
        *all = t->cnt;
    }

    if (rw) {
        *rw = t->rw_cnt;
    }

    if (ro) {
        *ro = t->cnt - t->rw_cnt;
    }
}

CK_RV session_table_new_entry(session_table *t, CK_SESSION_HANDLE *handle,
        token *tok, CK_FLAGS flags) {

    /*
     * TODO need to search for open slot here so we don't
     * exhaust handles.
     */
    session_ctx **open_slot = &t->table[t->free_handle];
    assert(!*open_slot);

    CK_RV rv = session_ctx_new(open_slot, tok->login_state, flags);
    if (rv != CKR_OK) {
        return rv;
    }

    *handle = t->free_handle;
    t->free_handle++;
    t->cnt++;

    if(flags & CKF_RW_SESSION) {
        t->rw_cnt++;
    }

    return CKR_OK;
}

static CK_RV do_logout_if_needed(token *tok) {

    if (tok->login_state == token_no_one_logged_in) {
        return CKR_OK;
    }

    return token_logout(tok);
}

static CK_RV session_table_free_ctx_by_ctx(token *t, session_ctx **ctx) {

    session_table *stable = t->s_table;

    CK_RV rv = CKR_OK;

    CK_STATE state = session_ctx_state_get(*ctx);
    if(state == CKS_RW_PUBLIC_SESSION
        || state == CKS_RW_USER_FUNCTIONS
        || state == CKS_RW_SO_FUNCTIONS) {
        assert(stable->rw_cnt);
        stable->rw_cnt--;
    }

    stable->cnt--;

    /* Per the spec, when session count hits 0, logout */
    if (!stable->cnt) {
        rv = do_logout_if_needed(t);
        if (rv != CKR_OK) {
            LOGE("do_logout_if_needed failed: 0x%x", rv);
        }
    }

    session_ctx_free(*ctx);

    *ctx = NULL;

    return rv;
}

CK_RV session_table_free_ctx_by_handle(token *t, CK_SESSION_HANDLE handle) {

    session_table *stable = t->s_table;

    session_ctx **ctx = &stable->table[handle];
    if (!*ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    return session_table_free_ctx_by_ctx(t, ctx);
}

CK_RV session_table_free_ctx_all(token *t) {

    bool had_error = false;

    unsigned i;
    for (i=0; i < ARRAY_LEN(t->s_table->table); i++) {
        CK_SESSION_HANDLE handle = i;

        /*
         * skip dead handles
         */
        session_ctx **ctx = &t->s_table->table[handle];
        if (!*ctx) {
            continue;
        }

        CK_RV rv = session_table_free_ctx_by_ctx(t, ctx);
        if (rv != CKR_OK) {
            LOGE("Failed to free session_ctx: 0x%x", rv);
            had_error = true;
        }
    }

    return !had_error ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV session_table_free_ctx(token *t, CK_SESSION_HANDLE handle) {

    return session_table_free_ctx_by_handle(t, handle);
}

session_ctx *session_table_lookup(session_table *t, CK_SESSION_HANDLE handle) {

    if (handle >= ARRAY_LEN(t->table)) {
        return NULL;
    }

    return t->table[handle];
}

void session_table_login_event(session_table *s_table, CK_USER_TYPE user) {

    size_t i;
    for (i=0; i < ARRAY_LEN(s_table->table); i++) {

        session_ctx *ctx = s_table->table[i];
        if (!ctx) {
            continue;
        }

        session_ctx_login_event(ctx, user);
    }
}

void token_logout_all_sessions(token *tok) {

    size_t i;
    for (i=0; i < ARRAY_LEN(tok->s_table->table); i++) {

        session_ctx *ctx = tok->s_table->table[i];
        if (!ctx) {
            continue;
        }

        session_ctx_logout_event(ctx);
    }
}
