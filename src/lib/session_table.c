/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <stdlib.h>

#include "assert.h"
#include "mutex.h"
#include "pkcs11.h"
#include "session_ctx.h"
#include "session_table.h"
#include "utils.h"

struct session_table {
    unsigned long cnt;
    unsigned long rw_cnt;
    CK_SESSION_HANDLE free_handle;
    session_ctx *table[MAX_NUM_OF_SESSIONS];
    void *lock;
};

CK_RV session_table_new(session_table **t) {

    session_table *x = calloc(1, sizeof(session_table));
    if (!x) {
        return CKR_HOST_MEMORY;
    }

    CK_RV rv = mutex_create(&x->lock);
    if (rv != CKR_OK) {
        session_table_free(x);
        return rv;
    }

    *t = x;

    return CKR_OK;
}

void session_table_free(session_table *t) {

    if (!t) {
        return;
    }

    if (t->lock) {
        mutex_destroy(t->lock);
    }
    free(t);
}

void session_table_lock(session_table *t) {
    mutex_lock_fatal(t->lock);
}

void session_table_unlock(session_table *t) {
    mutex_unlock_fatal(t->lock);
}

void session_table_get_cnt_unlocked(session_table *t, unsigned long *all, unsigned long *rw, unsigned long *ro) {

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

void session_table_get_cnt(session_table *t, unsigned long *all, unsigned long *rw, unsigned long *ro) {
    session_table_lock(t);
    session_table_get_cnt_unlocked(t, all, rw, ro);
    session_table_unlock(t);
}

session_ctx **session_table_lookup_unlocked(session_table *t, CK_SESSION_HANDLE handle) {
    return &t->table[handle];
}

CK_RV session_table_new_ctx_unlocked(session_table *t, CK_SESSION_HANDLE *handle,
        token *tok, CK_FLAGS flags) {

    session_ctx **c = session_table_lookup_unlocked(t, t->free_handle);
    assert(!*c);

    CK_RV rv = session_ctx_new(c, tok, flags);
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

CK_RV session_table_free_ctx_unlocked(session_table *t, CK_SESSION_HANDLE handle) {

    session_ctx **ctx = &t->table[handle];
    if (!*ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    CK_STATE state = session_ctx_state_get(*ctx);
    if(state == CKS_RW_PUBLIC_SESSION
        || state == CKS_RW_USER_FUNCTIONS
        || state == CKS_RW_SO_FUNCTIONS) {
        assert(t->rw_cnt);
        t->rw_cnt--;
    }

    t->cnt--;

    session_ctx_free(*ctx);
    *ctx = NULL;

    return CKR_OK;
}

void session_table_free_ctx_all(session_table *t) {

    session_table_lock(t);

    unsigned i;
    for (i=0; i < ARRAY_LEN(t->table); i++) {
        CK_SESSION_HANDLE handle = i;
        session_ctx **ctx = session_table_lookup_unlocked(t, handle);
        session_ctx_free(*ctx);
        *ctx = NULL;
    }

    session_table_unlock(t);
}

CK_RV session_table_free_ctx(session_table *t, CK_SESSION_HANDLE handle) {

    session_table_lock(t);
    CK_RV rv = session_table_free_ctx_unlocked(t, handle);
    session_table_unlock(t);

    return rv;
}

session_ctx *session_table_lookup(session_table *t, CK_SESSION_HANDLE handle) {

    session_ctx *ctx = NULL;

    if (handle > ARRAY_LEN(t->table)) {
        return NULL;
    }

    session_table_lock(t);

    ctx = *session_table_lookup_unlocked(t, handle);
    if (!ctx) {
        goto unlock;
    }

    session_ctx_lock(ctx);

unlock:
    session_table_unlock(t);

    return ctx;
}

void session_table_login_event(session_table *s_table, CK_USER_TYPE user, session_ctx *called_session) {

    size_t i;
    for (i=0; i < ARRAY_LEN(s_table->table); i++) {

        session_ctx *ctx = s_table->table[i];
        if (!ctx) {
            continue;
        }

        bool take_lock = ctx != called_session;

        session_ctx_login_event(ctx, user, take_lock);
    }
}

void session_table_logout_event(session_table *s_table, session_ctx *called_session) {

    size_t i;
    for (i=0; i < ARRAY_LEN(s_table->table); i++) {

        session_ctx *ctx = s_table->table[i];
        if (!ctx) {
            continue;
        }

        bool take_lock = ctx != called_session;

        session_ctx_logout_event(ctx, take_lock);
    }
}
