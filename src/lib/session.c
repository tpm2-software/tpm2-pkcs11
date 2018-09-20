/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "checks.h"
#include "general.h"
#include "log.h"
#include "mutex.h"
#include "pkcs11.h"
#include "session.h"
#include "session_table.h"
#include "session_ctx.h"
#include "token.h"
#include "tpm.h"
#include "utils.h"

static struct {
    session_table *s_table;
} global;

CK_RV session_init(void) {

    return session_table_new(&global.s_table);
}

void session_destroy(void) {

    session_table_free(global.s_table);
}

static CK_RV check_max_sessions(bool is_rw) {

    unsigned long cnt = session_table_get_cnt(global.s_table, is_rw);
    return (cnt > MAX_NUM_OF_SESSIONS) ?
        CKR_SESSION_COUNT : CKR_OK;
}

unsigned long session_cnt_get(bool is_rw) {
    return session_table_get_cnt(global.s_table, is_rw);
}

CK_RV session_open(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application,
		CK_NOTIFY notify, CK_SESSION_HANDLE *session) {

    (void) notify;
    (void) application; /* can be null */

    if (!(flags & CKF_SERIAL_SESSION)) {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    CK_RV rv = CKR_GENERAL_ERROR;

    check_is_init();
	check_pointer(session);

	token *t = slot_get_token(slot_id);
	if (!t) {
	    return CKR_SLOT_ID_INVALID;
	}

	bool is_rw = flags & CKF_RW_SESSION;

	session_table_lock(global.s_table);
	rv = check_max_sessions(is_rw);
	if (rv != CKR_OK) {
	    goto unlock;
	}

	rv = session_table_new_ctx_unlocked(global.s_table, session, t, is_rw);

unlock:
	session_table_unlock(global.s_table);
	return rv;
}

CK_RV session_close(CK_SESSION_HANDLE session) {

    check_is_init();

    return session_table_free_ctx(global.s_table, session);
}

CK_RV session_closeall(CK_SLOT_ID slot_id) {

    check_is_init();
    check_slot_id(slot_id);

    session_table_free_ctx_all(global.s_table);

    return CKR_OK;
}

session_ctx *session_lookup(CK_SESSION_HANDLE session) {

    return session_table_lookup(global.s_table, session);
}

CK_RV session_login (CK_SESSION_HANDLE session, CK_USER_TYPE user_type,
        unsigned char *pin, unsigned long pin_len) {

    check_is_init();

    twist tpin = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    session_ctx *ctx = session_lookup(session);
    if (!ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    tpin = twistbin_new(pin, pin_len);
    if (!tpin) {
        return CKR_HOST_MEMORY;
    }

    // TODO Handle CKU_CONTEXT_SPECIFIC
    // TODO Support CKA_ALWAYS_AUTHENTICATE
    switch(user_type) {
        case CKU_SO:
            rv = session_ctx_login(ctx, tpin, user_type);
        break;
        case CKU_USER:
            rv = session_ctx_login(ctx, tpin, user_type);
        break;
        case CKU_CONTEXT_SPECIFIC:
            rv = CKR_USER_TYPE_INVALID;
            break;
        default:
            rv = CKR_USER_TYPE_INVALID;
    }

    twist_free(tpin);
    session_ctx_unlock(ctx);

    return rv;
}

CK_RV session_logout (CK_SESSION_HANDLE session) {

    check_is_init();

    session_ctx *ctx = session_lookup(session);
    if (!ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    CK_RV rv = session_ctx_logout(ctx);

    session_ctx_unlock(ctx);

    return rv;
}

CK_RV session_get_info (CK_SESSION_HANDLE session, struct _CK_SESSION_INFO *info) {

    check_is_init();
    check_pointer(info);

    session_ctx *ctx = session_lookup(session);
    if (!ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    info->flags = CKF_SERIAL_SESSION;
    info->flags |= session_is_rw(ctx) ? CKF_RW_SESSION : 0;

    token *t = session_ctx_get_token(ctx);
    info->slotID = t->id;


    info->state = session_ctx_get_CKS_flags(ctx);

    // We'll need to set this state error at some point, perhaps TSS2_RC's
    info->ulDeviceError = 0;

    session_ctx_unlock(ctx);

    return CKR_OK;
}
