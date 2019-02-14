/* SPDX-License-Identifier: BSD-2 */
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
#include "token.h"
#include "tpm.h"
#include "utils.h"

static CK_RV check_max_sessions(session_table *s_table) {

    CK_ULONG all;

    session_table_get_cnt(s_table, &all, NULL, NULL);

    return (all > MAX_NUM_OF_SESSIONS) ?
        CKR_SESSION_COUNT : CKR_OK;
}

#define TOKID_SESSION_SHIFT ((sizeof(CK_SESSION_HANDLE) * 8) - 8)

static inline void add_tokid_to_session_handle(unsigned tokid,
        CK_SESSION_HANDLE *handle) {

    /*
     * Plop the token id in the high byte
     */
    *handle |= ((typeof(*handle))tokid << TOKID_SESSION_SHIFT);
}

static inline unsigned get_tokid_from_session_handle_and_cleanse(
        CK_SESSION_HANDLE *handle) {

    /*
     * Get the token id from the high byte
     */
    unsigned tokid = (*handle >> TOKID_SESSION_SHIFT);

    /*
     * drop the top byte, this is a simple way to deal
     * with CK_SESSION_HANDLE being architecture dependent
     * in size.
     */
    CK_SESSION_HANDLE tmp = *handle;
    tmp = tmp << 8;
    tmp = tmp >> 8;
    *handle = tmp;

    return tokid;
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

	rv = check_max_sessions(t->s_table);
	if (rv != CKR_OK) {
	    return rv;
	}

	/*
	 * Cannot open an R/O session when the SO is logged in
	 */
	if ((!(flags & CKF_RW_SESSION)) && (t->login_state == token_so_logged_in)) {
	    return CKR_SESSION_READ_WRITE_SO_EXISTS;
	}

	rv = session_table_new_entry(t->s_table, session, t, flags);
    if (rv != CKR_OK) {
        return rv;
    }

	add_tokid_to_session_handle(t->id, session);

	return CKR_OK;
}

CK_RV session_close(CK_SESSION_HANDLE session) {

    check_is_init();

    token *t = NULL;
    unsigned tokid = get_tokid_from_session_handle_and_cleanse(&session);
    check_slot_id(tokid, t, CKR_SESSION_HANDLE_INVALID);

    return session_table_free_ctx(t, session);
}

CK_RV session_closeall(CK_SLOT_ID slot_id) {

    check_is_init();

    token *t;
    check_slot_id(slot_id, t, CKR_SLOT_ID_INVALID);

    session_table_free_ctx_all(t);

    return CKR_OK;
}

CK_RV session_lookup(CK_SESSION_HANDLE session, token **tok, session_ctx **ctx) {

    token *tmp = NULL;
    unsigned tokid = get_tokid_from_session_handle_and_cleanse(&session);
    check_slot_id(tokid, tmp, CKR_SESSION_HANDLE_INVALID);

    *ctx = session_table_lookup(tmp->s_table, session);
    if (!*ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    token_lock(tmp);

    *tok = tmp;

    return CKR_OK;
}


CK_RV session_login(token *tok, CK_USER_TYPE user_type,
        CK_BYTE_PTR pin, CK_ULONG pin_len) {

    twist tpin = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    tpin = twistbin_new(pin, pin_len);
    if (!tpin) {
        return CKR_HOST_MEMORY;
    }

    // TODO Handle CKU_CONTEXT_SPECIFIC
    // TODO Support CKA_ALWAYS_AUTHENTICATE
    switch(user_type) {
        case CKU_SO:
            /* falls-through */
        case CKU_USER:
            rv = token_login(tok, tpin, user_type);
        break;
        case CKU_CONTEXT_SPECIFIC:
            rv = CKR_USER_TYPE_INVALID;
            break;
        default:
            rv = CKR_USER_TYPE_INVALID;
    }

    twist_free(tpin);

    return rv;
}

CK_RV session_logout(token *tok) {

    return token_logout(tok);
}

CK_RV session_get_info(token *tok, session_ctx *ctx, CK_SESSION_INFO *info) {

    check_pointer(info);

    info->flags = session_ctx_flags_get(ctx);

    info->slotID = tok->id;

    info->state = session_ctx_state_get(ctx);

    // We'll need to set this state error at some point, perhaps TSS2_RC's
    info->ulDeviceError = 0;

    return CKR_OK;
}
