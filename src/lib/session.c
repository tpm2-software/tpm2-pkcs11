/* SPDX-License-Identifier: BSD-2-Clause */

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

    /* Every function completes before it returns; CKF_ASYNC_SESSION_SUPPORTED is clear in the token info. */
    if (flags & CKF_ASYNC_SESSION) {
        return CKR_SESSION_ASYNC_NOT_SUPPORTED;
    }

    CK_RV rv = CKR_GENERAL_ERROR;

	check_pointer(session);

	token *t = slot_get_token(slot_id);
	if (!t) {
	    return CKR_SLOT_ID_INVALID;
	}

	/* The session table and the login state are the token's, shared with every other call. */
	token_lock(t);

	rv = check_max_sessions(t->s_table);
	if (rv != CKR_OK) {
	    goto out;
	}

	/*
	 * Cannot open an R/O session when the SO is logged in
	 */
	if ((!(flags & CKF_RW_SESSION)) && (t->login_state == token_so_logged_in)) {
	    rv = CKR_SESSION_READ_WRITE_SO_EXISTS;
	    goto out;
	}

	rv = session_table_new_entry(t->s_table, session, t, flags);
    if (rv != CKR_OK) {
        goto out;
    }

	add_tokid_to_session_handle(t->id, session);

out:
	token_unlock(t);
	return rv;
}

CK_RV session_close(CK_SESSION_HANDLE session) {

    token *t = NULL;
    unsigned tokid = get_tokid_from_session_handle_and_cleanse(&session);
    check_slot_id(tokid, t, CKR_SESSION_HANDLE_INVALID);

    /*
     * Closing the last session logs out, which flushes the token's TPM objects through the ESYS
     * context every other call uses: under the token lock, like them, or it races a call on
     * another thread ("Esys called in bad sequence").
     */
    token_lock(t);
    CK_RV rv = session_table_free_ctx(t, session);
    token_unlock(t);

    return rv;
}

CK_RV session_closeall(CK_SLOT_ID slot_id) {

    token *t;
    check_slot_id(slot_id, t, CKR_SLOT_ID_INVALID);

    /* As session_close(). */
    token_lock(t);
    CK_RV rv = session_table_free_ctx_all(t);
    token_unlock(t);

    return rv;
}

CK_RV session_lookup(CK_SESSION_HANDLE session, token **tok, session_ctx **ctx) {

    token *tmp = NULL;
    unsigned tokid = get_tokid_from_session_handle_and_cleanse(&session);
    check_slot_id(tokid, tmp, CKR_SESSION_HANDLE_INVALID);

    /*
     * Locked before the lookup: a session closed on another thread between the two would be freed
     * under the caller.
     */
    token_lock(tmp);

    *ctx = session_table_lookup(tmp->s_table, session);
    if (!*ctx) {
        token_unlock(tmp);
        return CKR_SESSION_HANDLE_INVALID;
    }

    *tok = tmp;

    return CKR_OK;
}
