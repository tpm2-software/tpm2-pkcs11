/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_fapi.h>

#include "checks.h"
#include "general.h"
#include "log.h"
#include "mutex.h"
#include "pkcs11.h"
#include "session.h"
#include "token.h"
#include "tpm.h"
#include "utils.h"

struct SESSION session_tab[MAX_NUM_OF_SESSIONS];

#define SESSION_FOR_EACH(session, X) \
    for (size_t _i = 0; _i < MAX_NUM_OF_SESSIONS; _i++) { \
        if (session_tab[_i].slot_id == 0) \
            continue; \
        session = &session_tab[_i]; \
        X; \
    }

#define SESSION_GET_EMPTY(session) { \
    size_t _i = 0; \
    for (; _i < sizeof(session_tab) / sizeof(session_tab[0]); _i++) { \
        if (session_tab[_i].slot_id == 0) \
            break; \
    } \
    session = _i; \
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

CK_RV session_getseal(CK_SESSION_HANDLE session, const uint8_t **seal) {
    if (session_tab[session].slot_id == 0) {
        LOGE("Session %lu is not open", session);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session_tab[session].seal_avail) {
        LOGE("Session %lu has no seal available", session);
        return CKR_USER_NOT_LOGGED_IN;
    }
    *seal = &session_tab[session].seal[0];
    return CKR_OK;
}

CK_RV session_getslot(CK_SESSION_HANDLE session, CK_SLOT_ID *slot_id) {
    if (session_tab[session].slot_id == 0) {
        LOGE("Session %lu is not open", session);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session_tab[session].seal_avail) {
        LOGE("Session %lu has no seal available", session);
        return CKR_USER_NOT_LOGGED_IN;
    }
    *slot_id = session_tab[session].slot_id;
    return CKR_OK;
}

CK_RV session_open(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application,
		CK_NOTIFY notify, CK_SESSION_HANDLE *session) {
    struct SESSION *s;
    char *path;
    (void) notify;
    (void) application; /* can be null */

    if (!(flags & CKF_SERIAL_SESSION)) {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

	check_pointer(session);

    /* Cannot open an R/O session when the SO is logged in */
    SESSION_FOR_EACH(s,
        if ((s->slot_id == slot_id) && (s->login_state == token_so_logged_in) &&
                (!(flags & CKF_RW_SESSION)))
            return CKR_SESSION_READ_WRITE_SO_EXISTS;
    );

    SESSION_GET_EMPTY(*session);
    if (*session >= MAX_NUM_OF_SESSIONS) {
        return CKR_SESSION_COUNT;
    }

    path = tss_path_from_id(slot_id);
    if (!path)
	    return CKR_SLOT_ID_INVALID;

    memset(&session_tab[*session], 0, sizeof(session_tab[0]));

    session_tab[*session].slot_id = slot_id;
    session_tab[*session].flags = flags;

    LOGV("Assigned session id %lu to slot 0x%08lx", *session, slot_id);

	return CKR_OK;
}

CK_RV session_close(CK_SESSION_HANDLE session) {
    if (session_tab[session].slot_id == 0) {
        LOGE("Session %lu is not open", session);
        return CKR_SESSION_HANDLE_INVALID;
    }

    LOGV("Closing session %lu for slot 0x%08lx", session, session_tab[session].slot_id);

    session_tab[session].slot_id = 0;

    return CKR_OK;
}

CK_RV session_closeall(CK_SLOT_ID slot_id) {
    struct SESSION *s;

    LOGV("Closing all sessions for slot %lu", slot_id);

    SESSION_FOR_EACH(s,
        if (s->slot_id == slot_id) {
            LOGV("Closing session %zu ", _i);
            s->slot_id = 0;
        }
    );

    return CKR_OK;
}

CK_RV session_login(CK_SESSION_HANDLE session, CK_USER_TYPE user_type,
        CK_BYTE_PTR pin, CK_ULONG pin_len) {
    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    char *path, *pinstring;
    uint8_t *seal;

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    // TODO Handle CKU_CONTEXT_SPECIFIC
    // TODO Support CKA_ALWAYS_AUTHENTICATE
    switch(user_type) {
        case CKU_SO:
            path = tss_path_from_id(session_tab[session].slot_id);
            break;
        case CKU_USER:
            path = tss_userpath_from_id(session_tab[session].slot_id);
            break;
        case CKU_CONTEXT_SPECIFIC:
            path = tss_userpath_from_id(session_tab[session].slot_id);
//            return CKR_USER_TYPE_INVALID;
            break;
        default:
            return CKR_USER_TYPE_INVALID;
    }

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    pinstring = malloc(pin_len + 1);
    memcpy(pinstring, pin, pin_len);
    pinstring[pin_len] = '\0';

    rc = Fapi_SetAuthCB(fctx, auth_cb, pinstring);
    check_tssrc(rc, Fapi_Finalize(&fctx); free(pinstring); return CKR_GENERAL_ERROR);

    rc = Fapi_Unseal(fctx, path, &seal, NULL);
    Fapi_Finalize(&fctx);
    free(pinstring);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    memcpy(&session_tab[session].seal[0], seal, 64);
    Fapi_Free(seal);

    session_tab[session].seal_avail = 1;
    session_tab[session].user_type = user_type;
    session_tab[session].state = (user_type == CKU_SO)?
                CKS_RW_SO_FUNCTIONS : CKS_RW_USER_FUNCTIONS;

    return CKR_OK;
}

CK_RV session_logout(CK_SESSION_HANDLE session) {
    if (session > MAX_NUM_OF_SESSIONS)
        return CKR_SESSION_HANDLE_INVALID;

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    CK_SLOT_ID slot_id = session_tab[session].slot_id;

    memset(&session_tab[session], 0, sizeof(session_tab[0]));

    session_tab[session].slot_id = slot_id;

    return CKR_OK;
}

CK_RV session_get_info(CK_SESSION_HANDLE session, CK_SESSION_INFO *info) {

    check_pointer(info);

    info->slotID = session_tab[session].slot_id;
    info->state = session_tab[session].state;
    info->flags = session_tab[session].flags;

    // We'll need to set this state error at some point, perhaps TSS2_RC's
    info->ulDeviceError = 0;

    return CKR_OK;
}
