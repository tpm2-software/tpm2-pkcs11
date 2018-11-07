/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_SESSION_H_
#define SRC_PKCS11_SESSION_H_

#include <stdbool.h>

#include "pkcs11.h"
#include "object.h"
#include "session_ctx.h"
#include "tpm.h"

#define MAX_NUM_OF_SESSIONS 1024

CK_RV session_init(void);

void session_destroy(void);

CK_RV session_open(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application,
        CK_NOTIFY notify, CK_SESSION_HANDLE *session);

CK_RV session_close(CK_SESSION_HANDLE session);

CK_RV session_closeall(CK_SLOT_ID slot_id);

session_ctx *session_lookup(CK_SESSION_HANDLE session);

CK_RV session_login (CK_SESSION_HANDLE session, CK_USER_TYPE user_type,
        unsigned char *pin, unsigned long pin_len);

CK_RV session_logout (CK_SESSION_HANDLE session);

unsigned long session_cnt_get(bool is_rw);

CK_RV session_get_info (CK_SESSION_HANDLE session, CK_SESSION_INFO *info);

#endif /* SRC_PKCS11_SESSION_H_ */
