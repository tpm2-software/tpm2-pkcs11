/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_SESSION_H_
#define SRC_PKCS11_SESSION_H_

#include <stdbool.h>

#include "pkcs11.h"
#include "tpm.h"

typedef struct session_ctx session_ctx;
typedef struct token token;

/*
 * This max value CANNOT extend into the upper byte of a CK_SESSION_HANDLE,
 * as that is reserved for the tokid.
 */
#define MAX_NUM_OF_SESSIONS 1024

CK_RV session_open(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application,
        CK_NOTIFY notify, CK_SESSION_HANDLE *session);

CK_RV session_close(CK_SESSION_HANDLE session);

CK_RV session_closeall(CK_SLOT_ID slot_id);

CK_RV session_lookup(CK_SESSION_HANDLE session, token **tok, session_ctx **ctx);

#endif /* SRC_PKCS11_SESSION_H_ */
