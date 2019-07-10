/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_SESSION_H_
#define SRC_PKCS11_SESSION_H_

#include <stdbool.h>

#include "sign.h"
#include "encrypt.h"
#include "pkcs11.h"
#include "tpm.h"
#include "token.h"

typedef enum operation operation;
enum operation {
    operation_none = 0,
    operation_find,
    operation_sign,
    operation_verify,
    operation_encrypt,
    operation_decrypt,
    operation_digest,
    operation_count
};

struct SESSION {
    CK_SLOT_ID slot_id;
    CK_STATE state;
    CK_FLAGS flags;
    token_login_state login_state;
    CK_USER_TYPE user_type;
    int seal_avail;
    uint8_t seal[64];
    CK_OBJECT_HANDLE *search;
    CK_ULONG search_count;
    operation op;
    union {
        signverifydata signverify;
        encryptdecryptdata encryptdecrypt;
    } opdata;
};

#define MAX_NUM_OF_SESSIONS 1024

extern struct SESSION session_tab[MAX_NUM_OF_SESSIONS];

typedef struct session_ctx session_ctx;
typedef struct token token;

/*
 * This max value CANNOT extend into the upper byte of a CK_SESSION_HANDLE,
 * as that is reserved for the tokid.
 */

CK_RV session_getseal(CK_SESSION_HANDLE session, const uint8_t **seal);

CK_RV session_getslot(CK_SESSION_HANDLE session, CK_SLOT_ID *slot_id);

CK_RV session_open(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application,
        CK_NOTIFY notify, CK_SESSION_HANDLE *session);

CK_RV session_close(CK_SESSION_HANDLE session);

CK_RV session_closeall(CK_SLOT_ID slot_id);

CK_RV session_lookup(CK_SESSION_HANDLE session, token **tok, session_ctx **ctx);

CK_RV session_login(CK_SESSION_HANDLE session, CK_USER_TYPE user_type,
        CK_BYTE_PTR pin, CK_ULONG pin_len);

CK_RV session_logout(CK_SESSION_HANDLE session);

CK_RV session_get_info(CK_SESSION_HANDLE session, CK_SESSION_INFO *info);

#endif /* SRC_PKCS11_SESSION_H_ */
