/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_LIB_DB_H_
#define SRC_PKCS11_LIB_DB_H_

#include <sqlite3.h>

#include "pkcs11.h"
#include "token.h"

/*
 * This HAS to be smaller than 1 byte, as this is embedded
 * in the top byte of the session handle.
 */
#define MAX_TOKEN_CNT 255

CK_RV db_init(void);
CK_RV db_destroy(void);

CK_RV db_new(sqlite3 **db);
CK_RV db_free(sqlite3 **db);

CK_RV db_get_tokens(token **t, size_t *len);

#endif /* SRC_PKCS11_LIB_DB_H_ */
