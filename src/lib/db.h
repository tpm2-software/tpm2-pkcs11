/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_LIB_DB_H_
#define SRC_PKCS11_LIB_DB_H_

#include <sqlite3.h>

#include "pkcs11.h"
#include "token.h"
#include "twist.h"

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

CK_RV db_update_for_pinchange(
        token *tok,
        bool is_so,

        /* new seal object auth metadata */
        twist newauthsalthex,

        /* private and public blobs */
        twist newprivblob,
        twist newpubblob);

CK_RV db_init_pobject(unsigned pid, pobject *pobj, tpm_ctx *tpm);

CK_RV db_add_new_object(token *tok, tobject *tobj);

/**
 * Delete a tobject from the DB.
 * @param tobj
 *  The tobject to remove.
 * @return
 */
CK_RV db_delete_object(tobject *tobj);

CK_RV db_get_first_pid(unsigned *id);

CK_RV db_add_primary(twist blob, unsigned *pid);

CK_RV db_add_token(token *tok);

#endif /* SRC_PKCS11_LIB_DB_H_ */
