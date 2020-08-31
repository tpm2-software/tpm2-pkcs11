/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_LIB_DB_H_
#define SRC_PKCS11_LIB_DB_H_

#include <sqlite3.h>

#include "attrs.h"
#include "debug.h"
#include "pkcs11.h"
#include "token.h"
#include "twist.h"
#include "utils.h"

/*
 * This HAS to be smaller than 1 byte, as this is embedded
 * in the top byte of the session handle.
 */
#define MAX_TOKEN_CNT 255

typedef struct pobject_v3 pobject_v3;
struct pobject_v3 {
    int id;
    char *hierarchy;
    twist handle;
    char *objauth;
};

typedef struct pobject_v4 pobject_v4;
struct pobject_v4 {
    int id;
    char *hierarchy;
    char *config;
    char *objauth;
};

CK_RV db_init(void);
CK_RV db_destroy(void);

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

CK_RV db_add_primary(pobject *pobj, unsigned *pid);

CK_RV db_add_token(token *tok);

CK_RV db_update_token_config(token *tok);

CK_RV db_update_tobject_attrs(unsigned id, attr_list *attrs);

/* Debug testing */
#ifdef TESTING
#include "twist.h"

int get_blob_null(sqlite3_stmt *stmt, int i, twist *blob);
int get_blob(sqlite3_stmt *stmt, int i, twist *blob);
tobject *db_tobject_new(sqlite3_stmt *stmt);
int init_pobject_v3_from_stmt(sqlite3_stmt *stmt, pobject_v3 *old_pobj);
int init_tobjects(token *tok);
CK_RV convert_pobject_v3_to_v4(pobject_v3 *old_pobj, pobject_v4 *new_pobj);
CK_RV db_add_pobject_v4(sqlite3 *updb, pobject_v4 *new_pobj);

#endif

#endif /* SRC_PKCS11_LIB_DB_H_ */
