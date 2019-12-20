/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_TOKEN_H_
#define SRC_TOKEN_H_

#include "checks.h"
#include "object.h"
#include "pkcs11.h"
#include "session_ctx.h"
#include "tpm.h"
#include "twist.h"
#include "utils.h"

typedef struct token_config token_config;
struct token_config {
    bool is_initialized;  /* token initialization state */
    char *tcti;           /* token specific tcti config */
} config;

typedef struct session_table session_table;
typedef struct session_ctx session_ctx;

typedef enum token_login_state token_login_state;
enum token_login_state {
    token_no_one_logged_in = 0,
    token_user_logged_in   = 1 << 0,
    token_so_logged_in     = 1 << 1,
};

typedef struct token token;
struct token {

    unsigned id;
    unsigned pid;
    unsigned char label[32];

    token_config config;

    pobject pobject;

    twist wappingkey;

    sealobject sealobject;

    tobject *tobjects;

    session_table *s_table;

    token_login_state login_state;

    tpm_ctx *tctx;

    void *mutex;
};

/**
 * Frees a token
 * @param t
 *  The token to free
 */
void token_free(token *t);

/**
 * Free's a list of tokens
 * @param t
 *  The token list to free
 * @param len
 *  The number of elements to free
 */
void token_free_list(token *t, size_t len);

CK_RV token_get_info(token *t, CK_TOKEN_INFO *info);

/**
 * Checks if anyone is logged into the token.
 * @param tok
 *  The token to check
 * @return
 *  True if logged in, false otherwise.
 */
bool token_is_any_user_logged_in(token *tok);

bool token_is_user_logged_in(token *tok);

/**
 * TODO
 * @param tok
 * @param old_pin
 * @param old_len
 * @param new_pin
 * @param new_len
 * @return
 */
CK_RV token_setpin(token *tok, CK_UTF8CHAR_PTR old_pin, CK_ULONG old_len, CK_UTF8CHAR_PTR new_pin, CK_ULONG new_len);

CK_RV token_initpin(token *tok, CK_UTF8CHAR_PTR new_pin, CK_ULONG new_len);

void token_lock(token *t);
void token_unlock(token *t);

/**
 * Look up and possibly load an unloaded tobject.
 * @param tok
 *  The token to look up the object on.
 * @param key
 *  The object handle to look for.
 * @param loaded_tobj
 *  The pointer to the backing tobject
 * @return
 *   CKR_OK - everything is good.
 *   CKR_INVALID_KEY_HANDLE - not found
 *   CKR_KEY_HANDLE_INVALID - invalid key handle
 *   Others like: CKR_GENERAL_ERROR and CKR_HOST_MEMORY
 */
CK_RV token_load_object(token *tok, CK_OBJECT_HANDLE key, tobject **loaded_tobj);

/**
 * Retrieves the supported mechanism list for the token.
 * @param t
 *  The token to query.
 * @param mechanism_list
 *  The mechanism list to populate.
 * @param count
 *  The length of the mechanism_list, which is set to the actual length on return.
 * @return
 *  CKR_* status codes.
 */
CK_RV token_get_mechanism_list(token *t, CK_MECHANISM_TYPE_PTR mechanism_list, CK_ULONG_PTR count);

#endif /* SRC_TOKEN_H_ */
