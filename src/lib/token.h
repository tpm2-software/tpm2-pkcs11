/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_TOKEN_H_
#define SRC_TOKEN_H_

#include "checks.h"
#include "pkcs11.h"
#include "session_ctx.h"
#include "tpm.h"
#include "twist.h"
#include "utils.h"

typedef struct token_config token_config;
struct token_config {
    bool is_initialized;  /* token initialization state */
    char *tcti;           /* token specific tcti config */
};

typedef struct session_table session_table;
typedef struct session_ctx session_ctx;

typedef enum token_login_state token_login_state;
enum token_login_state {
    token_no_one_logged_in = 0,
    token_user_logged_in   = 1 << 0,
    token_so_logged_in     = 1 << 1,
};

typedef struct tobject tobject;

typedef struct pobject pobject;
struct pobject {
    uint32_t handle;
    twist objauth;
};

typedef struct sealobject sealobject;
struct sealobject {

    unsigned id;

    twist userpub;
    twist userpriv;
    twist userauthsalt;

    twist sopub;
    twist sopriv;
    twist soauthsalt;

    uint32_t handle;
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

    struct {
        tobject *head;
        tobject *tail;
    } tobjects;

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
 * Free the token internals, but keep the lock
 * @param t
 *  The token to free
 * @param keep_lock
 *  Whether or not to free the mutex.
 */
void token_free_ex(token *t, bool keep_lock);

/**
 * Free's a list of tokens
 * @param t
 *  The token list to free
 * @param len
 *  The number of elements to free
 */
void token_free_list(token *t, size_t len);

/**
 * Adds a tobject into the token tobject list filling in
 * gaps along the way and using the gap index as the object
 * handle index.
 * @param tok
 *  The token to insert into.
 * @param t
 *  The tobject to insert.
 * @return
 *  CKR_OK on success.
 */
CK_RV token_add_tobject(token *tok, tobject *t);

CK_RV token_find_tobject(token *tok, CK_OBJECT_HANDLE handle, tobject **tobj);

/**
 * Adds a tobject to the END of the tobject list incrementing the
 * previous tobject index number and using that. This DOES NOT gap
 * fill, and thus is really best for use only in the DB initialization
 * logic to prevent multiple iterations of the linked list during initialization.
 * @param tok
 *  The token to insert into.
 * @param t
 *  The tobject to insert.
 * @return
 *  CKR_OK on success.
 */
CK_RV token_add_tobject_last(token *tok, tobject *t);

void token_rm_tobject(token *tok, tobject *t);

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

bool token_is_so_logged_in(token *tok);

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

CK_RV token_min_init(token *t);
void token_reset(token *t);

CK_RV token_init(token *t, CK_BYTE_PTR pin, CK_ULONG pin_len, CK_BYTE_PTR label);

#endif /* SRC_TOKEN_H_ */
