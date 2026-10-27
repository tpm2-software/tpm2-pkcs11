/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_OBJECT_H_
#define SRC_PKCS11_OBJECT_H_

#include <stdbool.h>
#include <stdint.h>

#include "attrs.h"
#include "debug.h"
#include "list.h"
#include "pkcs11.h"
#include "twist.h"

typedef struct session_ctx session_ctx;
typedef struct token token;
typedef struct pobject pobject;

typedef struct tobject tobject;
struct tobject {

    unsigned active;     /** number of active users */

    unsigned id; /** external handle */

    CK_OBJECT_HANDLE obj_handle; /** application visible handle */

    /*
     * these all exist in the attribute array, but we'll keep some
     * twist copies of them handy for convenience.
     */
    twist pub;           /** public tpm data */
    twist priv;          /** private tpm data */
    twist objauth;       /** wrapped object auth value */

    attr_list *attrs;    /** object attributes */

    list l;             /** list pointer for "listifying" tobjects */

    twist unsealed_auth; /** unwrapped auth value */

    uint32_t tpm_esys_tr;     /** loaded ESYS_TR */
    twist tpm_serialized_tr; /** serialized ESYS_TR **/

    bool is_authenticated; /** true if a context specific login has authenticated use of the object */

    session_ctx *owner; /** the session that created a session object (CKA_TOKEN=false); NULL for a token object */
    bool orphaned; /** a session object whose session closed while another session used it: it has no owner, nor a store */
};

tobject *tobject_new(void);

/**
 * Sets the internal private and public TPM data blob fields via deep copy.
 * Thus the caller is still responsible to free the priv and pub parameters.
 * @param tobj
 *  The tobject to set.
 * @param pub
 *  The public portion, cannot be NULL.
 * @param priv
 *  The private portion, may be NULL.
 * @return
 *  CKR_OK on success or CKR_HOST_MEMORY.
 */
CK_RV tobject_set_blob_data(tobject *tobj, twist pub, twist priv);

/**
 * Sets the internal TPm auth fields via deep copy.
 * Thus the caller is still responsible to free the authbin and pub wrappedauthhex.
 * @param tobj
 *  The tobject to set.
 * @param authbin
 *  The auth in plaintext binary form.
 * @param wrappedauthhex
 *  The wrapping key wrapped auth.
 * @return
 *  CKR_OK on success or CKR_HOST_MEMORY.
 */
CK_RV tobject_set_auth(tobject *tobj, twist authbin, twist wrappedauthhex);

void tobject_set_esys_tr(tobject *tobj, uint32_t esys_tr);
void tobject_set_id(tobject *tobj, unsigned id);
void tobject_free(tobject *tobj);

CK_RV object_find_init(session_ctx *ctx, CK_ATTRIBUTE_PTR templ, unsigned long count);

CK_RV object_find(session_ctx *ctx, CK_OBJECT_HANDLE *object, unsigned long max_object_count, unsigned long *object_count);

CK_RV object_find_final(session_ctx *ctx);

CK_RV object_get_attributes(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE *templ, unsigned long count);

CK_RV object_set_attributes(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE *templ, unsigned long count);

CK_ATTRIBUTE_PTR tobject_get_attribute_full(tobject *tobj, CK_ATTRIBUTE_PTR attr);

CK_RV tobject_get_min_buf_size(tobject *tobj, CK_MECHANISM_PTR mech, size_t *maxsize);

CK_RV object_mech_is_supported(tobject *tobj, CK_MECHANISM_PTR mech);

/**
 * Gets the attributes for a tobject. If it's a link to a tobject, follows it
 * and retrieves the public attributes, as the link object is the public portion.
 * Else, it's not the link object and retrieves the private attributes.
 * @param tobj
 *  The tobject to fetch the attributes from.
 * @return
 *  The attribute array.
 */
attr_list *tobject_get_attrs(tobject *tobj);

CK_RV _tobject_user_decrement(tobject *tobj, const char *filename, int lineno);
CK_RV _tobject_user_increment(tobject *tobj, const char *filename, int lineno);

/**
 * Marks a tobject no longer being used by an operation.
 *
 * @param tobj
 *  The tobject to retire.
 * @return
 *  CKR_OK on success, CKR_GENERAL_ERROR if not active.
 */
#define tobject_user_decrement(tobj) _tobject_user_decrement(tobj, __FILE__, __LINE__)

/**
 * Marks a tobject as in use by an operation.
 *
 * @param tobj
 *  The tobject to mark as in use.
 * @return
 *  CKR_OK on success, CKR_GENERAL_ERROR if not active.
 */
#define tobject_user_increment(tobj) _tobject_user_increment(tobj, __FILE__, __LINE__)

CK_RV object_destroy(session_ctx *ctx, CK_OBJECT_HANDLE object);


CK_RV object_create(session_ctx *ctx, CK_ATTRIBUTE *templ, CK_ULONG count, CK_OBJECT_HANDLE *object);

/* object_create() for a secret key the caller gives its CKA_VALUE once made (C_DeriveKey). */
CK_RV object_create_valueless_secret(session_ctx *ctx, CK_ATTRIBUTE *templ, CK_ULONG count,
        CK_OBJECT_HANDLE *object);

WEAK CK_RV object_init_from_attrs(tobject *tobj);

/**
 * Keeps a new object: a token object (CKA_TOKEN=true, the default) in the token's persistent
 * store; a session object only in memory, owned by ctx, which destroys it when it closes.
 * @param tok
 *  The token.
 * @param ctx
 *  The session creating the object.
 * @param tobj
 *  The new object.
 * @return
 *  CKR_OK on success.
 */
CK_RV object_store(token *tok, session_ctx *ctx, tobject *tobj);

/**
 * Removes a token object from the persistent store; a session object has nothing to remove.
 */
CK_RV object_unstore(token *tok, tobject *tobj);

/**
 * Destroys the session objects ctx created, as PKCS#11 has it when a session closes. One still in
 * use by another session's operation is left to the token, which frees it at C_Finalize.
 */
void object_destroy_session_objects(token *tok, session_ctx *ctx);

#ifdef TESTING
tobject *__real_tobject_new(void);
void pobject_free(pobject *pobj);
#endif

#endif /* SRC_PKCS11_OBJECT_H_ */
