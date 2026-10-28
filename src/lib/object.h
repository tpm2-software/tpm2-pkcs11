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

/**
 * Changes attributes of an object (C_SetAttributeValue), all of them or none. Only what PKCS#11 lets an
 * application modify: CKA_LABEL; a data object's CKA_APPLICATION, CKA_OBJECT_ID and CKA_VALUE; a
 * certificate's CKA_ID, CKA_ISSUER and CKA_SERIAL_NUMBER, as its type allows; a key's CKA_ID, dates and
 * (public or private) CKA_SUBJECT. Its usages, CKA_EXTRACTABLE, CKA_COPYABLE and CKA_DESTROYABLE can only
 * become false, CKA_SENSITIVE only true. CKA_MODIFIABLE=false isn't enforced (see the code).
 * @param ctx
 *  The session.
 * @param object
 *  The object to change.
 * @param templ
 *  The new values.
 * @param count
 *  The number of attributes in templ.
 * @return
 *  CKR_OK on success.
 *  CKR_ATTRIBUTE_READ_ONLY for any other attribute of the object's class, the vendor ones among them.
 *  CKR_ATTRIBUTE_TYPE_INVALID for an attribute its class doesn't have.
 *  CKR_ATTRIBUTE_VALUE_INVALID for a malformed bool or date.
 */
CK_RV object_set_attributes(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE *templ, unsigned long count);

/**
 * Sets CKA_VALUE of a key C_DeriveKey has just made, which C_SetAttributeValue can't do: a key's value
 * is read-only.
 * @param ctx
 *  The session.
 * @param object
 *  The derived key, made with object_create_valueless_secret().
 * @param value
 *  The CKA_VALUE attribute.
 * @return
 *  CKR_OK on success.
 */
CK_RV object_set_derived_value(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR value);

/**
 * Gets the plain text CKA_VALUE of an object held on the host, a data object or a secret key that
 * isn't in the TPM, unwrapping it from CKA_TPM2_ENC_BLOB when it's protected.
 * @param tok
 *  The token.
 * @param tobj
 *  The object.
 * @param value
 *  The value, on success. The caller cleanses it with OPENSSL_cleanse() and frees it.
 * @return
 *  CKR_OK on success.
 *  CKR_USER_NOT_LOGGED_IN when the value is protected and the wrapping key isn't loaded.
 *  CKR_KEY_HANDLE_INVALID when the object has no value on the host: a key in the TPM, or a
 *  secret key stored before its value was kept wrapped.
 */
CK_RV object_get_host_value(token *tok, tobject *tobj, twist *value);

/**
 * Copies an object (C_CopyObject). The copy is a new object, stored unless it's a session object,
 * with the same TPM blobs, so destroying either leaves the other usable. The template may set what
 * C_SetAttributeValue may change (see object_set_attributes()), except CKA_VALUE, and also CKA_TOKEN,
 * CKA_PRIVATE, CKA_MODIFIABLE and CKA_DESTROYABLE to either value. Any other attribute of the object may
 * only be given its current value; CKA_VALUE and the vendor attributes not even that.
 * @param ctx
 *  The session.
 * @param object
 *  The object to copy.
 * @param templ
 *  The attributes to change on the copy.
 * @param count
 *  The number of attributes in templ.
 * @param new_object
 *  The copy's handle, on success.
 * @return
 *  CKR_OK on success.
 *  CKR_ACTION_PROHIBITED when the object's CKA_COPYABLE is false.
 *  CKR_ATTRIBUTE_READ_ONLY when the template changes what a copy can't.
 *  CKR_TEMPLATE_INCONSISTENT when it would make a sensitive or unextractable host-held key public.
 */
CK_RV object_copy(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR templ, CK_ULONG count,
        CK_OBJECT_HANDLE_PTR new_object);

/**
 * Gets an approximate size of an object (C_GetObjectSize): the lengths of its attributes and of its
 * TPM public and private blobs.
 * @param ctx
 *  The session.
 * @param object
 *  The object.
 * @param size
 *  The size in bytes, on success.
 * @return
 *  CKR_OK on success.
 */
CK_RV object_get_size(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ULONG_PTR size);

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

/**
 * C_DestroyObject: removes the object from the token, and from the store if it's a token object.
 * @return
 *  CKR_ACTION_PROHIBITED when the object's CKA_DESTROYABLE is false (an absent one is true), leaving it
 *  as it was.
 */
CK_RV object_destroy(session_ctx *ctx, CK_OBJECT_HANDLE object);


CK_RV object_create(session_ctx *ctx, CK_ATTRIBUTE *templ, CK_ULONG count, CK_OBJECT_HANDLE *object);

/**
 * Whether object_create() makes a secret key of this type and template in the TPM, as an AES or HMAC
 * key, rather than as a plain object holding its value: a generic secret whose template asks for a value
 * that can be read back (CKA_EXTRACTABLE=true or CKA_SENSITIVE=false), or a type the TPM doesn't hold.
 */
bool object_secret_in_tpm(CK_KEY_TYPE key_type, CK_ATTRIBUTE_PTR templ, CK_ULONG count);

/* object_create() for a secret key the caller gives its CKA_VALUE once made (C_DeriveKey). */
CK_RV object_create_valueless_secret(session_ctx *ctx, CK_ATTRIBUTE *templ, CK_ULONG count,
        CK_OBJECT_HANDLE *object);

WEAK CK_RV object_init_from_attrs(tobject *tobj);

/**
 * Keeps a new object: a token object (CKA_TOKEN=true, the default) in the token's persistent
 * store; a session object only in memory, owned by ctx, which destroys it when it closes.
 * Every new object goes through here, and first gets a new CKA_UNIQUE_ID (PKCS#11 4.4.1), replacing
 * any it has (a copy's is the original's): see object_new_unique_id(). The attribute list may then be
 * reallocated, so a pointer into it taken before isn't valid after.
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
 * Gives tobj a new CKA_UNIQUE_ID: 16 random bytes, hex-encoded, so 32 ASCII characters, none other in
 * the token has. One it already has is replaced. Nothing is written to the store.
 */
CK_RV object_new_unique_id(token *tok, tobject *tobj);

/**
 * Gives each object loaded from the store without a CKA_UNIQUE_ID one: tpm2_ptool doesn't know the
 * attribute, and older versions of the library didn't set it. The new one is written back to the store
 * so it stays the same across loads; if that fails (a read-only store, say) it's kept in memory, so
 * it lasts until C_Finalize, and the load carries on.
 * @return
 *  CKR_OK, or the error making an ID (CKR_HOST_MEMORY, CKR_GENERAL_ERROR).
 */
CK_RV object_add_missing_unique_ids(token *tok);

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
