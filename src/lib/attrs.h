/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SRC_LIB_ATTRS_H_
#define SRC_LIB_ATTRS_H_

#include <stdbool.h>
#include <stdlib.h>

#include "pkcs11.h"

/*
 * We will allow these to be accessed, but the values are not stable
 */
#define CKA_VENDOR_TPM2_DEFINED 0x0F000000UL
#define CKA_TPM2_OBJAUTH_ENC (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x1UL)
#define CKA_TPM2_PUB_BLOB    (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x2UL)
#define CKA_TPM2_PRIV_BLOB   (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x3UL)
#define CKA_TPM2_ENC_BLOB    (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x4UL)

/* Invalid values for error detection */
#define CK_OBJECT_CLASS_BAD (~(CK_OBJECT_CLASS)0)
#define CKA_KEY_TYPE_BAD    (~(CK_KEY_TYPE)0)

/**
 * The heart of any PKCS11 object is it's attribute list. This list
 * attempts to make dealing with list attributes simple. It allows you
 * to easily add scalar and buffer types (deep copy) and maintains metadata
 * about the type stored in the attribute. Thus, de-serialization can occur
 * much more simply.
 */
typedef struct attr_list attr_list;

typedef struct attr_handler attr_handler;
struct attr_handler {
    /** Attribute type to invoke the handler for */
    CK_ULONG type;
    /** handler to invoke for the attribute type */
    CK_RV (*handler)(const CK_ATTRIBUTE_PTR attr, void *userdat);
};

/**
 * Creates a new attribute list
 * @return
 *  attribute list or NULL on error.
 */
attr_list *attr_list_new(void);

/**
 * Duplicates an attribute list.
 * @param old
 *  The attribute list to duplicate.
 * @param new
 *  The new attribute list, that's a duplicate of old.
 * @return
 *  CKR_OK on success.
 */
CK_RV attr_list_dup(attr_list *old, attr_list **new);

/**
 * Adds a buffer to the attribute list and adds type data.
 * @param l
 *  The list to add to.
 * @param type
 *  The attribute type to add.
 * @param value
 *  The buffer, can be NULL.
 * @param len
 *  The length of the buffer. 0 is treated as NULL value.
 * @return
 *  true on success, false otherwise.
 */
bool attr_list_add_buf(attr_list *l, CK_ATTRIBUTE_TYPE type, CK_BYTE_PTR value, CK_ULONG len);

/**
 * Adds a CK_BOOL to the attribute list and adds type data.
 * @param l
 *  The list to add to.
 * @param type
 *  The attribute type to add.
 * @param value
 *  The Attributes CK_BBOOL value to add.
 * @return
 *  true on success, false otherwise.
 * @note
 * Some PKCS11 types are just typedefs of CK_BYTE, like CK_BOOL.
 * However, CK_BOOL is more common, so for now this interface
 * can serve both use cases: adding any CK_BYTE typedef type.
 */
bool attr_list_add_bool(attr_list *l, CK_ATTRIBUTE_TYPE type, CK_BBOOL value);

/**
 * Adds a CK_ULONG to the attribute list and adds type data.
 * @param l
 *  The list to add to.
 * @param type
 *  The attribute type to add.
 * @param value
 *  The Attributes CK_ULONG value to add.
 * @return
 *  true on success, false otherwise.
 * @note
 * Most PKCS11 types are just typedefs of CK_ULONG, so this works
 * for most types. However, don't use this for CK_BYTE typedefs
 * as the storage size will be bigger than expected by clients.
 */
bool attr_list_add_int(attr_list *l, CK_ATTRIBUTE_TYPE type, CK_ULONG value);

/**
 * Returns the count items in the attribute list.
 *
 * @param l
 *  The list to query the length of. MUST not  be NULL.
 * @return
 *  The count in items.
 */
CK_ULONG attr_list_get_count(attr_list *l);

/**
 * The pointer to the internal pkcs11 formatted attribute list.
 * @param l
 *  The list to access.
 * @return
 *  The attribute ptr, may be NULL.
 */
CK_ATTRIBUTE_PTR attr_list_get_ptr(attr_list *l);

/**
 * Frees all storage of the attribute list.
 * @param attrs
 *  The attribute list to free.
 */
void attr_list_free(attr_list *attrs);

/**
 * Scrubs the memory pointed to by the pValue pointer and frees it.
 * The attribute pointer is expected to be contained within in attr_list.
 * The attribute is NOT REMOVED from the list and type remains unchanged.
 * Sets ulValueLen to 0.
 * @param attr
 *  The attr to free.
 */
void attr_pfree_cleanse(CK_ATTRIBUTE_PTR attr);

/**
 * Given a raw attribute list, perhaps from a client caller,
 * creates an attr_list which contains the caller supplied data,
 * deep copied with type metadata.
 *
 * @param attrs
 *  The attributes to deep copy and add type metadata from.
 * @param cnt
 *  The number of attributes.
 * @param copy
 *  The allocated attr_list.
 * @return
 *  true on success, false otherwise.
 * @note
 *  Internally this function has registered converters for known attributes,
 *  however, if an unknown attribute is converted, the default conversion is
 *  to figure out type from the value length (ulValueLen). It will print a
 *  warning message to add a specific handler.
 */
bool attr_typify(CK_ATTRIBUTE_PTR attrs, CK_ULONG cnt, attr_list **copy);

/**
 * Appends one attr_list to another.
 * @param old_attrs
 *  The list to append to.
 * @param new_attrs
 *  The list to append. Resource is de-allocated on success and
 *  the new_attrs pointer is NULL.
 * @return
 *  The new list which should be passed to attr_list_free().
 */
attr_list *attr_list_append_attrs(
        attr_list *old_attrs,
        attr_list **new_attrs);

/**
 * Given an object created of type mech, and a list of starting attributes,
 * populate the public and private attribute lists for the object(s).
 * @param public_attrs
 *  The public attribute list to allocate and populate.
 * @param private_attrs
 *  The private attribute list to allocate and populate.
 * @param attrs
 *  The initial attribute list to start with.
 * @param mech
 *  The mechanism used to generate the object.
 * @return
 *  CKR_OK on success, false otherwise.
 */
CK_RV attr_add_missing_attrs(attr_list **public_attrs, attr_list **private_attrs, attr_list *attrs,
        CK_MECHANISM_TYPE mech);

/**
 * Invokes a list of handlers on a raw pkcs11 list. Handlers using this interface must not
 * expect typed_memory.h interface on pValue pointers.
 *
 * @param attrs
 *  The attribute list.
 * @param count
 *  The number of items in the attribute list.
 * @param handlers
 *  The handlers to invoke.
 * @param len
 *  The number of handlers to invoke.
 * @param udata
 *  User data to pass to the handlers.
 * @return
 */
CK_RV attr_list_raw_invoke_handlers(const CK_ATTRIBUTE_PTR attrs, CK_ULONG count,
        const attr_handler *handlers, size_t len, void *udata);

/**
 * Invokes a list of handlers on an attr_list. Handlers using this interface may
 * expect typed_memory.h interface on pValue pointers.
 *
 * @param attrs
 *  The attribute list.
 * @param handlers
 *  The handlers to invoke.
 * @param len
 *  The number of handlers to invoke.
 * @param udata
 *  User data to pass to the handlers.
 * @return
 */
CK_RV attr_list_invoke_handlers(attr_list *l, const attr_handler *handlers, size_t len, void *udata);

/**
 * Given an attribute pointer, retrieves the CK_BBOOL value if present.
 * @param attr
 *  The attribute ptr.
 * @param x
 *  The extracted CK_BBOOL value.
 * @return
 *  CKR_OK on success.
 */
CK_RV attr_CK_BBOOL(CK_ATTRIBUTE_PTR attr, CK_BBOOL *x);

/**
 * Given an attribute pointer, retrieves the CK_ULONG value if present.
 * @param attr
 *  The attribute ptr.
 * @param x
 *  The extracted CK_ULONG value.
 * @return
 *  CKR_OK on success.
 */
CK_RV attr_CK_ULONG(CK_ATTRIBUTE_PTR attr, CK_ULONG *x);

/**
 * Given an attribute pointer, retrieves the CK_CLASS value if present.
 * @param attr
 *  The attribute ptr.
 * @param x
 *  The extracted CK_CLASS value.
 * @return
 *  CKR_OK on success.
 */
CK_RV attr_CK_OBJECT_CLASS(CK_ATTRIBUTE_PTR attr, CK_OBJECT_CLASS *x);

CK_RV attr_CK_KEY_TYPE(CK_ATTRIBUTE_PTR attr, CK_KEY_TYPE *x);

CK_BBOOL attr_list_get_CKA_PRIVATE(attr_list *attrs, CK_BBOOL defvalue);

CK_BBOOL attr_list_get_CKA_TOKEN(attr_list *attrs, CK_BBOOL defvalue);

CK_KEY_TYPE attr_list_get_CKA_KEY_TYPE(attr_list *attrs, CK_KEY_TYPE defvalue);

CK_OBJECT_CLASS attr_list_get_CKA_CLASS(attr_list *attrs, CK_OBJECT_CLASS defvalue);

/**
 * Searches an attr_list for an attribute specified by type.
 * @param haystack
 *  The attr_list to search.
 * @param needle
 *  The attribute type to search for.
 * @return
 *  The attribute or NULL if not found.
 */
CK_ATTRIBUTE_PTR attr_get_attribute_by_type(attr_list *haystack, CK_ATTRIBUTE_TYPE needle);

/**
 * Searches a raw attribute list for an attribute specified by type.
 * @param haystack
 *  The raw attribute list to search.
 * @ param haystack_count
 *  The raw attribute list count.
 * @param needle
 *  The attribute type to search for.
 * @return
 *  The attribute or NULL if not found.
 */
CK_ATTRIBUTE_PTR attr_get_attribute_by_type_raw(CK_ATTRIBUTE_PTR haystack, CK_ULONG haystack_count,
        CK_ATTRIBUTE_TYPE needle);

CK_RV attr_list_append_entry(attr_list **attrs, CK_ATTRIBUTE_PTR untrusted_attr);

CK_RV attr_list_update_entry(attr_list *attrs, CK_ATTRIBUTE_PTR untrusted_attr);

CK_RV attr_common_add_RSA_publickey(attr_list **public_attrs);

CK_RV attr_common_add_storage(attr_list **public_attrs);

CK_RV attr_common_add_data(attr_list **storage_attrs);

CK_RV rsa_gen_mechs(attr_list *new_pub_attrs, attr_list *new_priv_attrs);

CK_RV attr_list_append_entry(attr_list **attrs, CK_ATTRIBUTE_PTR untrusted_attr);

CK_RV attr_list_update_entry(attr_list *attrs, CK_ATTRIBUTE_PTR untrusted_attr);

#endif /* SRC_LIB_ATTRS_H_ */
