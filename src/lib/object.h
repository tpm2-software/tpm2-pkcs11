/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_OBJECT_H_
#define SRC_PKCS11_OBJECT_H_

#include <stdbool.h>
#include <stdint.h>

#include "list.h"
#include "pkcs11.h"
#include "twist.h"
#include "utils.h"

typedef struct token token;
typedef struct session_ctx session_ctx;

typedef struct pobject pobject;
struct pobject {
    uint32_t handle;
    twist objauth;
};

typedef struct sobject sobject;
struct sobject {

    uint32_t handle;

    unsigned id;
    twist pub;
    twist priv;
    twist objauth;
    twist authraw;
};

typedef struct objattrs objattrs;
struct objattrs {
    unsigned long count;
    CK_ATTRIBUTE_PTR attrs;
};

/*
 * A tobject is the actual backing key used for cryptographic API calls by the client
 * application.
 *
 * a CK_OBJECT_HANDLE can have the link bit set indicating the link field is valid.
 *
 * A linked object occurs for asymmetric keys where we need to split out
 * valid template attributes based on key class. Ie if someone calls
 * getinfo on a key, CKO_CLASS could be PRIVATE or PUBLIC, and we can't
 * know what to populate without this differentiation (no dups allowed).
 * This the high bit set in the handle id serves this purpose of indicating
 * which attribute set to query.
 */
typedef struct tobject tobject;
struct tobject {

    CK_OBJECT_HANDLE id; /** external handle */

    twist pub;           /** public tpm data */
    twist priv;          /** private tpm data */
    twist objauth;       /** wrapped object auth value */

    struct {
        objattrs pub;   /** public object attributes */
        objattrs priv;  /** private object attributes */
    } atributes;

    struct {
        unsigned long count;
        CK_MECHANISM_PTR mech;
    } mechanisms;       /** list of supported object mechanisms */

    list l;             /** list pointer for "listifying" tobjects */

    twist unsealed_auth; /** unwrapped auth value */

    uint32_t handle;     /** loaded tpm handle */

    tobject *link;       /** a pointer to a backing tobject when linked */
};

typedef struct sealobject sealobject;
struct sealobject {

    unsigned id;

    twist userpub;
    twist userpriv;
    twist userauthsalt;
    unsigned userauthiters;

    twist sopub;
    twist sopriv;
    twist soauthsalt;
    unsigned soauthiters;

    uint32_t handle;
};

typedef struct wrappingobject wrappingobject;
struct wrappingobject {

    uint32_t handle;

    unsigned id;
    twist pub;
    twist priv;

    twist objauth;
};

tobject *tobject_new(void);

void tobject_set_blob_data(tobject *tobj, twist pub, twist priv);
void tobject_set_auth(tobject *tobj, twist authbin, twist wrappedauthhex);
void tobject_set_handle(tobject *tobj, uint32_t handle);
CK_RV tobject_append_attrs(tobject *tobj, bool is_public, CK_ATTRIBUTE_PTR attrs, CK_ULONG count);
CK_RV tobject_append_mechs(tobject *tobj, CK_MECHANISM_PTR mech, CK_ULONG count);
void tobject_set_id(tobject *tobj, unsigned id);
void tobject_free(tobject *tobj);
CK_ATTRIBUTE_PTR object_get_pub_attr_by_type(tobject *tobj, CK_ATTRIBUTE_TYPE atype);
CK_ATTRIBUTE_PTR object_get_priv_attr_by_type(tobject *tobj, CK_ATTRIBUTE_TYPE atype);
CK_ATTRIBUTE_PTR object_get_pub_attr_full(tobject *tobj, CK_ATTRIBUTE_PTR attr);
CK_ATTRIBUTE_PTR object_get_priv_attr_full(tobject *tobj, CK_ATTRIBUTE_PTR attr);
void sobject_free(sobject *sobj);

void wrappingobject_free(wrappingobject *wobj);
void sealobject_free(sealobject *sealobj);

CK_RV object_find_init(session_ctx *ctx, CK_ATTRIBUTE_PTR templ, unsigned long count);

CK_RV object_find(session_ctx *ctx, CK_OBJECT_HANDLE *object, unsigned long max_object_count, unsigned long *object_count);

CK_RV object_find_final(session_ctx *ctx);

CK_RV object_get_attributes(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE *templ, unsigned long count);

/**
 * Given an attribute type, retrieves the attribute data if present.
 * @param tobj
 *  The object whose attribute set to query.
 * @param atype
 *  The attribute type to query for.
 * @return
 *  A pointer to the attribute or NULL if nothing found.
 */
CK_ATTRIBUTE_PTR object_get_attribute_by_type(tobject *tobj, CK_ATTRIBUTE_TYPE atype);

CK_ATTRIBUTE_PTR object_get_attribute_full(tobject *tobj, CK_ATTRIBUTE_PTR attr);

CK_RV object_mech_is_supported(tobject *tobj, CK_MECHANISM_PTR mech);

/**
 * Determines if the handle range is invalid and overflows
 * into the high bit of a CK_OBJECT_HANDLE.
 * @param handle
 *  The handle to test.
 * @return
 *  True if the handle range is OK, false if not.
 */
bool tobject_id_range_ok(CK_OBJECT_HANDLE handle);

/**
 * Creates a new tobject and links it to a backing tobject.
 * @param linked
 *  The tobject to link too.
 * @return
 *  A tobject on success or NULL on error.
 */
tobject *tobject_link(tobject *linked);

/**
 * Gets the attributes for a tobject. If it's a link to a tobject, follows it
 * and retrieves the public attributes, as the link object is the public portion.
 * Else, it's not the link object and retrieves the private attributes.
 * @param tobj
 *  The tobject to fetch the attributes from.
 * @return
 *  The attribute array.
 */
objattrs *tobject_get_attrs(tobject *tobj);

#endif /* SRC_PKCS11_OBJECT_H_ */
