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

typedef struct tobject tobject;
struct tobject {

    unsigned active;     /** number of active users */

    CK_OBJECT_HANDLE id; /** external handle */

    twist pub;           /** public tpm data */
    twist priv;          /** private tpm data */
    twist objauth;       /** wrapped object auth value */

    objattrs attrs;     /** object attributes */

    struct {
        unsigned long count;
        CK_MECHANISM_PTR mech;
    } mechanisms;       /** list of supported object mechanisms */

    list l;             /** list pointer for "listifying" tobjects */

    twist unsealed_auth; /** unwrapped auth value */

    uint32_t handle;     /** loaded tpm handle */
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

void tobject_set_handle(tobject *tobj, uint32_t handle);
CK_RV tobject_append_attrs(tobject *tobj, CK_ATTRIBUTE_PTR attrs, CK_ULONG count);
CK_RV tobject_append_mechs(tobject *tobj, CK_MECHANISM_PTR mech, CK_ULONG count);
void tobject_set_id(tobject *tobj, unsigned id);
void tobject_free(tobject *tobj);
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
CK_ATTRIBUTE_PTR tobject_get_attribute_by_type(tobject *tobj, CK_ATTRIBUTE_TYPE atype);

CK_ATTRIBUTE_PTR tobject_get_attribute_full(tobject *tobj, CK_ATTRIBUTE_PTR attr);

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
objattrs *tobject_get_attrs(tobject *tobj);

/**
 * Marks a tobject no longer being used by an operation.
 *
 * @param tobj
 *  The tobject to retire.
 * @return
 *  CKR_OK on success, CKR_GENERAL_ERROR if not active.
 */
CK_RV tobject_user_decrement(tobject *tobj);

/**
 * Marks a tobject as in use by an operation.
 *
 * @param tobj
 *  The tobject to mark as in use.
 * @return
 *  CKR_OK on success, CKR_GENERAL_ERROR if not active.
 */
CK_RV tobject_user_increment(tobject *tobj);

CK_RV object_destroy(session_ctx *ctx, CK_OBJECT_HANDLE object);

#endif /* SRC_PKCS11_OBJECT_H_ */
