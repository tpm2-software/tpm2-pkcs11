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

typedef struct tobject tobject;
struct tobject {

    uint32_t handle;

    unsigned id;
    twist pub;
    twist priv;
    twist objauth;

    struct {
        unsigned long count;
        CK_ATTRIBUTE_PTR attrs;
    } atributes;

    struct {
        unsigned long count;
        CK_MECHANISM_PTR mech;
    } mechanisms;

    list l;

    twist unsealed_auth;
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
CK_ATTRIBUTE_PTR object_get_attribute_by_type(tobject *tobj, CK_ATTRIBUTE_TYPE atype);

CK_ATTRIBUTE_PTR object_get_attribute_full(tobject *tobj, CK_ATTRIBUTE_PTR attr);

CK_RV object_mech_is_supported(tobject *tobj, CK_MECHANISM_PTR mech);

#endif /* SRC_PKCS11_OBJECT_H_ */
