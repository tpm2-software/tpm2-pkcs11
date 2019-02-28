/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "checks.h"
#include "db.h"
#include "key.h"
#include "pkcs11.h"
#include "session.h"
#include "session_ctx.h"
#include "utils.h"

#define ADD_ATTR(T, A, V, newattrs, offset)           \
  do {                                                \
    assert(offset < ARRAY_LEN(newattrs));             \
    T t = V;                                          \
    newattrs[offset].type = A;                        \
    newattrs[offset].ulValueLen = sizeof(t);          \
    newattrs[offset].pValue = malloc(sizeof(t));      \
    if (!newattrs[offset].pValue) {                   \
        LOGE("oom");                                  \
        goto error;                                   \
    }                                                 \
    memcpy(newattrs[offset++].pValue, &t, sizeof(t)); \
  } while(0)

#define ADD_ATTR_STR(A, V, newattrs, offset)        \
  do {                                              \
    assert(offset < ARRAY_LEN(newattrs));           \
    newattrs[offset].type = A;                      \
    newattrs[offset].ulValueLen = strlen(V);        \
    newattrs[offset].pValue = strdup(V);            \
    if (!newattrs[offset++].pValue) {               \
        LOGE("oom");                                \
        goto error;                                 \
    }                                               \
  } while(0)

#define ADD_ATTR_TWIST(A, V, newattrs, offset)                       \
  do {                                                               \
    assert(offset < ARRAY_LEN(newattrs));                            \
    newattrs[offset].type = A;                                       \
    newattrs[offset].ulValueLen = twist_len(V);                      \
    newattrs[offset].pValue = malloc(twist_len(V));                  \
    if (!newattrs[offset].pValue) {                                  \
        LOGE("oom");                                                 \
        goto error;                                                  \
    }                                                                \
    memcpy(newattrs[offset].pValue, V, newattrs[offset].ulValueLen); \
    offset++;                                                        \
  } while(0)

UTILS_GENERIC_ATTR_TYPE_CONVERT(CK_BBOOL);

CK_RV rsa_add_missing_mechs(tobject *tobj) {

    CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
        .hashAlg = CKM_SHA256,
        .mgf = CKG_MGF1_SHA256,
    };

    CK_MECHANISM mechs[2] = {
        { .mechanism = CKM_RSA_X_509,     .pParameter = NULL,         .ulParameterLen = 0                   },
        { .mechanism = CKM_RSA_PKCS_OAEP, .pParameter = &oaep_params, .ulParameterLen = sizeof(oaep_params) },
    };

   return tobject_append_mechs(tobj, mechs, ARRAY_LEN(mechs));
}

static CK_RV rsa_add_missing_attrs(tobject *tobj, tpm_object_data *objdata) {

    CK_RV tmp_rv;
    CK_RV rv = CKR_HOST_MEMORY;

    CK_ULONG index = 0;
    CK_ATTRIBUTE newattrs[9] = { 0 };

    CK_ATTRIBUTE_PTR a = object_get_attribute_by_type(tobj, CKA_KEY_TYPE);
    if (!a) {
        ADD_ATTR(CK_KEY_TYPE, CKA_KEY_TYPE, CKK_RSA, newattrs, index);
    }

    /*
     * if their is no object class add it. This code doesn't check that public AND private
     * are checked, which is needed in the design. We assume if empty, we need to add both
     * and we assume if we find one, we will have the other.
     */
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE match = {
       .type = CKA_CLASS,
       .ulValueLen = sizeof(class),
       .pValue = &class
    };

    a = object_get_attribute_full(tobj, &match);
    if (!a) {
        ADD_ATTR(CK_OBJECT_CLASS, CKA_CLASS, CKO_PRIVATE_KEY, newattrs, index);
    }

    class = CKO_PUBLIC_KEY;
    a = object_get_attribute_full(tobj, &match);
    if (!a) {
        ADD_ATTR(CK_OBJECT_CLASS, CKA_CLASS, CKO_PUBLIC_KEY,  newattrs, index);
    }

    /* add a string byte array of the object id if no other id is specified */
    a = object_get_attribute_by_type(tobj, CKA_ID);
    if (!a) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%u", tobj->id);
        ADD_ATTR_STR(CKA_ID, tmp, newattrs, index);
    }

    a = object_get_attribute_by_type(tobj, CKA_MODULUS);
    if (!a) {
        ADD_ATTR_TWIST(CKA_MODULUS, objdata->rsa.modulus, newattrs, index);
    }

    a = object_get_attribute_by_type(tobj, CKA_PUBLIC_EXPONENT);
    if (!a) {
        BIGNUM *b = BN_new();
        if (!b) {
            LOGE("oom");
            goto error;
        }

        int rc = BN_set_word(b, objdata->rsa.exponent);
        if (!rc) {
            LOGE("BN_set_word failed: %d", rc);
            BN_free(b);
            goto error;
        }

        int bytes = BN_num_bytes(b);

        void *x = malloc(bytes);
        if (!x) {
            LOGE("oom");
            BN_free(b);
            goto error;
        }

        rc = BN_bn2bin(b, x);
        BN_free(b);
        if (!rc) {
            free(x);
            LOGE("BN_bn2bin failed: %d", rc);
            goto error;
        }

        assert(index < ARRAY_LEN(newattrs));
        newattrs[index].type = CKA_PUBLIC_EXPONENT;
        newattrs[index].pValue = x;
        newattrs[index++].ulValueLen = bytes;
    }

    /*
     * We come into the CKA_SENSITIVE and CKA_EXTRACTABLE block assuming that:
     * CKA_EXTRACTABLE CKA_SENSITIVE
     *              0 | 0 = error checked before thus not possible
     *              0 | 1 = OK
     *              1 | 0 = OK
     *              1 | 1 = error checked before thus not possible
     */
    /* if the object is missing sensitive, the TPM defaults to sensitive, so mark it */

    CK_BBOOL sensitive = CK_TRUE;
    a = object_get_attribute_by_type(tobj, CKA_SENSITIVE);
    if (!a) {
        ADD_ATTR(CK_BBOOL, CKA_SENSITIVE, CK_TRUE, newattrs, index);
    } else {
        tmp_rv = generic_CK_BBOOL(a, &sensitive);
        if (tmp_rv != CKR_OK) {
            goto error;
        }
    }

    /* mark always sensitive if not specified by user */
    a = object_get_attribute_by_type(tobj, CKA_ALWAYS_SENSITIVE);
    if (!a) {
        ADD_ATTR(CK_BBOOL, CKA_ALWAYS_SENSITIVE, sensitive ? CK_TRUE : CK_FALSE, newattrs, index);
    }

    /* if the object is missing CKA_EXTRACTABLE use the value of CKA_SENSITIVE to determine */
    CK_BBOOL extractable = CK_FALSE;
    a = object_get_attribute_by_type(tobj, CKA_EXTRACTABLE);
    if (!a) {
        ADD_ATTR(CK_BBOOL, CKA_EXTRACTABLE, !sensitive, newattrs, index);
    } else {
        tmp_rv = generic_CK_BBOOL(a, &extractable);
        if (tmp_rv != CKR_OK) {
            goto error;
        }
    }

    /* mark never extractable if not specified by user */
    a = object_get_attribute_by_type(tobj, CKA_NEVER_EXTRACTABLE);
    if (!a) {
        ADD_ATTR(CK_BBOOL, CKA_NEVER_EXTRACTABLE, extractable ? CK_FALSE : CK_TRUE, newattrs, index);
    }

    /* add the new attrs */
    rv = tobject_append_attrs(tobj, newattrs, index);

error:
    tmp_rv = utils_attr_free(newattrs, index);
    if (tmp_rv != CKR_OK) {
        LOGW("Could not free attributes");
        assert(0);
    }

    return rv;
}

typedef struct sanity_check_data sanity_check_data;
struct sanity_check_data {
    bool is_extractable;
    bool is_sensitive;
};

static CK_RV handle_extractable_common(CK_ATTRIBUTE_PTR attr, bool is_extractable, void *udata) {

    sanity_check_data *scd = (sanity_check_data *)udata;
    assert(scd);

    CK_BBOOL value;
    CK_RV rv = generic_CK_BBOOL(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    if (value != CK_TRUE && value != CK_FALSE) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (is_extractable) {
        scd->is_extractable = !!value;
    } else {
        scd->is_sensitive = !!value;
    }

    return CKR_OK;
}

static CK_RV handle_sensitive(CK_ATTRIBUTE_PTR attr, CK_ULONG index, void *udata) {
    UNUSED(index);

    return handle_extractable_common(attr, false, udata);
}

static CK_RV handle_extractable(CK_ATTRIBUTE_PTR attr, CK_ULONG index, void *udata) {
    UNUSED(index);

    return handle_extractable_common(attr, true, udata);
}

CK_RV check_common_attrs(
        CK_ATTRIBUTE_PTR private_key_template,
        CK_ULONG private_key_attribute_count) {

    static const attr_handler common_attr_check_handlers[] = {
        { CKA_PRIVATE,         handle_sensitive      },
        { CKA_EXTRACTABLE,     handle_extractable    },
        { CKA_TOKEN,           ATTR_HANDLER_IGNORE   },
        { CKA_ID,              ATTR_HANDLER_IGNORE   },
        { CKA_LABEL,           ATTR_HANDLER_IGNORE   },
        { CKA_VERIFY,          ATTR_HANDLER_IGNORE   },
        { CKA_ENCRYPT,         ATTR_HANDLER_IGNORE   },
        { CKA_DECRYPT,         ATTR_HANDLER_IGNORE   },
        { CKA_SIGN,            ATTR_HANDLER_IGNORE   },
        { CKA_MODULUS_BITS,    ATTR_HANDLER_IGNORE   },
        { CKA_PUBLIC_EXPONENT, ATTR_HANDLER_IGNORE   },
        { CKA_SENSITIVE,       ATTR_HANDLER_IGNORE   },
        { CKA_CLASS,           ATTR_HANDLER_IGNORE },
    };

    sanity_check_data udata = { 0 };

    CK_RV rv = utils_handle_attrs(common_attr_check_handlers,
            ARRAY_LEN(common_attr_check_handlers),
            private_key_template,
            private_key_attribute_count, &udata);
    if (rv != CKR_OK) {
        return rv;
    }

    if (udata.is_extractable && udata.is_sensitive) {
        LOGE("Cannot mark object both extractable AND sensitive");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

CK_RV key_gen (
        token *tok,

        CK_MECHANISM_PTR mechanism,

        CK_ATTRIBUTE_PTR public_key_template,
        CK_ULONG public_key_attribute_count,

        CK_ATTRIBUTE_PTR private_key_template,
        CK_ULONG private_key_attribute_count,

        CK_OBJECT_HANDLE_PTR public_key,
        CK_OBJECT_HANDLE_PTR private_key) {

    CK_RV rv = CKR_GENERAL_ERROR;

    twist newauthbin = NULL;
    twist newauthhex = NULL;
    twist newwrapped_auth = NULL;

    tobject *new_tobj = NULL;

    tpm_object_data objdata = { 0 };

    rv = check_common_attrs(
            private_key_template,
            private_key_attribute_count);

    new_tobj = tobject_new();
    if (!new_tobj) {
        goto out;
    }

    rv = utils_new_random_object_auth(&newauthbin, &newauthhex);
    if (rv != CKR_OK) {
        LOGE("Failed to create new object auth");
        goto out;
    }

    rv = utils_ctx_wrap_objauth(tok, newauthhex, &newwrapped_auth);
    if (rv != CKR_OK) {
        LOGE("Failed to wrap new object auth");
        goto out;
    }


    rv = tpm2_generate_key(
            tok->tctx,
            tok->sobject.handle,
            tok->sobject.authraw,
            newauthbin,
            mechanism,
            public_key_attribute_count, public_key_template,
            private_key_attribute_count, private_key_template,
            &objdata);
    if (rv != CKR_OK) {
        LOGE("Failed to generate key");
        goto out;
    }

    rv = tobject_append_attrs(new_tobj, public_key_template, public_key_attribute_count);
    if (rv != CKR_OK) {
        LOGE("Failed to append public template");
        goto out;
    }

    rv = tobject_append_attrs(new_tobj, private_key_template, private_key_attribute_count);
    if (rv != CKR_OK) {
        LOGE("Failed to append private template");
        goto out;
    }

    /*
     * Need to convert the generation to mech to supported object mechs.
     */
    rv = rsa_add_missing_attrs(new_tobj, &objdata);
    if (rv != CKR_OK) {
        LOGE("Failed to add missing rsa attrs");
        goto out;
    }

    tobject_set_auth(new_tobj, newauthbin, newwrapped_auth);
    tobject_set_blob_data(new_tobj, objdata.pubblob, objdata.privblob);
    tobject_set_handle(new_tobj, objdata.handle);

    rv = rsa_add_missing_mechs(new_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add missing rsa mechanisms");
        goto out;
    }

    rv = db_add_new_object(tok, new_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add object to db");
        goto out;
    }

    /* add to object list preserving old object list if present */
    if (tok->tobjects) {
        new_tobj->l.next = &tok->tobjects->l;
    }

    tok->tobjects = new_tobj;

    *public_key = *private_key = new_tobj->id;

out:

    twist_free(objdata.rsa.modulus);
    twist_free(newauthhex);

    if (rv != CKR_OK) {
        tobject_free(new_tobj);
    }

    return rv;
}
