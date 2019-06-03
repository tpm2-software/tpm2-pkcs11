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

#define ADD_ATTR_BUF(A, V, L, newattrs, offset)                      \
  do {                                                               \
    assert(offset < ARRAY_LEN(newattrs));                            \
    newattrs[offset].type = A;                                       \
    newattrs[offset].ulValueLen = L;                                 \
    newattrs[offset].pValue = V;                                     \
    offset++;                                                        \
  } while(0)

UTILS_GENERIC_ATTR_TYPE_CONVERT(CK_BBOOL);

CK_RV ecc_add_missing_mechs(tobject *tobj) {

    CK_MECHANISM mechs[1] = {
        { .mechanism = CKM_ECDSA,     .pParameter = NULL,         .ulParameterLen = 0                   },
    };

   return tobject_append_mechs(tobj, mechs, ARRAY_LEN(mechs));
}

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

CK_RV object_add_missing_mechs(tobject *tobj, CK_MECHANISM_TYPE mech) {

    /* dispatch table here */
    switch (mech) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        return rsa_add_missing_mechs(tobj);
    case CKM_EC_KEY_PAIR_GEN:
        return ecc_add_missing_mechs(tobj);
    default:
        LOGE("Unsupported keygen mechanism: 0x%x", mech);
        return CKR_MECHANISM_INVALID;
    }
}

static CK_RV ecc_add_missing_attrs(tobject *public_tobj, tobject *private_tobj, tpm_object_data *objdata) {

    CK_RV tmp_rv;
    CK_RV rv = CKR_HOST_MEMORY;

    CK_ULONG pubindex = 0;
    CK_ATTRIBUTE newpubattrs[1] = { 0 };

    CK_ULONG privindex = 0;
    CK_ATTRIBUTE newprivattrs[1] = { 0 };


    CK_ATTRIBUTE_PTR a = tobject_get_attribute_by_type(public_tobj, CKA_EC_POINT);
    if (!a) {
        ADD_ATTR_TWIST(CKA_EC_POINT, objdata->ecc.ecpoint, newpubattrs, pubindex);
    }

    /*
     * Private ECC objects require the CKA_EC_PARAMS
     */
    a = tobject_get_attribute_by_type(public_tobj, CKA_EC_PARAMS);
    if (!a) {
        LOGE("CKA_EC_PARAMS missing");
        rv = CKR_GENERAL_ERROR;
        goto error;
    }

    void *x = buf_dup(a->pValue, a->ulValueLen);
    if (!x) {
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    ADD_ATTR_BUF(CKA_EC_PARAMS, x, a->ulValueLen, newprivattrs, privindex);

    /* add the new attrs */
    rv = tobject_append_attrs(public_tobj, newpubattrs, pubindex);
    if (rv != CKR_OK) {
        LOGW("Could not append pub attributes");
        goto error;
    }

    /* add the new attrs */
    rv = tobject_append_attrs(private_tobj, newprivattrs, privindex);
    if (rv != CKR_OK) {
        LOGW("Could not append priv attributes");
        goto error;
    }

error:

    tmp_rv = utils_attr_free(newpubattrs, pubindex);
    if (tmp_rv != CKR_OK) {
        LOGW("Could not free pub attributes");
        assert(0);
    }

    tmp_rv = utils_attr_free(newprivattrs, privindex);
    if (tmp_rv != CKR_OK) {
        LOGW("Could not free priv attributes");
        assert(0);
    }

    return rv;
}

static CK_RV uint32_to_BN(uint32_t value, void **bytes, CK_ULONG_PTR len) {

    CK_RV rv = CKR_GENERAL_ERROR;

    BIGNUM *b = BN_new();
    if (!b) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    int rc = BN_set_word(b, value);
    if (!rc) {
        LOGE("BN_set_word failed: %d", rc);
        goto out;
    }

    int l = BN_num_bytes(b);

    void *x = malloc(l);
    if (!x) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    rc = BN_bn2bin(b, x);
    if (!rc) {
        free(x);
        LOGE("BN_bn2bin failed: %d", rc);
        goto out;
    }

    *bytes = x;
    *len = l;

    rv = CKR_OK;

out:
    BN_free(b);
    return rv;
}

/*
 * Add required attributes to the RSA objects based on:
 *   - http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850406
 *     - 2.1.2 and 2.1.3
 */
static CK_RV rsa_add_missing_attrs(tobject *public_tobj, tobject *private_tobj, tpm_object_data *objdata) {

    CK_RV tmp_rv;
    CK_RV rv = CKR_HOST_MEMORY;

    CK_ULONG privindex = 0;
    CK_ATTRIBUTE newprivattrs[3] = { 0 };

    CK_ULONG pubindex = 0;
    CK_ATTRIBUTE newpubattrs[3] = { 0 };

    /* pub/priv: CKA_MODULUS */
    CK_ATTRIBUTE_PTR a = tobject_get_attribute_by_type(public_tobj, CKA_MODULUS);
    if (!a) {
        ADD_ATTR_TWIST(CKA_MODULUS, objdata->rsa.modulus, newpubattrs, pubindex);
    }

    a = tobject_get_attribute_by_type(private_tobj, CKA_MODULUS);
    if (!a) {
        ADD_ATTR_TWIST(CKA_MODULUS, objdata->rsa.modulus, newprivattrs, privindex);
    }

    /* pub/priv: CKA_PUBLIC_EXPONENT */
    a = tobject_get_attribute_by_type(public_tobj, CKA_PUBLIC_EXPONENT);
    if (!a) {

        void *bnexp;
        CK_ULONG len;
        rv = uint32_to_BN(objdata->rsa.exponent, &bnexp, &len);
        if (rv != CKR_OK) {
            goto error;
        }

        ADD_ATTR_BUF(CKA_PUBLIC_EXPONENT, bnexp, len, newpubattrs, pubindex);
    }

    a = tobject_get_attribute_by_type(private_tobj, CKA_PUBLIC_EXPONENT);
    if (!a) {

        void *bnexp;
        CK_ULONG len;
        rv = uint32_to_BN(objdata->rsa.exponent, &bnexp, &len);
        if (rv != CKR_OK) {
            goto error;
        }

        ADD_ATTR_BUF(CKA_PUBLIC_EXPONENT, bnexp, len, newprivattrs, privindex);
    }


    /* make sure both have keybits specified via CKA_MODULUS_BITS */
    CK_ULONG keybits = twist_len(objdata->rsa.modulus) * 8;
    a = tobject_get_attribute_by_type(private_tobj, CKA_MODULUS_BITS);
    if (!a) {
        ADD_ATTR(CK_ULONG, CKA_MODULUS_BITS, keybits, newprivattrs, privindex);
    }

    a = tobject_get_attribute_by_type(public_tobj, CKA_MODULUS_BITS);
    if (!a) {
        ADD_ATTR(CK_ULONG, CKA_MODULUS_BITS, keybits, newpubattrs, pubindex);
    }

    rv = tobject_append_attrs(public_tobj, newpubattrs, pubindex);
    if (rv != CKR_OK) {
        goto error;
    }

    rv = tobject_append_attrs(private_tobj, newprivattrs, privindex);

error:
    tmp_rv = utils_attr_free(newprivattrs, privindex);
    if (tmp_rv != CKR_OK) {
        LOGW("Could not free attributes");
        assert(0);
    }

    tmp_rv = utils_attr_free(newpubattrs, pubindex);
    if (tmp_rv != CKR_OK) {
        LOGW("Could not free attributes");
        assert(0);
    }

    return rv;
}

static CK_RV object_add_missing_attrs(tobject *public_tobj, tobject *private_tobj, tpm_object_data *objdata, CK_MECHANISM_TYPE mech) {

    CK_KEY_TYPE keytype;
    switch (mech) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        keytype = CKK_RSA;
        break;
    case CKM_EC_KEY_PAIR_GEN:
        keytype = CKK_EC;
        break;
    default:
        LOGE("Unsupported keygen mechanism: 0x%x", mech);
        return CKR_MECHANISM_INVALID;
    }

    CK_RV tmp_rv;
    CK_RV rv = CKR_HOST_MEMORY;

    CK_ULONG privindex = 0;
    CK_ULONG pubindex = 0;
    CK_ATTRIBUTE newprivattrs[8] = { 0 };
    CK_ATTRIBUTE newpubattrs[8] = { 0 };

    /*
     * Ensure that keytype is set for both public and private
     */
    CK_ATTRIBUTE_PTR a = tobject_get_attribute_by_type(public_tobj, CKA_KEY_TYPE);
    if (!a) {
        ADD_ATTR(CK_KEY_TYPE, CKA_KEY_TYPE, keytype, newpubattrs, pubindex);
    }

    a = tobject_get_attribute_by_type(private_tobj, CKA_KEY_TYPE);
    if (!a) {
        ADD_ATTR(CK_KEY_TYPE, CKA_KEY_TYPE, keytype, newprivattrs, privindex);
    }

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE match = {
       .type = CKA_CLASS,
       .ulValueLen = sizeof(class),
       .pValue = &class
    };

    a = tobject_get_attribute_full(private_tobj, &match);
    if (!a) {
        ADD_ATTR(CK_OBJECT_CLASS, CKA_CLASS, CKO_PRIVATE_KEY, newprivattrs, privindex);
    }

    class = CKO_PUBLIC_KEY;
    a = tobject_get_attribute_full(public_tobj, &match);
    if (!a) {
        ADD_ATTR(CK_OBJECT_CLASS, CKA_CLASS, CKO_PUBLIC_KEY, newpubattrs, pubindex);
    }

    /*
     * We come into the CKA_SENSITIVE and CKA_EXTRACTABLE block assuming that:
     * CKA_EXTRACTABLE CKA_SENSITIVE
     *   0 | 0 = error checked before thus not possible
     *   0 | 1 = OK
     *   1 | 0 = OK
     *   1 | 1 = error checked before thus not possible
     *
     * if the object is missing sensitive, the TPM defaults to sensitive, so mark it.
     * This only applies to the private object, as public objects are always extractable.
     */

    CK_BBOOL sensitive = CK_TRUE;
    a = tobject_get_attribute_by_type(private_tobj, CKA_SENSITIVE);
    if (!a) {
        ADD_ATTR(CK_BBOOL, CKA_SENSITIVE, CK_TRUE, newprivattrs, privindex);
    } else {
        tmp_rv = generic_CK_BBOOL(a, &sensitive);
        if (tmp_rv != CKR_OK) {
            goto error;
        }
    }

    /* mark always sensitive if not specified by user */
    a = tobject_get_attribute_by_type(private_tobj, CKA_ALWAYS_SENSITIVE);
    if (!a) {
        ADD_ATTR(CK_BBOOL, CKA_ALWAYS_SENSITIVE, sensitive ? CK_TRUE : CK_FALSE, newprivattrs, privindex);
    }

    /* if the object is missing CKA_EXTRACTABLE use the value of CKA_SENSITIVE to determine */
    CK_BBOOL extractable = CK_FALSE;
    a = tobject_get_attribute_by_type(private_tobj, CKA_EXTRACTABLE);
    if (!a) {
        extractable = !sensitive;
        ADD_ATTR(CK_BBOOL, CKA_EXTRACTABLE, extractable, newprivattrs, privindex);
    } else {
        tmp_rv = generic_CK_BBOOL(a, &extractable);
        if (tmp_rv != CKR_OK) {
            goto error;
        }
    }

    /* mark never extractable if not specified by user */
    a = tobject_get_attribute_by_type(private_tobj, CKA_NEVER_EXTRACTABLE);
    if (!a) {
        ADD_ATTR(CK_BBOOL, CKA_NEVER_EXTRACTABLE, extractable ? CK_FALSE : CK_TRUE, newprivattrs, privindex);
    }

    /* key type specific stuff */
    /* TODO dispatch table */
    switch (keytype) {
    case CKK_RSA:
        rv = rsa_add_missing_attrs(public_tobj, private_tobj, objdata);
        break;
    case CKK_EC:
        rv = ecc_add_missing_attrs(public_tobj, private_tobj, objdata);
        break;
    default:
        rv = CKR_GENERAL_ERROR;
        LOGE("Unsupported keytype, got: 0x%x", keytype);
        goto error;
    }

    if (rv != CKR_OK) {
        LOGE("Could not add key-type specific attributes");
        goto error;
    }

    /* add the new attrs */
    rv = tobject_append_attrs(private_tobj, newprivattrs, privindex);
    if (rv != CKR_OK) {
        goto error;
    }

    rv = tobject_append_attrs(public_tobj, newpubattrs, pubindex);

error:
    tmp_rv = utils_attr_free(newprivattrs, privindex);
    if (tmp_rv != CKR_OK) {
        LOGW("Could not free attributes");
        assert(0);
    }

    tmp_rv = utils_attr_free(newpubattrs, pubindex);
    if (tmp_rv != CKR_OK) {
        LOGW("Could not free attributes");
        assert(0);
    }

    return rv;
}

static CK_RV object_add_missing_ids(tobject *tobj) {

    CK_RV tmp_rv;
    CK_RV rv = CKR_HOST_MEMORY;

    CK_ULONG privindex = 0;
    CK_ATTRIBUTE newprivattrs[1] = { 0 };

    CK_ATTRIBUTE_PTR a = tobject_get_attribute_by_type(tobj, CKA_ID);
    if (a) {
        /* nothing to do, already has an ID */
        return CKR_OK;
    }

    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%lu", tobj->id);
    ADD_ATTR_STR(CKA_ID, tmp, newprivattrs, privindex);

    /* add the new attrs */
    rv = tobject_append_attrs(tobj, newprivattrs, privindex);
    if (rv != CKR_OK) {
        LOGE("Could not append CKA_ID to object: %lu", tobj->id);
        goto error;
    }

    rv = db_update_attrs(tobj);

error:
    tmp_rv = utils_attr_free(newprivattrs, privindex);
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

static CK_RV handle_derive(CK_ATTRIBUTE_PTR attr, CK_ULONG index, void *udata) {
    UNUSED(index);
    UNUSED(udata);

    CK_BBOOL value;
    CK_RV rv = generic_CK_BBOOL(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    if (value) {
        LOGE("CKA_DERIVE=true not supported");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
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
        { CKA_DERIVE,          handle_derive         },
        { CKA_MODULUS_BITS,    ATTR_HANDLER_IGNORE   },
        { CKA_PUBLIC_EXPONENT, ATTR_HANDLER_IGNORE   },
        { CKA_SENSITIVE,       ATTR_HANDLER_IGNORE   },
        { CKA_CLASS,           ATTR_HANDLER_IGNORE   },
        /* TODO should be sanity checking this here? */
        { CKA_EC_PARAMS,       ATTR_HANDLER_IGNORE   }
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

static CK_RV ecc_check_attrs(
        CK_ATTRIBUTE_PTR public_key_template, CK_ULONG public_key_attribute_count,
        CK_ATTRIBUTE_PTR private_key_template, CK_ULONG private_key_attribute_count) {

    CK_ATTRIBUTE_PTR a = util_get_attribute_by_type(CKA_EC_PARAMS, public_key_template, public_key_attribute_count);
    if (!a) {
        LOGE("EC keygen requires CKA_EC_PARAMS in public template");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    CK_ATTRIBUTE_PTR b = util_get_attribute_by_type(CKA_EC_PARAMS, private_key_template, private_key_attribute_count);
    if (b) {
        LOGW("EC keygen CKA_EC_PARAMS should not be in private template");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    return CKR_OK;
}

static CK_RV check_specific_attrs(CK_MECHANISM_TYPE mech,
        CK_ATTRIBUTE_PTR public_key_template, CK_ULONG public_key_attribute_count,
        CK_ATTRIBUTE_PTR private_key_template, CK_ULONG private_key_attribute_count) {

    switch (mech) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        return CKR_OK;
    case CKM_EC_KEY_PAIR_GEN:
        return ecc_check_attrs(public_key_template, public_key_attribute_count,
                    private_key_template, private_key_attribute_count);
    default:
        LOGE("Unsupported keygen mechanism: 0x%x", mech);
        return CKR_MECHANISM_INVALID;
    }
}

CK_RV key_gen (
        session_ctx *ctx,

        CK_MECHANISM_PTR mechanism,

        CK_ATTRIBUTE_PTR public_key_template,
        CK_ULONG public_key_attribute_count,

        CK_ATTRIBUTE_PTR private_key_template,
        CK_ULONG private_key_attribute_count,

        CK_OBJECT_HANDLE_PTR public_key_handle,
        CK_OBJECT_HANDLE_PTR private_key_handle) {

    CK_RV rv = CKR_GENERAL_ERROR;

    twist newauthbin = NULL;
    twist newauthhex = NULL;
    twist newwrapped_auth = NULL;

    tobject *new_private_tobj = NULL;
    tobject *new_public_tobj = NULL;

    tpm_object_data objdata = { 0 };

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    rv = check_common_attrs(
            private_key_template,
            private_key_attribute_count);
    if (rv != CKR_OK) {
        LOGE("Failed checking private attrs");
        goto out;
    }

    rv = check_common_attrs(
            public_key_template,
            public_key_attribute_count);
    if (rv != CKR_OK) {
        LOGE("Failed checking public attrs");
        goto out;
    }

    check_specific_attrs(mechanism->mechanism,
            public_key_template, public_key_attribute_count,
            private_key_template, private_key_attribute_count);

    new_private_tobj = tobject_new();
    if (!new_private_tobj) {
        goto out;
    }

    new_public_tobj = tobject_new();
    if (!new_public_tobj) {
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

    /* set the tpm object handles */
    tobject_set_handle(new_private_tobj, objdata.privhandle);
    tobject_set_handle(new_public_tobj, objdata.pubhandle);

    rv = tobject_append_attrs(new_public_tobj, public_key_template, public_key_attribute_count);
    if (rv != CKR_OK) {
        LOGE("Failed to append public template");
        goto out;
    }

    rv = tobject_append_attrs(new_private_tobj, private_key_template, private_key_attribute_count);
    if (rv != CKR_OK) {
        LOGE("Failed to append private template");
        goto out;
    }

    /*
     * objects have default required attributes, add them if not present.
     */
    /* TODO dispatch table here */
    rv = object_add_missing_attrs(new_public_tobj, new_private_tobj, &objdata, mechanism->mechanism);
    if (rv != CKR_OK) {
        LOGE("Failed to add missing rsa attrs");
        goto out;
    }

    /* populate blob data */
    rv = tobject_set_blob_data(new_private_tobj, objdata.pubblob, objdata.privblob);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = tobject_set_blob_data(new_public_tobj, objdata.pubblob, NULL);
    if (rv != CKR_OK) {
        goto out;
    }

    /* populate auth data */
    rv = tobject_set_auth(new_public_tobj, newauthbin, newwrapped_auth);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = tobject_set_auth(new_private_tobj, newauthbin, newwrapped_auth);
    if (rv != CKR_OK) {
        goto out;
    }

    /*
     * Add the missing supported mechanisms
     */
    rv = object_add_missing_mechs(new_private_tobj, mechanism->mechanism);
    if (rv != CKR_OK) {
        LOGE("Failed to add missing mechanisms");
        goto out;
    }

    rv = object_add_missing_mechs(new_public_tobj, mechanism->mechanism);
    if (rv != CKR_OK) {
        LOGE("Failed to add missing mechanisms");
        goto out;
    }

    /* populates tobj->id */
    rv = db_add_new_object(tok, new_private_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add private object to db");
        goto out;
    }

    rv = db_add_new_object(tok, new_public_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add public object to db");
        goto out;
    }

    /* set CKA_ID if not present based on tobj->id */
    rv = object_add_missing_ids(new_private_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add missing CKA_ID's");
        goto out;
    }

    /* set CKA_ID if not present based on tobj->id */
    rv = object_add_missing_ids(new_public_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add missing CKA_ID's");
        goto out;
    }

    /* start a list of two elements public pointing to private */
    new_public_tobj->l.next = &new_private_tobj->l;

    /* add to object list preserving old object list if present */
    if (tok->tobjects) {
        new_private_tobj->l.next = &tok->tobjects->l;
    }

    tok->tobjects = new_public_tobj;

    *public_key_handle = new_public_tobj->id;
    *private_key_handle = new_private_tobj->id;

out:

    tpm_objdata_free(&objdata);
    twist_free(newauthhex);
    twist_free(newauthbin);
    twist_free(newwrapped_auth);

    if (rv != CKR_OK) {
        tobject_free(new_private_tobj);
        tobject_free(new_public_tobj);
    }

    return rv;
}
