/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <stdio.h>

#include <assert.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "checks.h"
#include "key.h"
#include "session.h"
#include "pkcs11.h"
#include "log.h"
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

CK_RV object_add_missing_attrs(tobject *public_tobj, tobject *private_tobj, tpm_object_data *objdata, CK_MECHANISM_TYPE mech) {

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
        { CKA_KEY_TYPE,        ATTR_HANDLER_IGNORE   },
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

struct ATTRS {
    char pubid[65];
    char publabel[65];
    char privid[65];
    char privlabel[65];
    uint64_t keysize;
    uint32_t exponent;
};

static CK_RV extract_attrs(CK_MECHANISM_PTR mechanism,
        CK_ATTRIBUTE_PTR pub, CK_ULONG pub_count,
        CK_ATTRIBUTE_PTR priv, CK_ULONG priv_count,
        struct ATTRS *attrs) {
    memset(attrs, 0, sizeof(*attrs));

    switch(mechanism->mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        break;
    default:
        LOGE("Unknown key generation type: 0x%x", mechanism->mechanism);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    /* Starting with public attributes */
    for (CK_ULONG i = 0; i < pub_count; i++) {
        switch(pub[i].type) {
        //TODO: Check that we can ignore them all
        case CKA_CLASS:
        case CKA_TOKEN:
        case CKA_PRIVATE:
        case CKA_ENCRYPT:
        case CKA_VERIFY:
            LOGV("Ignoring public attribute: 0x%x", pub[i].type);
            break;
        case CKA_ID:
            LOGV("Copying public key id");
            if (pub[i].ulValueLen > 64) {
                LOGE("CKA_ID's ulValueLen too large. Expect <=64, got: %li",
                     pub[i].ulValueLen);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            for (CK_ULONG j = 0; j < pub[i].ulValueLen; j++)
                sprintf(&attrs->pubid[2*j], "%02x", ((CK_BYTE *)pub[i].pValue)[j]);
            break;
        case CKA_LABEL:
            LOGV("Copying public key label");
            if (pub[i].ulValueLen > 64) {
                LOGE("CKA_LABEL's ulValueLen too large. Expect <=64, got: %li",
                     pub[i].ulValueLen);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            memcpy(&attrs->publabel[0], pub[i].pValue, pub[i].ulValueLen);
            break;
        case CKA_MODULUS_BITS:
            LOGV("Copying modulus bits");
            if (pub[i].ulValueLen > 8) {
                LOGE("CKA_MODULUS_BITS's ulValueLen too large. Expect <=8, got: %li",
                     pub[i].ulValueLen);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            uint8_t tmp1[8] = { 0 };
            memcpy(&tmp1[8-pub[i].ulValueLen], pub[i].pValue, pub[i].ulValueLen);
            memcpy(&attrs->keysize, &tmp1[0], 8);
            attrs->keysize = be64toh(attrs->keysize);
            break;
        case CKA_PUBLIC_EXPONENT:
            LOGV("Copying public exponent");
            if (pub[i].ulValueLen > 4) {
                LOGE("CKA_PUBLIC_EXPONENT's ulValueLen too large. Expect <=4, got: %li",
                     pub[i].ulValueLen);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            uint8_t tmp2[4] = { 0 };
            memcpy(&tmp2[4-pub[i].ulValueLen], pub[i].pValue, pub[i].ulValueLen);
            memcpy(&attrs->exponent, &tmp2[0], 4);
            attrs->exponent = be32toh(attrs->exponent);
            break;
        default:
            LOGE("Unknown attribute: 0x%x", pub[i].type);
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }

    for (CK_ULONG i = 0; i < priv_count; i++) {
        switch(priv[i].type) {
        //TODO: Look at these, esp decrypt vs sign
        case CKA_CLASS:
        case CKA_DECRYPT:
        case CKA_SIGN:
        case CKA_PRIVATE:
        case CKA_TOKEN:
        case CKA_SENSITIVE:
            LOGV("Ignoring private attribute: 0x%x", priv[i].type);
            break;
        case CKA_ID:
            LOGV("Copying priv key id");
            if (priv[i].ulValueLen > 32) {
                LOGE("CKA_ID's ulValueLen too large. Expect <=64, got: %li",
                     priv[i].ulValueLen);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            for (CK_ULONG j = 0; j < priv[i].ulValueLen; j++)
                sprintf(&attrs->privid[2*j], "%02x", ((CK_BYTE *)priv[i].pValue)[j]);
            break;
        case CKA_LABEL:
            LOGV("Copying priv key label");
            if (priv[i].ulValueLen > 64) {
                LOGE("CKA_LABEL's ulValueLen too large. Expect <=64, got: %li",
                     priv[i].ulValueLen);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            memcpy(&attrs->privlabel[0], priv[i].pValue, priv[i].ulValueLen);
            break;
        default:
            LOGE("Unknown attribute: 0x%x", priv[i].type);
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }

    return CKR_OK;
}

CK_RV key_gen (
        CK_SESSION_HANDLE session,

        CK_MECHANISM_PTR mechanism,

        CK_ATTRIBUTE_PTR public_key_template,
        CK_ULONG public_key_attribute_count,

        CK_ATTRIBUTE_PTR private_key_template,
        CK_ULONG private_key_attribute_count,

        CK_OBJECT_HANDLE_PTR public_key_handle,
        CK_OBJECT_HANDLE_PTR private_key_handle) {

    TSS2_RC rc;
    CK_RV rv;
    int ri;
    FAPI_CONTEXT *fctx;
    char *path, *description;
    CK_OBJECT_HANDLE keyhandle;
    struct ATTRS attrs;

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_tab[session].seal_avail) {
        LOGE("Session %lu has no seal available", session);
        return CKR_USER_NOT_LOGGED_IN;
    }

    rv = check_common_attrs(
            private_key_template,
            private_key_attribute_count);
    if (rv != CKR_OK) {
        LOGE("Failed checking private attrs");
        return rv;
    }

    rv = check_common_attrs(
            public_key_template,
            public_key_attribute_count);
    if (rv != CKR_OK) {
        LOGE("Failed checking public attrs");
        return rv;
    }

    rv = check_specific_attrs(mechanism->mechanism,
            public_key_template, public_key_attribute_count,
            private_key_template, private_key_attribute_count);
    if (rv != CKR_OK) {
        LOGE("Failed checking other attrs");
        return rv;
    }

    rv = extract_attrs(mechanism,
            public_key_template, public_key_attribute_count,
            private_key_template, private_key_attribute_count,
            &attrs);
    if (rv != CKR_OK) {
        LOGE("Failed extracting attrs");
        return rv;
    }

    //TODO: Turn attributes into Fapi_CreateKey-attributes, wrt sign, decrypt, keysize, exponent

    rc = Fapi_Initialize(&fctx, NULL);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    path = NULL;
    do {
        if (path)
            free(path);

        keyhandle = (CK_OBJECT_HANDLE) rand() & 0x0FFFFFFF;
        path = tss_keypath_from_id(session_tab[session].slot_id, keyhandle);

        rc = Fapi_CreateKey(fctx, path, "sign, decrypt",
                            NULL, (char *)&session_tab[session].seal[0]);
    } while (rc == TSS2_FAPI_RC_PATH_ALREADY_EXISTS);
    check_tssrc(rc, free(path); Fapi_Finalize(&fctx); return CKR_GENERAL_ERROR);
    LOGV("Created key at path %s", path);

    /* Put those attributes that belong there into the description */
    //TODO: Escape the label for reading
    ri = asprintf(&description, "%s:%s:%s:%s", &attrs.privid[0], &attrs.privlabel[0],
                                               &attrs.pubid[0], &attrs.publabel[0]);
    if (ri < 0) {
        LOGE("asprintf failed");
        free(path);
        Fapi_Finalize(&fctx);
        return CKR_GENERAL_ERROR;
    }

    LOGV("Setting description of key %s to %s", path, description);
    Fapi_SetDescription(fctx, path, description);
    free(path);
    free(description);
    Fapi_Finalize(&fctx);
    check_tssrc(rc, return CKR_GENERAL_ERROR);

    *public_key_handle = keyhandle | 0x10000000;
    *private_key_handle = keyhandle;

    return CKR_OK;
}
