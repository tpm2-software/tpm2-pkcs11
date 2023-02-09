/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <assert.h>
#include <stdlib.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include "attrs.h"
#include "backend.h"
#include "checks.h"
#include "derive.h"
#include "digest.h"
#include "encrypt.h"
#include "log.h"
#include "mech.h"
#include "ssl_util.h"
#include "session.h"
#include "session_ctx.h"
#include "token.h"
#include "tpm.h"

typedef struct sanity_check_data sanity_check_data;
struct sanity_check_data {
    size_t len;
};

CK_RV handle_token(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    CK_BBOOL value;
    UNUSED(userdat);
    CK_RV rv = attr_CK_BBOOL(attr, &value);

    LOGV("attr: name %s,\t\t val = %d", attr_get_name(attr->type), value);
    return rv;
}

CK_RV handle_class(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    CK_OBJECT_CLASS value = 0;
    UNUSED(userdat);
    CK_RV rv = attr_CK_OBJECT_CLASS(attr, &value);

    if (value != CKO_SECRET_KEY)
        rv = CKR_ARGUMENTS_BAD;

    LOGV("attr: name %s, \t\t val = %s", attr_get_name(attr->type), "CKO_SECRET_KEY");
    return rv;
}

CK_RV handle_key_type(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    CK_KEY_TYPE value;
    UNUSED(userdat);
    CK_RV rv = attr_CK_KEY_TYPE(attr, &value);

    if (value != CKK_GENERIC_SECRET)
        rv = CKR_ARGUMENTS_BAD;

    LOGV("attr: name %s,\t val = %s", attr_get_name(attr->type), "CKK_GENERIC_SECRET");
    return rv;
}

CK_RV handle_sensitive(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    UNUSED(userdat);

    LOGV("attr: name %s", attr_get_name(attr->type));
    return CKR_OK;
}

CK_RV handle_extractable(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    UNUSED(userdat);

    LOGV("attr: name %s", attr_get_name(attr->type));
    return CKR_OK;
}

CK_RV handle_encrypt(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    CK_BBOOL value;
    UNUSED(userdat);
    CK_RV rv = attr_CK_BBOOL(attr, &value);

    LOGV("attr: name %s,\t\t val = %d", attr_get_name(attr->type), value);
    return rv;
}

CK_RV handle_decrypt(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    CK_BBOOL value;
    UNUSED(userdat);
    CK_RV rv = attr_CK_BBOOL(attr, &value);

    LOGV("attr: name %s,\t\t val = %d", attr_get_name(attr->type), value);
    return rv;
}

CK_RV handle_wrap(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    CK_BBOOL value;
    UNUSED(userdat);
    CK_RV rv = attr_CK_BBOOL(attr, &value);

    LOGV("attr: name %s,\t\t val = %d", attr_get_name(attr->type), value);
    return rv;
}

CK_RV handle_unwrap(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    CK_BBOOL value;
    UNUSED(userdat);
    CK_RV rv = attr_CK_BBOOL(attr, &value);

    LOGV("attr: name %s,\t\t val = %d", attr_get_name(attr->type), value);
    return rv;
}

CK_RV handle_value_len(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    CK_ULONG value;
    CK_RV rv = attr_CK_ULONG(attr, &value);

    if (rv == CKR_OK) {
        ((sanity_check_data*)userdat)->len = value;
    }

    LOGV("attr: name %s,\t val = 0x%lx", attr_get_name(attr->type), value);
    return rv;
}

CK_RV derive(session_ctx* ctx,  CK_MECHANISM_PTR mechanism, /* public EC point */
             CK_OBJECT_HANDLE tpm_key,   /* private key */
             CK_ATTRIBUTE_PTR secret_template, CK_ULONG secret_template_count,
             CK_OBJECT_HANDLE_PTR secret) { /* secret buffer in CKA_VALUE */
    CK_RV rv = CKR_GENERAL_ERROR;

    check_pointer(mechanism);

    LOGV("mechanism: 0x%lx\n\thas_params: %s\n\tlen: %lu",
         mechanism->mechanism,
         mechanism->pParameter ? "yes" : "no", mechanism->ulParameterLen);

    if (mechanism->mechanism != CKM_ECDH1_DERIVE)
        return CKR_MECHANISM_INVALID;

    if (session_ctx_opdata_is_active(ctx))
        return CKR_OPERATION_ACTIVE;

    token* tok = session_ctx_get_token(ctx);
    assert(tok);

    tobject* tobj = NULL;
    rv = token_load_object(tok, tpm_key, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = object_mech_is_supported(tobj, mechanism);
    if (rv != CKR_OK) {
        tobject_user_decrement(tobj);
        return rv;
    }

    /*  Validate the keysize against the one provided by the mechanism */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_EC_PARAMS);
    if (!a) {
        LOGE("Expected tobject to have attribute CKA_EC_PARAMS");
        return CKR_GENERAL_ERROR;
    }

    int nid = 0;
    rv = ssl_util_params_to_nid(a, &nid);
    if (rv != CKR_OK) {
        return rv;
    }

    unsigned keysize;
    switch (nid) {
        case NID_X9_62_prime192v1:
            keysize = 24;
            break;
        case NID_secp224r1:
            keysize = 28;
            break;
        case NID_X9_62_prime256v1:
            keysize = 32;
            break;
        case NID_secp384r1:
            keysize = 48;
            break;
        case NID_secp521r1:
            keysize = 66;
            break;
        default:
            return CKR_CURVE_NOT_SUPPORTED;
    }

    /* 1. Get the public EC point to use in the derivation from the mechanism */
    CK_ECDH1_DERIVE_PARAMS_PTR mecha_params;
    SAFE_CAST(mechanism, mecha_params);

    if (mecha_params->kdf != CKD_NULL) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* 2. Uncompressed EC_POINT: is a DER OCTECT string of 04||x||y */
    if (!mecha_params->public_data_len ||
        (mecha_params->public_data_len - 1) != 2 * keysize) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* Validate the shared secret attributes */
    static const attr_handler secret_check_handlers[] = {
        { CKA_TOKEN, handle_token },
        { CKA_CLASS, handle_class },
        { CKA_KEY_TYPE, handle_key_type },
        { CKA_SENSITIVE, handle_sensitive },
        { CKA_EXTRACTABLE, handle_extractable },
        { CKA_ENCRYPT, handle_encrypt },
        { CKA_DECRYPT, handle_decrypt },
        { CKA_WRAP, handle_wrap },
        { CKA_UNWRAP, handle_unwrap },
        { CKA_VALUE_LEN, handle_value_len },
    };
    sanity_check_data udata = { 0 };

    rv = attr_list_raw_invoke_handlers(secret_template, secret_template_count,
                                       secret_check_handlers,
                                       ARRAY_LEN(secret_check_handlers),
                                       &udata);
    if (rv != CKR_OK) {
        tobject_user_decrement(tobj);
        return rv;
    }

    /* Get the shaed secret */
    CK_BYTE* shared_secret = NULL;
    rv = tpm_ec_ecdh1_derive(tok->tctx, tobj, /* EC private */
                             mecha_params->public_data, /* EC point */
                             mecha_params->public_data_len,
                             &shared_secret, &udata.len);
    if (rv != CKR_OK) {
         tobject_user_decrement(tobj);
         return rv;
    }

    CK_ATTRIBUTE shared_secret_attr = {
        .ulValueLen = udata.len,
        .pValue = shared_secret,
        .type = CKA_VALUE,
    };

    /* Return the shared secret in a CKO_SECRET_KEY class object */
    rv = object_create(ctx, secret_template, secret_template_count, secret);
    if (rv != CKR_OK) {
        tobject_user_decrement(tobj);
        goto out;
    }

    rv = object_set_attributes(ctx, *secret, &shared_secret_attr, 1);
    if (rv != CKR_OK) {
        tobject_user_decrement(tobj);
        goto out;
    }

out:
    free(shared_secret);
    return rv;
}
