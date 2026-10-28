/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <assert.h>
#include <stdlib.h>

#include <openssl/crypto.h>
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
#include "utils.h"
#include "wrap.h"

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
    if (rv != CKR_OK) {
        return rv;
    }

    LOGV("attr: name %s, \t\t val = 0x%lx", attr_get_name(attr->type), value);

    if (value != CKO_SECRET_KEY) {
        LOGE("The derived key can only be a CKO_SECRET_KEY, got CKA_CLASS 0x%lx", value);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

/*
 * The derived secret is kept as the object's CKA_VALUE, not as a TPM key, so it is a generic secret:
 * an AES key, say, couldn't be used.
 */
CK_RV handle_key_type(const CK_ATTRIBUTE_PTR attr, void* userdat) {
    CK_KEY_TYPE value;
    UNUSED(userdat);
    CK_RV rv = attr_CK_KEY_TYPE(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    LOGV("attr: name %s,\t val = 0x%lx", attr_get_name(attr->type), value);

    if (value != CKK_GENERIC_SECRET) {
        LOGE("The derived key can only be a CKK_GENERIC_SECRET, got CKA_KEY_TYPE 0x%lx", value);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
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

CK_RV ecdh1_params_get(CK_MECHANISM_PTR mechanism, CK_ECDH1_DERIVE_PARAMS_PTR *params) {

    if (!mechanism->pParameter || mechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)) {
        LOGE("Expected a CK_ECDH1_DERIVE_PARAMS");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    CK_ECDH1_DERIVE_PARAMS_PTR p = (CK_ECDH1_DERIVE_PARAMS_PTR)mechanism->pParameter;
    if (p->kdf != CKD_NULL) {
        LOGE("Only CKD_NULL is supported as the ECDH1 KDF, got 0x%lx", p->kdf);
        return CKR_MECHANISM_PARAM_INVALID;
    }

    *params = p;
    return CKR_OK;
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

    /* before the TPM derives anything: the secret's CKA_UNIQUE_ID is the token's to give */
    rv = attr_refuse_unique_id(secret_template, secret_template_count);
    if (rv != CKR_OK) {
        return rv;
    }

    token* tok = session_ctx_get_token(ctx);
    assert(tok);

    /* From here on, every return goes through out, which releases the key. */
    tobject* tobj = NULL;
    rv = token_load_object(tok, tpm_key, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_BYTE* shared_secret = NULL;

    rv = object_mech_is_supported(tobj, mechanism);
    if (rv != CKR_OK) {
        goto out;
    }

    /*
     * CKA_DERIVE=false is enforced on a key made by this token, which stores CKA_DECAPSULATE on every
     * key pair it makes (attrs.c) and a CKA_DERIVE that says whether the template asked for ECDH
     * (tpm.c). Such a key with the TPM's decrypt attribute for decapsulating alone doesn't derive, nor
     * does its copy, or the key itself, once CKA_DECAPSULATE is turned off: Z would give the value of
     * every key it ever decapsulated, the unextractable ones too. A key without CKA_DECAPSULATE was
     * stored before it was known, by an older version of this token or by tpm2_ptool, with
     * CKA_DERIVE=false whatever it was made for (objects.py, and the old keygen default): it derives
     * through the TPM's decrypt attribute alone, as it always did.
     */
    if (!attr_list_get_CKA_DERIVE(tobj->attrs, CK_TRUE)
            && attr_get_attribute_by_type(tobj->attrs, CKA_DECAPSULATE)) {
        LOGE("The key doesn't allow derivation (CKA_DERIVE=false)");
        rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto out;
    }

    /*  Validate the keysize against the one provided by the mechanism */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_EC_PARAMS);
    if (!a) {
        LOGE("Expected tobject to have attribute CKA_EC_PARAMS");
        rv = CKR_GENERAL_ERROR;
        goto out;
    }

    CK_ULONG keysize = 0;
    rv = ssl_util_ec_field_size(a, &keysize);
    if (rv != CKR_OK) {
        goto out;
    }

    /* 1. Get the public EC point to use in the derivation from the mechanism */
    CK_ECDH1_DERIVE_PARAMS_PTR mecha_params = NULL;
    rv = ecdh1_params_get(mechanism, &mecha_params);
    if (rv != CKR_OK) {
        goto out;
    }

    /* 2. Uncompressed EC_POINT 04||x||y, raw or DER-encoded */
    if (!mecha_params->pPublicData) {
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto out;
    }

    CK_BYTE_PTR point = NULL;
    CK_ULONG point_len = 0;
    if (!utils_ec_point_unwrap(mecha_params->pPublicData, mecha_params->ulPublicDataLen, keysize,
            &point, &point_len)) {
        LOGE("Expected the peer's uncompressed point for a %lu-byte field, raw or DER-encoded, "
                "got %lu bytes", keysize, mecha_params->ulPublicDataLen);
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto out;
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
        goto out;
    }

    /* Get the shaed secret */
    rv = tpm_ec_ecdh1_derive(tok->tctx, tobj, /* EC private */
                             point, point_len,
                             &shared_secret, &udata.len);
    if (rv == CKR_DATA_INVALID) {
        /* the TPM says the point isn't on the curve */
        rv = CKR_MECHANISM_PARAM_INVALID;
    }
    if (rv != CKR_OK) {
        goto out;
    }

    CK_ATTRIBUTE shared_secret_attr = {
        .ulValueLen = udata.len,
        .pValue = shared_secret,
        .type = CKA_VALUE,
    };

    /* Return the shared secret in a CKO_SECRET_KEY class object */
    rv = object_create_valueless_secret(ctx, secret_template, secret_template_count, secret);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = object_set_derived_value(ctx, *secret, &shared_secret_attr);
    if (rv != CKR_OK) {
        goto out;
    }

out:
    if (shared_secret) {
        OPENSSL_cleanse(shared_secret, udata.len);
    }
    free(shared_secret);

    /* The base key is released whatever happened, or it stays busy and can't be destroyed. */
    CK_RV tmp_rv = tobject_user_decrement(tobj);
    if (tmp_rv != CKR_OK && rv == CKR_OK) {
        rv = tmp_rv;
    }

    return rv;
}
