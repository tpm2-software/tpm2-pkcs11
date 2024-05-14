/* SPDX-License-Identifier: BSD-2-Clause */

#include <openssl/bn.h>
#include <openssl/rand.h>

#include "attrs.h"
#include "backend.h"
#include "checks.h"
#include "key.h"
#include "list.h"
#include "pkcs11.h"
#include "session.h"
#include "session_ctx.h"
#include "utils.h"

enum keygen_mode {
    keygen_mode_normal,
    keygen_mode_kobjs,
    keygen_mode_phandle
};

typedef struct sanity_check_data sanity_check_data;
struct sanity_check_data {
    bool is_extractable;
    bool is_sensitive;
};

static CK_RV handle_extractable_common(CK_ATTRIBUTE_PTR attr, bool is_extractable, void *udata) {

    sanity_check_data *scd = (sanity_check_data *)udata;
    assert(scd);

    CK_BBOOL value;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
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

static CK_RV handle_sensitive(CK_ATTRIBUTE_PTR attr,void *udata) {

    return handle_extractable_common(attr, false, udata);
}

static CK_RV handle_extractable(CK_ATTRIBUTE_PTR attr,void *udata) {

    return handle_extractable_common(attr, true, udata);
}

static CK_RV handle_expect_false(CK_ATTRIBUTE_PTR attr,void *udata) {
    UNUSED(udata);

    CK_BBOOL value;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
    if (rv != CKR_OK) {
        return rv;
    }

    if (value) {
        LOGE("%s=true not supported", attr_get_name(attr->type));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

CK_RV check_common_attrs(
        CK_ATTRIBUTE_PTR private_key_template,
        CK_ULONG private_key_attribute_count) {

    static const attr_handler common_attr_check_handlers[] = {
        { CKA_PRIVATE,           handle_sensitive     },
        { CKA_EXTRACTABLE,       handle_extractable   },
        { CKA_SIGN_RECOVER,      handle_expect_false  },
        { CKA_VERIFY_RECOVER,    handle_expect_false  },
        { CKA_TRUSTED,           handle_expect_false  },
    };

    sanity_check_data udata = { 0 };

    CK_RV rv = attr_list_raw_invoke_handlers(
            private_key_template,
            private_key_attribute_count,
            common_attr_check_handlers,
            ARRAY_LEN(common_attr_check_handlers),
            &udata);
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

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type_raw(public_key_template, public_key_attribute_count, CKA_EC_PARAMS);
    if (!a) {
        LOGE("EC keygen requires CKA_EC_PARAMS in public template");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    CK_ATTRIBUTE_PTR b = attr_get_attribute_by_type_raw(private_key_template, private_key_attribute_count, CKA_EC_PARAMS);
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
        LOGE("Unsupported keygen mechanism: 0x%lx", mech);
        return CKR_MECHANISM_INVALID;
    }
}

static CK_RV check_tpm_vendor_attrs(
        attr_list *pubkey_templ_w_types, attr_list *privkey_templ_w_types,
        enum keygen_mode *keygen_mode) {

    /* From pPublicKeyTemplate */
    CK_ATTRIBUTE_PTR a_pub_blob = attr_get_attribute_by_type(pubkey_templ_w_types, CKA_TPM2_PUB_BLOB);
    CK_ATTRIBUTE_PTR a_pub_handle = attr_get_attribute_by_type(pubkey_templ_w_types, CKA_TPM2_PERSISTENT_HANDLE);

    /* From pPrivateKeyTemplate */
    CK_ATTRIBUTE_PTR a_priv_auth = attr_get_attribute_by_type(privkey_templ_w_types, CKA_TPM2_OBJAUTH);
    CK_ATTRIBUTE_PTR a_priv_blob = attr_get_attribute_by_type(privkey_templ_w_types, CKA_TPM2_PRIV_BLOB);
    CK_ATTRIBUTE_PTR a_priv_handle = attr_get_attribute_by_type(privkey_templ_w_types, CKA_TPM2_PERSISTENT_HANDLE);

    if (a_pub_handle && a_priv_handle && !(a_pub_blob || a_priv_blob)) {
        /* Persistent key found */
        *keygen_mode = keygen_mode_phandle;
    } else if (a_pub_blob && a_priv_blob && !(a_pub_handle || a_priv_handle)) {
        /* TPM key objects found */
        *keygen_mode = keygen_mode_kobjs;
    } else if (!(a_pub_blob || a_pub_handle || a_priv_auth || a_priv_blob || a_priv_handle)) {
        *keygen_mode = keygen_mode_normal;
    } else {
        /* Invalid combination */
        LOGE("Key import request detected, but the attribute combination is invalid or missing");
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    return CKR_OK;
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

    enum keygen_mode keygen_mode = keygen_mode_normal;

    twist newauthhex = NULL;
    twist newwrapped_auth = NULL;

    twist pub_blob = NULL;
    twist priv_blob = NULL;

    attr_list *pubkey_templ_w_types = NULL;
    attr_list *privkey_templ_w_types = NULL;

    tobject *new_private_tobj = NULL;
    tobject *new_public_tobj = NULL;

    tpm_object_data objdata = { 0 };

    CK_ATTRIBUTE_PTR attr_ptr = NULL;

    uint32_t priv_esys_tr = 0, pub_esys_tr = 0;
    CK_ULONG priv_persistent_handle = 0;
    CK_ULONG pub_persistent_handle = 0;

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    /*
     * Attribute arrays specified by the user don't have the type
     * information, but are safe for basic sanity checks (for now).
     */
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

    /*
     * Following functions demand to know about the type tagging,
     * so "typeify" the user supplied attrs.
     */
    bool res = attr_typify(public_key_template, public_key_attribute_count, &pubkey_templ_w_types);
    if (!res) {
        LOGE("Failed typifying public attrs");
        goto out;
    }

    res = attr_typify(private_key_template, private_key_attribute_count, &privkey_templ_w_types);
    if (!res) {
        LOGE("Failed typifying private attrs");
        goto out;
    }

    /* re-seat pointers to type safe ones */
    public_key_template = NULL;
    private_key_template = NULL;

    new_private_tobj = tobject_new();
    if (!new_private_tobj) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    new_public_tobj = tobject_new();
    if (!new_public_tobj) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    /* Initialize the objects attributes */
    new_public_tobj->attrs = pubkey_templ_w_types;
    new_private_tobj->attrs = privkey_templ_w_types;

    /* make it clear that tobj now owns these */
    pubkey_templ_w_types = privkey_templ_w_types = NULL;

    /* Check if the import of an existing TPM key (persistent handle or key objects) is requested */
    rv = check_tpm_vendor_attrs(
                 new_public_tobj->attrs, new_private_tobj->attrs,
                 &keygen_mode);
    if (rv) {
        goto out;
    }

    if (keygen_mode == keygen_mode_normal) { /* Generate a new TPM key */

        rv = utils_new_random_object_auth(&newauthhex);
        if (rv != CKR_OK) {
            LOGE("Failed to create new object auth");
            goto out;
        }

        rv = tpm2_generate_key(
                tok->tctx,
                tok->pobject.handle,
                tok->pobject.objauth,
                newauthhex,
                mechanism,
                new_public_tobj->attrs,
                new_private_tobj->attrs,
                &objdata);
        if (rv != CKR_OK) {
            LOGE("Failed to generate key");
            goto out;
        }

        /* set the tpm object handles */
        tobject_set_esys_tr(new_private_tobj, objdata.privhandle);
        tobject_set_esys_tr(new_public_tobj, objdata.pubhandle);

        /* populate blob data */
        rv = tobject_set_blob_data(new_private_tobj, objdata.pubblob, objdata.privblob);
        if (rv != CKR_OK) {
            goto out;
        }

        rv = tobject_set_blob_data(new_public_tobj, objdata.pubblob, NULL);
        if (rv != CKR_OK) {
            goto out;
        }

    } else { /* Import an existing TPM key */

        /* Read the CKA_TPM2_OBJAUTH */
        attr_ptr = attr_get_attribute_by_type(new_private_tobj->attrs, CKA_TPM2_OBJAUTH);
        if (attr_ptr) {
            newauthhex = twistbin_new(attr_ptr->pValue, attr_ptr->ulValueLen);

            /* Secure erase the CKA_TPM2_OBJAUTH field in the privkey template */
            memset(attr_ptr->pValue, 0, attr_ptr->ulValueLen);
            attr_pfree_cleanse(attr_ptr);

            /* [To-do] delete the CKA_TPM2_OBJAUTH from the privkey template to save storage space */
        }

        if (keygen_mode == keygen_mode_phandle) { /* The key to import is a persistent handle */

            attr_ptr = attr_get_attribute_by_type(new_private_tobj->attrs, CKA_TPM2_PERSISTENT_HANDLE);
            rv = attr_CK_ULONG(attr_ptr, &priv_persistent_handle);
            if (rv != CKR_OK) {
                LOGE("Failed to get private key persistent handle");
                goto out;
            }

            attr_ptr = attr_get_attribute_by_type(new_public_tobj->attrs, CKA_TPM2_PERSISTENT_HANDLE);
            rv = attr_CK_ULONG(attr_ptr, &pub_persistent_handle);
            if (rv != CKR_OK) {
                LOGE("Failed to get public key persistent handle");
                goto out;
            }

            if (priv_persistent_handle != pub_persistent_handle) {
                LOGE("The public and private key persistent handles are not the same");
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }

            rv = tpm_get_esys_tr(tok->tctx, (uint32_t)priv_persistent_handle,
                    &priv_esys_tr, &pub_esys_tr);
            if (rv != CKR_OK) {
                LOGE("Failed to get ESYS_TR of privkey");
                goto out;
            }

            tobject_set_persistent_handle(new_private_tobj, priv_persistent_handle);
            tobject_set_persistent_handle(new_public_tobj, pub_persistent_handle);
            tobject_set_esys_tr(new_private_tobj, priv_esys_tr);
            tobject_set_esys_tr(new_public_tobj, pub_esys_tr);

        } else if (keygen_mode == keygen_mode_kobjs) { /* The key to import includes both public and private blobs */

            attr_ptr = attr_get_attribute_by_type(new_public_tobj->attrs, CKA_TPM2_PUB_BLOB);
            pub_blob = twistbin_new(attr_ptr->pValue, attr_ptr->ulValueLen);

            attr_ptr = attr_get_attribute_by_type(new_private_tobj->attrs, CKA_TPM2_PRIV_BLOB);
            priv_blob = twistbin_new(attr_ptr->pValue, attr_ptr->ulValueLen);

            rv = tpm_loadobj(tok->tctx, tok->pobject.handle, tok->pobject.objauth,
                        pub_blob, NULL, &pub_esys_tr);
            if (rv != CKR_OK) {
                LOGE("Failed to load key objects");
                goto out;
            }

            rv = tpm_loadobj(tok->tctx, tok->pobject.handle, tok->pobject.objauth,
                        pub_blob, priv_blob, &priv_esys_tr);
            if (rv != CKR_OK) {
                LOGE("Failed to load key objects");
                goto out;
            }

            tobject_set_esys_tr(new_private_tobj, priv_esys_tr);
            tobject_set_esys_tr(new_public_tobj, pub_esys_tr);

            rv = tobject_set_blob_data(new_private_tobj, pub_blob, priv_blob);
            if (rv != CKR_OK) {
                goto out;
            }

            rv = tobject_set_blob_data(new_public_tobj, pub_blob, NULL);
            if (rv != CKR_OK) {
                goto out;
            }
        } else { /* Will not reach here */
            assert(0);
        }

        /* Populate the mandatory attributes based on the TPM key */
        rv = tpm_parse_key_to_attrs(tok->tctx, priv_esys_tr, mechanism,
                    new_public_tobj->attrs, new_private_tobj->attrs,
                    &objdata);
        if (rv != CKR_OK) {
            goto out;
        }
    }

    if (newauthhex) {
        rv = utils_ctx_wrap_objauth(tok->wrappingkey, newauthhex, &newwrapped_auth);
        if (rv != CKR_OK) {
            LOGE("Failed to wrap new object auth");
            goto out;
        }

        /* populate auth data, public objects do not need an auth */
        rv = tobject_set_auth(new_private_tobj, newauthhex, newwrapped_auth);
        if (rv != CKR_OK) {
            goto out;
        }
    }

    /*
     * objects have default required attributes, add them if not present.
     */
    rv = attr_add_missing_attrs(&new_public_tobj->attrs, &new_private_tobj->attrs,
            objdata.attrs, mechanism->mechanism);
    if (rv != CKR_OK) {
        LOGE("Failed to add missing rsa attrs");
        goto out;
    }

    rv = backend_add_object(tok, new_public_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add public object to db");
        goto out;
    }

    rv = backend_add_object(tok, new_private_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add public object to db");
        goto out;
    }

    rv = token_add_tobject(tok, new_public_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add public object to token");
        goto out;
    }

    rv = token_add_tobject(tok, new_private_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add private object to token");
        goto out;
    }

    *public_key_handle = new_public_tobj->obj_handle;
    *private_key_handle = new_private_tobj->obj_handle;

out:
    tpm_objdata_free(&objdata);
    twist_free(newauthhex);
    twist_free(newwrapped_auth);
    twist_free(pub_blob);
    twist_free(priv_blob);
    attr_list_free(pubkey_templ_w_types);
    attr_list_free(privkey_templ_w_types);

    if (rv != CKR_OK) {
        tobject_free(new_private_tobj);
        tobject_free(new_public_tobj);
    }

    return rv;
}
