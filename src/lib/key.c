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

static CK_RV handle_always_auth(CK_ATTRIBUTE_PTR attr,void *udata) {
    UNUSED(udata);

    CK_BBOOL value;
    return attr_CK_BBOOL(attr, &value);
}

static CK_RV handle_expect_false(CK_ATTRIBUTE_PTR attr,void *udata) {
    UNUSED(udata);

    CK_BBOOL value;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
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
        { CKA_PRIVATE,           handle_sensitive     },
        { CKA_EXTRACTABLE,       handle_extractable   },
        { CKA_DERIVE,            handle_expect_false  },
        { CKA_SIGN_RECOVER,      handle_expect_false  },
        { CKA_VERIFY_RECOVER,    handle_expect_false  },
        { CKA_UNWRAP,            handle_expect_false  },
        { CKA_WRAP,              handle_expect_false  },
        { CKA_WRAP_WITH_TRUSTED, handle_expect_false  },
        { CKA_TRUSTED,           handle_expect_false  },
        { CKA_ALWAYS_AUTHENTICATE, handle_always_auth },
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

    twist newauthhex = NULL;
    twist newwrapped_auth = NULL;

    attr_list *pubkey_templ_w_types = NULL;
    attr_list *privkey_templ_w_types = NULL;

    tobject *new_private_tobj = NULL;
    tobject *new_public_tobj = NULL;

    tpm_object_data objdata = { 0 };

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

    rv = utils_new_random_object_auth(&newauthhex);
    if (rv != CKR_OK) {
        LOGE("Failed to create new object auth");
        goto out;
    }

    rv = utils_ctx_wrap_objauth(tok->wrappingkey, newauthhex, &newwrapped_auth);
    if (rv != CKR_OK) {
        LOGE("Failed to wrap new object auth");
        goto out;
    }

    rv = tpm2_generate_key(
            tok->tctx,
            tok->pobject.handle,
            tok->pobject.objauth,
            newauthhex,
            mechanism,
            pubkey_templ_w_types,
            privkey_templ_w_types,
            &objdata);
    if (rv != CKR_OK) {
        LOGE("Failed to generate key");
        goto out;
    }

    /* set the tpm object handles */
    tobject_set_handle(new_private_tobj, objdata.privhandle);
    tobject_set_handle(new_public_tobj, objdata.pubhandle);

    new_public_tobj->attrs = pubkey_templ_w_types;
    new_private_tobj->attrs = privkey_templ_w_types;

    /* make it clear that tobj now owns these */
    pubkey_templ_w_types = privkey_templ_w_types = NULL;

    /*
     * objects have default required attributes, add them if not present.
     */
    rv = attr_add_missing_attrs(&new_public_tobj->attrs, &new_private_tobj->attrs,
            objdata.attrs, mechanism->mechanism);
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

    /* populate auth data, public objects do not need an auth */
    rv = tobject_set_auth(new_private_tobj, newauthhex, newwrapped_auth);
    if (rv != CKR_OK) {
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
    attr_list_free(pubkey_templ_w_types);
    attr_list_free(privkey_templ_w_types);

    if (rv != CKR_OK) {
        tobject_free(new_private_tobj);
        tobject_free(new_public_tobj);
    }

    return rv;
}
