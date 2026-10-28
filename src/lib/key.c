/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/rand.h>

#include "attrs.h"
#include "backend.h"
#include "checks.h"
#include "key.h"
#include "tpm.h"
#include "token.h"
#include "object.h"
#include "mech.h"
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

    /* What a failure must undo, in reverse: the TPM objects, the store, the token. */
    bool public_stored = false;
    bool private_stored = false;
    bool public_added = false;
    bool private_added = false;

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    /* Before the TPM makes anything: what only the token sets can't come from the templates. */
    rv = attr_refuse_token_set(public_key_template, public_key_attribute_count, false);
    if (rv != CKR_OK) {
        return rv;
    }
    rv = attr_refuse_token_set(private_key_template, private_key_attribute_count, false);
    if (rv != CKR_OK) {
        return rv;
    }

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
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    res = attr_typify(private_key_template, private_key_attribute_count, &privkey_templ_w_types);
    if (!res) {
        LOGE("Failed typifying private attrs");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    /* The key size or curve, from the public template, before the TPM is asked for it. */
    rv = mech_validate(tok->mdtl, mechanism, pubkey_templ_w_types);
    if (rv != CKR_OK) {
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
    tobject_set_esys_tr(new_private_tobj, objdata.privhandle);
    tobject_set_esys_tr(new_public_tobj, objdata.pubhandle);

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

    /* to the db, unless they're session objects */
    rv = object_store(tok, ctx, new_public_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add public object to db");
        goto out;
    }
    public_stored = true;

    rv = object_store(tok, ctx, new_private_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add private object to db");
        goto out;
    }
    private_stored = true;

    rv = token_add_tobject(tok, new_public_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add public object to token");
        goto out;
    }
    public_added = true;

    rv = token_add_tobject(tok, new_private_tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add private object to token");
        goto out;
    }
    private_added = true;

    *public_key_handle = new_public_tobj->obj_handle;
    *private_key_handle = new_private_tobj->obj_handle;

out:
    tpm_objdata_free(&objdata);
    twist_free(newauthhex);
    twist_free(newwrapped_auth);
    attr_list_free(pubkey_templ_w_types);
    attr_list_free(privkey_templ_w_types);

    if (rv != CKR_OK) {
        /*
         * The key pair the TPM made would otherwise stay: loaded in the TPM (each failure costing
         * the resource manager two of its slots for this connection), and in the store with
         * nothing on the token to reach it.
         */
        if (private_added) {
            token_rm_tobject(tok, new_private_tobj);
        }
        if (public_added) {
            token_rm_tobject(tok, new_public_tobj);
        }
        if (private_stored && object_unstore(tok, new_private_tobj) != CKR_OK) {
            LOGW("Could not remove the private object from the store");
        }
        if (public_stored && object_unstore(tok, new_public_tobj) != CKR_OK) {
            LOGW("Could not remove the public object from the store");
        }
        if (objdata.privhandle) {
            tpm_flushcontext(tok->tctx, objdata.privhandle);
        }
        if (objdata.pubhandle) {
            tpm_flushcontext(tok->tctx, objdata.pubhandle);
        }

        tobject_free(new_private_tobj);
        tobject_free(new_public_tobj);
    }

    return rv;
}

/* The secret keys this token keeps in the TPM: AES, and HMAC (generic secrets and typed HMAC keys). */
static bool is_hmac_key_type(CK_KEY_TYPE type) {

    switch (type) {
    case CKK_GENERIC_SECRET:
    case CKK_SHA_1_HMAC:
    case CKK_SHA256_HMAC:
    case CKK_SHA384_HMAC:
    case CKK_SHA512_HMAC:
        return true;
    default:
        return false;
    }
}

bool key_is_tpm_secret(CK_KEY_TYPE type) {
    return type == CKK_AES || is_hmac_key_type(type);
}

/* What a secret key template asks for, read once whatever the attributes' order. */
typedef struct secret_template secret_template;
struct secret_template {
    CK_KEY_TYPE key_type;     /* what the mechanism or the template says it is */
    bool importing;           /* C_CreateObject, with the key's value */
    CK_ATTRIBUTE_PTR value;   /* CKA_VALUE, when importing */
    CK_ULONG value_len;       /* CKA_VALUE_LEN */
    CK_BBOOL encrypt;
    CK_BBOOL decrypt;
    CK_BBOOL sign;
    CK_BBOOL verify;
    CK_BBOOL wrap;
    CK_BBOOL unwrap;
};

static CK_RV check_false(CK_ATTRIBUTE_PTR attr, const char *why) {

    CK_BBOOL value = CK_FALSE;
    CK_RV rv = attr_CK_BBOOL(attr, &value);
    if (rv == CKR_OK && value) {
        LOGE("%s=true not supported: %s", attr_get_name(attr->type), why);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return rv;
}

static CK_RV secret_template_check(CK_ATTRIBUTE_PTR attr, void *udata) {

    secret_template *t = (secret_template *)udata;
    bool hmac = is_hmac_key_type(t->key_type);
    CK_RV rv = CKR_OK;

    switch (attr->type) {
    case CKA_CLASS: {
        CK_OBJECT_CLASS clazz = 0;
        rv = attr_CK_OBJECT_CLASS(attr, &clazz);
        if (rv == CKR_OK && clazz != CKO_SECRET_KEY) {
            LOGE("Expected a CKO_SECRET_KEY, got CKA_CLASS 0x%lx", clazz);
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
        break;
    }
    case CKA_KEY_TYPE: {
        CK_KEY_TYPE type = 0;
        rv = attr_CK_KEY_TYPE(attr, &type);
        if (rv == CKR_OK && type != t->key_type) {
            LOGE("Expected CKA_KEY_TYPE 0x%lx, got 0x%lx", t->key_type, type);
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
        break;
    }
    case CKA_VALUE_LEN:
        rv = attr_CK_ULONG(attr, &t->value_len);
        break;
    case CKA_VALUE:
        if (!t->importing) {
            LOGE("CKA_VALUE can't be given to C_GenerateKey");
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
        t->value = attr;
        break;
    case CKA_ENCRYPT:
        rv = hmac ? check_false(attr, "an HMAC key doesn't encrypt") : attr_CK_BBOOL(attr, &t->encrypt);
        break;
    case CKA_DECRYPT:
        rv = hmac ? check_false(attr, "an HMAC key doesn't decrypt") : attr_CK_BBOOL(attr, &t->decrypt);
        break;
    case CKA_SIGN:
        rv = hmac ? attr_CK_BBOOL(attr, &t->sign) : check_false(attr, "there is no AES MAC mechanism");
        break;
    case CKA_VERIFY:
        rv = hmac ? attr_CK_BBOOL(attr, &t->verify) : check_false(attr, "there is no AES MAC mechanism");
        break;
    /* an AES key wraps with CKM_AES_CBC_PAD, using the TPM's encrypt and decrypt as CKA_ENCRYPT does */
    case CKA_WRAP:
        rv = hmac ? check_false(attr, "an HMAC key doesn't wrap keys") : attr_CK_BBOOL(attr, &t->wrap);
        break;
    case CKA_UNWRAP:
        rv = hmac ? check_false(attr, "an HMAC key doesn't unwrap keys") : attr_CK_BBOOL(attr, &t->unwrap);
        break;
    /*
     * CKA_DERIVE is kept as given: it permits derivation, and whether the token has a mechanism to
     * derive with is for C_DeriveKey to say.
     */
    case CKA_EXTRACTABLE:
        rv = check_false(attr, "the key never leaves the TPM");
        break;
    case CKA_SENSITIVE: {
        CK_BBOOL value = CK_TRUE;
        rv = attr_CK_BBOOL(attr, &value);
        if (rv == CKR_OK && !value) {
            LOGE("CKA_SENSITIVE=false not supported: the key never leaves the TPM");
            rv = CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
    }
    default:
        break;
    }

    return rv;
}

/* The mechanisms of key_type the token lists, which the key allows. */
static CK_RV secret_allowed_mechanisms(token *tok, CK_KEY_TYPE key_type,
        CK_MECHANISM_TYPE *mechs, CK_ULONG *count) {

    static const CK_MECHANISM_TYPE aes[] = {
        CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CFB128, CKM_AES_ECB, CKM_AES_CTR,
    };
    static const CK_MECHANISM_TYPE hmac[] = {
        CKM_SHA_1_HMAC, CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC,
    };

    const CK_MECHANISM_TYPE *wanted = aes;
    size_t wanted_count = ARRAY_LEN(aes);
    CK_MECHANISM_TYPE one = 0;
    switch (key_type) {
    case CKK_AES:
        break;
    case CKK_GENERIC_SECRET:
        wanted = hmac;
        wanted_count = ARRAY_LEN(hmac);
        break;
    default:
        /* a typed HMAC key has its one mechanism */
        one = key_type == CKK_SHA_1_HMAC ? CKM_SHA_1_HMAC
            : key_type == CKK_SHA256_HMAC ? CKM_SHA256_HMAC
            : key_type == CKK_SHA384_HMAC ? CKM_SHA384_HMAC
            : CKM_SHA512_HMAC;
        wanted = &one;
        wanted_count = 1;
        break;
    }

    CK_MECHANISM_TYPE supported[128];
    CK_ULONG supported_count = ARRAY_LEN(supported);
    CK_RV rv = mech_get_supported(tok->mdtl, supported, &supported_count);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG n = 0;
    for (size_t i = 0; i < wanted_count; i++) {
        for (CK_ULONG j = 0; j < supported_count; j++) {
            if (supported[j] == wanted[i]) {
                mechs[n++] = wanted[i];
                break;
            }
        }
    }

    if (!n) {
        LOGE("The token lists no mechanism for CKA_KEY_TYPE 0x%lx", key_type);
        return CKR_MECHANISM_INVALID;
    }

    *count = n;
    return CKR_OK;
}

/* The attributes a secret key has, besides those its template gave. */
static CK_RV secret_key_attrs(token *tok, const secret_template *t, CK_ULONG value_len,
        attr_list **attrs) {

    CK_MECHANISM_TYPE mechs[8];
    CK_ULONG mech_count = 0;
    CK_RV rv = secret_allowed_mechanisms(tok, t->key_type, mechs, &mech_count);
    if (rv != CKR_OK) {
        return rv;
    }

    attr_list *add = attr_list_new();
    if (!add) {
        return CKR_HOST_MEMORY;
    }

    /* A key the TPM made never had its value outside it; an imported one did. */
    CK_BBOOL local = !t->importing;
    struct { CK_ATTRIBUTE_TYPE type; CK_BBOOL value; } bools[] = {
        { CKA_ENCRYPT, t->encrypt },
        { CKA_DECRYPT, t->decrypt },
        { CKA_SIGN, t->sign },
        { CKA_VERIFY, t->verify },
        { CKA_WRAP, t->wrap },
        { CKA_UNWRAP, t->unwrap },
        { CKA_DERIVE, CK_FALSE },
        { CKA_SENSITIVE, CK_TRUE },
        { CKA_EXTRACTABLE, CK_FALSE },
        { CKA_ALWAYS_SENSITIVE, local },
        { CKA_NEVER_EXTRACTABLE, local },
        { CKA_LOCAL, local },
        { CKA_PRIVATE, CK_TRUE },
        { CKA_TRUSTED, CK_FALSE },
        { CKA_WRAP_WITH_TRUSTED, CK_FALSE },
    };

    bool r = true;
    for (size_t i = 0; r && i < ARRAY_LEN(bools); i++) {
        if (!attr_get_attribute_by_type(*attrs, bools[i].type)) {
            r = attr_list_add_bool(add, bools[i].type, bools[i].value);
        }
    }

    if (r && !attr_get_attribute_by_type(*attrs, CKA_CLASS)) {
        r = attr_list_add_int(add, CKA_CLASS, CKO_SECRET_KEY);
    }
    if (r && !attr_get_attribute_by_type(*attrs, CKA_KEY_TYPE)) {
        r = attr_list_add_int(add, CKA_KEY_TYPE, t->key_type);
    }
    if (r && !attr_get_attribute_by_type(*attrs, CKA_VALUE_LEN)) {
        r = attr_list_add_int(add, CKA_VALUE_LEN, value_len);
    }
    if (r && !attr_get_attribute_by_type(*attrs, CKA_KEY_GEN_MECHANISM)) {
        r = attr_list_add_int(add, CKA_KEY_GEN_MECHANISM,
                t->importing ? CK_UNAVAILABLE_INFORMATION : CKM_AES_KEY_GEN);
    }
    if (r && !attr_get_attribute_by_type(*attrs, CKA_ALLOWED_MECHANISMS)) {
        r = attr_list_add_int_seq(add, CKA_ALLOWED_MECHANISMS, (CK_BYTE_PTR)mechs,
                mech_count * sizeof(mechs[0]));
    }
    if (r && !attr_get_attribute_by_type(*attrs, CKA_ID)) {
        r = attr_list_add_buf(add, CKA_ID, NULL, 0);
    }
    if (r && !attr_get_attribute_by_type(*attrs, CKA_START_DATE)) {
        r = attr_list_add_buf(add, CKA_START_DATE, NULL, 0);
    }
    if (r && !attr_get_attribute_by_type(*attrs, CKA_END_DATE)) {
        r = attr_list_add_buf(add, CKA_END_DATE, NULL, 0);
    }
    if (!r) {
        attr_list_free(add);
        return CKR_HOST_MEMORY;
    }

    *attrs = attr_list_append_attrs(*attrs, &add);
    if (!*attrs) {
        return CKR_HOST_MEMORY;
    }

    return attr_common_add_storage(attrs);
}

/* Reads the template of a secret key made in the TPM into t, refusing what the key can't be */
static CK_RV secret_template_read(CK_KEY_TYPE key_type, bool importing,
        CK_ATTRIBUTE_PTR template, CK_ULONG attribute_count, secret_template *t) {

    bool hmac = is_hmac_key_type(key_type);
    *t = (secret_template) {
        .key_type = key_type,
        .importing = importing,
        .encrypt = hmac ? CK_FALSE : CK_TRUE,
        .decrypt = hmac ? CK_FALSE : CK_TRUE,
        .sign = hmac ? CK_TRUE : CK_FALSE,
        .verify = hmac ? CK_TRUE : CK_FALSE,
    };
    static const attr_handler handlers[] = {
        { CKA_CLASS, secret_template_check },
        { CKA_KEY_TYPE, secret_template_check },
        { CKA_VALUE_LEN, secret_template_check },
        { CKA_VALUE, secret_template_check },
        { CKA_ENCRYPT, secret_template_check },
        { CKA_DECRYPT, secret_template_check },
        { CKA_SIGN, secret_template_check },
        { CKA_VERIFY, secret_template_check },
        { CKA_WRAP, secret_template_check },
        { CKA_UNWRAP, secret_template_check },
        { CKA_EXTRACTABLE, secret_template_check },
        { CKA_SENSITIVE, secret_template_check },
    };
    return attr_list_raw_invoke_handlers(template, attribute_count,
            handlers, ARRAY_LEN(handlers), t);
}

CK_RV key_check_secret_template(CK_KEY_TYPE key_type, CK_ATTRIBUTE_PTR templ, CK_ULONG count) {

    secret_template t;
    return secret_template_read(key_type, true, templ, count, &t);
}

/*
 * Makes a secret key in the TPM, under the token's primary key: an AES key the TPM generates
 * (C_GenerateKey), or an AES or HMAC key holding the template's CKA_VALUE (C_CreateObject). Its value
 * is never kept outside the TPM.
 */
static CK_RV secret_key_create(session_ctx *ctx, CK_KEY_TYPE key_type, bool importing,
        CK_ATTRIBUTE_PTR template, CK_ULONG attribute_count, CK_OBJECT_HANDLE_PTR key) {

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    CK_RV rv = attr_refuse_token_set(template, attribute_count, importing);
    if (rv != CKR_OK) {
        return rv;
    }

    bool hmac = is_hmac_key_type(key_type);
    secret_template t;
    rv = secret_template_read(key_type, importing, template, attribute_count, &t);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG value_len = 0;
    if (importing) {
        if (!t.value) {
            LOGE("Importing a secret key needs its CKA_VALUE");
            return CKR_TEMPLATE_INCOMPLETE;
        }
        if (!t.value->pValue || !t.value->ulValueLen) {
            LOGE("Importing a secret key needs a CKA_VALUE that isn't empty");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        value_len = t.value->ulValueLen;
        if (t.value_len && t.value_len != value_len) {
            LOGE("CKA_VALUE_LEN %lu contradicts the %lu-byte CKA_VALUE", t.value_len, value_len);
            return CKR_TEMPLATE_INCONSISTENT;
        }
    } else {
        if (!t.value_len) {
            LOGE("CKM_AES_KEY_GEN needs CKA_VALUE_LEN");
            return CKR_TEMPLATE_INCOMPLETE;
        }
        value_len = t.value_len;
    }

    if (key_type == CKK_AES) {
        CK_ULONG min = 0, max = 0;
        rv = tpm_find_aes_keysizes(tok->tctx, &min, &max);
        if (rv != CKR_OK) {
            return rv;
        }
        if ((value_len != 16 && value_len != 24 && value_len != 32)
                || value_len < min || value_len > max) {
            LOGE("AES keys are 16, 24 or 32 bytes, up to %lu here; got %lu", max, value_len);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    twist newauthhex = NULL;
    twist newwrapped_auth = NULL;
    attr_list *attrs = NULL;
    tobject *tobj = NULL;
    tpm_object_data objdata = { 0 };
    bool stored = false;

    /* The key's value is the TPM's to keep: it isn't one of the object's attributes. */
    CK_ATTRIBUTE *kept = calloc(attribute_count ? attribute_count : 1, sizeof(*kept));
    if (!kept) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }
    CK_ULONG kept_count = 0;
    for (CK_ULONG i = 0; i < attribute_count; i++) {
        if (template[i].type != CKA_VALUE) {
            kept[kept_count++] = template[i];
        }
    }

    bool typified = attr_typify(kept, kept_count, &attrs);
    free(kept);
    if (!typified) {
        LOGE("Failed typifying the template");
        rv = CKR_GENERAL_ERROR;
        goto out;
    }

    rv = secret_key_attrs(tok, &t, value_len, &attrs);
    if (rv != CKR_OK) {
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

    if (hmac) {
        rv = tpm2_import_hmac_key(tok->tctx, tok->pobject.handle, tok->pobject.objauth, newauthhex,
                t.value->pValue, value_len, &objdata);
    } else {
        /*
         * Wrapping encrypts and unwrapping decrypts in the TPM, as CKA_ENCRYPT and CKA_DECRYPT ask;
         * C_EncryptInit and C_DecryptInit still go by those. The TPM refuses an AES key it can
         * neither encrypt nor decrypt with, which PKCS#11 allows: such a key gets the TPM's decrypt
         * attribute, and C_DecryptInit refuses it for its CKA_DECRYPT=false.
         */
        bool tpm_encrypt = t.encrypt || t.wrap;
        bool tpm_decrypt = t.decrypt || t.unwrap || !tpm_encrypt;
        rv = importing
            ? tpm2_import_aes_key(tok->tctx, tok->pobject.handle, tok->pobject.objauth, newauthhex,
                    t.value->pValue, value_len, tpm_encrypt, tpm_decrypt, &objdata)
            : tpm2_generate_aes_key(tok->tctx, tok->pobject.handle, tok->pobject.objauth, newauthhex,
                    value_len * 8, tpm_encrypt, tpm_decrypt, &objdata);
    }
    if (rv != CKR_OK) {
        LOGE("Failed to make the secret key in the TPM");
        goto out;
    }

    tobj = tobject_new();
    if (!tobj) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    tobject_set_esys_tr(tobj, objdata.privhandle);
    tobj->attrs = attrs;
    attrs = NULL;

    rv = tobject_set_blob_data(tobj, objdata.pubblob, objdata.privblob);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = tobject_set_auth(tobj, newauthhex, newwrapped_auth);
    if (rv != CKR_OK) {
        goto out;
    }

    /* to the db, unless it's a session object */
    rv = object_store(tok, ctx, tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add the key to the db");
        goto out;
    }
    stored = true;

    rv = token_add_tobject(tok, tobj);
    if (rv != CKR_OK) {
        LOGE("Failed to add the key to the token");
        goto out;
    }

    *key = tobj->obj_handle;

out:
    if (rv != CKR_OK) {
        if (stored && object_unstore(tok, tobj) != CKR_OK) {
            LOGW("Could not remove the key from the store");
        }
        if (objdata.privhandle) {
            tpm_flushcontext(tok->tctx, objdata.privhandle);
        }
        tobject_free(tobj);
    }

    tpm_objdata_free(&objdata);
    attr_list_free(attrs);
    twist_free(newauthhex);
    twist_free(newwrapped_auth);

    return rv;
}

CK_RV key_gen_secret(
        session_ctx *ctx,

        CK_MECHANISM_PTR mechanism,

        CK_ATTRIBUTE_PTR template,
        CK_ULONG attribute_count,

        CK_OBJECT_HANDLE_PTR key) {

    check_pointer(mechanism);
    check_pointer(key);
    if (attribute_count) {
        check_pointer(template);
    }

    if (mechanism->mechanism != CKM_AES_KEY_GEN) {
        LOGE("C_GenerateKey supports only CKM_AES_KEY_GEN, got 0x%lx", mechanism->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (mechanism->pParameter || mechanism->ulParameterLen) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return secret_key_create(ctx, CKK_AES, false, template, attribute_count, key);
}

CK_RV key_import_secret(session_ctx *ctx, CK_KEY_TYPE key_type,
        CK_ATTRIBUTE_PTR template, CK_ULONG attribute_count, CK_OBJECT_HANDLE_PTR key) {

    check_pointer(key);
    check_pointer(template);

    return secret_key_create(ctx, key_type, true, template, attribute_count, key);
}
