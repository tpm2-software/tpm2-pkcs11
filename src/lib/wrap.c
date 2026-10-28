/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "attrs.h"
#include "checks.h"
#include "encrypt.h"
#include "key.h"
#include "log.h"
#include "mech.h"
#include "object.h"
#include "session_ctx.h"
#include "token.h"
#include "twist.h"
#include "utils.h"
#include "wrap.h"

#define AES_BLOCK 16

CK_BBOOL key_attr_bool(attr_list *attrs, CK_ATTRIBUTE_TYPE type) {

    CK_BBOOL value = CK_FALSE;
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, type);
    if (!a || attr_CK_BBOOL(a, &value) != CKR_OK) {
        return CK_FALSE;
    }

    return value;
}

/* The key type a wrapping mechanism takes. */
static CK_KEY_TYPE mech_key_type(CK_MECHANISM_TYPE type) {

    switch (type) {
    case CKM_RSA_PKCS_OAEP:
    case CKM_RSA_PKCS:
    case CKM_RSA_X_509:
        return CKK_RSA;
    case CKM_AES_CBC_PAD:
        return CKK_AES;
    default:
        return CKK_VENDOR_DEFINED;
    }
}

bool key_has_template(attr_list *attrs, CK_ATTRIBUTE_TYPE type) {

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, type);
    return a && a->ulValueLen;
}

/*
 * Checks the key that wraps (C_WrapKey: an RSA public key or an AES key) or unwraps (an RSA private key
 * or an AES key) suits the mechanism, has usage true, and takes the mechanism's parameter.
 */
static CK_RV check_wrapping_key(token *tok, CK_MECHANISM_PTR mech, tobject *tobj, bool unwrap,
        CK_ATTRIBUTE_TYPE usage) {

    CK_KEY_TYPE want_type = mech_key_type(mech->mechanism);
    CK_OBJECT_CLASS want_class = want_type == CKK_AES ? CKO_SECRET_KEY
            : unwrap ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;

    CK_OBJECT_CLASS clazz = attr_list_get_CKA_CLASS(tobj->attrs, CK_OBJECT_CLASS_BAD);
    CK_KEY_TYPE key_type = attr_list_get_CKA_KEY_TYPE(tobj->attrs, CKA_KEY_TYPE_BAD);
    if (want_type == CKK_VENDOR_DEFINED || clazz != want_class || key_type != want_type) {
        LOGE("Mechanism 0x%lx doesn't %s with a key of class 0x%lx and type 0x%lx",
                mech->mechanism, unwrap ? "unwrap" : "wrap", clazz, key_type);
        return unwrap ? CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT : CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
    }

    if (!key_attr_bool(tobj->attrs, usage)) {
        LOGE("The key doesn't allow %s (%s isn't true)", unwrap ? "unwrapping" : "wrapping",
                attr_get_name(usage));
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    /*
     * PKCS#11 4.10: a CKA_ALWAYS_AUTHENTICATE key is used only after a context-specific login, made
     * after a C_*Init. C_WrapKey and C_UnwrapKey have none, so it can't be authenticated for them.
     */
    if (key_attr_bool(tobj->attrs, CKA_ALWAYS_AUTHENTICATE)) {
        LOGE("A CKA_ALWAYS_AUTHENTICATE key can't be authenticated to %s", unwrap ? "unwrap" : "wrap");
        return CKR_USER_NOT_LOGGED_IN;
    }

    CK_RV rv = object_mech_is_supported(tobj, mech);
    if (rv != CKR_OK) {
        LOGE("The key doesn't allow mechanism 0x%lx", mech->mechanism);
        return rv;
    }

    if (want_type == CKK_AES) {
        if (!mech->pParameter || mech->ulParameterLen != AES_BLOCK) {
            LOGE("CKM_AES_CBC_PAD needs a %u-byte IV, got %lu bytes", AES_BLOCK, mech->ulParameterLen);
            return CKR_MECHANISM_PARAM_INVALID;
        }
        return CKR_OK;
    }

    /* the RSA mechanisms' parameters */
    return mech_validate(tok->mdtl, mech, tobj->attrs);
}

/* The RSA key's modulus length, k */
static CK_RV modulus_len(tobject *tobj, CK_ULONG *k) {

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_MODULUS);
    if (!a || !a->ulValueLen) {
        LOGE("Expected the RSA key to have CKA_MODULUS");
        return CKR_GENERAL_ERROR;
    }

    *k = a->ulValueLen;
    return CKR_OK;
}

/*
 * How long a wrapped value_len-byte key is, without the TPM: k for OAEP, which takes up to
 * k - 2 hLen - 2 bytes (RFC 8017 7.1.1); the next whole block for CBC with PKCS#7 padding.
 */
static CK_RV wrapped_size(CK_MECHANISM_PTR mech, tobject *wrapping, CK_ULONG value_len,
        CK_ULONG *size) {

    if (mech->mechanism == CKM_AES_CBC_PAD) {
        *size = (value_len / AES_BLOCK + 1) * AES_BLOCK;
        return CKR_OK;
    }

    assert(mech->mechanism == CKM_RSA_PKCS_OAEP);

    CK_ULONG k = 0;
    CK_RV rv = modulus_len(wrapping, &k);
    if (rv != CKR_OK) {
        return rv;
    }

    /* checked by mech_validate() */
    CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)mech->pParameter;
    CK_ULONG hlen = utils_get_halg_size(params->hashAlg);
    if (!hlen || k < 2 * hlen + 2 || value_len > k - 2 * hlen - 2) {
        LOGE("A %lu-byte key doesn't fit an OAEP message for a %lu-byte modulus", value_len, k);
        return CKR_KEY_SIZE_RANGE;
    }

    *size = k;
    return CKR_OK;
}

CK_RV key_wrap(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped, CK_ULONG_PTR wrapped_len) {

    assert(ctx);
    check_pointer(mech);
    check_pointer(wrapped_len);

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    bool is_wrap = false;
    CK_RV rv = mech_is_wrap(tok->mdtl, mech->mechanism, false, &is_wrap);
    if (rv != CKR_OK) {
        return rv;
    }
    if (!is_wrap) {
        LOGE("Mechanism 0x%lx doesn't wrap keys", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    /* found, not loaded: nothing here needs the TPM until the key is encrypted */
    tobject *wrapping = NULL;
    rv = token_find_tobject(tok, wrapping_key, &wrapping);
    if (rv != CKR_OK) {
        return CKR_WRAPPING_KEY_HANDLE_INVALID;
    }

    rv = check_wrapping_key(tok, mech, wrapping, false, CKA_WRAP);
    if (rv != CKR_OK) {
        return rv;
    }

    /* PKCS#11 5.18.3: the key must match the template, else CKR_KEY_HANDLE_INVALID */
    if (key_has_template(wrapping->attrs, CKA_WRAP_TEMPLATE)) {
        LOGE("The wrapping key has a CKA_WRAP_TEMPLATE, which isn't supported");
        return CKR_KEY_HANDLE_INVALID;
    }

    tobject *tobj = NULL;
    rv = token_find_tobject(tok, key, &tobj);
    if (rv != CKR_OK) {
        return CKR_KEY_HANDLE_INVALID;
    }

    /*
     * A private key, extractable or not, is in the TPM: it isn't exported (TPM2_Duplicate isn't used).
     * A public key isn't a secret to wrap.
     */
    CK_OBJECT_CLASS clazz = attr_list_get_CKA_CLASS(tobj->attrs, CK_OBJECT_CLASS_BAD);
    if (clazz == CKO_PRIVATE_KEY || clazz == CKO_PUBLIC_KEY) {
        LOGE("A %s key can't be wrapped", clazz == CKO_PRIVATE_KEY ? "private" : "public");
        return CKR_KEY_NOT_WRAPPABLE;
    }
    if (clazz != CKO_SECRET_KEY) {
        LOGE("Only a secret key can be wrapped, got class 0x%lx", clazz);
        return CKR_KEY_HANDLE_INVALID;
    }

    /* CKA_EXTRACTABLE alone decides: a sensitive key may be wrapped, that's what wrapping is for */
    if (!key_attr_bool(tobj->attrs, CKA_EXTRACTABLE)) {
        LOGE("The key isn't extractable");
        return CKR_KEY_UNEXTRACTABLE;
    }

    /*
     * Only the SO may make a key trusted, and no template here can (attr_refuse_trusted()); a store made
     * before may hold a key a user made CKA_TRUSTED=true, so a wrapping key's CKA_TRUSTED isn't believed.
     */
    if (key_attr_bool(tobj->attrs, CKA_WRAP_WITH_TRUSTED)) {
        LOGE("The key is only wrapped with a trusted key, and the token has none");
        return CKR_KEY_NOT_WRAPPABLE;
    }

    twist value = NULL;
    rv = object_get_host_value(tok, tobj, &value);
    if (rv == CKR_KEY_HANDLE_INVALID) {
        /* in the TPM, or no value kept on the host */
        LOGE("The key's value isn't held outside the TPM");
        return CKR_KEY_UNEXTRACTABLE;
    }
    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG value_len = twist_len(value);
    encrypt_op_data *opdata = NULL;
    CK_ULONG size = 0;
    CK_ULONG out_len = 0;
    CK_RV tmp_rv = CKR_OK;
    rv = wrapped_size(mech, wrapping, value_len, &size);
    if (rv != CKR_OK) {
        goto out;
    }

    /* PKCS#11 5.2: the length, and nothing more */
    if (!wrapped) {
        *wrapped_len = size;
        goto out;
    }

    if (*wrapped_len < size) {
        *wrapped_len = size;
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    /* the operation data is the caller's, so no session operation is started */
    opdata = encrypt_op_data_new();
    if (!opdata) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    rv = encrypt_init_op(ctx, opdata, mech, wrapping_key);
    if (rv != CKR_OK) {
        encrypt_op_data_free(&opdata);
        goto out;
    }

    out_len = *wrapped_len;
    rv = encrypt_oneshot_op(ctx, opdata, (CK_BYTE_PTR)value, value_len, wrapped, &out_len);
    encrypt_op_data_free(&opdata);

    /* encrypt_init_op() loaded the wrapping key, which its caller releases */
    tmp_rv = tobject_user_decrement(wrapping);
    if (rv == CKR_OK) {
        rv = tmp_rv;
    }

    if (rv == CKR_OK) {
        *wrapped_len = out_len;
    }

out:
    OPENSSL_cleanse((void *)value, value_len);
    twist_free(value);

    return rv;
}

CK_RV key_check_new_template(CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_KEY_TYPE *key_type,
        CK_BBOOL *extractable, bool *has_extractable) {

    /*
     * What only the token sets: CKA_UNIQUE_ID, CKA_ALWAYS_SENSITIVE, ..., and CKA_TRUSTED=true, which only
     * the SO may set; CKA_LOCAL may be false.
     */
    CK_RV rv = attr_refuse_token_set(templ, count, true);
    if (rv != CKR_OK) {
        return rv;
    }

    /* the value is the one recovered */
    if (attr_get_attribute_by_type_raw(templ, count, CKA_VALUE)) {
        LOGE("The new key's template can't have CKA_VALUE");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type_raw(templ, count, CKA_CLASS);
    if (!a) {
        LOGE("The new key's template needs CKA_CLASS");
        return CKR_TEMPLATE_INCOMPLETE;
    }
    CK_OBJECT_CLASS clazz = CK_OBJECT_CLASS_BAD;
    rv = attr_CK_OBJECT_CLASS(a, &clazz);
    if (rv != CKR_OK) {
        return rv;
    }
    if (clazz != CKO_SECRET_KEY) {
        LOGE("Only a secret key can be made this way, got class 0x%lx", clazz);
        return CKR_TEMPLATE_INCONSISTENT;
    }

    a = attr_get_attribute_by_type_raw(templ, count, CKA_KEY_TYPE);
    if (!a) {
        LOGE("The new key's template needs CKA_KEY_TYPE");
        return CKR_TEMPLATE_INCOMPLETE;
    }
    rv = attr_CK_KEY_TYPE(a, key_type);
    if (rv != CKR_OK) {
        return rv;
    }
    if (!key_is_tpm_secret(*key_type)) {
        LOGE("Only AES, HMAC and generic secret keys are made, got CKA_KEY_TYPE 0x%lx", *key_type);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    /*
     * The extractable-default rule. PKCS#11 has CKA_EXTRACTABLE default to true, but an AES or HMAC key
     * goes into the TPM, where it can't be: there it defaults to false, and true is refused. A generic
     * secret has the spec's default, and stays a plain object holding its value.
     */
    *extractable = *key_type == CKK_GENERIC_SECRET;
    a = attr_get_attribute_by_type_raw(templ, count, CKA_EXTRACTABLE);
    *has_extractable = a != NULL;
    if (a) {
        rv = attr_CK_BBOOL(a, extractable);
        if (rv != CKR_OK) {
            return rv;
        }
        if (*extractable && *key_type != CKK_GENERIC_SECRET) {
            LOGE("An AES or HMAC key is kept in the TPM, it can't be extractable");
            return CKR_TEMPLATE_INCONSISTENT;
        }
    }

    /*
     * What making the key would refuse in the template, so it is refused now, before a value is
     * recovered: after, any refusal is one code (see key_unwrap_as()).
     */
    /* where key_create_from_value() puts it: a generic secret readable by default stays on the host */
    bool in_tpm = object_secret_in_tpm(*key_type, templ, count)
            && !(*key_type == CKK_GENERIC_SECRET && *extractable);
    if (in_tpm) {
        return key_check_secret_template(*key_type, templ, count);
    }

    /*
     * A public object's value is kept in plain text in the store: a sensitive or unextractable one
     * isn't made public, as C_CopyObject has it.
     */
    CK_BBOOL is_private = CK_TRUE, sensitive = CK_FALSE;
    a = attr_get_attribute_by_type_raw(templ, count, CKA_PRIVATE);
    if (a && attr_CK_BBOOL(a, &is_private) != CKR_OK) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    a = attr_get_attribute_by_type_raw(templ, count, CKA_SENSITIVE);
    if (a && attr_CK_BBOOL(a, &sensitive) != CKR_OK) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (!is_private && (sensitive || !*extractable)) {
        LOGE("A sensitive or unextractable key held on the host can't be public");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    return CKR_OK;
}

/*
 * The key's value must be the length its template says (CKA_VALUE_LEN) and an AES key's must be. A
 * value that isn't is refused as one that didn't decrypt, CKR_WRAPPED_KEY_INVALID: telling the two apart
 * would tell whether the padding was good, a padding oracle on the ciphertext (Vaudenay for CBC).
 */
static CK_RV check_value_len(CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_ULONG value_len) {

    if (!value_len) {
        LOGE("The wrapped key is empty");
        return CKR_WRAPPED_KEY_INVALID;
    }

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type_raw(templ, count, CKA_VALUE_LEN);
    if (a) {
        CK_ULONG want = 0;
        CK_RV rv = attr_CK_ULONG(a, &want);
        if (rv != CKR_OK) {
            return rv;
        }
        if (want != value_len) {
            LOGE("CKA_VALUE_LEN is %lu, the unwrapped key %lu bytes", want, value_len);
            return CKR_WRAPPED_KEY_INVALID;
        }
    }

    a = attr_get_attribute_by_type_raw(templ, count, CKA_KEY_TYPE);
    CK_KEY_TYPE key_type = CKA_KEY_TYPE_BAD;
    if (a && attr_CK_KEY_TYPE(a, &key_type) == CKR_OK && key_type == CKK_AES
            && value_len != 16 && value_len != 24 && value_len != 32) {
        LOGE("An AES key is 16, 24 or 32 bytes, the unwrapped key %lu", value_len);
        return CKR_WRAPPED_KEY_INVALID;
    }

    return CKR_OK;
}

CK_RV key_unwrap_as(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE unwrapping_key,
        CK_ATTRIBUTE_TYPE usage, CK_BYTE_PTR wrapped, CK_ULONG wrapped_len, CK_ATTRIBUTE_PTR templ,
        CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {

    assert(ctx);
    check_pointer(mech);
    check_pointer(key);
    if (wrapped_len) {
        check_pointer(wrapped);
    }
    if (count) {
        check_pointer(templ);
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tobject *unwrapping = NULL;
    CK_RV rv = token_find_tobject(tok, unwrapping_key, &unwrapping);
    if (rv != CKR_OK) {
        return CKR_UNWRAPPING_KEY_HANDLE_INVALID;
    }

    rv = check_wrapping_key(tok, mech, unwrapping, true, usage);
    if (rv != CKR_OK) {
        return rv;
    }

    /* PKCS#11 5.18.4: the template's attributes are added; refused, as matching isn't supported */
    CK_ATTRIBUTE_TYPE templ_attr = usage == CKA_DECAPSULATE ? CKA_DECAPSULATE_TEMPLATE
            : CKA_UNWRAP_TEMPLATE;
    if (key_has_template(unwrapping->attrs, templ_attr)) {
        LOGE("The unwrapping key has a %s, which isn't supported", attr_get_name(templ_attr));
        return CKR_TEMPLATE_INCONSISTENT;
    }

    /*
     * What the template asks for, before the TPM decrypts anything. The session's state, which
     * object_create() also checks, was checked on entry (C_UnwrapKey and C_DecapsulateKey need a R/W
     * user session), so nothing that fails after the decrypt depends on it.
     */
    CK_KEY_TYPE key_type = CKA_KEY_TYPE_BAD;
    CK_BBOOL extractable = CK_FALSE;
    bool has_extractable = false;
    rv = key_check_new_template(templ, count, &key_type, &extractable, &has_extractable);
    if (rv != CKR_OK) {
        return rv;
    }

    /* The ciphertext's length, before the TPM is asked: the modulus', or whole blocks for CBC */
    CK_ULONG plain_size = wrapped_len;
    if (mech_key_type(mech->mechanism) == CKK_RSA) {
        rv = modulus_len(unwrapping, &plain_size);
        if (rv != CKR_OK) {
            return rv;
        }
        if (wrapped_len != plain_size) {
            LOGE("The wrapped key is %lu bytes, the modulus %lu", wrapped_len, plain_size);
            return CKR_WRAPPED_KEY_LEN_RANGE;
        }
    } else if (!wrapped_len || wrapped_len % AES_BLOCK) {
        LOGE("The wrapped key is %lu bytes, not whole blocks", wrapped_len);
        return CKR_WRAPPED_KEY_LEN_RANGE;
    }

    CK_BYTE_PTR plain = calloc(1, plain_size);
    if (!plain) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }
    CK_ULONG plain_len = plain_size;

    /* the operation data is the caller's, so no session operation is started */
    encrypt_op_data *opdata = encrypt_op_data_new();
    if (!opdata) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    rv = decrypt_init_op(ctx, opdata, mech, unwrapping_key);
    if (rv != CKR_OK) {
        encrypt_op_data_free(&opdata);
        goto out;
    }

    rv = decrypt_oneshot_op(ctx, opdata, wrapped, wrapped_len, plain, &plain_len);
    encrypt_op_data_free(&opdata);

    /* decrypt_init_op() loaded the unwrapping key, which its caller releases */
    CK_RV tmp_rv = tobject_user_decrement(unwrapping);
    if (rv != CKR_OK) {
        /*
         * Whatever the failure, one code: the ciphertext's length was checked above, from what the
         * caller gave, so any other difference would come from the plaintext (a padding oracle).
         */
        LOGE("The wrapped key doesn't decrypt");
        rv = CKR_WRAPPED_KEY_INVALID;
        goto out;
    }
    if (tmp_rv != CKR_OK) {
        rv = tmp_rv;
        goto out;
    }

    rv = check_value_len(templ, count, plain_len);
    if (rv != CKR_OK) {
        goto out;
    }

    /* the template was checked before the decrypt: what fails now depends on the value, one code */
    rv = key_create_from_value(ctx, templ, count, plain, plain_len, key);
    if (rv != CKR_OK && rv != CKR_HOST_MEMORY) {
        LOGE("The unwrapped key can't be made");
        rv = CKR_WRAPPED_KEY_INVALID;
    }

out:
    OPENSSL_cleanse(plain, plain_size);
    free(plain);

    return rv;
}

CK_RV key_unwrap(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE unwrapping_key,
        CK_BYTE_PTR wrapped, CK_ULONG wrapped_len, CK_ATTRIBUTE_PTR templ, CK_ULONG count,
        CK_OBJECT_HANDLE_PTR key) {

    assert(ctx);
    check_pointer(mech);

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    bool is_unwrap = false;
    CK_RV rv = mech_is_wrap(tok->mdtl, mech->mechanism, true, &is_unwrap);
    if (rv != CKR_OK) {
        return rv;
    }
    if (!is_unwrap) {
        LOGE("Mechanism 0x%lx doesn't unwrap keys", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    return key_unwrap_as(ctx, mech, unwrapping_key, CKA_UNWRAP, wrapped, wrapped_len,
            templ, count, key);
}

CK_RV key_create_from_value(session_ctx *ctx, CK_ATTRIBUTE_PTR templ, CK_ULONG count,
        const CK_BYTE *value, CK_ULONG value_len, CK_OBJECT_HANDLE_PTR key) {

    assert(ctx);
    check_pointer(value);
    check_pointer(key);
    if (count) {
        check_pointer(templ);
    }

    CK_KEY_TYPE key_type = CKA_KEY_TYPE_BAD;
    CK_BBOOL extractable = CK_FALSE;
    bool has_extractable = false;
    CK_RV rv = key_check_new_template(templ, count, &key_type, &extractable, &has_extractable);
    if (rv != CKR_OK) {
        return rv;
    }

    /* the template, what it lacks, and the value */
    CK_ATTRIBUTE *full = calloc(count + 5, sizeof(*full));
    if (!full) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }
    if (count) {
        memcpy(full, templ, count * sizeof(*full));
    }
    CK_ULONG n = count;

    CK_BBOOL ck_false = CK_FALSE;
    if (!has_extractable) {
        full[n++] = (CK_ATTRIBUTE) { CKA_EXTRACTABLE, &extractable, sizeof(extractable) };
    }

    /* a key in the TPM gets these from key_import_secret(); a plain object from here */
    if (!object_secret_in_tpm(key_type, full, n)) {
        /* key_check_new_template() refused a public one that is sensitive or unextractable */
        if (!attr_get_attribute_by_type_raw(templ, count, CKA_LOCAL)) {
            full[n++] = (CK_ATTRIBUTE) { CKA_LOCAL, &ck_false, sizeof(ck_false) };
        }
        full[n++] = (CK_ATTRIBUTE) { CKA_ALWAYS_SENSITIVE, &ck_false, sizeof(ck_false) };
        full[n++] = (CK_ATTRIBUTE) { CKA_NEVER_EXTRACTABLE, &ck_false, sizeof(ck_false) };
    }

    full[n++] = (CK_ATTRIBUTE) { CKA_VALUE, (CK_BYTE_PTR)value, value_len };
    assert(n <= count + 5);

    rv = object_create(ctx, full, n, key);

    OPENSSL_cleanse(full, (count + 5) * sizeof(*full));
    free(full);

    return rv;
}

CK_RV key_wrap_authenticated(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key, CK_BYTE_PTR associated_data, CK_ULONG associated_data_len,
        CK_BYTE_PTR wrapped, CK_ULONG_PTR wrapped_len) {

    UNUSED(ctx);
    UNUSED(wrapping_key);
    UNUSED(key);
    UNUSED(associated_data);
    UNUSED(associated_data_len);
    UNUSED(wrapped);
    check_pointer(mech);
    check_pointer(wrapped_len);

    LOGV("Mechanism 0x%lx doesn't wrap keys with associated data", mech->mechanism);
    return CKR_MECHANISM_INVALID;
}

CK_RV key_unwrap_authenticated(session_ctx *ctx, CK_MECHANISM_PTR mech,
        CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped, CK_ULONG wrapped_len,
        CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_BYTE_PTR associated_data,
        CK_ULONG associated_data_len, CK_OBJECT_HANDLE_PTR key) {

    UNUSED(ctx);
    UNUSED(unwrapping_key);
    UNUSED(wrapped);
    UNUSED(wrapped_len);
    UNUSED(templ);
    UNUSED(count);
    UNUSED(associated_data);
    UNUSED(associated_data_len);
    check_pointer(mech);
    check_pointer(key);

    LOGV("Mechanism 0x%lx doesn't unwrap keys with associated data", mech->mechanism);
    return CKR_MECHANISM_INVALID;
}
