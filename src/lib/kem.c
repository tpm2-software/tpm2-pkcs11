/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "attrs.h"
#include "checks.h"
#include "derive.h"
#include "encrypt.h"
#include "kem.h"
#include "log.h"
#include "mech.h"
#include "object.h"
#include "random.h"
#include "session_ctx.h"
#include "ssl_util.h"
#include "token.h"
#include "tpm.h"
#include "twist.h"
#include "utils.h"
#include "wrap.h"

/*
 * CKM_RSA_X_509 isn't one: PKCS#11 6.1.12 has it encapsulate "according to RSASVE defined in
 * [FIPS SP 800-56B]", whose secret is a k-byte integer, but says nothing of how that becomes the new
 * key's CKA_VALUE (SP 800-56B derives keys from it with a KDF it leaves to the scheme). Nor is
 * CKM_RSA_PKCS (6.1.6), which the spec allows: decapsulating with PKCS#1 v1.5 would make
 * C_DecapsulateKey a padding oracle (Bleichenbacher), whose success alone tells a conforming
 * ciphertext. CKM_RSA_PKCS_OAEP does what it would.
 */
static CK_RV check_kem_mech(token *tok, CK_MECHANISM_PTR mech, bool decapsulate) {

    bool is_kem = false;
    CK_RV rv = mech_is_kem(tok->mdtl, mech->mechanism, decapsulate, &is_kem);
    if (rv != CKR_OK) {
        return rv;
    }
    if (!is_kem) {
        LOGE("Mechanism 0x%lx doesn't %s keys", mech->mechanism,
                decapsulate ? "decapsulate" : "encapsulate");
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/* PKCS#11 6.3.17: in C_EncapsulateKey and C_DecapsulateKey, pPublicData is NULL and ulPublicDataLen 0 */
static CK_RV check_ecdh_params(CK_MECHANISM_PTR mech) {

    CK_ECDH1_DERIVE_PARAMS_PTR params = NULL;
    CK_RV rv = ecdh1_params_get(mech, &params);
    if (rv != CKR_OK) {
        return rv;
    }

    if (params->pPublicData || params->ulPublicDataLen) {
        LOGE("Key encapsulation with ECDH takes no public data");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return CKR_OK;
}

static bool is_aes_len(CK_ULONG len) {
    return len == 16 || len == 24 || len == 32;
}

/*
 * The new key's value length, from the template before the TPM is asked for anything: CKA_VALUE_LEN, or
 * the whole of the secret_len-byte secret the mechanism makes when the template has none and the
 * mechanism allows it (needs_len false). A CKA_VALUE_LEN over secret_len gives too_long.
 */
static CK_RV new_value_len(CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_KEY_TYPE key_type,
        CK_ULONG secret_len, bool needs_len, CK_RV too_long, CK_ULONG *value_len) {

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type_raw(templ, count, CKA_VALUE_LEN);
    if (!a) {
        if (needs_len || (key_type == CKK_AES && !is_aes_len(secret_len))) {
            LOGE("The new key's template needs CKA_VALUE_LEN");
            return CKR_TEMPLATE_INCOMPLETE;
        }
        *value_len = secret_len;
        return CKR_OK;
    }

    CK_ULONG len = 0;
    CK_RV rv = attr_CK_ULONG(a, &len);
    if (rv != CKR_OK) {
        return rv;
    }

    if (!len || (key_type == CKK_AES && !is_aes_len(len))) {
        LOGE("CKA_VALUE_LEN %lu isn't a length for key type 0x%lx", len, key_type);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (len > secret_len) {
        LOGE("CKA_VALUE_LEN %lu is over the %lu bytes the mechanism makes", len, secret_len);
        return too_long;
    }

    *value_len = len;
    return CKR_OK;
}

/*
 * The most an RSA key of a k-byte modulus encapsulates with OAEP (PKCS#11 6.1.8): k - 2 hLen - 2 bytes.
 * The parameters were checked by mech_validate().
 */
static CK_ULONG rsa_max_secret(CK_MECHANISM_PTR mech, CK_ULONG k) {

    assert(mech->mechanism == CKM_RSA_PKCS_OAEP);

    CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)mech->pParameter;
    CK_ULONG hlen = utils_get_halg_size(params->hashAlg);
    return hlen && k > 2 * hlen + 2 ? k - 2 * hlen - 2 : 0;
}

/* The RSA public key's CKA_MODULUS length, k */
static CK_RV modulus_len(tobject *tobj, CK_ULONG *k) {

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_MODULUS);
    if (!a || !a->ulValueLen) {
        LOGE("Expected the RSA key to have CKA_MODULUS");
        return CKR_GENERAL_ERROR;
    }

    *k = a->ulValueLen;
    return CKR_OK;
}

/* The EC key's field size, from its CKA_EC_PARAMS */
static CK_RV field_size(tobject *tobj, CK_ULONG *size) {

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_EC_PARAMS);
    if (!a) {
        LOGE("Expected the EC key to have CKA_EC_PARAMS");
        return CKR_GENERAL_ERROR;
    }

    return ssl_util_ec_field_size(a, size);
}

/* Encrypts the secret with the RSA public key, in software, into the ct_size-byte ciphertext */
static CK_RV rsa_encrypt_secret(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE public_key,
        tobject *tobj, CK_BYTE_PTR secret, CK_ULONG secret_len, CK_BYTE_PTR ct, CK_ULONG ct_size) {

    /* the operation data is the caller's, so no session operation is started */
    encrypt_op_data *opdata = encrypt_op_data_new();
    if (!opdata) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    CK_RV rv = encrypt_init_op(ctx, opdata, mech, public_key);
    if (rv != CKR_OK) {
        encrypt_op_data_free(&opdata);
        return rv;
    }

    CK_ULONG out_len = ct_size;
    rv = encrypt_oneshot_op(ctx, opdata, secret, secret_len, ct, &out_len);
    encrypt_op_data_free(&opdata);

    /* encrypt_init_op() loaded the key, which its caller releases */
    CK_RV tmp_rv = tobject_user_decrement(tobj);
    if (rv == CKR_OK) {
        rv = tmp_rv;
    }

    if (rv == CKR_OK && out_len != ct_size) {
        LOGE("Expected a %lu-byte ciphertext, got %lu bytes", ct_size, out_len);
        rv = CKR_GENERAL_ERROR;
    }

    return rv;
}

CK_RV kem_encapsulate(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE public_key,
        CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_BYTE_PTR ciphertext, CK_ULONG_PTR ciphertext_len,
        CK_OBJECT_HANDLE_PTR key) {

    assert(ctx);
    check_pointer(mech);
    check_pointer(ciphertext_len);
    check_pointer(key);
    if (count) {
        check_pointer(templ);
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    CK_RV rv = check_kem_mech(tok, mech, false);
    if (rv != CKR_OK) {
        return rv;
    }
    bool is_ecdh = mech->mechanism == CKM_ECDH1_DERIVE;

    /* found, not loaded: nothing here needs the TPM until the secret is made */
    tobject *tobj = NULL;
    rv = token_find_tobject(tok, public_key, &tobj);
    if (rv != CKR_OK) {
        return CKR_KEY_HANDLE_INVALID;
    }

    CK_OBJECT_CLASS clazz = attr_list_get_CKA_CLASS(tobj->attrs, CK_OBJECT_CLASS_BAD);
    CK_KEY_TYPE key_type = attr_list_get_CKA_KEY_TYPE(tobj->attrs, CKA_KEY_TYPE_BAD);
    if (clazz != CKO_PUBLIC_KEY || key_type != (is_ecdh ? CKK_EC : CKK_RSA)) {
        LOGE("Mechanism 0x%lx doesn't encapsulate with a key of class 0x%lx and type 0x%lx",
                mech->mechanism, clazz, key_type);
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    if (!key_attr_bool(tobj->attrs, CKA_ENCAPSULATE)) {
        LOGE("The key doesn't allow encapsulation (CKA_ENCAPSULATE isn't true)");
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    rv = object_mech_is_supported(tobj, mech);
    if (rv != CKR_OK) {
        LOGE("The key doesn't allow mechanism 0x%lx", mech->mechanism);
        return rv;
    }

    rv = is_ecdh ? check_ecdh_params(mech) : mech_validate(tok->mdtl, mech, tobj->attrs);
    if (rv != CKR_OK) {
        return rv;
    }

    /* PKCS#11 4.10: the new key's template takes it; refused, as merging isn't supported */
    if (key_has_template(tobj->attrs, CKA_ENCAPSULATE_TEMPLATE)) {
        LOGE("The key has a CKA_ENCAPSULATE_TEMPLATE, which isn't supported");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    /* what the template asks for, before the TPM makes anything */
    CK_KEY_TYPE new_type = CKA_KEY_TYPE_BAD;
    CK_BBOOL extractable = CK_FALSE;
    bool has_extractable = false;
    rv = key_check_new_template(templ, count, &new_type, &extractable, &has_extractable);
    if (rv != CKR_OK) {
        return rv;
    }

    /* the most the mechanism makes, and the ciphertext's length: the modulus', or the point's */
    CK_ULONG size = 0, secret_len = 0;
    if (is_ecdh) {
        rv = field_size(tobj, &secret_len);
        size = utils_ec_point_der_len(secret_len);
    } else {
        rv = modulus_len(tobj, &size);
        secret_len = rsa_max_secret(mech, size);
    }
    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG value_len = 0;
    rv = new_value_len(templ, count, new_type, secret_len, !is_ecdh, CKR_KEY_SIZE_RANGE, &value_len);
    if (rv != CKR_OK) {
        return rv;
    }

    /* PKCS#11 5.2: the length, and nothing more */
    if (!ciphertext) {
        *ciphertext_len = size;
        return CKR_OK;
    }

    if (*ciphertext_len < size) {
        *ciphertext_len = size;
        return CKR_BUFFER_TOO_SMALL;
    }

    CK_BYTE_PTR secret = NULL;
    twist z = NULL;
    twist point = NULL;
    if (is_ecdh) {
        rv = tpm_ec_ecdh_keygen(tok->tctx, tobj, &z, &point);
        if (rv != CKR_OK) {
            goto out;
        }
        if (twist_len(point) != size || twist_len(z) != secret_len) {
            LOGE("Expected a %lu-byte point and a %lu-byte Z", size, secret_len);
            rv = CKR_GENERAL_ERROR;
            goto out;
        }
        memcpy(ciphertext, point, size);
        /* PKCS#11 6.3.17: the truncation removes bytes from the leading end */
        secret = (CK_BYTE_PTR)z + secret_len - value_len;
    } else {
        secret = calloc(1, value_len);
        if (!secret) {
            LOGE("oom");
            rv = CKR_HOST_MEMORY;
            goto out;
        }
        rv = random_get(ctx, secret, value_len);
        if (rv != CKR_OK) {
            goto out;
        }
        rv = rsa_encrypt_secret(ctx, mech, public_key, tobj, secret, value_len, ciphertext, size);
        if (rv != CKR_OK) {
            goto out;
        }
    }

    rv = key_create_from_value(ctx, templ, count, secret, value_len, key);
    if (rv == CKR_OK) {
        *ciphertext_len = size;
    }

out:
    if (z) {
        OPENSSL_cleanse((void *)z, twist_len(z));
        twist_free(z);
    } else if (secret) {
        OPENSSL_cleanse(secret, value_len);
        free(secret);
    }
    twist_free(point);

    return rv;
}

/* The ECDH half of kem_decapsulate(), its mechanism checked */
static CK_RV ecdh_decapsulate(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE private_key,
        CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_BYTE_PTR ciphertext, CK_ULONG ciphertext_len,
        CK_OBJECT_HANDLE_PTR key) {

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    /* found, not loaded: nothing here needs the TPM until Z is computed */
    tobject *tobj = NULL;
    CK_RV rv = token_find_tobject(tok, private_key, &tobj);
    if (rv != CKR_OK) {
        return CKR_UNWRAPPING_KEY_HANDLE_INVALID;
    }

    CK_OBJECT_CLASS clazz = attr_list_get_CKA_CLASS(tobj->attrs, CK_OBJECT_CLASS_BAD);
    CK_KEY_TYPE key_type = attr_list_get_CKA_KEY_TYPE(tobj->attrs, CKA_KEY_TYPE_BAD);
    if (clazz != CKO_PRIVATE_KEY || key_type != CKK_EC) {
        LOGE("ECDH doesn't decapsulate with a key of class 0x%lx and type 0x%lx", clazz, key_type);
        return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
    }

    if (!key_attr_bool(tobj->attrs, CKA_DECAPSULATE)) {
        LOGE("The key doesn't allow decapsulation (CKA_DECAPSULATE isn't true)");
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    /*
     * PKCS#11 4.10: a CKA_ALWAYS_AUTHENTICATE key is used only after a context-specific login, made
     * after a C_*Init. C_DecapsulateKey has none, so it can't be authenticated for it.
     */
    if (key_attr_bool(tobj->attrs, CKA_ALWAYS_AUTHENTICATE)) {
        LOGE("A CKA_ALWAYS_AUTHENTICATE key can't be authenticated to decapsulate");
        return CKR_USER_NOT_LOGGED_IN;
    }

    rv = object_mech_is_supported(tobj, mech);
    if (rv != CKR_OK) {
        LOGE("The key doesn't allow mechanism 0x%lx", mech->mechanism);
        return rv;
    }

    rv = check_ecdh_params(mech);
    if (rv != CKR_OK) {
        return rv;
    }

    /* PKCS#11 4.10: the new key's template takes it; refused, as merging isn't supported */
    if (key_has_template(tobj->attrs, CKA_DECAPSULATE_TEMPLATE)) {
        LOGE("The key has a CKA_DECAPSULATE_TEMPLATE, which isn't supported");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    CK_KEY_TYPE new_type = CKA_KEY_TYPE_BAD;
    CK_BBOOL extractable = CK_FALSE;
    bool has_extractable = false;
    rv = key_check_new_template(templ, count, &new_type, &extractable, &has_extractable);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG fsize = 0;
    rv = field_size(tobj, &fsize);
    if (rv != CKR_OK) {
        return rv;
    }

    /* PKCS#11 5.18.9: a template that can't be honoured */
    CK_ULONG value_len = 0;
    rv = new_value_len(templ, count, new_type, fsize, false, CKR_TEMPLATE_INCONSISTENT, &value_len);
    if (rv != CKR_OK) {
        return rv;
    }

    /* the ephemeral point, raw or DER-encoded as kem_encapsulate() gives it */
    if (ciphertext_len != 2 * fsize + 1 && ciphertext_len != utils_ec_point_der_len(fsize)) {
        LOGE("A %lu-byte ciphertext isn't a point for a %lu-byte field", ciphertext_len, fsize);
        return CKR_WRAPPED_KEY_LEN_RANGE;
    }

    CK_BYTE_PTR point = NULL;
    CK_ULONG point_len = 0;
    if (!utils_ec_point_unwrap(ciphertext, ciphertext_len, fsize, &point, &point_len)) {
        LOGE("The ciphertext isn't an uncompressed point");
        return CKR_WRAPPED_KEY_INVALID;
    }

    rv = token_load_object(tok, private_key, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_BYTE_PTR z = NULL;
    size_t z_len = 0;
    rv = tpm_ec_ecdh1_derive(tok->tctx, tobj, point, point_len, &z, &z_len);

    /* the key is released whatever happened, or it stays busy and can't be destroyed */
    CK_RV tmp_rv = tobject_user_decrement(tobj);
    if (rv == CKR_DATA_INVALID) {
        LOGE("The ciphertext isn't a point on the key's curve");
        rv = CKR_WRAPPED_KEY_INVALID;
        goto out;
    }
    if (rv != CKR_OK) {
        goto out;
    }
    if (tmp_rv != CKR_OK) {
        rv = tmp_rv;
        goto out;
    }

    /* a TPM may leave out Z's leading zero bytes, which the truncation removes first */
    if (z_len > fsize) {
        LOGE("Expected Z of at most %lu bytes, got %zu", fsize, z_len);
        rv = CKR_GENERAL_ERROR;
        goto out;
    }

    /* P-521's, the longest field ssl_util_ec_field_size() gives */
    CK_BYTE value[66] = { 0 };
    assert(fsize <= sizeof(value));
    memcpy(&value[fsize - z_len], z, z_len);

    /* PKCS#11 6.3.17: the truncation removes bytes from the leading end */
    rv = key_create_from_value(ctx, templ, count, &value[fsize - value_len], value_len, key);
    OPENSSL_cleanse(value, sizeof(value));
    /* the template was checked before Z: what fails now depends on Z, one code as key_unwrap_as() */
    if (rv != CKR_OK && rv != CKR_HOST_MEMORY) {
        LOGE("The decapsulated key can't be made");
        rv = CKR_WRAPPED_KEY_INVALID;
    }

out:
    if (z) {
        OPENSSL_cleanse(z, z_len);
    }
    free(z);

    return rv;
}

CK_RV kem_decapsulate(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE private_key,
        CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_BYTE_PTR ciphertext, CK_ULONG ciphertext_len,
        CK_OBJECT_HANDLE_PTR key) {

    assert(ctx);
    check_pointer(mech);
    check_pointer(key);
    if (ciphertext_len) {
        check_pointer(ciphertext);
    }
    if (count) {
        check_pointer(templ);
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    CK_RV rv = check_kem_mech(tok, mech, true);
    if (rv != CKR_OK) {
        return rv;
    }

    if (mech->mechanism == CKM_ECDH1_DERIVE) {
        return ecdh_decapsulate(ctx, mech, private_key, templ, count, ciphertext, ciphertext_len,
                key);
    }

    /* PKCS#11 6.1.8: "C_DecapsulateKey is exactly equivalent to C_UnwrapKey" */
    return key_unwrap_as(ctx, mech, private_key, CKA_DECAPSULATE, ciphertext, ciphertext_len,
            templ, count, key);
}
