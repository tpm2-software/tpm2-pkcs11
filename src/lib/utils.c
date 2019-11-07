/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "log.h"
#include "token.h"
#include "utils.h"

CK_RV utils_setup_new_object_auth(twist newpin, twist *newauthhex, twist *newsalthex) {

    CK_RV rv = CKR_GENERAL_ERROR;

    bool allocated_pin_to_use = false;
    twist pin_to_use = NULL;

    *newsalthex = utils_get_rand_hex_str(SALT_HEX_STR_SIZE);
    if (!newsalthex) {
        goto out;
    }

    if (!newpin) {
        allocated_pin_to_use = true;
        pin_to_use = utils_get_rand_hex_str(32);
        if (!pin_to_use) {
            goto out;
        }
    } else {
        pin_to_use = newpin;
    }

    *newauthhex = utils_hash_pass(pin_to_use, *newsalthex);
    if (!*newauthhex) {
        goto out;
    }

    rv = CKR_OK;

out:

    if (rv != CKR_OK) {
        twist_free(*newauthhex);
        if (newsalthex) {
            twist_free(*newsalthex);
            *newsalthex = NULL;
        }

        *newauthhex = NULL;
    }

    if (allocated_pin_to_use) {
        twist_free(pin_to_use);
    }

    return rv;
}

static twist encrypt_parts_to_twist(CK_BYTE tag[16], CK_BYTE iv[12], CK_BYTE_PTR ctextbin, int ctextbinlen) {

    /*
     * Build the <iv>:<tag>:<ctext> data format
     * and convert from binary formats to hex encoded.
     */

    twist ivhex = NULL;
    twist taghex = NULL;
    twist ctexthex = NULL;
    twist constructed = NULL;

    taghex = twist_hex_new((char *)tag, 16);
    if (!taghex) {
        LOGE("oom");
        goto out;
    }

    ivhex = twist_hex_new((char *)iv, 12);
    if (!ivhex) {
        LOGE("oom");
        goto out;
    }

    ctexthex = twist_hex_new((char *)ctextbin, ctextbinlen);
    if (!ctexthex) {
        LOGE("oom");
        goto out;
    }

    /*
     * create a buffer with enough space for hex encoded <iv>:<tag>:<ctext>
     * (note + 3 is for 2 : delimiters and a NULL byte.
     */
    size_t constructed_len = twist_len(taghex) + twist_len(ivhex)
            + twist_len(ctexthex) + 3;
    constructed = twist_calloc(constructed_len);
    if (!constructed) {
        LOGE("oom");
        goto out;
    }

    /* impossible to have truncation */
    snprintf((char *)constructed, constructed_len, "%s:%s:%s", ivhex, taghex, ctexthex);

out:
    twist_free(ivhex);
    twist_free(taghex);
    twist_free(ctexthex);

    return constructed;
}

twist aes256_gcm_encrypt(twist keybin, twist plaintextbin) {

    twist constructed = NULL;
    CK_BYTE_PTR ctextbin = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    CK_BYTE ivbin[12];
    int rc = RAND_bytes(ivbin, sizeof(ivbin));
    if (rc != 1) {
        LOGE("Could not generate random bytes");
        return NULL;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOGE("oom");
        goto out;
    }

    int ret = EVP_EncryptInit(ctx, EVP_aes_256_gcm(),
            (const CK_BYTE_PTR )keybin, (const CK_BYTE_PTR )ivbin);
    if (!ret) {
        LOGE("EVP_DecryptInit failed");
        goto out;
    }

    ctextbin = calloc(1, twist_len(plaintextbin));
    if (!ctextbin) {
        LOGE("oom");
        goto out;
    }

    int len = 0;
    ret = EVP_EncryptUpdate(ctx, (CK_BYTE_PTR )ctextbin, &len, (CK_BYTE_PTR )plaintextbin, twist_len(plaintextbin));
    if (!ret) {
        LOGE("EVP_EncryptUpdate failed");
        goto out;
    }

    assert((size_t)len == twist_len(plaintextbin));

    int left = 0;
    ret = EVP_EncryptFinal_ex(ctx, ctextbin + len, &left);
    if (!ret) {
        LOGE("AES GCM verification failed!");
        goto out;
    }

    assert(left == 0);

    CK_BYTE tagbin[16];
    ret = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tagbin), tagbin);
    if (!ret) {
        LOGE("EVP_CIPHER_CTX_ctrl failed");
        goto out;
    }

    constructed = encrypt_parts_to_twist(tagbin, ivbin, ctextbin, len);

out:

    EVP_CIPHER_CTX_free(ctx);
    free(ctextbin);

    return constructed;
}

twist aes256_gcm_decrypt(const twist key, const twist objauth) {

    int ok = 0;

    twist ivbin = NULL;
    twist tagbin = NULL;
    twist objcopy = NULL;
    twist ctextbin = NULL;
    twist plaintext = NULL;

    EVP_CIPHER_CTX *ctx = NULL;

    /*
     * Split apart the <iv>:<tag>:<ctext> data
     * and convert to binary formats.
     */

    objcopy = twist_dup(objauth);
    if (!objcopy) {
        LOGE("oom");
        return NULL;
    }

    char *iv = (char *)objcopy;

    char *tag = strchr(objcopy, ':');
    if (!tag) {
        LOGE("Could not find : to split tag");
        goto out;
    }
    *tag = '\0';
    tag++;

    char *ctext = strchr(tag, ':');
    if (!ctext) {
        LOGE("Could not find : to split ctext");
        goto out;
    }
    *ctext = '\0';
    ctext++;

    ivbin = twistbin_unhexlify(iv);
    if (!ivbin) {
        LOGE("oom");
        goto out;
    }

    tagbin = twistbin_unhexlify(tag);
    if (!tagbin) {
        LOGE("oom");
        goto out;
    }

    ctextbin = twistbin_unhexlify(ctext);
    if (!ctextbin) {
        LOGE("oom");
        goto out;
    }

    plaintext = twist_calloc(twist_len(ctextbin));
    if (!plaintext) {
        LOGE("oom");
        goto out;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOGE("oom");
        goto out;
    }

    int ret = EVP_DecryptInit (ctx, EVP_aes_256_gcm(),
            (const CK_BYTE_PTR )key, (const CK_BYTE_PTR )ivbin);
    if (!ret) {
        LOGE("EVP_DecryptInit failed");
        goto out;
    }

    int len = 0;
    ret = EVP_DecryptUpdate(ctx, (CK_BYTE_PTR )plaintext, &len, (CK_BYTE_PTR )ctextbin,
            twist_len(ctextbin));
    if (!ret) {
        LOGE("EVP_DecryptUpdate failed");
        goto out;
    }

    ret = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tagbin);
    if (!ret) {
        LOGE("EVP_CIPHER_CTX_ctrl failed");
        goto out;
    }

    ret = EVP_DecryptFinal_ex(ctx, ((CK_BYTE_PTR )plaintext) + len, &len);
    if (!ret) {
        LOGE("AES GCM verification failed!");
        goto out;
    }

    ok = 1;

out:
    twist_free(objcopy);
    twist_free(ctextbin);
    twist_free(tagbin);
    twist_free(ivbin);
    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        twist_free(plaintext);
        plaintext = NULL;
    }

    return plaintext;

}

twist utils_hash_pass(const twist pin, const twist salt) {


    unsigned char md[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    SHA256_Update(&sha256, pin, twist_len(pin));
    SHA256_Update(&sha256, salt, twist_len(salt));
    SHA256_Final(md, &sha256);

    /* truncate the password to 32 characters */
    return twist_hex_new((char *)md, sizeof(md)/2);
}

size_t utils_get_halg_size(CK_MECHANISM_TYPE mttype) {

    switch(mttype) {
        case CKM_ECDSA:
        case CKM_ECDSA_SHA1:
            /* falls-thru */
        case CKM_SHA1_RSA_PKCS:
            return 20;
        case CKM_SHA256_RSA_PKCS:
            return 32;
        case CKM_SHA384_RSA_PKCS:
            return 48;
        case CKM_SHA512_RSA_PKCS:
            return 64;
    }

    return 0;
}

bool utils_mech_is_raw_sign(CK_MECHANISM_TYPE mech) {

    switch(mech) {
    case CKM_RSA_PKCS:
        return true;
    default:
        return false;
    }
}

bool utils_mech_is_rsa_pkcs(CK_MECHANISM_TYPE mech) {

    switch(mech) {
    case CKM_RSA_PKCS:
        /* falls-thru*/
    case CKM_SHA1_RSA_PKCS:
        /* falls-thru*/
    case CKM_SHA256_RSA_PKCS:
        /* falls-thru*/
    case CKM_SHA384_RSA_PKCS:
        /* falls-thru*/
    case CKM_SHA512_RSA_PKCS:
        return true;
    default:
        return false;
    }
}

bool utils_mech_is_ecdsa(CK_MECHANISM_TYPE mech) {

    switch(mech) {
    case CKM_ECDSA:
        /* falls-thru*/
    case CKM_ECDSA_SHA1:
        return true;
    default:
        return false;
    }
}

twist utils_get_rand_hex_str(size_t size) {

    if (size == 0) {
        return NULL;
    }

    if (size & 0x1) {
        return NULL;
    }

    twist salt = twist_calloc(size);
    if (!salt) {
        return NULL;
    }

    int rc = RAND_bytes((CK_BYTE_PTR )salt, size);
    if (rc != 1) {
        LOGE("Could not generate random bytes");
        return NULL;
    }

    twist hex = twist_hex_new(salt, twist_len(salt));
    twist_free(salt);

    return hex;
}

CK_RV utils_ctx_unwrap_objauth(token *tok, twist objauth, twist *unwrapped_auth) {
    assert(tok);
    assert(objauth);
    assert(unwrapped_auth);

     twist tmp = aes256_gcm_decrypt(tok->wappingkey, objauth);
    if (!tmp) {
        return CKR_GENERAL_ERROR;
    }

    *unwrapped_auth = tmp;

    return CKR_OK;
}

CK_RV utils_ctx_wrap_objauth(token *tok, twist data, twist *wrapped_auth) {
    assert(tok);
    assert(data);

    twist wrapped = aes256_gcm_encrypt(tok->wappingkey, data);
    if (!wrapped) {
        return CKR_GENERAL_ERROR;
    }

    *wrapped_auth = wrapped;

    return CKR_OK;
}

CK_RV generic_attr_copy(CK_ATTRIBUTE_PTR in, CK_ULONG count, void *udata) {
    CK_ATTRIBUTE_PTR out = &((CK_ATTRIBUTE_PTR)udata)[count];


    void *newval = NULL;

    if (in->pValue) {
        newval = calloc(1, in->ulValueLen);
        if (!newval) {
            return CKR_HOST_MEMORY;
        }
        memcpy(newval, in->pValue, in->ulValueLen);
    }

    out->ulValueLen = in->ulValueLen;
    out->type = in->type;
    out->pValue = newval;

    return CKR_OK;
}
CK_RV fake_ec_param_copy(CK_ATTRIBUTE_PTR in, CK_ULONG count, void *udata) {
    CK_ATTRIBUTE_PTR out = &((CK_ATTRIBUTE_PTR)udata)[count];


    void *newval = NULL;
    unsigned char fake_oid[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };


    if (in->pValue) {
        newval = calloc(1, 10);
        if (!newval) {
            return CKR_HOST_MEMORY;
        }
        memcpy(newval, fake_oid, 10);
    }

    out->ulValueLen = 10;
    out->type = in->type;
    out->pValue = newval;

    return CKR_OK;
}

CK_RV utils_attr_deep_copy(CK_ATTRIBUTE_PTR attrs, CK_ULONG attr_count, CK_ATTRIBUTE_PTR copy) {

    static const attr_handler deep_copy_attr_handlers[] = {
        { CKA_CLASS,             generic_attr_copy },
        { CKA_TOKEN,             generic_attr_copy },
        { CKA_MODULUS,           generic_attr_copy },
        { CKA_PRIVATE,           generic_attr_copy },
        { CKA_KEY_TYPE,          generic_attr_copy },
        { CKA_ID,                generic_attr_copy },
        { CKA_LABEL,             generic_attr_copy },
        { CKA_VERIFY,            generic_attr_copy },
        { CKA_ENCRYPT,           generic_attr_copy },
        { CKA_DECRYPT,           generic_attr_copy },
        { CKA_SIGN,              generic_attr_copy },
        { CKA_MODULUS_BITS,      generic_attr_copy },
        { CKA_PUBLIC_EXPONENT,   generic_attr_copy },
        { CKA_SENSITIVE,         generic_attr_copy },
        { CKA_ALWAYS_SENSITIVE,  generic_attr_copy },
        { CKA_EXTRACTABLE,       generic_attr_copy },
        { CKA_NEVER_EXTRACTABLE, generic_attr_copy },
        { CKA_EC_PARAMS,         fake_ec_param_copy},
        { CKA_EC_POINT,          generic_attr_copy },
        { CKA_ALWAYS_AUTHENTICATE, generic_attr_copy },
    };

    return utils_handle_attrs(deep_copy_attr_handlers, ARRAY_LEN(deep_copy_attr_handlers), attrs, attr_count, copy);
}

CK_RV utils_handle_attrs(const attr_handler *handlers, size_t handler_count, CK_ATTRIBUTE_PTR attrs, CK_ULONG attr_count, void *udata) {

    CK_ULONG i;
    for (i=0; i < attr_count; i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];

        size_t k = 0;
        bool handled = false;
        for (k=0; k < handler_count; k++) {
            const attr_handler *h = &handlers[k];
            if (a->type == h->value) {
                if (h->handler) {
                    CK_RV tmp = h->handler(a, i, udata);
                    if (tmp != CKR_OK) {
                        return tmp;
                    }
                }
                handled = true;
                break;
            }
        }

        if (!handled) {
            LOGE("Attribute 0x%x not handled", a->type);
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }

    return CKR_OK;
}

CK_RV generic_mech_copy(CK_MECHANISM_PTR in, CK_ULONG count, void *udata) {
    CK_MECHANISM_PTR out = &((CK_MECHANISM_PTR)udata)[count];


    void *newval = NULL;

    if (in->pParameter) {
        newval = calloc(1, in->ulParameterLen);
        if (!newval) {
            return CKR_HOST_MEMORY;
        }
        memcpy(newval, in->pParameter, in->ulParameterLen);
    }

    out->ulParameterLen = in->ulParameterLen;
    out->mechanism = in->mechanism;
    out->pParameter = newval;

    return CKR_OK;
}

static CK_RV generic_attr_free(CK_ATTRIBUTE_PTR in, CK_ULONG count, void *udata) {
    UNUSED(count);
    UNUSED(udata);

    free(in->pValue);

    return CKR_OK;
}

CK_RV utils_attr_free(CK_ATTRIBUTE_PTR attrs, CK_ULONG attr_count) {

    static const attr_handler free_attr_handlers[] = {
        { CKA_CLASS,             generic_attr_free },
        { CKA_TOKEN,             generic_attr_free },
        { CKA_MODULUS,           generic_attr_free },
        { CKA_PRIVATE,           generic_attr_free },
        { CKA_KEY_TYPE,          generic_attr_free },
        { CKA_ID,                generic_attr_free },
        { CKA_LABEL,             generic_attr_free },
        { CKA_VERIFY,            generic_attr_free },
        { CKA_ENCRYPT,           generic_attr_free },
        { CKA_DECRYPT,           generic_attr_free },
        { CKA_SIGN,              generic_attr_free },
        { CKA_MODULUS_BITS,      generic_attr_free },
        { CKA_PUBLIC_EXPONENT,   generic_attr_free },
        { CKA_SENSITIVE,         generic_attr_free },
        { CKA_EXTRACTABLE,       generic_attr_free },
        { CKA_ALWAYS_SENSITIVE,  generic_attr_free },
        { CKA_NEVER_EXTRACTABLE, generic_attr_free },
        { CKA_VALUE_LEN,         generic_attr_free },
        { CKA_EC_PARAMS,         generic_attr_free },
        { CKA_EC_POINT,          generic_attr_free },
        { CKA_ALWAYS_AUTHENTICATE, generic_attr_free },
    };

    return utils_handle_attrs(free_attr_handlers, ARRAY_LEN(free_attr_handlers), attrs, attr_count, NULL);
}

CK_RV utils_handle_mechs(const mech_handler *handlers, size_t handler_count, CK_MECHANISM_PTR mechs, CK_ULONG mech_count, void *udata) {

    CK_ULONG i;
    for (i=0; i < mech_count; i++) {
        CK_MECHANISM_PTR m = &mechs[i];

        size_t k = 0;
        bool handled = false;
        for (k=0; k < handler_count; k++) {
            const mech_handler *h = &handlers[k];
            if (m->mechanism == h->mechanism) {
                if (h->handler) {
                    CK_RV tmp = h->handler(m, i, udata);
                    if (tmp != CKR_OK) {
                        return tmp;
                    }
                }
                handled = true;
                break;
            }
        }

        if (!handled) {
            return CKR_MECHANISM_INVALID;
        }
    }

    return CKR_OK;
}

CK_RV utils_mech_deep_copy(CK_MECHANISM_PTR mechs, CK_ULONG mech_count, CK_MECHANISM_PTR copy) {

    static const mech_handler mech_deep_copy_handlers[] = {
        { CKM_ECDSA,         generic_mech_copy },
        { CKM_RSA_X_509,     generic_mech_copy },
        { CKM_RSA_PKCS_OAEP, generic_mech_copy },
    };

    return utils_handle_mechs(mech_deep_copy_handlers, ARRAY_LEN(mech_deep_copy_handlers), mechs, mech_count, copy);
}

static CK_RV generic_mech_free(CK_MECHANISM_PTR in, CK_ULONG count, void *udata) {
    UNUSED(count);
    UNUSED(udata);

    free(in->pParameter);

    return CKR_OK;
}

CK_RV utils_mech_free(CK_MECHANISM_PTR mechs, CK_ULONG mech_count, CK_MECHANISM_PTR copy) {

    static const mech_handler mech_free_handlers[] = {
        { CKM_RSA_X_509,     generic_mech_free },
        { CKM_RSA_PKCS_OAEP, generic_mech_free },
    };

    return utils_handle_mechs(mech_free_handlers, ARRAY_LEN(mech_free_handlers), mechs, mech_count, copy);
}

CK_RV ec_params_to_nid(CK_ATTRIBUTE_PTR ecparams, int *nid) {

    const unsigned char *p = ecparams->pValue;

    ASN1_OBJECT *a = d2i_ASN1_OBJECT(NULL, &p, ecparams->ulValueLen);
    if (!a) {
        LOGE("Unknown CKA_EC_PARAMS value");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    * nid = OBJ_obj2nid(a);
    ASN1_OBJECT_free(a);

    return CKR_OK;
}

CK_ATTRIBUTE_PTR util_get_attribute_by_type(CK_ATTRIBUTE_TYPE needle, CK_ATTRIBUTE_PTR haystack, CK_ULONG count) {

    CK_ULONG i;
    for (i=0; i < count; i++) {

        CK_ATTRIBUTE_PTR a = &haystack[i];

        if (a->type == needle) {
            return a;
        }
    }

    return NULL;
}

CK_ATTRIBUTE_PTR util_get_attribute_full(CK_ATTRIBUTE_PTR needle, CK_ATTRIBUTE_PTR haystack, CK_ULONG count) {

    CK_ULONG i;
    for (i=0; i < count; i++) {

        CK_ATTRIBUTE_PTR a = &haystack[i];

        if (a->type == needle->type
         && a->ulValueLen == needle->ulValueLen) {
            if (a->ulValueLen > 0
             && memcmp(a->pValue, needle->pValue, needle->ulValueLen)) {
                /* length is greater then 0 and don't match, keep looking */
                continue;
            }
            /* length is both 0 OR length > 0 and matched on memcmp */
            return a;
        }
    }

    return NULL;
}

void *buf_dup(void *buf, size_t len) {

    void *x = malloc(len);
    if (x) {
        memcpy(x, buf, len);
    }

    return x;
}
