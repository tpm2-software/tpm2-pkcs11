/* SPDX-License-Identifier: BSD-2-Clause */

#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "log.h"
#include "token.h"
#include "utils.h"

int str_to_ul(const char *val, size_t *res) {

    errno=0;
    *res = strtoul(val, NULL, 0);
    if (errno) {
        LOGE("Could not convert \"%s\" to integer", val);
        return 1;
    }

    return 0;
}

CK_RV utils_setup_new_object_auth(twist newpin, twist *newauthhex, twist *newsalthex) {

    CK_RV rv = CKR_GENERAL_ERROR;

    bool allocated_pin_to_use = false;
    twist pin_to_use = NULL;
    twist salt_to_use = NULL;

    salt_to_use = utils_get_rand_hex_str(SALT_HEX_STR_SIZE);
    if (!salt_to_use) {
        goto out;
    }

    if (!newpin) {
        allocated_pin_to_use = true;
        pin_to_use = utils_get_rand_hex_str(AUTH_HEX_STR_SIZE);
        if (!pin_to_use) {
            goto out;
        }
    } else {
        pin_to_use = newpin;
    }

    *newauthhex = utils_hash_pass(pin_to_use, salt_to_use);
    if (!*newauthhex) {
        goto out;
    }

    if (newsalthex) {
        *newsalthex = salt_to_use;
        salt_to_use = NULL;
    }

    rv = CKR_OK;

out:

    if (rv != CKR_OK) {
        twist_free(*newauthhex);
        twist_free(*newsalthex);
        *newsalthex = NULL;
    }

    if (allocated_pin_to_use) {
        twist_free(pin_to_use);
    }

    twist_free(salt_to_use);

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
    size_t a = twist_len(taghex);
    size_t b = twist_len(ivhex);
    size_t c = twist_len(ctexthex);

    size_t constructed_len = 0;
    safe_add(constructed_len, a, b);
    safe_adde(constructed_len, c);
    safe_adde(constructed_len, 3);

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
    ret = EVP_EncryptUpdate(ctx, ctextbin, &len, (CK_BYTE_PTR )plaintextbin, twist_len(plaintextbin));
    if (!ret) {
        LOGE("EVP_EncryptUpdate failed");
        goto out;
    }

    assert((size_t)len == twist_len(plaintextbin));

    int left = 0;
    ret = EVP_EncryptFinal_ex(ctx, &ctextbin[len], &left);
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
        LOGE("oom0");
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

    size_t clen = twist_len(ctextbin);
    if (!clen) {
        plaintext = twist_new("");
        if (!plaintext) {
            LOGE("oom");
        } else {
            ok = 1;
        }
        goto out;
    }

    plaintext = twist_calloc(clen);
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

    ret = EVP_DecryptFinal_ex(ctx, &((CK_BYTE_PTR )plaintext)[len], &len);
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
            /* falls-thru */
        case CKM_SHA1_RSA_PKCS_PSS:
            return 20;
        case CKM_SHA256_RSA_PKCS:
            /* falls-thru */
        case CKM_SHA256_RSA_PKCS_PSS:
            return 32;
        case CKM_SHA384_RSA_PKCS:
            /* falls-thru */
        case CKM_SHA384_RSA_PKCS_PSS:
            return 48;
        case CKM_SHA512_RSA_PKCS:
            /* falls-thru */
        case CKM_SHA512_RSA_PKCS_PSS:
            return 64;
    }

    return 0;
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

CK_RV utils_ctx_unwrap_objauth(twist wrappingkey, twist objauth, twist *unwrapped_auth) {
    assert(wrappingkey);
    assert(unwrapped_auth);

    if (!objauth) {
        *unwrapped_auth = NULL;
        return CKR_OK;
    }

    twist tmp = aes256_gcm_decrypt(wrappingkey, objauth);
    if (!tmp) {
        return CKR_GENERAL_ERROR;
    }

    *unwrapped_auth = tmp;

    return CKR_OK;
}

CK_RV utils_ctx_wrap_objauth(twist wrappingkey, twist data, twist *wrapped_auth) {
    assert(wrappingkey);
    assert(data);

    twist wrapped = aes256_gcm_encrypt(wrappingkey, data);
    if (!wrapped) {
        return CKR_GENERAL_ERROR;
    }

    *wrapped_auth = wrapped;

    return CKR_OK;
}

CK_RV ec_params_to_nid(CK_ATTRIBUTE_PTR ecparams, int *nid) {

    const unsigned char *p = ecparams->pValue;

    ASN1_OBJECT *a = d2i_ASN1_OBJECT(NULL, &p, ecparams->ulValueLen);
    if (!a) {
        LOGE("Unknown CKA_EC_PARAMS value");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    *nid = OBJ_obj2nid(a);
    ASN1_OBJECT_free(a);

    return CKR_OK;
}
