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

static twist encrypt_parts_to_twist(unsigned char tag[16], unsigned char iv[12], unsigned char *ctextbin, int ctextbinlen) {

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
    unsigned char *ctextbin = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    unsigned char ivbin[12];
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
            (const unsigned char *)keybin, (const unsigned char *)ivbin);
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
    ret = EVP_EncryptUpdate(ctx, (unsigned char *)ctextbin, &len, (unsigned char *)plaintextbin, twist_len(plaintextbin));
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

    unsigned char tagbin[16];
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
            (const unsigned char *)key, (const unsigned char *)ivbin);
    if (!ret) {
        LOGE("EVP_DecryptInit failed");
        goto out;
    }

    int len = 0;
    ret = EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &len, (unsigned char *)ctextbin,
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

    ret = EVP_DecryptFinal_ex(ctx, ((unsigned char *)plaintext) + len, &len);
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

twist utils_pdkdf2_hmac_sha256_bin_raw(const twist pin, const twist binsalt,
        int iterations) {

    twist digest = twist_calloc(SHA256_DIGEST_LENGTH);
    if (!digest) {
        return NULL;
    }

    int rc = PKCS5_PBKDF2_HMAC(pin, twist_len(pin),
            (const unsigned char *)binsalt, twist_len(binsalt),
            iterations,
            EVP_sha256(), SHA256_DIGEST_LENGTH, (unsigned char *)digest);
    if (!rc) {
        LOGE("Error pdkdf2_hmac_sha256");
        goto error;
    }

    return digest;

error:
    twist_free(digest);
    twist_free(binsalt);
    return NULL;
}

twist utils_pdkdf2_hmac_sha256_raw(const twist pin, const twist salt,
        int iterations) {

    twist binsalt = twistbin_unhexlify(salt);
    if (!binsalt) {
        return NULL;
    }

    twist x = utils_pdkdf2_hmac_sha256_bin_raw(pin, binsalt, iterations);
    twist_free(binsalt);

    return x;
}

twist decrypt(const twist pin, const twist salt, unsigned iters,
        const twist objauth) {

    twist key = utils_pdkdf2_hmac_sha256_raw(pin, salt, iters);
    if (!key) {
        return NULL;
    }

    twist ptext = aes256_gcm_decrypt(key, objauth);
    twist_free(key);
    if (!ptext) {
        return NULL;
    }

    twist raw = twistbin_unhexlify(ptext);
    twist_free(ptext);

    return raw;
}

twist utils_pdkdf2_hmac_sha256(const twist pin, const twist salt, int iterations) {


    twist digest = utils_pdkdf2_hmac_sha256_raw(pin, salt, iterations);
    if (!digest) {
        return NULL;
    }

    twist hex = twist_hexlify(digest);
    twist_free(digest);
    return hex;
}

size_t utils_get_halg_size(CK_MECHANISM_TYPE mttype) {

    switch(mttype) {
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

twist utils_get_rand(size_t size) {

    if (size == 0) {
        return NULL;
    }

    twist salt = twist_calloc(size);
    if (!salt) {
        return NULL;
    }

    int rc = RAND_bytes((unsigned char *)salt, size);
    if (rc != 1) {
        LOGE("Could not generate random bytes");
        return NULL;
    }

    return salt;
}
