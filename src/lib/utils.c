/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "log.h"
#include "token.h"
#include "utils.h"

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

twist utils_pdkdf2_hmac_sha256_raw(const twist pin, const twist salt,
        int iterations) {

    twist digest = twist_calloc(SHA256_DIGEST_LENGTH);
    twist binsalt = twistbin_unhexlify(salt);
    if (!digest || !binsalt) {
        goto error;
    }

    int rc = PKCS5_PBKDF2_HMAC(pin, twist_len(pin),
            (const unsigned char *)binsalt, twist_len(binsalt),
            iterations,
            EVP_sha256(), SHA256_DIGEST_LENGTH, (unsigned char *)digest);
    if (!rc) {
        LOGE("Error pdkdf2_hmac_sha256");
        goto error;
    }
    twist_free(binsalt);

    return digest;

error:
    twist_free(digest);
    twist_free(binsalt);
    return NULL;
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
