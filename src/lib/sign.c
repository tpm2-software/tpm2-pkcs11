/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <stdlib.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "checks.h"
#include "digest.h"
#include "log.h"
#include "session.h"
#include "session_ctx.h"
#include "sign.h"
#include "token.h"
#include "tpm.h"

typedef struct sign_opdata sign_opdata;
struct sign_opdata {
    tobject *tobj;
    CK_MECHANISM_TYPE mtype;
    bool do_hash;
    twist buffer;
    digest_op_data *digest_opdata;
};

static bool is_hashing_needed(CK_MECHANISM_TYPE mech) {

    switch(mech) {
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
        return true;
    case CKM_RSA_PKCS:
        return false;
    default:
        LOGE("Unknown mech: %lu", mech);
    }

    return false;
}

/*
 * XXX this is probably best to query the TPM layer
 */
static bool is_mech_supported(CK_MECHANISM_TYPE mech) {

    switch (mech) {
    case CKM_RSA_PKCS_OAEP:
        /* falls-thru */
    case CKM_AES_CBC:
        return true;
        /* no default */
    }

    return false;
}

static CK_RV common_init(operation op, token *tok, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    check_pointer(mechanism);

    CK_RV rv = CKR_GENERAL_ERROR;

    bool is_mech_sup = is_mech_supported(mechanism->mechanism);
    if (!is_mech_sup) {
        return CKR_MECHANISM_INVALID;
    }

    digest_op_data *digest_opdata = NULL;
    bool do_hash = is_hashing_needed(mechanism->mechanism);
    if (do_hash) {

        digest_opdata = digest_op_data_new();
        if (!digest_opdata) {
            return CKR_HOST_MEMORY;
        }

        rv = digest_init_op(tok, digest_opdata, mechanism);
        if (rv != CKR_OK) {
            digest_op_data_free(&digest_opdata);
            return rv;
        }
    }

    bool is_active = token_opdata_is_active(tok);
    if (is_active) {
        return CKR_OPERATION_ACTIVE;
    }

    sign_opdata *opdata = calloc(1, sizeof(*opdata));
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }


    rv = token_load_object(tok, key, &opdata->tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    opdata->do_hash = do_hash;
    opdata->mtype = mechanism->mechanism;
    opdata->digest_opdata = digest_opdata;

    /*
     * Store everything for later
     */
    token_opdata_set(tok, op, opdata);

    return CKR_OK;
}

static CK_RV common_update(operation op, token *tok, unsigned char *part, unsigned long part_len) {

    check_pointer(part);

    CK_RV rv = CKR_GENERAL_ERROR;

    sign_opdata *opdata = NULL;
    rv = token_opdata_get(tok, op, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    if (opdata->do_hash) {
        rv = digest_update_op(tok, opdata->digest_opdata, part, part_len);
        if (rv != CKR_OK) {
            return rv;
        }
    } else {
        twist tmp = twistbin_append(opdata->buffer, part, part_len);
        if (!tmp) {
            return CKR_HOST_MEMORY;
        }
        opdata->buffer = tmp;
    }

    return CKR_OK;
}

CK_RV sign_init(token *tok, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_sign, tok, mechanism, key);
}

CK_RV sign_update(token *tok, unsigned char *part, unsigned long part_len) {

    return common_update(operation_sign, tok, part, part_len);
}

static CK_RV pkcs1_5_build_struct(CK_MECHANISM_TYPE mech,
        CK_BYTE_PTR hash, CK_ULONG hash_len,
        char **built, size_t *built_len) {

    /* These headers are defined in the following RFC
     *   - https://www.ietf.org/rfc/rfc3447.txt
     *     - Page 42
     */
    static const unsigned char pkcs1_5_hdr_sha1[15] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
        0x05, 0x00, 0x04, 0x14,
    };

    static const unsigned char pkcs1_5_hdr_sha256[19] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    };

    static const unsigned char pkcs1_5_hdr_sha384[19] = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
    };

    static const unsigned char pkcs1_5_hdr_sha512[19] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
    };

    const unsigned char *hdr;
    size_t hdr_size;

    switch(mech) {
    case CKM_SHA1_RSA_PKCS:
        hdr = pkcs1_5_hdr_sha1;
        hdr_size = sizeof(pkcs1_5_hdr_sha1);
        break;
    case CKM_SHA256_RSA_PKCS:
        hdr = pkcs1_5_hdr_sha256;
        hdr_size = sizeof(pkcs1_5_hdr_sha256);
        break;
    case CKM_SHA384_RSA_PKCS:
        hdr = pkcs1_5_hdr_sha384;
        hdr_size = sizeof(pkcs1_5_hdr_sha384);
        break;
    case CKM_SHA512_RSA_PKCS:
        hdr = pkcs1_5_hdr_sha512;
        hdr_size = sizeof(pkcs1_5_hdr_sha512);
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    /*
     * Build and populate a buffer with hdr + hash
     */
    char *b = calloc(1, hdr_size + hash_len);
    if (!b) {
        return CKR_HOST_MEMORY;
    }

    memcpy(b, hdr, hdr_size);
    memcpy(&b[hdr_size], hash, hash_len);

    *built_len = hdr_size + hash_len;
    *built = b;

    return CKR_OK;
}

static CK_RV apply_pkcs_1_5_pad(tobject *tobj, char *built, size_t built_len, char **padded, size_t *padded_len) {

    CK_ATTRIBUTE_PTR a = object_get_attribute(tobj, CKA_MODULUS);
    if (!a) {
        LOGE("Signing key has no modulus");
        return CKR_GENERAL_ERROR;
    }

    size_t out_len = a->ulValueLen;

    char *out = malloc(out_len);
    if (!out) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    /* Apply the PKCS1.5 padding */
    int rc = RSA_padding_add_PKCS1_type_1((unsigned char *)out, out_len,
            (const unsigned char *)built, built_len);
    if (!rc) {
        LOGE("Applying RSA padding failed");
    }

    *padded = out;
    *padded_len = out_len;

    return CKR_OK;
}

CK_RV sign_final(token *tok, unsigned char *signature, unsigned long *signature_len) {

    check_pointer(signature);
    check_pointer(signature_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    CK_BYTE_PTR hash = NULL;
    CK_ULONG hash_len = 0;

    sign_opdata *opdata = NULL;
    rv = token_opdata_get(tok, operation_sign, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    assert(opdata);

    tpm_ctx *tpm = tok->tctx;

    /*
     * Double checking of opdata to silence scan-build
     */
    if (opdata->do_hash) {

        hash_len = utils_get_halg_size(opdata->mtype);

        hash = malloc(hash_len);
        if (!hash) {
            LOGE("oom");
            rv = CKR_HOST_MEMORY;
            goto session_out;
        }

        rv = digest_final_op(tok, opdata->digest_opdata, hash, &hash_len);
        if (rv != CKR_OK) {
            goto session_out;
        }
    }

    /*
     * Their are two cases when we need to use the raw RSA Decrypt to sign the signature:
     *
     * CASE 1
     * In the case of CKM_RSA_PKCS the raw DigestInfo structure has been done off-card, just perform
     * a an RSA PKCS1.5 padded private-key encryption formally known as RSA decrypt.
     *
     * CASE 2
     * This method should also be used if the TPM doesn't support the hash algorithm, ie hash off card,
     * build digest info ASN1 structure, apply padding and RSA_Decrypt() AND the signing structure
     * is PKCS1.5
     */
    bool is_raw_sign = utils_mech_is_raw_sign(opdata->mtype);
    bool is_sw_hash = opdata->digest_opdata && opdata->digest_opdata->use_sw_hash;
    if (is_raw_sign || is_sw_hash) {

        bool is_rsa_pkcs1_5 = utils_mech_is_rsa_pkcs(opdata->mtype);
        if (!is_rsa_pkcs1_5) {
            LOGE("Do not support synthesizing non PKCS 1_5 signing/padding schemes");
            return CKR_MECHANISM_INVALID;
        }

        bool free_built = false;
        char *built = NULL;
        size_t built_len = 0;

        if(opdata->do_hash) {
            /*
             * Ok we did the hash, AND because of the entry condition, it's a SW hash, as is_raw_sign
             * means we didn't do the hashing. In this case, hash and hash_len should be set with
             * the digest.
             */
            assert(hash);
            assert(hash_len);
            assert(!opdata->buffer);

            rv = pkcs1_5_build_struct(opdata->mtype, hash, hash_len, &built, &built_len);
            if (rv != CKR_OK) {
                return rv;
            }

            free_built = true;

        } else {
            /*
             * We just mark the existing PKCS1.5 signing structure as
             * hash so we can just apply padding to hash below.
             */
            assert(!hash);
            assert(!hash_len);
            assert(opdata->buffer);

            built = (char *)opdata->buffer;
            built_len = twist_len(opdata->buffer);
        }

        /* apply padding */
        char *padded = NULL;
        size_t padded_len = 0;
        rv = apply_pkcs_1_5_pad(opdata->tobj, built, built_len, &padded, &padded_len);
        if (free_built) {
            free(built);
        }
        if (rv != CKR_OK) {
            goto session_out;
        }

        /* sign padded pkcs 1.5 structure */
        rv = tpm_rsa_decrypt(tpm, opdata->tobj, opdata->mtype, (CK_BYTE_PTR)padded, padded_len, signature, signature_len);
        free(padded);
        if (rv != CKR_OK) {
            goto session_out;
        }
    } else {
        bool res = tpm_sign(tpm, opdata->tobj, opdata->mtype, hash, hash_len, signature, signature_len);
        if (!res) {
            rv = CKR_GENERAL_ERROR;
            goto session_out;
        }
    }

    rv = CKR_OK;

session_out:

    free(hash);

    if (opdata && !opdata->do_hash) {
        twist_free(opdata->buffer);
    }

    token_opdata_clear(tok);
    digest_op_data_free(&opdata->digest_opdata);
    free(opdata);

    return rv;
}

CK_RV sign(token *tok, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len) {

    CK_RV rv = sign_update(tok, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return sign_final(tok, signature, signature_len);
}

CK_RV verify_init (token *tok, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_verify, tok, mechanism, key);
}

CK_RV verify_update (token *tok, unsigned char *part, unsigned long part_len) {

    return common_update(operation_verify, tok, part, part_len);
}

CK_RV verify_final (token *tok, unsigned char *signature, unsigned long signature_len) {

    check_pointer(signature);
    check_pointer(signature_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    sign_opdata *opdata = NULL;
    rv = token_opdata_get(tok, operation_verify, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    tpm_ctx *tpm = tok->tctx;

    // TODO mode to buffer size
    CK_BYTE hash[1024];
    CK_ULONG hash_len = sizeof(hash);

    rv = digest_final_op(tok, opdata->digest_opdata, hash, &hash_len);
    if (rv != CKR_OK) {
        return rv;
    }

    bool res = tpm_verify(tpm, opdata->tobj, hash, hash_len, signature, signature_len);
    rv = res ? CKR_OK : CKR_GENERAL_ERROR;
    if (rv != CKR_OK) {
        return rv;
    }

    token_opdata_clear(tok);
    free(opdata);

    return rv;
}

CK_RV verify(token *tok, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long signature_len) {

    CK_RV rv = verify_update(tok, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return verify_final(tok, signature, signature_len);
}
