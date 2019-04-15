/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include "config.h"
#include <assert.h>
#include <stdlib.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "checks.h"
#include "digest.h"
#include "encrypt.h"
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
    encrypt_op_data *encrypt_opdata;
};

static sign_opdata *sign_opdata_new(void) {
    return calloc(1, sizeof(sign_opdata));
}

static void sign_opdata_free(sign_opdata **opdata) {
    digest_op_data_free(&(*opdata)->digest_opdata);

    if (*opdata && !(*opdata)->do_hash) {
        twist_free((*opdata)->buffer);
    }

    free(*opdata);

    *opdata = NULL;
}


static bool is_hashing_needed(CK_MECHANISM_TYPE mech) {

    switch(mech) {
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_ECDSA_SHA1:
        return true;
    case CKM_ECDSA:
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
    case CKM_RSA_PKCS:
        /* falls-thru */
    case CKM_SHA1_RSA_PKCS:
        /* falls-thru */
    case CKM_SHA256_RSA_PKCS:
        /* falls-thru */
    case CKM_SHA384_RSA_PKCS:
        /* falls-thru */
    case CKM_SHA512_RSA_PKCS:
        /* falls-thru */
    case CKM_AES_CBC:
        /* falls-thru */
    case CKM_ECDSA:
        /* falls-thru */
    case CKM_ECDSA_SHA1:
        return true;
        /* no default */
    }

    return false;
}

static CK_RV ec_fixup_size(CK_MECHANISM_TYPE mech, tobject *tobj, CK_ULONG_PTR signature_len) {

    if (mech != CKM_ECDSA
            || mech != CKM_ECDSA_SHA1) {
        /* nothing to fix up */
        return CKR_OK;
    }

    CK_ATTRIBUTE_PTR a = object_get_attribute_by_type(tobj, CKA_EC_PARAMS);

    int nid = 0;
    CK_RV rv = ec_params_to_nid(a, &nid);
    if (rv != CKR_OK) {
        return rv;
    }

    /*
     * Math below is based off of ECDSA signature:
     * SEQUENCE (2 elem)
     *  INTEGER R
     *  INTEGER S
     *
     *  Integers R and S are bounded by keysize in bytes, followed by their
     *  respective headers(2bytes) followed by the SEQUENCE header(2 bytes)
     */
    unsigned keysize;

    switch (nid) {
    case NID_X9_62_prime192v1:
        keysize = 24;
    break;
    case NID_secp224r1:
        keysize = 28;
    break;
    case NID_X9_62_prime256v1:
        keysize = 32;
    break;
    case NID_secp384r1:
        keysize = 48;
    break;
    case NID_secp521r1:
        keysize = 66; /* round up */
    break;
    default:
        LOGE("Unsupported nid to tpm signature size maaping: %d", nid);
        return CKR_CURVE_NOT_SUPPORTED;
    }

    /* R and S are INTEGER objects with a header and len byte */
    static const unsigned INT_HDR = 2U;
    /* R and S are combined in a SEQUENCE object with a header and len byte */
    static const unsigned SEQ_HDR = 2U;
    /* an R or S with a high bit set needs an extra nul byte so it's not negative (twos comp)*/
    static const unsigned EXTRA = 1U;

    unsigned tmp = ((keysize + INT_HDR + EXTRA) * 2); /* x2 1 for R and 1 for S */

    tmp += SEQ_HDR;

    *signature_len = tmp;

    return CKR_OK;
}


static CK_RV common_init(operation op, session_ctx *ctx, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    check_pointer(mechanism);

    CK_RV rv = CKR_GENERAL_ERROR;

    bool is_mech_sup = is_mech_supported(mechanism->mechanism);
    if (!is_mech_sup) {
        return CKR_MECHANISM_INVALID;
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    digest_op_data *digest_opdata = NULL;
    bool do_hash = is_hashing_needed(mechanism->mechanism);
    if (do_hash) {

        digest_opdata = digest_op_data_new();
        if (!digest_opdata) {
            return CKR_HOST_MEMORY;
        }

        rv = digest_init_op(ctx, digest_opdata, mechanism->mechanism);
        if (rv != CKR_OK) {
            digest_op_data_free(&digest_opdata);
            return rv;
        }
    }

    bool is_active = session_ctx_opdata_is_active(ctx);
    if (is_active) {
        digest_op_data_free(&digest_opdata);
        return CKR_OPERATION_ACTIVE;
    }

    sign_opdata *opdata = sign_opdata_new();
    if (!opdata) {
        digest_op_data_free(&digest_opdata);
        return CKR_HOST_MEMORY;
    }

    rv = token_load_object(tok, key, &opdata->tobj);
    if (rv != CKR_OK) {
        digest_op_data_free(&digest_opdata);
        sign_opdata_free(&opdata);
        return rv;
    }

    opdata->do_hash = do_hash;
    opdata->mtype = mechanism->mechanism;
    opdata->digest_opdata = digest_opdata;

    /*
     * Store everything for later
     */
    session_ctx_opdata_set(ctx, op, opdata, (opdata_free_fn)sign_opdata_free);

    return CKR_OK;
}

static CK_RV common_update(operation op, session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len) {

    check_pointer(part);

    CK_RV rv = CKR_GENERAL_ERROR;

    sign_opdata *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, op, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    if (opdata->do_hash) {
        rv = digest_update_op(ctx, opdata->digest_opdata, part, part_len);
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

CK_RV sign_init(session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_sign, ctx, mechanism, key);
}

CK_RV sign_update(session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len) {

    return common_update(operation_sign, ctx, part, part_len);
}

static CK_RV pkcs1_5_build_struct(CK_MECHANISM_TYPE mech,
        CK_BYTE_PTR hash, CK_ULONG hash_len,
        char **built, size_t *built_len) {

    /* These headers are defined in the following RFC
     *   - https://www.ietf.org/rfc/rfc3447.txt
     *     - Page 42
     */
    static const CK_BYTE pkcs1_5_hdr_sha1[15] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
        0x05, 0x00, 0x04, 0x14,
    };

    static const CK_BYTE pkcs1_5_hdr_sha256[19] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    };

    static const CK_BYTE pkcs1_5_hdr_sha384[19] = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
    };

    static const CK_BYTE pkcs1_5_hdr_sha512[19] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
    };

    const CK_BYTE *hdr;
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

    CK_ATTRIBUTE_PTR a = object_get_attribute_by_type(tobj, CKA_MODULUS_BITS);
    if (!a) {
        LOGE("Signing key has no modulus");
        return CKR_GENERAL_ERROR;
    }

    if (a->ulValueLen != sizeof(CK_ULONG)) {
        LOGE("Modulus bit pointer data not size of CK_ULONG, got %lu, expected %zu",
                a->ulValueLen, sizeof(CK_ULONG));
        return CKR_GENERAL_ERROR;
    }

    CK_ULONG_PTR keybits = (CK_ULONG_PTR)a->pValue;

    size_t out_len = *keybits / 8;

    char *out = malloc(out_len);
    if (!out) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    /* Apply the PKCS1.5 padding */
    int rc = RSA_padding_add_PKCS1_type_1((CK_BYTE_PTR )out, out_len,
            (const CK_BYTE_PTR )built, built_len);
    if (!rc) {
        LOGE("Applying RSA padding failed");
    }

    *padded = out;
    *padded_len = out_len;

    return CKR_OK;
}

CK_RV sign_final_ex(session_ctx *ctx, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len, bool is_oneshot) {

    check_pointer(signature_len);

    bool reset_ctx = false;

    CK_RV rv = CKR_GENERAL_ERROR;

    CK_BYTE_PTR hash = NULL;
    CK_ULONG hash_len = 0;

    sign_opdata *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, operation_sign, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }
    assert(opdata);

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tpm_ctx *tpm = tok->tctx;

    if (opdata->do_hash) {

        hash_len = utils_get_halg_size(opdata->mtype);

        hash = malloc(hash_len);
        if (!hash) {
            LOGE("oom");
            rv = CKR_HOST_MEMORY;
            goto session_out;
        }

        rv = digest_final_op(ctx, opdata->digest_opdata, hash, &hash_len);
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
        encrypt_op_data *encrypt_opdata = encrypt_op_data_new();
        if (!encrypt_opdata) {
            free(padded);
            rv = CKR_HOST_MEMORY;
            goto session_out;
        }

        /* perform a RAW RSA encryption */
        CK_MECHANISM mechanism = {
                CKM_RSA_X_509, NULL, 0
        };

        /* RSA Decrypt is the RSA operation with the private key, which is what we want */
        rv = decrypt_init_op(ctx, encrypt_opdata, &mechanism, opdata->tobj->id);
        if (rv != CKR_OK) {
            free(padded);
            encrypt_op_data_free(&encrypt_opdata);
            goto session_out;
        }

        rv = decrypt_oneshot_op(ctx, encrypt_opdata, (CK_BYTE_PTR)padded, padded_len, signature, signature_len);
        free(padded);
        encrypt_op_data_free(&encrypt_opdata);
        if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
            goto session_out;
        }
    } else {

        /*
         * CKM_ECDSA is never considered a "raw sign" since the TPM natively supports it
         * by setting the hashalg to TPM2_ALG_NULL. So just make sure that we propagate
         * the raw data provided (hash) into the hash variable and perform a sign.
         */
        if (opdata->mtype == CKM_ECDSA){
            assert(!hash);
            assert(!hash_len);
            assert(opdata->buffer);
            hash_len = twist_len(opdata->buffer);
            assert(hash_len >= 20); /* Minimum for SHA1 */
            hash = malloc(hash_len);
            if (!hash) {
                LOGE("oom");
                rv = CKR_HOST_MEMORY;
                goto session_out;
            }

            memcpy(hash, opdata->buffer, hash_len);
        }

        rv = tpm_sign(tpm, opdata->tobj, opdata->mtype, hash, hash_len, signature, signature_len);
        if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
            goto session_out;
        }
    }

    /*
     * Detect 1 of 3 states:
     *   - 1 - everything is ok from enc/sign and sig is set (continue normally)
     *   - 2 - buffer too small from enc/sign and sig is set (reset hashing state and keep sign operation alive)
     *   - 3 - everything is ok but sig is NULL, handle like state 2.
     *
     * Reset the hashing state IF we're actually doing the hash internally
     */
    reset_ctx = (rv == CKR_BUFFER_TOO_SMALL || !signature);
    if (reset_ctx) {
        if (opdata->do_hash) {
            /* reset the hashing state */
            digest_op_data *new_digest_state = digest_op_data_new();
            if (!new_digest_state) {
                rv = CKR_HOST_MEMORY;
                reset_ctx = false;
                goto session_out;
            }

            assert(opdata->digest_opdata);

            CK_RV tmp = digest_init_op(ctx, new_digest_state, opdata->digest_opdata->mechanism);
            if (tmp != CKR_OK) {
                digest_op_data_free(&new_digest_state);
                reset_ctx = false;
                goto session_out;
            }

            digest_op_data_free(&opdata->digest_opdata);
            opdata->digest_opdata = new_digest_state;

            /* ec signature size is not stable between calls, fix it up */
            tmp = ec_fixup_size(opdata->mtype, opdata->tobj, signature_len);
            if (tmp != CKR_OK) {
                digest_op_data_free(&new_digest_state);
                reset_ctx = false;
                goto session_out;
            }

        } else if (is_oneshot) {
            twist_free(opdata->buffer);
            opdata->buffer = NULL;
        }
    } else {
        /* not resetting the state, and all is well */
        rv = CKR_OK;
    }

session_out:

    assert(opdata->tobj);
    if (!reset_ctx) {
        CK_RV tmp_rv = tobject_user_decrement(opdata->tobj);
        if (tmp_rv != CKR_OK && rv == CKR_OK) {
            rv = tmp_rv;
        }
    }

    if (!reset_ctx) {
        session_ctx_opdata_clear(ctx);
    }

    free(hash);

    return rv;
}

CK_RV sign(session_ctx *ctx, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG *signature_len) {

    CK_RV rv = sign_update(ctx, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }
    return sign_final_ex(ctx, signature, signature_len, true);
}

CK_RV verify_init (session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_verify, ctx, mechanism, key);
}

CK_RV verify_update (session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len) {

    return common_update(operation_verify, ctx, part, part_len);
}

CK_RV verify_final (session_ctx *ctx, CK_BYTE_PTR signature, CK_ULONG signature_len) {

    check_pointer(signature);
    check_pointer(signature_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    sign_opdata *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, operation_verify, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tpm_ctx *tpm = tok->tctx;

    // TODO mode to buffer size
    CK_BYTE hash[1024];
    CK_ULONG hash_len = sizeof(hash);

    if (opdata->do_hash) {
        rv = digest_final_op(ctx, opdata->digest_opdata, hash, &hash_len);
        if (rv != CKR_OK) {
            goto out;
        }
    } else {
        size_t datalen = twist_len(opdata->buffer);
        if (datalen > hash_len) {
            LOGE("Internal buffer too small, got: %zu expected less than %zu",
                    datalen, hash_len);
            return CKR_GENERAL_ERROR;
        }
        hash_len = datalen;
        memcpy(hash, opdata->buffer, datalen);
    }

    rv = tpm_verify(tpm, opdata->tobj, opdata->mtype, hash, hash_len, signature, signature_len);

out:
    assert(opdata->tobj);
    CK_RV tmp_rv = tobject_user_decrement(opdata->tobj);
    if (tmp_rv != CKR_OK && rv == CKR_OK) {
        rv = tmp_rv;
    }

    session_ctx_opdata_clear(ctx);

    return rv;
}

CK_RV verify(session_ctx *ctx, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG signature_len) {

    CK_RV rv = verify_update(ctx, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return verify_final(ctx, signature, signature_len);
}
