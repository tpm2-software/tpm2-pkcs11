/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <stdlib.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "checks.h"
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
    union {
        twist buffer;
        uint32_t sequence_handle;
    };
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

static CK_RV common_init(operation op, token *tok, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    check_pointer(mechanism);

    CK_RV rv = CKR_GENERAL_ERROR;

    /*
     * Start a hashing sequence with the TPM, but only if requested.
     * Some callers perform hashing and padding "off-card".
     */
    uint32_t sequence_handle = 0;
    bool do_hash = is_hashing_needed(mechanism->mechanism);
    if (do_hash) {
        tpm_ctx *tpm = tok->tctx;
        rv = tpm_hash_init(tpm, mechanism->mechanism, &sequence_handle);
        if (rv != CKR_OK) {
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
    opdata->sequence_handle = sequence_handle;

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
        tpm_ctx *tpm = tok->tctx;
        rv = tpm_hash_update(tpm, opdata->sequence_handle, part, part_len);
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

        rv = tpm_hash_final(tpm, opdata->sequence_handle, hash, &hash_len);
        if (rv != CKR_OK) {
            goto session_out;
        }
    }

    /*
     * In the case of CKM_RSA_PKCS the raw DigestInfo structure has been done off-card, just perform
     * a an RSA PKCS1.5 padded private-key encryption formally known as RSA decrypt.
     *
     * This method should also be used if the TPM doesn't support the hash algorithm, ie hash off card,
     * build digest info ASN1 structure, apply padding and RSA_Decrypt().
     */
    if (opdata->mtype == CKM_RSA_PKCS) {

        CK_ATTRIBUTE_PTR a = object_get_attribute(opdata->tobj, CKA_MODULUS);
        if (!a) {
            LOGE("Signing key has no modulus");
            goto session_out;
        }

        hash_len = a->ulValueLen;

        hash = malloc(hash_len);
        if (!hash_len) {
            LOGE("oom");
            rv = CKR_HOST_MEMORY;
            goto session_out;
        }

        /* Apply the PKCS1.5 padding */
        unsigned int len = twist_len(opdata->buffer);
        int rc = RSA_padding_add_PKCS1_type_1(hash, hash_len,
                (unsigned char *)opdata->buffer, len);
        if (!rc) {
            LOGE("Applying RSA padding failed");
            goto session_out;
        }

        rv = tpm_rsa_decrypt(tpm, opdata->tobj, opdata->mtype, hash, hash_len, signature, signature_len);
        if (rv != CKR_OK) {
            goto session_out;
        }
    } else {
        bool res = tpm_sign(tpm, opdata->tobj, opdata->mtype, hash, hash_len, signature, signature_len);
        if (!res) {
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

    rv = tpm_hash_final(tpm, opdata->sequence_handle, hash, &hash_len);
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
