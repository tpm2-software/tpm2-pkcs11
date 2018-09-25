/* SPDX-License-Identifier: Apache-2.0 */
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

static CK_RV common_init(operation op, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    check_is_init();
    check_pointer(mechanism);

    CK_RV rv = CKR_GENERAL_ERROR;

    session_ctx *ctx = session_lookup(session);
    if (!ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx_is_user_logged_in(ctx)) {
        rv = CKR_USER_NOT_LOGGED_IN;
        goto out;
    }

    /*
     * Start a hashing sequence with the TPM, but only if requested.
     * Some callers perform hashing and padding "off-card".
     */
    uint32_t sequence_handle = 0;
    bool do_hash = is_hashing_needed(mechanism->mechanism);
    if (do_hash) {
        tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);
        rv = tpm_hash_init(tpm, mechanism->mechanism, &sequence_handle);
        if (rv != CKR_OK) {
            goto out;
        }
    }

    sign_opdata *opdata = (sign_opdata *)session_ctx_opdata_get(ctx, op);
    if (opdata) {
        rv = CKR_OPERATION_ACTIVE;
        goto out;
    }

    opdata = calloc(1, sizeof(*opdata));
    if (!opdata) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    rv = session_ctx_load_object(ctx, key, &opdata->tobj);
    if (rv != CKR_OK) {
        goto out;
    }

    opdata->do_hash = do_hash;
    opdata->mtype = mechanism->mechanism;
    opdata->sequence_handle = sequence_handle;

    /*
     * Store everything for later
     */
    session_ctx_opdata_set(ctx, op, opdata);

    rv = CKR_OK;

out:
    session_ctx_unlock(ctx);

    return rv;
}

static CK_RV common_update(operation op, CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len) {

    check_is_init();
    check_pointer(part);

    CK_RV rv = CKR_GENERAL_ERROR;

    session_ctx *ctx = session_lookup(session);
    if (!ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx_is_user_logged_in(ctx)) {
        rv = CKR_USER_NOT_LOGGED_IN;
        goto out;
    }

    sign_opdata *opdata = (sign_opdata *)session_ctx_opdata_get(ctx, op);
    if (!opdata) {
        rv = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    if (opdata->do_hash) {
        tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);
        rv = tpm_hash_update(tpm, opdata->sequence_handle, part, part_len);
        if (rv != CKR_OK) {
            goto out;
        }
    } else {
        twist tmp = twistbin_append(opdata->buffer, part, part_len);
        if (!tmp) {
            rv = CKR_HOST_MEMORY;
            goto out;
        }
        opdata->buffer = tmp;
    }

    rv = CKR_OK;

out:
    session_ctx_unlock(ctx);

    return rv;

}

CK_RV sign_init (CK_SESSION_HANDLE session, struct _CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_sign, session, mechanism, key);
}

CK_RV sign_update (CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len) {

    return common_update(operation_sign, session, part, part_len);
}

CK_RV sign_final (CK_SESSION_HANDLE session, unsigned char *signature, unsigned long *signature_len) {

    check_is_init();
    check_pointer(signature);
    check_pointer(signature_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    session_ctx *ctx = session_lookup(session);
    if (!ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx_is_user_logged_in(ctx)) {
        rv = CKR_USER_NOT_LOGGED_IN;
        goto out;
    }

    CK_BYTE_PTR hash = NULL;
    CK_ULONG hash_len = 0;

    sign_opdata *opdata = (sign_opdata *)session_ctx_opdata_get(ctx, operation_sign);
    if (!opdata) {
        rv = CKR_OPERATION_NOT_INITIALIZED;
        goto session_out;
    }

    tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);
    /*
     * Double checking of opdata to silence scan-build
     */
    if (opdata && opdata->do_hash) {

        // TODO dynamically get hash buffer size based on alg;
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
    session_ctx_opdata_set(ctx, operation_sign, NULL);
    free(opdata);

out:
    session_ctx_unlock(ctx);

    return rv;
}

CK_RV sign(CK_SESSION_HANDLE session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len) {

    CK_RV rv = sign_update(session, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return sign_final(session, signature, signature_len);
}

CK_RV verify_init (CK_SESSION_HANDLE session, struct _CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_verify, session, mechanism, key);
}

CK_RV verify_update (CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len) {

    return common_update(operation_verify, session, part, part_len);
}

CK_RV verify_final (CK_SESSION_HANDLE session, unsigned char *signature, unsigned long signature_len) {

    check_is_init();
    check_pointer(signature);
    check_pointer(signature_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    session_ctx *ctx = session_lookup(session);
    if (!ctx) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx_is_user_logged_in(ctx)) {
        rv = CKR_USER_NOT_LOGGED_IN;
        goto out;
    }

    sign_opdata *opdata = (sign_opdata *)session_ctx_opdata_get(ctx, operation_verify);
    if (!opdata) {
        rv = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);

    // TODO mode to buffer size
    CK_BYTE hash[1024];
    CK_ULONG hash_len = sizeof(hash);

    rv = tpm_hash_final(tpm, opdata->sequence_handle, hash, &hash_len);
    if (rv != CKR_OK) {
        goto out;
    }

    bool res = tpm_verify(tpm, opdata->tobj, hash, hash_len, signature, signature_len);
    rv = res ? CKR_OK : CKR_GENERAL_ERROR;
    if (rv != CKR_OK) {
        goto out;
    }

    session_ctx_opdata_set(ctx, operation_verify, NULL);
    free(opdata);

out:
    session_ctx_unlock(ctx);
    return rv;
}

CK_RV verify (CK_SESSION_HANDLE session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long signature_len) {

    CK_RV rv = verify_update(session, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return verify_final(session, signature, signature_len);
}
