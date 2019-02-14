/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "checks.h"
#include "digest.h"
#include "session.h"
#include "session_ctx.h"
#include "token.h"
#include "tpm.h"

static inline const char *get_openssl_err(void) {
    return ERR_error_string(ERR_get_error(), NULL);
}

digest_op_data *digest_op_data_new(void) {
    return calloc(1, sizeof(digest_op_data));
}

void digest_op_data_free(digest_op_data **opdata) {
    free(*opdata);
    *opdata = NULL;
}

const EVP_MD *ossl_halg_from_mech(CK_MECHANISM_TYPE mech) {

    switch(mech) {
        case CKM_SHA1_RSA_PKCS:
            return EVP_sha1();
        case CKM_SHA256_RSA_PKCS:
            return EVP_sha256();
        case CKM_SHA384_RSA_PKCS:
            return EVP_sha384();
        case CKM_SHA512_RSA_PKCS:
            return EVP_sha512();
        default:
            return NULL;
    }
    /* no return, not possible */
}

static CK_RV digest_sw_init(digest_op_data *opdata) {

    const EVP_MD *md = ossl_halg_from_mech(opdata->mechanism);
    if (!md) {
        return CKR_MECHANISM_INVALID;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        LOGE("%s", get_openssl_err());
        return CKR_GENERAL_ERROR;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        EVP_MD_CTX_destroy(mdctx);
        LOGE("%s", get_openssl_err());
        return CKR_GENERAL_ERROR;
    }

    opdata->mdctx = mdctx;

    return CKR_OK;
}

static CK_RV digest_sw_update(digest_op_data *opdata, const void *d, size_t cnt) {

    int rc = EVP_DigestUpdate(opdata->mdctx, d, cnt);
    if (!rc) {
        LOGE("%s", get_openssl_err());
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

static CK_RV digest_sw_final(digest_op_data *opdata, CK_BYTE_PTR md, CK_ULONG_PTR s) {

    CK_RV rv = CKR_GENERAL_ERROR;

    /*
     * Warn on truncation, this is likely not an issue unless digest message lengths overflow
     * int.
     */
    if (*s > INT_MAX) {
        LOGW("OSSL takes an int pointer, anything past %u is lost, got %lu", INT_MAX, *s);
    }

    int rc = EVP_DigestFinal_ex(opdata->mdctx, md, (unsigned int *)s);
    if (!rc) {
        LOGE("%s", get_openssl_err());
        goto out;
    }

    rv = CKR_OK;

out:
    EVP_MD_CTX_destroy(opdata->mdctx);

    return rv;
}

CK_RV digest_init_op(token *tok, digest_op_data *supplied_opdata, CK_MECHANISM_TYPE mechanism) {

    CK_RV rv = CKR_GENERAL_ERROR;

    if (!supplied_opdata) {
        bool is_active = token_opdata_is_active(tok);
        if (is_active) {
            return CKR_OPERATION_ACTIVE;
        }
    }

    /*
     * Start a hashing sequence with the TPM
     */
    tpm_ctx *tpm = tok->tctx;

    bool use_sw_hash = false;

    uint32_t sequence_handle;
    rv = tpm_hash_init(tpm, mechanism, &sequence_handle);
    if (rv != CKR_OK) {
        if (rv == CKR_MECHANISM_INVALID) {
            use_sw_hash = true;
        } else {
            return rv;
        }
    }

    digest_op_data *opdata = NULL;
    if (!supplied_opdata) {
        opdata = digest_op_data_new();
        if (!opdata) {
            return CKR_HOST_MEMORY;
        }
    } else {
        opdata = supplied_opdata;
    }

    opdata->use_sw_hash = use_sw_hash;
    opdata->mechanism = mechanism;

    if (use_sw_hash) {
        rv = digest_sw_init(opdata);
        if (rv != CKR_OK) {
            if (!supplied_opdata) {
                digest_op_data_free(&opdata);
            }
            return rv;
        }
    } else {
        opdata->sequence_handle = sequence_handle;
    }

    if (!supplied_opdata) {
        /* Store everything for later */
        token_opdata_set(tok, operation_digest, opdata);
    }

    return CKR_OK;
}

CK_RV digest_update_op(token *tok, digest_op_data *supplied_opdata, CK_BYTE_PTR part, CK_ULONG part_len) {

    check_pointer(part);

    CK_RV rv = CKR_GENERAL_ERROR;

    digest_op_data *opdata = NULL;
    if (!supplied_opdata) {
        rv = token_opdata_get(tok, operation_digest, &opdata);
        if (rv != CKR_OK) {
            return rv;
        }
    } else {
        opdata = supplied_opdata;
    }

    if (opdata->use_sw_hash) {
        rv = digest_sw_update(opdata, part, part_len);
    } else {
        tpm_ctx *tpm = tok->tctx;
        rv = tpm_hash_update(tpm, opdata->sequence_handle, part, part_len);
    }

    return rv;
}

CK_RV digest_final_op(token *tok, digest_op_data *supplied_opdata, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) {

    check_pointer(digest);
    check_pointer(digest_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    digest_op_data *opdata = NULL;
    if (!supplied_opdata) {
        rv = token_opdata_get(tok, operation_digest, &opdata);
        if (rv != CKR_OK) {
            return rv;
        }
    } else {
        opdata = supplied_opdata;
    }

    if (opdata->use_sw_hash) {
        rv = digest_sw_final(opdata, digest, digest_len);
    } else {
        tpm_ctx *tpm = tok->tctx;
        rv = tpm_hash_final(tpm, opdata->sequence_handle, digest, digest_len);
    }

    if (!supplied_opdata) {
        token_opdata_clear(tok);
        digest_op_data_free(&opdata);
    }

    return rv;
}

CK_RV digest_oneshot(token *tok, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) {

    CK_RV rv = digest_update(tok, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return digest_final(tok, digest, digest_len);
}
