/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "checks.h"
#include "digest.h"
#include "mech.h"
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

    /* nothing to do if NULL or pointer to NULL */
    if (!opdata || !*opdata) {
        return;
    }

    if ((*opdata)->mdctx) {
        EVP_MD_CTX_destroy((*opdata)->mdctx);
    }
    free(*opdata);
    *opdata = NULL;
}

static CK_RV digest_sw_init(mdetail *mdtl, digest_op_data *opdata) {

    const EVP_MD *md = NULL;
    CK_RV rv = mech_get_digester(mdtl, &opdata->mechanism, &md);
    if (rv != CKR_OK) {
        return rv;
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
    if (*s > UINT_MAX) {
        LOGW("OSSL takes an int pointer, anything past %u is lost, got %lu", UINT_MAX, *s);
    }

    int rc = EVP_DigestFinal_ex(opdata->mdctx, md, (unsigned int *)s);
    if (!rc) {
        LOGE("%s", get_openssl_err());
        goto out;
    }

    rv = CKR_OK;

out:
    EVP_MD_CTX_destroy(opdata->mdctx);
    opdata->mdctx = NULL;

    return rv;
}

static CK_RV digest_get_min_size(session_ctx *ctx,
        digest_op_data *opdata, CK_ULONG_PTR digest_len) {

    if (!opdata) {
        CK_RV rv = session_ctx_opdata_get(ctx, operation_digest, &opdata);
        if (rv != CKR_OK) {
            LOGE("Could not get session data");
            return rv;
        }
    }

    *digest_len = EVP_MD_CTX_size(opdata->mdctx);
    return CKR_OK;
}

CK_RV digest_init_op(session_ctx *ctx, digest_op_data *supplied_opdata, CK_MECHANISM_PTR mechanism) {

    CK_RV rv = CKR_GENERAL_ERROR;

    if (!supplied_opdata) {
        bool is_active = session_ctx_opdata_is_active(ctx);
        if (is_active) {
            return CKR_OPERATION_ACTIVE;
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

    opdata->mechanism = *mechanism;

    token *tok = session_ctx_get_token(ctx);

    rv = digest_sw_init(tok->mdtl, opdata);
    if (rv != CKR_OK) {
        if (!supplied_opdata) {
            digest_op_data_free(&opdata);
        }
        return rv;
    }

    if (!supplied_opdata) {
        /* Store everything for later */
        session_ctx_opdata_set(ctx, operation_digest, NULL, opdata, (opdata_free_fn)digest_op_data_free);
    }

    return CKR_OK;
}

CK_RV digest_update_op(session_ctx *ctx, digest_op_data *supplied_opdata, CK_BYTE_PTR part, CK_ULONG part_len) {

    check_pointer(part);

    CK_RV rv = CKR_GENERAL_ERROR;

    digest_op_data *opdata = NULL;
    if (!supplied_opdata) {
        rv = session_ctx_opdata_get(ctx, operation_digest, &opdata);
        if (rv != CKR_OK) {
            return rv;
        }
    } else {
        opdata = supplied_opdata;
    }

    return digest_sw_update(opdata, part, part_len);
}

CK_RV digest_final_op(session_ctx *ctx, digest_op_data *supplied_opdata, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) {

    check_pointer(digest_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    digest_op_data *opdata = NULL;
    if (!supplied_opdata) {
        rv = session_ctx_opdata_get(ctx, operation_digest, &opdata);
        if (rv != CKR_OK) {
            return rv;
        }
    } else {
        opdata = supplied_opdata;
    }

    CK_ULONG min_len = 0;
    rv = digest_get_min_size(ctx, opdata, &min_len);
    if (rv != CKR_OK) {
        goto error;
    }

    if (!digest) {
        *digest_len = min_len;
        return CKR_OK;
    } else if (*digest_len < min_len) {
        *digest_len = min_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    rv = digest_sw_final(opdata, digest, digest_len);

error:
    if (!supplied_opdata) {
        session_ctx_opdata_clear(ctx);
    }

    return rv;
}

CK_RV digest_oneshot(session_ctx *ctx, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) {

    CK_ULONG min_len = 0;
    CK_RV rv = digest_get_min_size(ctx, NULL, &min_len);
    if (rv != CKR_OK) {
        /* fatal error ends digest sate */
        session_ctx_opdata_clear(ctx);
        return rv;
    }

    if (!digest) {
        *digest_len = min_len;
        return CKR_OK;
    } else if (*digest_len < min_len) {
        *digest_len = min_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    rv = digest_update(ctx, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return digest_final(ctx, digest, digest_len);
}
