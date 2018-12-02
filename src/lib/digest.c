/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <stdint.h>

#include "checks.h"
#include "digest.h"
#include "session.h"
#include "session_ctx.h"
#include "token.h"
#include "tpm.h"

/*
 * TODO The digest code could be refactored to be shared between this and sign.
 */

typedef struct digest_op_data digest_op_data;
struct digest_op_data {
    tobject *tobj;
    CK_MECHANISM_TYPE mode;
    uint32_t sequence_handle;
};

CK_RV digest_init(token *tok, CK_MECHANISM *mechanism) {

    check_pointer(mechanism);

    CK_RV rv = CKR_GENERAL_ERROR;

    bool is_active = token_opdata_is_active(tok);
    if (is_active) {
        return CKR_OPERATION_ACTIVE;
    }

    /*
     * Start a hashing sequence with the TPM
     */
    tpm_ctx *tpm = tok->tctx;

    uint32_t sequence_handle;
    rv = tpm_hash_init(tpm, mechanism->mechanism, &sequence_handle);
    if (rv != CKR_OK) {
        return rv;
    }

    digest_op_data *opdata = calloc(1, sizeof(*opdata));
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->mode = mechanism->mechanism;
    opdata->sequence_handle = sequence_handle;

    /* Store everything for later */
    token_opdata_set(tok, operation_digest, opdata);

    return CKR_OK;
}

CK_RV digest_update(token *tok, unsigned char *part, unsigned long part_len) {

    check_pointer(part);

    CK_RV rv = CKR_GENERAL_ERROR;

    digest_op_data *opdata = NULL;
    rv = token_opdata_get(tok, operation_digest, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    tpm_ctx *tpm = tok->tctx;

    rv = tpm_hash_update(tpm, opdata->sequence_handle, part, part_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return CKR_OK;
}

CK_RV digest_final(token *tok, unsigned char *digest, unsigned long *digest_len) {

    check_pointer(digest);
    check_pointer(digest_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    digest_op_data *opdata = NULL;
    rv = token_opdata_get(tok, operation_digest, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    tpm_ctx *tpm = tok->tctx;

    rv = tpm_hash_final(tpm, opdata->sequence_handle, digest, digest_len);

    token_opdata_clear(tok);

    free(opdata);

    return rv;
}

CK_RV digest_oneshot(token *tok, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len) {

    CK_RV rv = digest_update(tok, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return digest_final(tok, digest, digest_len);
}
