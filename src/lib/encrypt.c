/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include "checks.h"
#include "encrypt.h"
#include "session.h"
#include "session_ctx.h"
#include "token.h"
#include "tpm.h"

typedef struct encrypt_op_data encrypt_op_data;
struct encrypt_op_data {
    tobject *object;
    twist iv;
    CK_MECHANISM_TYPE mode;
};

typedef CK_RV (*tpm_op)(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mode, twist iv, twist data_in, twist *data_out, twist *iv_out);

static CK_RV common_init (token *tok, operation op, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    check_pointer(mechanism);

    /*
     * TODO how is mode determined? Does a key have a fixed mode or is it flexible?
     */
    twist iv;
    CK_MECHANISM_TYPE mode;
    switch(mechanism->mechanism) {
    case CKM_AES_CBC_PAD:
        iv = twistbin_new(mechanism->pParameter, mechanism->ulParameterLen);
        if (!iv) {
            return CKR_HOST_MEMORY;
        }
        mode = CKM_AES_CBC;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    CK_RV rv = CKR_GENERAL_ERROR;

    bool is_active = token_opdata_is_active(tok);
    if (is_active) {
        rv = CKR_OPERATION_ACTIVE;
        return rv;
    }

    tobject *tobj;
    rv = token_load_object(tok, key, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    encrypt_op_data *opdata = (encrypt_op_data *)calloc(1, sizeof(*opdata));
    if (!opdata) {
        return CKR_HOST_MEMORY;
    }

    opdata->object = tobj;
    opdata->mode = mode;
    opdata->iv = iv;

    token_opdata_set(tok, op, opdata);

    return CKR_OK;
}

static CK_RV common_update (token *tok, operation op,
        unsigned char *part, unsigned long part_len,
        unsigned char *encrypted_part, unsigned long *encrypted_part_len) {

    check_pointer(part);
    check_pointer(encrypted_part);
    check_pointer(encrypted_part_len);

    tpm_op fop;
    switch(op) {
    case operation_encrypt:
        fop = tpm_encrypt;
        break;
    case operation_decrypt:
        fop = tpm_decrypt;
        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    CK_RV rv = CKR_GENERAL_ERROR;

    /*
     * XXX
     * Encrypted part len must be the same size as part
     * Hardcode to AES block size of 16, we will need to make
     * this check more robust later.
     */
    if (part_len != *encrypted_part_len && part_len != 16) {
        return CKR_BUFFER_TOO_SMALL;
    }

    twist input = twistbin_new(part, part_len);
    if (!input) {
        return CKR_HOST_MEMORY;
    }

    twist output = NULL;
    twist iv_out = NULL;

    encrypt_op_data *opdata = NULL;
    rv = token_opdata_get(tok, op, &opdata);
    if (rv != CKR_OK) {
        goto out;
    }

    tpm_ctx *tpm = tok->tctx;

    rv = fop(tpm, opdata->object, opdata->mode, opdata->iv, input, &output, &iv_out);
    if (rv != CKR_OK) {
        goto out;
    }

    /* swap iv's */
    twist_free(opdata->iv);
    opdata->iv = iv_out;

    /* copy ciphertext back to user structures */
    *encrypted_part_len = twist_len(output);
    memcpy(encrypted_part, output, *encrypted_part_len);

    rv = CKR_OK;

out:
    twist_free(input);
    twist_free(output);

    return rv;
}

static CK_RV common_final(token *tok, operation op,
        unsigned char *last_part, unsigned long *last_part_len) {

    /*
     * We have no use for these.
     */
    UNUSED(last_part);
    UNUSED(last_part_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    encrypt_op_data *opdata = NULL;
    rv = token_opdata_get(tok, op, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    twist_free(opdata->iv);
    free(opdata);

    token_opdata_clear(tok);

    return CKR_OK;
}

CK_RV encrypt_init (token *tok, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(tok, operation_encrypt, mechanism, key);
}

CK_RV decrypt_init (token *tok, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(tok, operation_decrypt, mechanism, key);
}

CK_RV encrypt_update (token *tok, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {

    return common_update(tok, operation_encrypt, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV decrypt_update (token *tok, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {

    return common_update(tok, operation_decrypt, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV encrypt_final (token *tok, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len) {

    return common_final(tok, operation_encrypt, last_encrypted_part, last_encrypted_part_len);
}

CK_RV decrypt_final (token *tok, unsigned char *last_part, unsigned long *last_part_len) {

    return common_final(tok, operation_decrypt, last_part, last_part_len);
}

CK_RV decrypt_oneshot (token *tok, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len) {

    CK_RV rv = decrypt_update(tok, encrypted_data, encrypted_data_len,
            data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return decrypt_final(tok, NULL, NULL);
}

CK_RV encrypt_oneshot (token *tok, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len) {

    CK_RV rv = encrypt_update(tok, data, data_len, encrypted_data, encrypted_data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return encrypt_final(tok, NULL, NULL);
}
