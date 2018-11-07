/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include "checks.h"
#include "encrypt.h"
#include "session.h"
#include "session_ctx.h"
#include "tpm.h"

typedef struct encrypt_op_data encrypt_op_data;
struct encrypt_op_data {
    tobject *object;
    twist iv;
    CK_MECHANISM_TYPE mode;
};

typedef CK_RV (*tpm_op)(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mode, twist iv, twist data_in, twist *data_out, twist *iv_out);

static CK_RV common_init (operation op, CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    check_is_init();
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

    session_ctx *ctx = NULL;
    rv = session_lookup(session, &ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    if (!session_ctx_is_user_logged_in(ctx)) {
        rv = CKR_USER_NOT_LOGGED_IN;
        goto out;
    }

    encrypt_op_data *opdata = (encrypt_op_data *)session_ctx_opdata_get(ctx, op);
    if (opdata) {
        rv = CKR_OPERATION_ACTIVE;
        goto out;
    }

    tobject *tobj;
    rv = session_ctx_load_object(ctx, key, &tobj);
    if (rv != CKR_OK) {
        goto out;
    }

    opdata = (encrypt_op_data *)calloc(1, sizeof(*opdata));
    if (!opdata) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    opdata->object = tobj;
    opdata->mode = mode;
    opdata->iv = iv;

    session_ctx_opdata_set(ctx, op, opdata);

    rv = CKR_OK;

out:
    session_ctx_unlock(ctx);

    return rv;
}

static CK_RV common_update (operation op, CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {

    check_is_init();
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

    session_ctx *ctx = NULL;
    rv = session_lookup(session, &ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    if (!session_ctx_is_user_logged_in(ctx)) {
        rv = CKR_USER_NOT_LOGGED_IN;
        goto out;
    }

    encrypt_op_data *opdata = session_ctx_opdata_get(ctx, op);
    if (!opdata) {
        rv = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    tpm_ctx *tpm = session_ctx_get_tpm_ctx(ctx);

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
    session_ctx_unlock(ctx);

    twist_free(input);
    twist_free(output);

    return rv;
}

static CK_RV common_final (operation op, CK_SESSION_HANDLE session, unsigned char *last_part, unsigned long *last_part_len) {

    check_is_init();

    /*
     * We have no use for these.
     */
    UNUSED(last_part);
    UNUSED(last_part_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    session_ctx *ctx = NULL;
    rv = session_lookup(session, &ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    if (!session_ctx_is_user_logged_in(ctx)) {
        rv = CKR_USER_NOT_LOGGED_IN;
        goto out;
    }

    encrypt_op_data *opdata = session_ctx_opdata_get(ctx, op);
    if (!opdata) {
        rv = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    twist_free(opdata->iv);
    free(opdata);

    session_ctx_opdata_set(ctx, op, NULL);

    rv = CKR_OK;

out:
    session_ctx_unlock(ctx);

    return rv;
}

CK_RV encrypt_init (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_encrypt, session, mechanism, key);
}

CK_RV decrypt_init (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_decrypt, session, mechanism, key);
}

CK_RV encrypt_update (CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {

    return common_update(operation_encrypt, session, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV decrypt_update (CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {

    return common_update(operation_decrypt, session, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV encrypt_final (CK_SESSION_HANDLE session, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len) {

    return common_final(operation_encrypt, session, last_encrypted_part, last_encrypted_part_len);
}

CK_RV decrypt_final (CK_SESSION_HANDLE session, unsigned char *last_part, unsigned long *last_part_len) {

    return common_final(operation_decrypt, session, last_part, last_part_len);
}
