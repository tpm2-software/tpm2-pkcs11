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

typedef CK_RV (*tpm_op)(tpm_encrypt_data *tpm_enc_data, CK_BYTE_PTR in, CK_ULONG inlen, CK_BYTE_PTR out, CK_ULONG_PTR outlen);

encrypt_op_data *encrypt_op_data_new(void) {

    return (encrypt_op_data *)calloc(1, sizeof(encrypt_op_data));
}

void encrypt_op_data_free(encrypt_op_data **opdata) {

    if (opdata) {
        tpm_encrypt_data_free((*opdata)->tpm_enc_data);
        free(*opdata);
        *opdata = NULL;
    }
}

static CK_RV common_init_op (token *tok, encrypt_op_data *supplied_opdata, operation op, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    check_pointer(mechanism);

    if (!supplied_opdata) {
        bool is_active = token_opdata_is_active(tok);
        if (is_active) {
            return CKR_OPERATION_ACTIVE;
        }
    }

    tobject *tobj;
    CK_RV rv = token_load_object(tok, key, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = object_mech_is_supported(tobj, mechanism);
    if (rv != CKR_OK) {
        return rv;
    }

    encrypt_op_data *opdata;
    if (!supplied_opdata) {
        opdata = encrypt_op_data_new();
        if (!opdata) {
            return CKR_HOST_MEMORY;
        }
    } else {
        opdata = supplied_opdata;
    }

    rv = tpm_encrypt_data_init(tok->tctx, tobj->handle, tobj->unsealed_auth, mechanism, &opdata->tpm_enc_data);
    if (rv != CKR_OK) {
        encrypt_op_data_free(&opdata);
        return rv;
    }

    if (!supplied_opdata) {
        token_opdata_set(tok, op, opdata);
    }

    return CKR_OK;
}

static CK_RV common_update_op (token *tok, encrypt_op_data *supplied_opdata, operation op,
        unsigned char *part, unsigned long part_len,
        unsigned char *encrypted_part, unsigned long *encrypted_part_len) {

    check_pointer(part);
    check_pointer(encrypted_part_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    twist input = twistbin_new(part, part_len);
    if (!input) {
        return CKR_HOST_MEMORY;
    }

    twist output = NULL;

    encrypt_op_data *opdata = NULL;
    if (!supplied_opdata) {
        rv = token_opdata_get(tok, op, &opdata);
        if (rv != CKR_OK) {
            goto out;
        }
    } else {
        opdata = supplied_opdata;
    }

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

    rv = fop(opdata->tpm_enc_data, part, part_len,
            encrypted_part, encrypted_part_len);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = CKR_OK;

out:
    twist_free(input);
    twist_free(output);

    return rv;
}

static CK_RV common_final_op(token *tok, encrypt_op_data *supplied_opdata, operation op,
        unsigned char *last_part, unsigned long *last_part_len) {

    /*
     * We have no use for these.
     */
    UNUSED(last_part);
    UNUSED(last_part_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    /* nothing to do if opdata is supplied externally */
    if (supplied_opdata) {
        return CKR_OK;
    }

    encrypt_op_data *opdata = NULL;
    rv = token_opdata_get(tok, op, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    encrypt_op_data_free(&opdata);

    token_opdata_clear(tok);

    return CKR_OK;
}

CK_RV encrypt_init_op (token *tok, encrypt_op_data *supplied_opdata, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init_op(tok, supplied_opdata, operation_encrypt, mechanism, key);
}

CK_RV decrypt_init_op (token *tok, encrypt_op_data *supplied_opdata, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init_op(tok, supplied_opdata, operation_decrypt, mechanism, key);
}

CK_RV encrypt_update_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {

    return common_update_op(tok, supplied_opdata, operation_encrypt, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV decrypt_update_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {

    return common_update_op(tok, supplied_opdata, operation_decrypt, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV encrypt_final_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len) {

    return common_final_op(tok, supplied_opdata, operation_encrypt, last_encrypted_part, last_encrypted_part_len);
}

CK_RV decrypt_final_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *last_part, unsigned long *last_part_len) {

    return common_final_op(tok, supplied_opdata, operation_decrypt, last_part, last_part_len);
}

CK_RV decrypt_oneshot_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len) {

    CK_RV rv = decrypt_update_op(tok, supplied_opdata, encrypted_data, encrypted_data_len,
            data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return decrypt_final_op(tok, supplied_opdata, NULL, NULL);
}

CK_RV encrypt_oneshot_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len) {

    CK_RV rv = encrypt_update_op (tok, supplied_opdata, data, data_len, encrypted_data, encrypted_data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return encrypt_final_op(tok, supplied_opdata, NULL, NULL);
}
