/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "db.h"
#include "pkcs11.h"
#include "slot.h"
#include "token.h"
#include "utils.h"

static struct {
    size_t token_cnt;
    token *token;
} global;

CK_RV slot_init(void) {

    return db_get_tokens(&global.token, &global.token_cnt);
}

void slot_destroy(void) {

    token_free_list(global.token, global.token_cnt);
}

token *slot_get_token(CK_SLOT_ID slot_id) {

    size_t i;
    for (i=0; i < global.token_cnt; i++) {
        token *t = &global.token[i];
        if (slot_id == t->id) {
            return t;
        }
    }

    return NULL;
}

CK_RV slot_get_list (CK_BYTE token_present, CK_SLOT_ID *slot_list, CK_ULONG_PTR count) {

    /*
     * True for token present only returns slots with tokens, False all slots. All
     * of our slots always have a token, so we can ignore this.
     */
    UNUSED(token_present);

    check_pointer(count);

    if (!slot_list) {
        *count = global.token_cnt;
        return CKR_OK;
    }

    if (*count < global.token_cnt) {
        *count = global.token_cnt;
        return CKR_BUFFER_TOO_SMALL;
    }

    size_t i;
    for (i=0; i < global.token_cnt; i++) {
        token *t = &global.token[i];
        slot_list[i] = t->id;
    }

    *count = global.token_cnt;

    return CKR_OK;
}

CK_RV slot_get_info (CK_SLOT_ID slot_id, CK_SLOT_INFO *info) {

    token *token;
    CK_TOKEN_INFO token_info;

    check_pointer(info);

    token = slot_get_token(slot_id);
    if (!token) {
        return CKR_SLOT_ID_INVALID;
    }

    memset(info, 0, sizeof(*info));

    if (token_get_info(token, &token_info)) {
        return CKR_GENERAL_ERROR;
    }

    str_padded_copy(info->manufacturerID, token_info.manufacturerID, sizeof(info->manufacturerID));
    str_padded_copy(info->slotDescription, token_info.label, sizeof(info->slotDescription));
    info->hardwareVersion = token_info.hardwareVersion;
    info->firmwareVersion = token_info.firmwareVersion;

    info->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

    return CKR_OK;
}


CK_RV slot_mechanism_list_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE *mechanism_list, CK_ULONG_PTR count) {
    token *t = slot_get_token(slot_id);
    if (!t) {
        return CKR_SLOT_ID_INVALID;
    }

    CK_RV rv = tpm2_getmechanisms(t->tctx, mechanism_list, count);
    return rv;
}

CK_RV slot_mechanism_info_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *info) {

    check_pointer(info);

    if (!slot_get_token(slot_id)) {
        return CKR_SLOT_ID_INVALID;
    }

    /* TODO pull these from TPM, currently they match the simulator */
    CK_ULONG aes_min_keysize = 128/8; // in bytes
    CK_ULONG aes_max_keysize = 256/8; // in bytes
    CK_ULONG ecc_min_keysize = 256;
    CK_ULONG ecc_max_keysize = 384;
    CK_ULONG rsa_min_keysize = 1024;
    CK_ULONG rsa_max_keysize = 2048;

    switch(type) {
    /* AES based crypto */
    /* Todo: Check if HW or Software and support */
    case CKM_AES_KEY_GEN:
        info->ulMinKeySize = aes_min_keysize;
        info->ulMaxKeySize = aes_max_keysize;
        info->flags = CKF_GENERATE;
        break;
    case CKM_AES_CBC:
    case CKM_AES_CFB1:
    case CKM_AES_ECB:
        info->ulMinKeySize = aes_min_keysize;
        info->ulMaxKeySize = aes_max_keysize;
        info->flags = 0;
        break;

    /* RSA based crypto */
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        info->ulMinKeySize = rsa_min_keysize;
        info->ulMaxKeySize = rsa_max_keysize;
        info->flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
        break;
    case CKM_RSA_PKCS:
    case CKM_RSA_X_509:
        info->ulMinKeySize = rsa_min_keysize;
        info->ulMaxKeySize = rsa_max_keysize;
        info->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
        break;
    case CKM_RSA_PKCS_OAEP:
        info->ulMinKeySize = rsa_min_keysize;
        info->ulMaxKeySize = rsa_max_keysize;
        info->flags = CKF_HW | CKF_ENCRYPT| CKF_DECRYPT;
        break;
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
        info->ulMinKeySize = rsa_min_keysize;
        info->ulMaxKeySize = rsa_max_keysize;
        info->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
        break;

    /* ECC based crypto */
    /* TODO: Add ECC specific flags */
    case CKM_EC_KEY_PAIR_GEN:
        info->ulMinKeySize = ecc_min_keysize;
        info->ulMaxKeySize = ecc_max_keysize;
        info->flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
        break;
    case CKM_ECDSA:
    case CKM_ECDSA_SHA1:
        info->ulMinKeySize = ecc_min_keysize;
        info->ulMaxKeySize = ecc_max_keysize;
        info->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
        break;

    /* Hashes */
    case CKM_SHA_1:
    case CKM_SHA256:
        info->ulMinKeySize = 0;
        info->ulMaxKeySize = 0;
        info->flags = CKF_HW | CKF_DIGEST;
        break;

    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}
