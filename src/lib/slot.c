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

    // TODO support more of these and check with the TPM for sizes.
    switch(type) {
    case CKM_AES_KEY_GEN:
        info->ulMinKeySize = 128;
        info->ulMaxKeySize = 512;
        info->flags = CKF_GENERATE;
        break;
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        info->ulMinKeySize = 1024;
        info->ulMaxKeySize = 4096;
        info->flags = CKF_GENERATE_KEY_PAIR;
        break;
    case CKM_EC_KEY_PAIR_GEN:
        info->ulMinKeySize = 192;
        info->ulMaxKeySize = 256;
        info->flags = CKF_GENERATE_KEY_PAIR;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}
