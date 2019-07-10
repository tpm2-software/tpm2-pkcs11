/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_fapi.h>

#include "checks.h"
#include "pkcs11.h"
#include "log.h"
#include "slot.h"
#include "token.h"
#include "utils.h"

/* We provide one empty token in a slot for each library invocation.
   In order to detect that token, we the following variable. */
CK_SLOT_ID emptyTokenSlot;

CK_RV slot_init(void) {
    CK_RV rv;
    CK_SLOT_ID *slot_list;
    CK_ULONG count, i;

    rv = tss_get_card_ids(NULL, &count);
    if (rv != CKR_OK)
        return rv;

    slot_list = calloc(count, sizeof(*slot_list));
    if (!slot_list)
        return CKR_GENERAL_ERROR;

    rv = tss_get_card_ids(slot_list, &count);
    if (rv != CKR_OK)
        goto cleanup;

    do {
        emptyTokenSlot = (((CK_SLOT_ID) rand()) & 0x0ffffffe) + 1;
        for (i = 0; i < count; i++) {
            if (slot_list[i] == emptyTokenSlot) {
                LOGV("Slot %i occupied, searching", emptyTokenSlot);
                emptyTokenSlot = 0;
                break;
            }
        }
    } while (emptyTokenSlot == 0);

    emptyTokenSlot |= EMPTY_TOKEN_BIT;

cleanup:
    free(slot_list);

    return CKR_OK;
}

void slot_destroy(void) {
}

CK_RV slot_get_list (CK_BYTE token_present, CK_SLOT_ID *slot_list, CK_ULONG_PTR count) {

    /*
     * True for token present only returns slots with tokens, False all slots. All
     * of our slots always have a token, so we can ignore this.
     */
    UNUSED(token_present);

    check_pointer(count);

    CK_RV rv;

    rv = tss_get_card_ids(slot_list, count);
    if (rv != CKR_OK) {
        LOGE("Erro during tss access");
        return rv;
    }

    if (emptyTokenSlot) {
        *count += 1;
        if (slot_list) {
            slot_list[*count - 1] = emptyTokenSlot;
        }
    }
    return rv;
}

CK_RV slot_get_info (CK_SLOT_ID slot_id, CK_SLOT_INFO *info) {
    UNUSED(slot_id);
    check_pointer(info);

    memset(info, 0, sizeof(*info));
    strcpy((char *)&info->slotDescription[0], "tpm2-pkcs11");
    strcpy((char *)&info->manufacturerID[0], "tpm2-software");

    info->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

    //TODO
    info->hardwareVersion.major = 0;
    info->hardwareVersion.minor = 0;
    info->firmwareVersion.major = 0;
    info->firmwareVersion.minor = 0;
    return CKR_OK;
}

CK_RV slot_mechanism_list_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE *mechanism_list, CK_ULONG_PTR count) {
    (void)(slot_id);

    CK_RV rv = tpm2_getmechanisms(mechanism_list, count);

    return rv;
}

CK_RV slot_mechanism_info_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *info) {
    (void)(slot_id);
    check_pointer(info);

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
