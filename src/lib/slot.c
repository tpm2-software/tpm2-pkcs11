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

    const CK_BYTE manufacturerID[] = "foo";
    const CK_BYTE slotDescription[] = "bar";

    check_pointer(info);

    if (!slot_get_token(slot_id)) {
        return CKR_SLOT_ID_INVALID;
    }

    memset(info, 0, sizeof(*info));

    /* TODO pull these from TPM */
    info->firmwareVersion.major =
            info->firmwareVersion.minor = 13;

    info->hardwareVersion.major =
    info->hardwareVersion.minor = 42;

    str_padded_copy(info->manufacturerID, manufacturerID, sizeof(info->manufacturerID));
    str_padded_copy(info->slotDescription, slotDescription, sizeof(info->slotDescription));

    info->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

    return CKR_OK;
}

CK_RV slot_mechanism_list_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE *mechanism_list, CK_ULONG_PTR count) {

    check_is_init();

    if (!slot_get_token(slot_id)) {
        return CKR_SLOT_ID_INVALID;
    }

    if (!count){
        return CKR_ARGUMENTS_BAD;
    }

    static const CK_MECHANISM_TYPE mechs[] = {
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_RSA_PKCS,
        CKM_RSA_9796,
        CKM_RSA_X_509,
        CKM_MD2_RSA_PKCS,
        CKM_MD5_RSA_PKCS,
        CKM_SHA1_RSA_PKCS,
        CKM_RIPEMD128_RSA_PKCS,
        CKM_RIPEMD160_RSA_PKCS,
        CKM_RSA_PKCS_OAEP,
        CKM_RSA_X9_31_KEY_PAIR_GEN,
        CKM_RSA_X9_31,
        CKM_SHA1_RSA_X9_31,
        CKM_RSA_PKCS_PSS,
        CKM_SHA1_RSA_PKCS_PSS,
        CKM_DSA_KEY_PAIR_GEN,
        CKM_DSA,
        CKM_DSA_SHA1,
        CKM_DH_PKCS_KEY_PAIR_GEN,
        CKM_DH_PKCS_DERIVE,
        CKM_X9_42_DH_KEY_PAIR_GEN,
        CKM_X9_42_DH_DERIVE,
        CKM_X9_42_DH_HYBRID_DERIVE,
        CKM_X9_42_MQV_DERIVE,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
        CKM_RC2_KEY_GEN,
        CKM_RC2_ECB,
        CKM_RC2_CBC,
        CKM_RC2_MAC,
        CKM_RC2_MAC_GENERAL,
        CKM_RC2_CBC_PAD,
        CKM_RC4_KEY_GEN,
        CKM_RC4,
        CKM_DES_KEY_GEN,
        CKM_DES_ECB,
        CKM_DES_CBC,
        CKM_DES_MAC,
        CKM_DES_MAC_GENERAL,
        CKM_DES_CBC_PAD,
        CKM_DES2_KEY_GEN,
        CKM_DES3_KEY_GEN,
        CKM_DES3_ECB,
        CKM_DES3_CBC,
        CKM_DES3_MAC,
        CKM_DES3_MAC_GENERAL,
        CKM_DES3_CBC_PAD,
        CKM_MD5,
        CKM_MD5_HMAC,
        CKM_MD5_HMAC_GENERAL,
        CKM_SHA_1,
        CKM_SHA_1_HMAC,
        CKM_SHA_1_HMAC_GENERAL,
        CKM_SHA256,
        CKM_SHA256_HMAC,
        CKM_SHA256_HMAC_GENERAL,
        CKM_SHA384,
        CKM_SHA384_HMAC,
        CKM_SHA384_HMAC_GENERAL,
        CKM_SHA512,
        CKM_SHA512_HMAC,
        CKM_SHA512_HMAC_GENERAL,
        CKM_CAST_KEY_GEN,
        CKM_ECDSA_KEY_PAIR_GEN,
        CKM_EC_KEY_PAIR_GEN,
        CKM_ECDSA,
        CKM_ECDSA_SHA1,
        CKM_ECDH1_DERIVE,
        CKM_ECDH1_COFACTOR_DERIVE,
        CKM_AES_KEY_GEN,
        CKM_AES_ECB,
        CKM_AES_CBC,
        CKM_AES_MAC,
        CKM_AES_MAC_GENERAL,
        CKM_AES_CBC_PAD,
        CKM_AES_CTR,
    };

    if (!mechanism_list) {
        *count = ARRAY_LEN(mechs);
        return CKR_OK;
    }

    if (*count < ARRAY_LEN(mechs)) {
        return CKR_BUFFER_TOO_SMALL;
    }

    *count = ARRAY_LEN(mechs);
    memcpy(mechanism_list, mechs, sizeof(mechs));

    return CKR_OK;
}

CK_RV slot_mechanism_info_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *info) {

    check_is_init();
    check_pointer(info);

    if (!slot_get_token(slot_id)) {
        return CKR_SLOT_ID_INVALID;
    }

    switch(type) {
    case CKM_AES_KEY_GEN:
        info->ulMinKeySize = 128;
        info->ulMaxKeySize = 512;
        //XXX What should flags look like?
        info->flags = 0;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}
