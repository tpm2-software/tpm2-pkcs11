/* SPDX-License-Identifier: BSD-2-Clause */

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

    check_pointer(info);

    token = slot_get_token(slot_id);
    if (!token) {
        return CKR_SLOT_ID_INVALID;
    }

    CK_TOKEN_INFO token_info;
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

    return token_get_mechanism_list(t, mechanism_list, count);
}

CK_RV slot_mechanism_info_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *info) {

    check_pointer(info);

    token *t = slot_get_token(slot_id);
    if (!t) {
        return CKR_SLOT_ID_INVALID;
    }

    /* tpm builds and maintains cache */
    CK_RV rv = tpm_get_mech_info(t->tctx, type, info);
    if (rv != CKR_OK) {
        return rv;
    }

    return CKR_OK;
}
