/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "db.h"
#include "mech.h"
#include "pkcs11.h"
#include "slot.h"
#include "token.h"
#include "utils.h"

static struct {
    size_t token_cnt;
    token *token;
    void *mutex;
} global;

CK_RV slot_init(void) {

    CK_RV rv = mutex_create(&global.mutex);
    if (rv != CKR_OK) {
        return rv;
    }

    return db_get_tokens(&global.token, &global.token_cnt);
}

static void slot_lock(void) {
    mutex_lock_fatal(global.mutex);
}

static void slot_unlock(void) {
    mutex_unlock_fatal(global.mutex);
}

void slot_destroy(void) {

    token_free_list(global.token, global.token_cnt);

    CK_RV rv = mutex_destroy(global.mutex);
    global.mutex = NULL;
    if (rv != CKR_OK) {
        LOGW("Failed to destroy mutex");
    }
}

token *slot_get_token(CK_SLOT_ID slot_id) {

    slot_lock();

    size_t i;
    for (i=0; i < global.token_cnt; i++) {
        token *t = &global.token[i];
        if (slot_id == t->id) {
            slot_unlock();
            return t;
        }
    }

    slot_unlock();
    return NULL;
}

CK_RV slot_get_list (CK_BYTE token_present, CK_SLOT_ID *slot_list, CK_ULONG_PTR count) {

    /*
     * True for token present only returns slots with tokens, False all slots. All
     * of our slots always have a token, so we can ignore this.
     */
    UNUSED(token_present);

    check_pointer(count);

    slot_lock();

    if (!slot_list) {
        slot_unlock();
        *count = global.token_cnt;
        return CKR_OK;
    }

    if (*count < global.token_cnt) {
        *count = global.token_cnt;
        slot_unlock();
        return CKR_BUFFER_TOO_SMALL;
    }

    size_t i;
    for (i=0; i < global.token_cnt; i++) {
        token *t = &global.token[i];
        slot_list[i] = t->id;
    }

    *count = global.token_cnt;

    slot_unlock();

    return CKR_OK;
}

CK_RV slot_get_info (CK_SLOT_ID slot_id, CK_SLOT_INFO *info) {

    token *token;

    check_pointer(info);

    token = slot_get_token(slot_id);
    if (!token) {
        return CKR_SLOT_ID_INVALID;
    }

    token_lock(token);

    CK_TOKEN_INFO token_info;
    if (token_get_info(token, &token_info)) {
        token_unlock(token);
        return CKR_GENERAL_ERROR;
    }

    str_padded_copy(info->manufacturerID, token_info.manufacturerID, sizeof(info->manufacturerID));
    str_padded_copy(info->slotDescription, token_info.label, sizeof(info->slotDescription));

    info->hardwareVersion = token_info.hardwareVersion;
    info->firmwareVersion = token_info.firmwareVersion;

    info->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

    token_unlock(token);
    return CKR_OK;
}


CK_RV slot_mechanism_list_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE *mechanism_list, CK_ULONG_PTR count) {

    token *t = slot_get_token(slot_id);
    if (!t) {
        return CKR_SLOT_ID_INVALID;
    }

    token_lock(t);
    CK_RV rv = mech_get_supported(t->tctx, mechanism_list, count);
    token_unlock(t);
    return rv;
}

CK_RV slot_mechanism_info_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *info) {

    check_pointer(info);

    token *t = slot_get_token(slot_id);
    if (!t) {
        return CKR_SLOT_ID_INVALID;
    }

    token_lock(t);

    /* tpm builds and maintains cache */
    CK_RV rv = mech_get_info(t->tctx, type, info);
    if (rv != CKR_OK) {
        token_unlock(t);
        return rv;
    }

    token_unlock(t);

    return CKR_OK;
}

CK_RV slot_add_uninit_token(void) {

    CK_RV rv = CKR_GENERAL_ERROR;

    slot_lock();

    if (global.token_cnt < MAX_TOKEN_CNT) {

        size_t i;
        for (i=0; i < global.token_cnt; i++) {
           token *t = &global.token[i];
           if (!t->config.is_initialized) {
               LOGV("Skipping adding unitialized token, one found");
               rv = CKR_OK;
               goto out;
           }
        }

        token *t = &global.token[global.token_cnt++];
        t->id = global.token_cnt;
        rv = token_min_init(t);
        if (rv != CKR_OK) {
           goto out;
        }

        assert(t->id);
    } else {
        LOGW("Reached max tokens in store");
    }

    rv = CKR_OK;

out:
    slot_unlock();
    return rv;
}
