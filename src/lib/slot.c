/* SPDX-License-Identifier: BSD-2-Clause */

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "backend.h"
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

/*
 * The slot events C_WaitForSlotEvent waits for. The slots and their tokens are fixed, so none ever
 * occurs: a blocking wait lasts until C_Finalize. Its mutex and conditions are static, not made by
 * C_Initialize nor freed by C_Finalize, so a waiter C_Finalize wakes touches nothing freed; and they
 * are none of the slot and token locks, so a waiter blocks holding none of those.
 */
static struct {
    pthread_mutex_t mutex;
    /* broadcast when C_Finalize starts */
    pthread_cond_t finalized;
    /* broadcast when the last waiter leaves */
    pthread_cond_t left;
    /* set by C_Finalize, cleared by C_Initialize: a wait then returns at once */
    bool finalizing;
    /*
     * The C_Finalize calls so far. A waiter waits for it to change rather than for finalizing, which
     * a C_Initialize right after the C_Finalize could clear before the waiter runs again.
     */
    unsigned long finalize_count;
    /* the waiters blocked, for C_Finalize to see leave */
    unsigned long waiters;
} events = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .finalized = PTHREAD_COND_INITIALIZER,
    .left = PTHREAD_COND_INITIALIZER,
};

static void events_lock(void) {

    int rc = pthread_mutex_lock(&events.mutex);
    assert(rc == 0);
    UNUSED(rc);
}

static void events_unlock(void) {

    int rc = pthread_mutex_unlock(&events.mutex);
    assert(rc == 0);
    UNUSED(rc);
}

/* A forked child has none of the parent's waiters, and may have copied the mutex locked: start afresh. */
static void events_reset_in_child(void) {

    pthread_mutex_init(&events.mutex, NULL);
    pthread_cond_init(&events.finalized, NULL);
    pthread_cond_init(&events.left, NULL);
    events.finalizing = false;
    events.waiters = 0;
}

static void events_register_atfork(void) {

    int rc = pthread_atfork(NULL, NULL, events_reset_in_child);
    if (rc) {
        LOGW("Failed to register the slot event fork handler: %d", rc);
    }
}

CK_RV slot_init(void) {

    static pthread_once_t atfork_once = PTHREAD_ONCE_INIT;
    pthread_once(&atfork_once, events_register_atfork);

    events_lock();
    events.finalizing = false;
    events_unlock();

    CK_RV rv = mutex_create(&global.mutex);
    if (rv != CKR_OK) {
        return rv;
    }

    return backend_get_tokens(&global.token, &global.token_cnt);
}

static void slot_lock(void) {
    mutex_lock_fatal(global.mutex);
}

static void slot_unlock(void) {
    mutex_unlock_fatal(global.mutex);
}

void slot_destroy(void) {

    token_free_list(&global.token, &global.token_cnt);

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

    str_padded_copy(info->manufacturerID, token_info.manufacturerID);
    str_padded_copy(info->slotDescription, token_info.label);

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
    CK_RV rv = mech_get_supported(t->mdtl, mechanism_list, count);
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

    CK_RV rv = mech_get_info(t->mdtl, t->tctx, type, info);
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
               LOGV("Skipping adding uninitialized token, one found");
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

CK_RV slot_wait_for_event(CK_FLAGS flags, CK_SLOT_ID_PTR slot, CK_VOID_PTR reserved) {

    check_pointer(slot);
    if (reserved) {
        return CKR_ARGUMENTS_BAD;
    }

    /* no slot's event flag is ever set */
    if (flags & CKF_DONT_BLOCK) {
        return CKR_NO_EVENT;
    }

    CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

    events_lock();

    /* finalized since the caller checked the library was initialized */
    if (events.finalizing) {
        goto out;
    }

    events.waiters++;
    unsigned long count = events.finalize_count;
    while (count == events.finalize_count) {
        int rc = pthread_cond_wait(&events.finalized, &events.mutex);
        if (rc) {
            LOGE("Failed to wait for a slot event: %d", rc);
            rv = CKR_FUNCTION_FAILED;
            break;
        }
    }

    if (!--events.waiters) {
        pthread_cond_broadcast(&events.left);
    }

out:
    events_unlock();

    return rv;
}

void slot_wake_waiters(void) {

    events_lock();

    events.finalizing = true;
    events.finalize_count++;
    pthread_cond_broadcast(&events.finalized);

    /* each woken waiter only needs the mutex to leave, which waiting here releases */
    while (events.waiters) {
        int rc = pthread_cond_wait(&events.left, &events.mutex);
        if (rc) {
            LOGE("Failed to wait for the slot event waiters: %d", rc);
            break;
        }
    }

    events_unlock();
}
