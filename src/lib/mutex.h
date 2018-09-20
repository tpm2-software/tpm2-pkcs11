/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_MUTEX_H_
#define SRC_PKCS11_MUTEX_H_

#include <assert.h>

#include "pkcs11.h"

/**
 * Set's the mutex handlers. The mutex handlers default to internal
 * pthread mutexes unless specifically set, or cleared by setting NULL.
 * @param create
 *  The handler for creating a MUTEX.
 * @param destroy
 *  The handler for destroying a MUTEX.
 * @param lock
 *  The handler for locking a MUTEX.
 * @param unlock
 *  The handler for unlocking a MUTEX.
 */
void mutex_set_handlers(CK_CREATEMUTEX create,
        CK_DESTROYMUTEX destroy,
        CK_LOCKMUTEX lock,
        CK_UNLOCKMUTEX unlock);

/**
 * Allocates and initializes a mutex.
 * @param mutex
 *  The pointer to store the mutext at.
 * @return
 *  CKR_OK on success.
 */
CK_RV mutex_create(void **mutex);

/**
 * Deallocates and destroys a mutex.
 * @param mutex
 *  The mutex to deallocate.
 * @return
 *  CKR_OK on success.
 */
CK_RV mutex_destroy(void *mutex);

/**
 * locks a mutex.
 * @param mutex
 *  The mutex to lock.
 * @return
 *  CKR_OK on success.
 */
CK_RV mutex_lock(void *mutex);

/**
 * unlocks a mutex.
 * @param mutex
 *  The mutex to unlock.
 * @return
 *  CKR_OK on success.
 */
CK_RV mutex_unlock(void *mutex);

static inline void mutex_lock_fatal(void **mutex) {
    assert(mutex_lock(mutex) == CKR_OK);
}

static inline void mutex_unlock_fatal(void **mutex) {
    assert(mutex_unlock(mutex) == CKR_OK);
}

#endif /* SRC_PKCS11_MUTEX_H_ */
