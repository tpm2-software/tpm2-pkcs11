/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_MUTEX_H_
#define SRC_PKCS11_MUTEX_H_

#include <assert.h>

#include "log.h"
#include "pkcs11.h"
#include "utils.h"

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

static inline void _mutex_lock_fatal(void *mutex) {

    CK_RV rv = mutex_lock(mutex);
    assert(rv == CKR_OK);
    UNUSED(rv);
}

static inline void _mutex_unlock_fatal(void *mutex) {

    CK_RV rv = mutex_unlock(mutex);
    assert(rv == CKR_OK);
    UNUSED(rv);
}

#ifndef NDEBUG
/*
 * debugging lock macros, the LOGV is on the top line to report lineno correctly
 */
#define mutex_lock_fatal(mutex) do { LOGV("LOCK(%p)-attempt", mutex); \
        _mutex_lock_fatal(mutex); \
        LOGV("LOCK(%p)-aquired", mutex); \
    } while (0)

#define mutex_unlock_fatal(mutex) do { LOGV("UNLOCK(%p)-attempt", mutex); \
        _mutex_unlock_fatal(mutex); \
        LOGV("UNLOCK(%p)-released", mutex); \
    } while (0)
#else
#define mutex_lock_fatal(mutex) _mutex_lock_fatal(mutex)
#define mutex_unlock_fatal(mutex) _mutex_unlock_fatal(mutex)
#endif
#endif /* SRC_PKCS11_MUTEX_H_ */
