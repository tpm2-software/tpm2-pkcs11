/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <string.h>

#include <pthread.h>

#include "log.h"
#include "mutex.h"
#include "pkcs11.h"

/*
 * Default handlers for mutex operations
 */
static CK_RV default_mutex_create(void **mutex);
static CK_RV default_mutex_destroy(void *mutex);
static CK_RV default_mutex_lock(void *mutex);
static CK_RV default_mutex_unlock(void *mutex);

/*
 * Function pointers for the actual registered
 * mutex operation.
 */
static CK_CREATEMUTEX  _g_create   = default_mutex_create;
static CK_DESTROYMUTEX _g_destroy = default_mutex_destroy;
static CK_LOCKMUTEX    _g_lock       = default_mutex_lock;
static CK_UNLOCKMUTEX  _g_unlock   = default_mutex_unlock;

void mutex_set_handlers(CK_CREATEMUTEX create,
        CK_DESTROYMUTEX destroy,
        CK_LOCKMUTEX lock,
        CK_UNLOCKMUTEX unlock) {

    /*
     * We assume the caller checked all of these are set to either
     * NULL or fn-ptrs and NOT a mix.
     */

    _g_create  = create;
    _g_destroy = destroy;
    _g_lock    = lock;
    _g_unlock  = unlock;
}

static CK_RV default_mutex_create(void **mutex) {

    int rc;

    pthread_mutex_t *p = calloc(1, sizeof(pthread_mutex_t));
    if (!p) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    pthread_mutexattr_t *attr = NULL;
/*
 * When NOT NOT DEBUGGING, ie when building in DEBUG mode
 * (autotools uses NDEBUG for this, hence the double
 * negative) enable error checking mutexes to prevent
 * double locks and have assert() cause an abort().
 */
#ifndef NDEBUG
    pthread_mutexattr_t __attr;
    attr = &__attr;

    rc = pthread_mutexattr_init(attr);
    if (rc) {
        LOGE("Failed to initialize pthread attribute: %s\n",
                strerror(rc));
        free(p);
        return CKR_GENERAL_ERROR;
    }

    rc = pthread_mutexattr_settype(attr, PTHREAD_MUTEX_ERRORCHECK);
    if (rc) {
        LOGE("Could not set attribute type: %s", strerror(rc));
        free(p);
        return CKR_GENERAL_ERROR;
    }
#endif

    rc = pthread_mutex_init(p, attr);
    if (rc) {
        LOGE("Could not initialize mutex: %s", strerror(rc));
        free(p);
        return CKR_GENERAL_ERROR;
    }

    *mutex = p;
    return CKR_OK;
}

static CK_RV default_mutex_destroy(void *mutex) {

    pthread_mutex_t *p = (pthread_mutex_t *)mutex;
    if (!p) {
        return CKR_OK;
    }

    int rc = pthread_mutex_destroy(p);
    if (rc) {
        LOGE("Could not destroy mutex: %s", strerror(rc));
        return CKR_MUTEX_BAD;
    }

    free(p);

    return CKR_OK;
}

static CK_RV default_mutex_lock(void *mutex) {

    pthread_mutex_t *p = (pthread_mutex_t *)mutex;

    int rc = pthread_mutex_lock(p);
    if (rc) {
        LOGE("Could not lock mutex: %s", strerror(rc));
        return CKR_MUTEX_BAD;
    }

    return CKR_OK;
}

static CK_RV default_mutex_unlock(void *mutex) {

    pthread_mutex_t *p = (pthread_mutex_t *)mutex;

    int rc = pthread_mutex_unlock(p);
    if (rc) {
        LOGE("Could not unlock mutex: %s", strerror(rc));
        return CKR_MUTEX_BAD;
    }

    return CKR_OK;
}


CK_RV mutex_create(void **mutex) {

    if (!_g_create) {
        return CKR_OK;
    }

    return _g_create(mutex);
}

CK_RV mutex_destroy(void *mutex) {

    if (!_g_destroy) {
        return CKR_OK;
    }

    return _g_destroy(mutex);
}

CK_RV mutex_lock(void *mutex) {

    if (!_g_lock) {
        return CKR_OK;
    }

    return _g_lock(mutex);
}

CK_RV mutex_unlock(void *mutex) {

    if (!_g_unlock) {
        return CKR_OK;
    }

    return _g_unlock(mutex);
}
