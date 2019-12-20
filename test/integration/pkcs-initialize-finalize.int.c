/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include <tss2/tss2_sys.h>

#define LOGMODULE test
#include "log.h"
#include "pkcs11.h"
#include "db.h"

/**
 * This program contains integration test for C_Initialize and C_Finalize.
 * C_Initialize initializes the Cryptoki library.
 * C_Finalize is called to indicate that an application is finished with the Cryptoki library.
 */

static CK_RV create(void **mutex) {
    (void) mutex;
    return CKR_OK;
}

static CK_RV lock(void *mutex) {
    (void) mutex;
    return CKR_OK;
}

static CK_RV unlock(void *mutex) {
    (void) mutex;
    return CKR_OK;
}

static CK_RV destroy(void *mutex) {
    (void) mutex;
    return CKR_OK;
}

// Test the 4 states and additional error case of:
//   http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
// Section 5.4
void test_c_init_args() {

    // Case 1 - flags and fn ptr's clear. No threaded access.
    CK_C_INITIALIZE_ARGS args = {
        .flags = 0,
        .CreateMutex = NULL,
        .DestroyMutex = NULL,
        .LockMutex = NULL,
        .pReserved = NULL,
    };

    CK_RV rv = C_Initialize (&args);
    if (rv != CKR_OK) {
        LOGE("C_Initialize failed for Case 1! Response Code %x", rv);
        exit(1);
    }

    rv = C_Finalize(NULL);
    if (rv != CKR_OK) {
        LOGE("C_Finalize failed for Case 1! Response Code %x", rv);
        exit(1);
    }

    // Case 2 locking flag specified but no fn pointers. Threaded access and use
    // library lock defaults.
    args.flags = CKF_OS_LOCKING_OK;

    rv = C_Initialize (&args);
    if (rv != CKR_OK) {
        LOGE("C_Initialize failed for Case 2! Response Code %x", rv);
        exit(1);
    }
    rv = C_Finalize(NULL);
    if (rv != CKR_OK) {
        LOGE("C_Finalize failed for Case 2! Response Code %x", rv);
        exit(1);
    }

    // Case 3, no locking flag set, and set fn pointers. Threaded access and
    // use my call backs
    args.flags = 0;
    args.CreateMutex = create;
    args.DestroyMutex = destroy;
    args.LockMutex = lock;
    args.UnlockMutex = unlock;

    rv = C_Initialize (&args);
    if (rv != CKR_OK) {
        LOGE("C_Initialize failed for Case 3! Response Code %x", rv);
        exit(1);
    }

    rv = C_Finalize(NULL);
    if (rv != CKR_OK) {
        LOGE("C_Finalize failed Case 3! Response Code %x", rv);
        exit(1);
    }

    // Case 4, locking flag set, and set fn pointers. Threaded access and
    // optionally use my callbacks
    args.flags = CKF_OS_LOCKING_OK;
    rv = C_Initialize (&args);
    if (rv != CKR_OK) {
        LOGE("C_Initialize failed for Case 4! Response Code %x", rv);
        exit(1);
    }

    rv = C_Finalize(NULL);
    if (rv != CKR_OK) {
        LOGE("C_Finalize failed Case 4! Response Code %x", rv);
        exit(1);
    }

    // Clear args for negative test
    // Case 5: If some, but not all, of the supplied function pointers to C_Initialize are non-NULL_PTR,
    // then C_Initialize should return with the value CKR_ARGUMENTS_BAD.
    memset(&args, 0, sizeof(args));
    args.CreateMutex = create;
    rv = C_Initialize (&args);
    if (rv != CKR_ARGUMENTS_BAD) {
        LOGE("C_Initialize failed for Case 5! Response Code %x", rv);
        exit(1);
    }

    args.DestroyMutex = destroy;
    rv = C_Initialize (&args);
    if (rv != CKR_ARGUMENTS_BAD) {
        LOGE("C_Initialize failed for Case 5! Response Code %x", rv);
        exit(1);
    }

    args.LockMutex = lock;
    rv = C_Initialize (&args);
    if (rv != CKR_ARGUMENTS_BAD) {
        LOGE("C_Initialize failed Case 5! Response Code %x", rv);
        exit(1);
    }

    memset(&args, 0, sizeof(args));
    // Case 6: flag is set but only some function pointers are provided,
    // then C_Initialize should return with the value CKR_ARGUMENTS_BAD
    args.flags = CKF_OS_LOCKING_OK;
    args.DestroyMutex = destroy;
    rv = C_Initialize (&args);
    if (rv != CKR_ARGUMENTS_BAD) {
        LOGE("C_Initialize failed for Case 6! Response Code %x", rv);
        exit(1);
    }

    args.LockMutex = lock;
    rv = C_Initialize (&args);
    if (rv != CKR_ARGUMENTS_BAD) {
        LOGE("C_Initialize failed for Case 6! Response Code %x", rv);
        exit(1);
    }

    args.UnlockMutex = unlock;
    rv = C_Initialize (&args);
    if (rv != CKR_ARGUMENTS_BAD) {
        LOGE("C_Initialize failed for Case 6! Response Code %x", rv);
        exit(1);
    }

    // Case 7: the value of pReserved MUST be NULL_PTR; if it’s not,
    // then C_Initialize should return with the value CKR_ARGUMENTS_BAD.
    memset(&args, 0, sizeof(args));
    args.pReserved = (void *)0xDEADBEEF;
    rv = C_Initialize (&args);
    if (rv != CKR_ARGUMENTS_BAD) {
        LOGE("C_Initialize failed for Case 7! Response Code %x", rv);
        exit(1);
    }

    // If negative test cases, succesfully run C_Initialize
    rv = C_Finalize(NULL);
    if (rv != (CKR_CRYPTOKI_NOT_INITIALIZED|CKR_OK)) {
        LOGE("C_Finalize failed! Response Code %x", rv);
        exit(1);
    }
    LOGV("test_c_init_args Test Passed!");
}

void test_c_double_init() {

    CK_RV rv = C_Initialize(NULL);
    if(rv != CKR_OK){
        LOGE("C_Initialize failed! Response Code %x", rv);
        exit(1);
    }
    rv = C_Initialize (NULL);
    if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED){
        LOGE("C_Initialize failed for test_c_double_init! Response Code %x", rv);
        exit(1);
    }

    //Call a good C_Finalize
    rv = C_Finalize(NULL);
    if(rv != CKR_OK){
        LOGE("C_Finalize failed for test_c_finalize_bad! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_c_double_init Test Passed!");
}

static void test_c_finalize_bad() {

    CK_RV rv = C_Initialize(NULL);
    if(rv != CKR_OK){
        LOGE("C_Initialize failed! Response Code %x", rv);
        exit(1);
    }

    // Give it a pointer and make sure we don't try and dereference it.
    rv = C_Finalize((void *)0xDEADBEEF);
    if(rv != CKR_ARGUMENTS_BAD){
        LOGE("C_Finalize failed for test_c_finalize_bad! Response Code %x", rv);
        exit(1);
    }

    //Call a good C_Finalize
    rv = C_Finalize(NULL);
    if(rv != CKR_OK){
        LOGE("C_Finalize failed for test_c_finalize_bad! Response Code %x", rv);
        exit(1);
    }
    LOGV("test_c_finalize_bad Test Passed!");
}

int main() {

    test_c_init_args();
    test_c_double_init();
    test_c_finalize_bad();

    return 0;
}
