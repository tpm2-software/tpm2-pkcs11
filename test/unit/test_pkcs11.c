/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>

#include "db.h"
#include "pkcs11.h"
#include "tpm.h"
#include "utils.h"

#define add_test(x) cmocka_unit_test_setup_teardown(x, setup_c_init, teardown_c_destroy)
#define add_ttest(x) cmocka_unit_test_teardown(x, teardown_c_destroy)

#define add_session_test(x) cmocka_unit_test_setup_teardown(x, setup_c_opensession, teardown_c_closesession)

static inline CK_SESSION_HANDLE state_to_handle(void **state) {

    return (CK_SESSION_HANDLE)*state;
}

static int setup_c_init(void **state) {
    (void) state;

    return C_Initialize (NULL);
}

static int teardown_c_destroy(void **state) {
    (void) state;

    C_Finalize(NULL);
    return 0;
}

static int setup_c_opensession(void **state) {

    CK_RV rv = setup_c_init(NULL);
    assert_int_equal(rv, CKR_OK);

    CK_SLOT_ID slots[6];
    unsigned long count = ARRAY_LEN(slots);
    rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);

    CK_SESSION_HANDLE handle;

    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL , NULL, &handle);
    assert_int_equal(rv, CKR_OK);

    *state = (void *)handle;

    return 0;
}

static int teardown_c_closesession(void **state) {

    CK_SESSION_HANDLE handle = state_to_handle(state);

    CK_RV rv = C_CloseSession(handle);
    assert_int_equal(rv, CKR_OK);

    teardown_c_destroy(NULL);
    return 0;
}

static void test_c_init_destroy_ok(void **state) {
    (void) state;
    // Setup/Teardown IS the test
}

static void test_c_double_init(void **state) {
    (void) state;

    CK_RV rv = C_Initialize (NULL);
    assert_int_equal(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED);

}

static void test_c_finalize_bad(void **state) {
    (void) state;

    // Give it a pointer and make sure we don't try and dereference it.
    CK_RV rv = C_Finalize((void *)0xDEADBEEF);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);
}

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
static void test_c_init_args(void **state) {
    (void) state;

    // Case 1 - flags and fn ptr's clear. No threaded access.
    CK_C_INITIALIZE_ARGS args = {
        .flags = 0,
        .CreateMutex = NULL,
        .DestroyMutex = NULL,
        .LockMutex = NULL,
        .pReserved = NULL,
    };

    CK_RV rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_OK);

    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    // Case 2 locking flag specified but no fn pointers. Threaded access and use
    // library lock defaults.
    args.flags = CKF_OS_LOCKING_OK;

    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_OK);

    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    // Case 3, no locking flag set, and set fn pointers. Threaded access and
    // use my call backs
    args.flags = 0;
    args.CreateMutex = create;
    args.DestroyMutex = destroy;
    args.LockMutex = lock;
    args.UnlockMutex = unlock;

    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_OK);

    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    // Case 4, locking flag set, and set fn pointers. Threaded access and
    // optionally use my callbacks
    args.flags = CKF_OS_LOCKING_OK;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_OK);

    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    // Clear args an negative test
    memset(&args, 0, sizeof(args));
    args.CreateMutex = create;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    args.DestroyMutex = destroy;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    args.LockMutex = lock;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    memset(&args, 0, sizeof(args));

    args.flags = CKF_OS_LOCKING_OK;
    args.DestroyMutex = destroy;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    args.LockMutex = lock;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    args.UnlockMutex = unlock;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    memset(&args, 0, sizeof(args));
    args.pReserved = (void *)0xDEADBEEF;
    rv = C_Initialize (&args);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    // No Finalize, harness handles
}

static void test_c_getfunctionlist(void **state) {
    (void) state;

    //Case 1: Successfully obtain function list
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_RV rv = C_GetFunctionList(&pFunctionList);
    assert_int_equal(rv, CKR_OK);

    //Case 2: Null to obtain gunction list
    rv = C_GetFunctionList(NULL);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

}

static void test_get_slot_list(void **state) {
    (void) state;

    CK_SLOT_ID slots[6];
    unsigned long count;
    CK_RV rv = C_GetSlotList(true, NULL, &count);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(count, 2);

    rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);

    CK_SLOT_INFO sinfo;
    rv = C_GetSlotInfo(slots[0], &sinfo);
    assert_int_equal(rv, CKR_OK);

    assert_true(sinfo.flags & CKF_TOKEN_PRESENT);
    assert_true(sinfo.flags & CKF_HW_SLOT);

    CK_TOKEN_INFO tinfo;
    rv = C_GetTokenInfo(slots[0], &tinfo);
    assert_int_equal(rv, CKR_OK);
    assert_true(tinfo.flags & CKF_RNG);
    assert_true(tinfo.flags & CKF_TOKEN_INITIALIZED);

    char padd_model[16] = "TPM2 PKCS#11   \0";
    char padd_manuf[32] = "Intel                          \0";

    assert_string_equal(tinfo.manufacturerID, padd_manuf);
    assert_string_equal(tinfo.model, padd_model);
    assert_int_equal(tinfo.ulMaxPinLen, 128);
    assert_int_equal(tinfo.ulMinPinLen, 5);

    rv = C_GetTokenInfo(slots[1], &tinfo);
    assert_int_equal(rv, CKR_OK);
    assert_true(tinfo.flags & CKF_RNG);
    assert_true(tinfo.flags & CKF_TOKEN_INITIALIZED);

    assert_string_equal(tinfo.manufacturerID, padd_manuf);
    assert_string_equal(tinfo.model, padd_model);
    assert_int_equal(tinfo.ulMaxPinLen, 128);
    assert_int_equal(tinfo.ulMinPinLen, 5);
}

static void test_session_open_close(void **state) {
    (void) state;

    // The session setup/teardown IS the test
}

static void test_random(void **state) {

    unsigned char buf[4];
    CK_SESSION_HANDLE session = state_to_handle(state);
    CK_RV rv = C_GenerateRandom(session++, buf, 4);
    assert_int_equal(rv, CKR_OK);

    // Test bad session
    rv = C_GenerateRandom(session, buf, 4);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_seed(void **state) {

    unsigned char buf[]="ksadjfhjkhfsiudgfkjewsdjbkfcoidugshbvfewug";

    CK_SESSION_HANDLE session = state_to_handle(state);
    CK_RV rv = C_SeedRandom(session, buf, sizeof(buf));
    assert_int_equal(rv, CKR_OK);
}

static void test_sign_verify_good(void **state) {

    CK_SESSION_HANDLE session = state_to_handle(state);

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;

    CK_ATTRIBUTE tmpl[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* now that we have an object, login */
    unsigned char upin[] = "myuserpin";
    rv = C_Login(session, CKU_USER, upin, sizeof(upin) - 1);
    assert_int_equal(rv, CKR_OK);

    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256_RSA_PKCS,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    rv = C_SignInit(session, &smech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    // sizeof a sha256 hash
    unsigned char message[] = "Hello World This is My First Signing Message";
    unsigned char sig[1024];
    unsigned long siglen = sizeof(sig);

    rv = C_Sign(session, message, sizeof(message), sig, &siglen);
    assert_int_equal(rv, CKR_OK);

    rv = C_VerifyInit (session, &smech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    rv = C_Verify (session, message, sizeof(message), sig, siglen);
    assert_int_equal(rv, CKR_OK);

    C_Logout(session);
}

static void test_sign_verify_logout_fail(void **state) {

    CK_SESSION_HANDLE session = state_to_handle(state);

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;

    CK_ATTRIBUTE tmpl[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* now that we have an object, login */
    unsigned char upin[] = "myuserpin";
    rv = C_Login(session, CKU_USER, upin, sizeof(upin) - 1);
    assert_int_equal(rv, CKR_OK);

    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256_RSA_PKCS,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    rv = C_SignInit(session, &smech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    // sizeof a sha256 hash
    unsigned char message[] = "Hello World This is My First Signing Message";

    unsigned char sig[1024];
    unsigned long siglen = sizeof(sig);

    rv = C_Logout(session);
    assert_int_equal(rv, CKR_OK);

    rv = C_Sign(session, message, sizeof(message), sig, &siglen);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);
}

static void test_aes_encrypt_decrypt_good(void **state) {

    CK_SESSION_HANDLE session = state_to_handle(state);

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    /* get a AES key */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* now that we have an object, login */
    unsigned char upin[] = "myuserpin";
    rv = C_Login(session, CKU_USER, upin, sizeof(upin) - 1);
    assert_int_equal(rv, CKR_OK);

    /* init encryption */
    CK_BYTE iv[16] = {
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
    };

    CK_MECHANISM mechanism = {
        CKM_AES_CBC_PAD, iv, sizeof(iv)
    };

    /*
     * We're not dealing with padding schemes yet, but we do want to handle multi stage encrypt and decrypt.
     */
    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };

    CK_BYTE ciphertext[sizeof(plaintext)] = { 0 };

    /* init */
    rv = C_EncryptInit(session, &mechanism, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    /* part 1 */
    unsigned long ciphertext_len = 16;
    rv = C_EncryptUpdate(session, plaintext, 16,
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, 16);

    /* part 2 */
    ciphertext_len = 16;
    rv = C_EncryptUpdate(session, plaintext, 16,
            &ciphertext[16], &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, 16);

    /* final, shouldn't have anything left over */
    rv = C_EncryptFinal(session, NULL, NULL);
    assert_int_equal(rv, CKR_OK);

    rv = C_DecryptInit (session, &mechanism, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    unsigned char plaintext2[sizeof(plaintext)];
    unsigned long plaintext2_len = ciphertext_len = 16;

    rv = C_DecryptUpdate (session, ciphertext, ciphertext_len,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, 16);

    rv = C_DecryptUpdate (session, &ciphertext[ciphertext_len], ciphertext_len,
            &plaintext2[plaintext2_len], &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, 16);

    rv = C_DecryptFinal (session, NULL, NULL);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, 16);

    rv = C_Logout(session);
    assert_int_equal(rv, CKR_OK);

    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext2));
}

static void test_get_session_info (void **state) {

    CK_SESSION_HANDLE session = state_to_handle(state);

    CK_SESSION_INFO info;
    CK_RV rv = C_GetSessionInfo(session, &info);

    assert_int_equal(rv, CKR_OK);

    assert_int_equal(info.state, CKS_RW_USER_FUNCTIONS);

    assert_int_equal(info.flags, CKF_SERIAL_SESSION | CKF_RW_SESSION);

    assert_int_equal(info.slotID, 1);

    assert_int_equal(info.ulDeviceError, 0);
}

static void test_digest_good(void **state) {

    CK_SESSION_HANDLE session = state_to_handle(state);

    /* now that we have an object, login */
    unsigned char upin[] = "myuserpin";
    CK_RV rv = C_Login(session, CKU_USER, upin, sizeof(upin) - 1);
    assert_int_equal(rv, CKR_OK);

    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    rv = C_DigestInit(session, &smech);
    assert_int_equal(rv, CKR_OK);

    // sizeof a sha256 hash
    unsigned char data[] = "Hello World This is My First Digest Message";

    unsigned char hash[32];
    unsigned long hashlen = sizeof(hash);

    rv = C_DigestUpdate(session, data, sizeof(data) - 1);
    assert_int_equal(rv, CKR_OK);

    rv = C_DigestFinal(session, hash, &hashlen);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(hashlen, sizeof(hash));

    unsigned char hash2[32];
    unsigned long hash2len = sizeof(hash);

    rv = C_DigestInit(session, &smech);
    assert_int_equal(rv, CKR_OK);

    rv = C_Digest(session, data, sizeof(data) - 1, hash2, &hash2len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(hash2len, sizeof(hash2));

    assert_memory_equal(hash, hash2, sizeof(hash) - 1);

    rv = C_Logout(session);
    assert_int_equal(rv, CKR_OK);
}


int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    const struct CMUnitTest tests[] = {
            add_test(test_c_init_destroy_ok),
            add_test(test_c_double_init),
            add_test(test_c_finalize_bad),
            add_ttest(test_c_init_args),
            add_test(test_c_getfunctionlist),
            add_test(test_get_slot_list),
            add_session_test(test_session_open_close),
            add_session_test(test_random),
            add_session_test(test_seed),
            add_session_test(test_sign_verify_good),
            add_session_test(test_sign_verify_logout_fail),
            add_session_test(test_aes_encrypt_decrypt_good),
            add_session_test(test_get_session_info),
            add_session_test(test_digest_good),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
