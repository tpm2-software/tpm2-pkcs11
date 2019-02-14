/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#include "test.h"

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot;
    bool is_logged_in;
    struct {
        CK_OBJECT_HANDLE aes;
        CK_OBJECT_HANDLE rsa;
    } objects;
};

static int test_setup(void **state) {

    test_info *info = calloc(1, sizeof(*info));
    assert_non_null(info);

    /* get the slots */
    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 3);

    /* open a session on slot 1 */
    CK_SESSION_HANDLE handle;
    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
            NULL, &handle);
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    };

    rv = C_FindObjectsInit(handle, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    /* get a AES key */
    CK_OBJECT_HANDLE objhandles[2];
    rv = C_FindObjects(handle, objhandles, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(handle);
    assert_int_equal(rv, CKR_OK);

    /* get an rsa key */
    key_class = CKO_PRIVATE_KEY;
    key_type = CKK_RSA;

    tmpl[0].type = CKA_CLASS;
    tmpl[0].pValue = &key_class;
    tmpl[0].ulValueLen = sizeof(key_class);
    tmpl[1].type = CKA_KEY_TYPE;
    tmpl[1].pValue = &key_type;
    tmpl[1].ulValueLen = sizeof(key_type);

    rv = C_FindObjectsInit(handle, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjects(handle, &objhandles[1], 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(handle);
    assert_int_equal(rv, CKR_OK);

    /* assign to state */
    info->handle = handle;
    info->slot = slots[1];
    info->objects.aes = objhandles[0];
    info->objects.rsa = objhandles[1];

    *state = info;

    /* success */
    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    if (ti->is_logged_in) {
        CK_RV rv = C_Logout(ti->handle);
        assert_int_equal(rv, CKR_OK);
    }

    CK_RV rv = C_CloseSession(ti->handle);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

static void do_login(test_info *ti) {

    user_login(ti->handle);
    ti->is_logged_in = true;
}

static void test_aes_encrypt_decrypt_good(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

    /* now that we have an object, login */
    do_login(ti);

    /* init encryption */
    CK_BYTE iv[16] = {
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
    };

    CK_MECHANISM mechanism = {
        CKM_AES_CBC, iv, sizeof(iv)
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
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    /* part 1 */
    CK_ULONG ciphertext_len = 16;
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

    rv = C_DecryptInit (session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE plaintext2[sizeof(plaintext)];
    CK_ULONG plaintext2_len = ciphertext_len = 16;

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

    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext2));
}

static void test_aes_encrypt_decrypt_5_2_returns(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

    /* now that we have an object, login */
    do_login(ti);

    /* init encryption */
    CK_BYTE iv[16] = {
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
    };

    CK_MECHANISM mechanism = {
        CKM_AES_CBC, iv, sizeof(iv)
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
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    /* get buffer size on NULL case */
    CK_ULONG tmp = 42; // something not 16 to help verify it's ignored
    rv = C_EncryptUpdate(session, plaintext, 16,
            NULL, &tmp);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(tmp, 16);

    /* get buffer size on CKR_BUFFER_TOO_SMALL case */
    tmp--;
    rv = C_EncryptUpdate(session, plaintext, 16,
            ciphertext, &tmp);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(tmp, 16);

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

    rv = C_DecryptInit (session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    unsigned char plaintext2[sizeof(plaintext)];
    unsigned long plaintext2_len = ciphertext_len = 16;

    /* figure out buffer size via NULL*/
    tmp = 42;
    rv = C_DecryptUpdate (session, ciphertext, ciphertext_len,
            NULL, &tmp);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(tmp, plaintext2_len);

    /* figure out buffer size via CKR_BUFFER_TOO_SMALL*/
    tmp--;
    rv = C_DecryptUpdate (session, ciphertext, ciphertext_len,
            plaintext2, &tmp);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);

    /* do decrypt */
    assert_int_equal(tmp, plaintext2_len);

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

    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext2));
}

static void test_aes_encrypt_decrypt_oneshot_good(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

    do_login(ti);

    /* init encryption */
    CK_BYTE iv[16] = {
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
    };

    CK_MECHANISM mechanism = {
        CKM_AES_CBC, iv, sizeof(iv)
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
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    /* part 1 */
    CK_ULONG ciphertext_len = sizeof(plaintext);
    rv = C_Encrypt(session, plaintext, ciphertext_len,
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, sizeof(plaintext));

    rv = C_DecryptInit (session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE plaintext2[sizeof(plaintext)];
    CK_ULONG plaintext2_len = sizeof(plaintext2);

    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, sizeof(plaintext2));

    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext2));
}

static void test_aes_encrypt_decrypt_oneshot_5_2_returns(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

    do_login(ti);

    /* init encryption */
    CK_BYTE iv[16] = {
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
    };

    CK_MECHANISM mechanism = {
        CKM_AES_CBC, iv, sizeof(iv)
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
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG plaintext_len = sizeof(plaintext);

    /* NULL size */
    CK_ULONG tmp = 42;
    rv = C_Encrypt(session, plaintext, plaintext_len,
            NULL, &tmp);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(tmp, sizeof(plaintext));

    /* CKR_BUFFER_TOO_SMALL */
    tmp--;
    rv = C_Encrypt(session, plaintext, plaintext_len,
            ciphertext, &tmp);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(tmp, sizeof(plaintext));

    /* part 1 */
    unsigned long ciphertext_len = sizeof(plaintext);
    rv = C_Encrypt(session, plaintext, ciphertext_len,
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, sizeof(plaintext));

    rv = C_DecryptInit (session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    unsigned char plaintext2[sizeof(plaintext)];
    unsigned long plaintext2_len = sizeof(plaintext2);

    /* NULL size */
    tmp = 42;
    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            NULL, &tmp);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(tmp, sizeof(plaintext2));

    /* CKR_BUFFER_TOO_SMALL size */
    tmp--;
    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            plaintext2, &tmp);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(tmp, sizeof(plaintext2));

    /* good size */
    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, sizeof(plaintext2));

    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext2));
}

#define MGF1_LABEL "mylabel"

static void test_rsa_oaep_encrypt_decrypt_oneshot_good(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

    do_login(ti);

    CK_RSA_PKCS_OAEP_PARAMS params = {
        .hashAlg = CKM_SHA256,
        .pSourceData = MGF1_LABEL,
        .ulSourceDataLen = sizeof(MGF1_LABEL), // include NULL byte
        .source = CKZ_DATA_SPECIFIED,
        .mgf = CKG_MGF1_SHA256
    };

    CK_MECHANISM mechanism = {
        CKM_RSA_PKCS_OAEP, &params, sizeof(params)
    };

    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };

    /* size of RSA 2048 modulus length */
    CK_BYTE ciphertext[256] = { 0 };

    /* init */
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.rsa);
    assert_int_equal(rv, CKR_OK);

    /* part 1 */
    CK_ULONG ciphertext_len = sizeof(ciphertext);
    rv = C_Encrypt(session, plaintext, sizeof(plaintext),
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, sizeof(ciphertext));

    rv = C_DecryptInit (session, &mechanism, ti->objects.rsa);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE plaintext2[sizeof(ciphertext)];
    CK_ULONG plaintext2_len = sizeof(plaintext2);

    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, sizeof(plaintext));

    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext));
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_aes_encrypt_decrypt_oneshot_5_2_returns,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_aes_encrypt_decrypt_5_2_returns,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_aes_encrypt_decrypt_good,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_aes_encrypt_decrypt_oneshot_good,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_rsa_oaep_encrypt_decrypt_oneshot_good,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
