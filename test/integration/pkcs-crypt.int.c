/* SPDX-License-Identifier: BSD-2-Clause */

#include "test.h"

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot;
    struct {
        CK_OBJECT_HANDLE aes;
        CK_OBJECT_HANDLE aes_always_auth;
        struct {
            CK_OBJECT_HANDLE priv;
            CK_OBJECT_HANDLE pub;
        } rsa;
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
    assert_int_equal(count, TOKEN_COUNT);

    /* open a session on slot 0 */
    CK_SESSION_HANDLE handle;
    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
            NULL, &handle);
    assert_int_equal(rv, CKR_OK);

    CK_BBOOL _false = FALSE;
    CK_BBOOL _true  = TRUE;

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_ALWAYS_AUTHENTICATE, &_false, sizeof(_false)},
    };

    user_login(handle);

    rv = C_FindObjectsInit(handle, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    /* get a AES key without always auth*/
    CK_OBJECT_HANDLE objhandles[4];
    rv = C_FindObjects(handle, &objhandles[0], 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(handle);
    assert_int_equal(rv, CKR_OK);

    /* get an aes key with always auth */
    tmpl[2].pValue = &_true;
    rv = C_FindObjectsInit(handle, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjects(handle, &objhandles[1], 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(handle);
    assert_int_equal(rv, CKR_OK);

    /* get an rsa key */
    key_class = CKO_PRIVATE_KEY;
    key_type = CKK_RSA;

    char _label[] = "rsa0";

    CK_ATTRIBUTE tmpl_rsapriv[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_ALWAYS_AUTHENTICATE, &_false, sizeof(_false)},
      {CKA_LABEL, _label, sizeof(_label) - 1},
    };

    rv = C_FindObjectsInit(handle, tmpl_rsapriv, ARRAY_LEN(tmpl_rsapriv));
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjects(handle, &objhandles[2], 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(handle);
    assert_int_equal(rv, CKR_OK);

    /* get an rsa public key */
    key_class = CKO_PUBLIC_KEY;
    key_type = CKK_RSA;

    CK_ATTRIBUTE tmpl_rsapub[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_LABEL, _label, sizeof(_label) - 1},
    };

    rv = C_FindObjectsInit(handle, tmpl_rsapub, ARRAY_LEN(tmpl_rsapub));
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjects(handle, &objhandles[3], 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(handle);
    assert_int_equal(rv, CKR_OK);

    /* assign to state */
    info->handle = handle;
    info->slot = slots[1];
    info->objects.aes = objhandles[0];
    info->objects.aes_always_auth = objhandles[1];
    info->objects.rsa.priv = objhandles[2];
    info->objects.rsa.pub = objhandles[3];

    *state = info;

    /* success */
    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_Logout(ti->handle);
    assert_int_equal(rv, CKR_OK);

    rv = C_CloseSession(ti->handle);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

static void test_aes_encrypt_decrypt_good(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

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
    CK_BYTE final = 0;
    CK_ULONG final_len = 0;
    rv = C_EncryptFinal(session, &final, &final_len);
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
    CK_BYTE final;
    CK_ULONG final_len = 0;
    rv = C_EncryptFinal(session, &final, &final_len);
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

    rv = C_DecryptFinal (session, &final, &final_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(final_len, 0);

    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext2));
}

static void test_aes_encrypt_decrypt_oneshot_good(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

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
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.rsa.pub);
    assert_int_equal(rv, CKR_OK);

    /* part 1 */
    CK_ULONG ciphertext_len = sizeof(ciphertext);
    rv = C_Encrypt(session, plaintext, sizeof(plaintext),
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, sizeof(ciphertext));

    rv = C_DecryptInit (session, &mechanism, ti->objects.rsa.priv);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE plaintext2[sizeof(ciphertext)];
    CK_ULONG plaintext2_len = sizeof(plaintext2);

    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, sizeof(plaintext));

    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext));

    /* retry with SHA1 */
    params.hashAlg = CKM_SHA_1;
    params.mgf = CKG_MGF1_SHA1;
    rv = C_EncryptInit(session, &mechanism, ti->objects.rsa.pub);
    assert_int_equal(rv, CKR_OK);

    /* part 1 */
    rv = C_Encrypt(session, plaintext, sizeof(plaintext),
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, sizeof(ciphertext));

    rv = C_DecryptInit (session, &mechanism, ti->objects.rsa.priv);
    assert_int_equal(rv, CKR_OK);

    plaintext2_len = sizeof(plaintext2);
    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, sizeof(plaintext));

    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext));
}

static void test_aes_always_authenticate(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

    CK_RV rv = C_Logout(session);
    assert_int_equal(rv, CKR_OK);

    /* context specific require C_Login(USER) before */
    context_login_expects(session, CKR_USER_NOT_LOGGED_IN);

    user_login(session);

    /* should be able to initialize operation */
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
    rv = C_EncryptInit(session, &mechanism, ti->objects.aes_always_auth);
    assert_int_equal(rv, CKR_OK);

    /* shouldn't be able to perform actual operation */
    CK_ULONG ciphertext_len = sizeof(plaintext);
    rv = C_Encrypt(session, plaintext, ciphertext_len,
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    /* bad pin should fail */
    context_login_bad_pin(session);

    /* ok log in and go */
    context_login(session);

    rv = C_Encrypt(session, plaintext, ciphertext_len,
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, sizeof(plaintext));

    rv = C_DecryptInit (session, &mechanism, ti->objects.aes_always_auth);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE plaintext2[sizeof(plaintext)];
    CK_ULONG plaintext2_len = sizeof(plaintext2);

    /* shouldn't work */
    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    context_login(session);

    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, sizeof(plaintext2));

    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext2));
}

static void test_cert_no_good(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
    CK_KEY_TYPE cert_type = CKC_X_509;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &obj_class, sizeof(obj_class)  },
        { CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
    };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    /* Find a cert */
    CK_ULONG count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE iv[16] = {
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
    };

    CK_MECHANISM mechanism = {
        CKM_AES_CBC, iv, sizeof(iv)
    };

    rv = C_EncryptInit(session, &mechanism, objhandles[0]);
    assert_int_equal(rv, CKR_KEY_HANDLE_INVALID);

    rv = C_DecryptInit(session, &mechanism, objhandles[0]);
    assert_int_equal(rv, CKR_KEY_HANDLE_INVALID);
}


static void test_rsa_x509_encrypt_decrypt_oneshot_good(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_MECHANISM mechanism = {
            CKM_RSA_X_509, NULL, 0
    };

    /* size of RSA 2048 modulus length */
    CK_BYTE ciphertext[256] = { 0 };
    CK_BYTE plaintext[256] = { 0 };

    const char *secret= "my secret is cool";

    /*
     * PKCS11 guidance for ra wRSA is to prepend message with 0's
     */
    size_t len = strlen(secret);
    memcpy(&plaintext[sizeof(plaintext) - len], secret, len);


    /* init */
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.rsa.priv);
    assert_int_equal(rv, CKR_OK);

    /* part 1 */
    CK_ULONG ciphertext_len = sizeof(ciphertext);
    rv = C_Encrypt(session, plaintext, sizeof(plaintext),
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, sizeof(ciphertext));

    rv = C_DecryptInit (session, &mechanism, ti->objects.rsa.pub);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE plaintext2[sizeof(ciphertext)];
    CK_ULONG plaintext2_len = sizeof(plaintext2);

    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, sizeof(plaintext));

    /* after decrypt we need to undo the padding */
    assert_memory_equal(&plaintext2[plaintext2_len - len], secret, len);
}

static void test_rsa_pkcs_encrypt_decrypt_public_5_2_returns_good(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

    CK_MECHANISM mechanism = {
        CKM_RSA_PKCS, NULL, 0
    };

    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };

    /* size of RSA 2048 modulus length */
    CK_BYTE ciphertext[256] = { 0 };

    /* init */
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.rsa.pub);
    assert_int_equal(rv, CKR_OK);

    /* get size */
    CK_ULONG ciphertext_len = 42;
    rv = C_Encrypt(session, plaintext, sizeof(plaintext),
            NULL, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_not_equal(ciphertext_len, 42);

    /* do encryption */
    rv = C_Encrypt(session, plaintext, sizeof(plaintext),
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, sizeof(ciphertext));

    /* plaintext should not match ciphertext */
    assert_true(sizeof(plaintext) < ciphertext_len);
    assert_memory_not_equal(plaintext, ciphertext, sizeof(plaintext));

    rv = C_DecryptInit (session, &mechanism, ti->objects.rsa.priv);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE plaintext2[sizeof(ciphertext)];
    CK_ULONG plaintext2_len = sizeof(plaintext2);

    rv = C_Decrypt (session, ciphertext, ciphertext_len,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, sizeof(plaintext));
    assert_memory_equal(plaintext2, plaintext, sizeof(plaintext));
}

static void test_aes_big_blockboundry_buffer_encrypt_decrypt_oneshot_5_2_returns(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

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
    CK_BYTE plaintext[1048576] = { 0 };

    size_t i;
    /*
     * for each block memset it to a value so we get each block separated
     * makes looking at it easier.
     *  */
    uint8_t value = 0;
    for(i=0; i < sizeof(plaintext)/16; i++) {
        memset(&plaintext[i*16], value, 16);
        /* intentionally wanting rollover */
        value++;
    }

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

/*
 * This tests that 3 blocks of plaintext encrypted and decrypted
 * via C_EncryptUpdate and C_DecryptUpdate calls work as expected.
 */
static void test_aes_cbc_non_block_boundry_plaintext(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

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
    CK_BYTE plaintext[48] = {
         1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48
    };

    CK_BYTE ciphertext[sizeof(plaintext)] = { 0 };

    /* init */
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG counter = 0;
    CK_ULONG offset = 0;
    /* less than a block */
    unsigned long ciphertext_len = sizeof(plaintext);
    rv = C_EncryptUpdate(session,
            plaintext, 15,
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, 0);
    counter += ciphertext_len;
    offset += 15;

    /* add a block, 31 bytes should return a single block of 16 bytes */
    ciphertext_len = sizeof(plaintext) - counter;
    rv = C_EncryptUpdate(session,
            &plaintext[offset], 16,
            &ciphertext[counter], &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, 16);
    counter += ciphertext_len;
    offset += 16;

    /* add remaining 17 bytes with 15 bytes in the internal state buffer should yield 32 */
    ciphertext_len = sizeof(plaintext) - counter;
    rv = C_EncryptUpdate(session,
            &plaintext[offset], 17,
            &ciphertext[counter], &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, 32);
    counter += ciphertext_len;
    offset += 17;

    /* plain text should be exhausted at this point */
    assert_int_equal(offset, sizeof(plaintext));

    /* cipher text should be fully acquired at this point (AES CBC mode) */
    assert_int_equal(counter, sizeof(ciphertext));


    /*
     * call final to get the last remaining block,
     * which in AES CBC mode shouldn't have one
     */
    ciphertext_len = 42;
    rv = C_EncryptFinal(session,
            NULL, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, 0);

    /*
     *  call it again with a buffer to finish the operation
     *  This shouldn't change the contents of ciphertext buffer,
     *  so pass it in so we can detect bugs where we mutate the
     *  contents.
     */
    static const CK_BYTE all_zeros[sizeof(ciphertext)] = { 0 };
    CK_BYTE tmp[sizeof(ciphertext)] = { 0 };
    rv = C_EncryptFinal(session,
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, 0);
    assert_memory_equal(tmp, all_zeros, sizeof(all_zeros));

    /* now do something wonky for decrypt crossing boundries in weird ways */
    counter = 0;
    offset = 0;
    rv = C_DecryptInit (session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    unsigned char plaintext2[sizeof(plaintext)]= { 0 };
    unsigned long plaintext2_len = sizeof(plaintext2);

    /* go one past the block boundry */
    rv = C_DecryptUpdate (session, ciphertext, 17,
            plaintext2, &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, 16);
    counter += plaintext2_len;
    offset += 17;

    /* add less than a block, 1 byte on internal buffer */
    plaintext2_len = sizeof(plaintext) - counter;
    rv = C_DecryptUpdate (session, &ciphertext[offset], 14,
            &plaintext2[counter], &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, 0);
    counter += plaintext2_len;
    offset += 14;

    /* 15 bytes on internal buffer, add a block, 1 byte remains */
    plaintext2_len = sizeof(plaintext) - counter;
    rv = C_DecryptUpdate (session, &ciphertext[offset], 16,
            &plaintext2[counter], &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, 16);
    counter += plaintext2_len;
    offset += 16;

    /* 15 bytes on internal buffer, add remaining byte, we should get a block back */
    plaintext2_len = sizeof(plaintext) - counter;
    rv = C_DecryptUpdate (session, &ciphertext[offset], 1,
            &plaintext2[counter], &plaintext2_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(plaintext2_len, 16);
    counter += plaintext2_len;
    offset += 1;

    /* we should have decrypted ALL of the ciphertext */
    assert_int_equal(offset, sizeof(ciphertext));

    /* we should have acquired all the plaintext */
    assert_int_equal(counter, sizeof(plaintext2));

    /* the original plaintext and the decrypted plaintext should match */
    assert_memory_equal(plaintext, plaintext2, sizeof(plaintext2));
}

static void test_aes_cbc_non_block_boundry_plaintext_bad(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

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

    CK_BYTE plaintext[36] = {
         1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32, 33, 34, 35, 36
    };

    CK_BYTE ciphertext[sizeof(plaintext)] = { 0 };

    /* init */
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    unsigned long ciphertext_len = sizeof(plaintext);
    rv = C_Encrypt(session,
            plaintext, sizeof(plaintext),
            ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_DATA_LEN_RANGE);
}

static void test_aes_0_bytes(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

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
    CK_BYTE plaintext = 0;

    CK_BYTE ciphertext = 0;

    /* init */
    CK_RV rv = C_EncryptInit(session, &mechanism, ti->objects.aes);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG ciphertext_len = 0;
    rv = C_EncryptUpdate(session,
            &plaintext, 0,
            &ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, 0);

    /*
     * call final to get the last remaining block,
     * which in AES CBC mode shouldn't have one
     */
    ciphertext_len = 42;
    rv = C_EncryptFinal(session,
            NULL, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, 0);

    rv = C_EncryptFinal(session,
            &ciphertext, &ciphertext_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ciphertext_len, 0);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_aes_always_authenticate,
                test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_cert_no_good,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_rsa_x509_encrypt_decrypt_oneshot_good,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_rsa_pkcs_encrypt_decrypt_public_5_2_returns_good,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_aes_big_blockboundry_buffer_encrypt_decrypt_oneshot_5_2_returns,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_aes_big_blockboundry_buffer_encrypt_decrypt_oneshot_5_2_returns,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_aes_cbc_non_block_boundry_plaintext,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_aes_0_bytes,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_aes_cbc_non_block_boundry_plaintext_bad,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
