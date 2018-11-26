/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>
#include <tss2/tss2_sys.h>

#define LOGMODULE test
#include "log.h"
#include "pkcs11.h"
#include "db.h"
#include "test.h"

typedef struct test_info test_info;
struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot;
};

static inline test_info *test_info_from_state(void **state) {
    return (test_info *)*state;
}

static int test_setup(void **state) {

    test_info *info = calloc(1, sizeof(*info));
    assert_non_null(info);

    /* Initialize the library */
    CK_RV rv = C_Initialize(NULL);
    assert_int_equal(rv, CKR_OK);

    /* get the slots */
    CK_SLOT_ID slots[6];
    unsigned long count = ARRAY_LEN(slots);
    rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 3);

    /* open a session on slot 1 */
    CK_SESSION_HANDLE handle;
    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
            NULL, &handle);
    assert_int_equal(rv, CKR_OK);

    /* assign to state */
    info->handle = handle;
    info->slot = slots[1];

    *state = info;

    /* success */
    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_RV rv = C_CloseSession(ti->handle);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

static void test_aes_encrypt_decrypt_good(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE session = ti->handle;

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

int test_invoke(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_aes_encrypt_decrypt_good,
                test_setup, test_teardown),
     };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
