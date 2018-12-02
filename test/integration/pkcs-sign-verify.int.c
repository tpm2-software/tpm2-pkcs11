/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#include "test.h"

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
};

static test_info *test_info_new(void) {

    test_info *ti = calloc(1, sizeof(*ti));
    assert_non_null(ti);

    /* get the slots */
    CK_SLOT_ID slots[6];
    unsigned long count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 3);

    ti->slot_id = slots[0];

    return ti;
}

static int test_setup(void **state) {

    test_info *ti = test_info_new();

    CK_RV rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL,
            NULL, &ti->handle);
    assert_int_equal(rv, CKR_OK);

    *state = ti;

    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_CloseAllSessions(ti->slot_id);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

/*
 * Test that we can do a CKM_RSA_PKCS mechanism signature.
 *
 * This signature type will require an ASN1 digestinfo structure
 * to be populated, and then passed to the C_Sign().
 *
 * More information on the Digest Info structure can be found:
 *   - https://tools.ietf.org/html/rfc3447
 *
 * In short, its;
 *   DigestInfo ::= SEQUENCE {
 *     digestAlgorithm AlgorithmIdentifier,
 *     digest OCTET STRING
 *   }
 *
 * The nice part is the note specification has the ASN1 header you can just
 * append the hash too, so we do this:
 *
 * SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
 *              04 20 || H.
 *
 * We'll use SHA256 since the simulator supports it, we can then use
 * the CKM_SHA256_RSA_PKCS mechanism (which should go to tpm_sign
 * and the results should match.
 */

/*
 * The message to sign.
 */
static const unsigned char _data[] = { 'F', 'O', 'O', ' ', 'B', 'A', 'R' };

/*
 * The hash of the message to sign computed externally.
 */
static const unsigned char _data_hash_sha256[] = {
    0x8d, 0x35, 0xc9, 0x7b, 0xcd,
    0x90, 0x2b, 0x96, 0xd1, 0xb5, 0x51, 0x74, 0x1b, 0xbe, 0x8a, 0x7f, 0x50,
    0xbb, 0x5a, 0x69, 0x0b, 0x4d, 0x02, 0x25, 0x48, 0x2e, 0xaa, 0x63, 0xdb,
    0xfb, 0x9d, 0xed
};

static const unsigned char _data_hash_sha512[] = {
  0xcf, 0x4a, 0xca, 0x20, 0x77, 0xda, 0x02, 0xe6, 0x56, 0xc5, 0xe5, 0xed,
  0x26, 0xd7, 0x81, 0x6b, 0xfc, 0x20, 0x2f, 0x7d, 0x40, 0xfe, 0x01, 0x27,
  0x5f, 0x62, 0xd4, 0x91, 0x18, 0xa3, 0xbc, 0x5b, 0x20, 0xef, 0x94, 0x27,
  0x24, 0xfc, 0x35, 0xb6, 0x67, 0x37, 0xbd, 0xec, 0x26, 0x28, 0x33, 0xc7,
  0x49, 0xfd, 0xa9, 0x95, 0x54, 0x63, 0xc7, 0x55, 0xe9, 0x1a, 0x27, 0xc3,
  0x8d, 0xda, 0x9e, 0xfb
};

static void test_sign_verify_CKM_RSA_PKCS_sha256(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = { { CKA_CLASS, &key_class, sizeof(key_class) }, {
            CKA_KEY_TYPE, &key_type, sizeof(key_type) }, };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    /* Find an RSA key */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    user_login(session);

    /*
     * Now that we have a key for sign, build up what we need to sign,
     * which is the ASN1 digest info for CKM_RSA_PKCS
     */
    CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS };
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    /* 19 byte ASN1 header + sha256 32 byte size */
    unsigned char digest_info[19 + sizeof(_data_hash_sha256)] = {
        /* 19 byte ASN1 structure from the IETF rfc3447 for SHA256*/
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,

        /* the hash bytes, 0 them out */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, };

    memcpy(&digest_info[19], _data_hash_sha256, sizeof(_data_hash_sha256));

    unsigned char ckm_rsa_pkcs_sig[4096];
    unsigned long ckm_rsa_pkcs_siglen = sizeof(ckm_rsa_pkcs_sig);

    rv = C_Sign(session, digest_info, sizeof(digest_info), ckm_rsa_pkcs_sig,
            &ckm_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);

    /*
     * OK now internally hash/sign the data via CKM_SHA256_RSA_PKCS
     */
    mech.mechanism = CKM_SHA256_RSA_PKCS;
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    unsigned char ckm_sha256_rsa_pkcs_sig[4096];
    unsigned long ckm_sha256_rsa_pkcs_siglen = sizeof(ckm_rsa_pkcs_sig);

    rv = C_Sign(session, (unsigned char *) _data, sizeof(_data),
            ckm_sha256_rsa_pkcs_sig, &ckm_sha256_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(ckm_sha256_rsa_pkcs_siglen, ckm_rsa_pkcs_siglen);


    assert_memory_equal(ckm_sha256_rsa_pkcs_sig, ckm_rsa_pkcs_sig,
            ckm_sha256_rsa_pkcs_siglen);
}

/*
 * Verify that using a non-tpm supported SHA algorithm works. The Simulator
 * by default only goes to SHA384, so use SHA512.
 *
 * It uses CKM_RSA_PKCS and CKM_SHA512_RSA_PKCS to verify that
 * they match.
 *
 * This uses CKM_RSA_PKCS which means that the host application
 * builds out the RSA_PKCS v1.5 signing structure as defined in
 * https://www.ietf.org/rfc/rfc3447.txt
 */
static void test_sign_verify_CKM_RSA_PKCS_sha512(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
    };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    /* Find an RSA key */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    user_login(session);

    /*
     * Now that we have a key for sign, build up what we need to sign,
     * which is the ASN1 digest info for CKM_RSA_PKCS
     */
    CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS };
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    /* 19 byte ASN1 header + sha512 64 byte size */
    unsigned char digest_info[19 + sizeof(_data_hash_sha512)] = {
        /* https://www.ietf.org/rfc/rfc3447.txt
         * Page 42
         * 19 byte ASN1 structure from the IETF rfc3447 for SHA512
         */
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,

        /* the hash bytes (64 of them), 0 them out */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 16 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 32 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 48 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 64 */
    };

    memcpy(&digest_info[19], _data_hash_sha512, sizeof(_data_hash_sha512));

    unsigned char ckm_rsa_pkcs_sig[4096];
    unsigned long ckm_rsa_pkcs_siglen = sizeof(ckm_rsa_pkcs_sig);

    rv = C_Sign(session, digest_info, sizeof(digest_info), ckm_rsa_pkcs_sig,
            &ckm_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);

    /*
     * OK now internally hash/sign the data via CKM_SHA512_RSA_PKCS
     */
    mech.mechanism = CKM_SHA512_RSA_PKCS;
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    unsigned char ckm_sha512_rsa_pkcs_sig[4096];
    unsigned long ckm_sha512_rsa_pkcs_siglen = sizeof(ckm_rsa_pkcs_sig);

    rv = C_Sign(session, (unsigned char *) _data, sizeof(_data),
            ckm_sha512_rsa_pkcs_sig, &ckm_sha512_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(ckm_sha512_rsa_pkcs_siglen, ckm_rsa_pkcs_siglen);

    assert_memory_equal(ckm_sha512_rsa_pkcs_sig, ckm_rsa_pkcs_sig,
            ckm_sha512_rsa_pkcs_siglen);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sign_verify_CKM_RSA_PKCS_sha256,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_verify_CKM_RSA_PKCS_sha512,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

