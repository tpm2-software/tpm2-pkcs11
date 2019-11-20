/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

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
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, TOKEN_COUNT);

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
static const CK_BYTE _data[] = { 'F', 'O', 'O', ' ', 'B', 'A', 'R' };

/*
 * The hash of the message to sign computed externally.
 */
static const CK_BYTE _data_hash_sha256[] = {
    0x8d, 0x35, 0xc9, 0x7b, 0xcd,
    0x90, 0x2b, 0x96, 0xd1, 0xb5, 0x51, 0x74, 0x1b, 0xbe, 0x8a, 0x7f, 0x50,
    0xbb, 0x5a, 0x69, 0x0b, 0x4d, 0x02, 0x25, 0x48, 0x2e, 0xaa, 0x63, 0xdb,
    0xfb, 0x9d, 0xed
};

static const CK_BYTE _data_hash_sha512[] = {
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

    user_login(session);

    /* Find an RSA key */
    CK_ULONG count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /*
     * Now that we have a key for sign, build up what we need to sign,
     * which is the ASN1 digest info for CKM_RSA_PKCS
     */
    CK_MECHANISM mech = { .mechanism =  CKM_RSA_PKCS };
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    /* 19 byte ASN1 header + sha256 32 byte size */
    CK_BYTE digest_info[19 + sizeof(_data_hash_sha256)] = {
        /* 19 byte ASN1 structure from the IETF rfc3447 for SHA256*/
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,

        /* the hash bytes, 0 them out */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, };

    memcpy(&digest_info[19], _data_hash_sha256, sizeof(_data_hash_sha256));

    CK_BYTE ckm_rsa_pkcs_sig[4096];
    CK_ULONG ckm_rsa_pkcs_siglen = sizeof(ckm_rsa_pkcs_sig);

    rv = C_Sign(session, digest_info, sizeof(digest_info), ckm_rsa_pkcs_sig,
            &ckm_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);

    /*
     * OK now internally hash/sign the data via CKM_SHA256_RSA_PKCS
     */
    mech.mechanism = CKM_SHA256_RSA_PKCS;
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE ckm_sha256_rsa_pkcs_sig[4096];
    CK_ULONG ckm_sha256_rsa_pkcs_siglen = sizeof(ckm_rsa_pkcs_sig);

    rv = C_Sign(session, (CK_BYTE_PTR ) _data, sizeof(_data),
            ckm_sha256_rsa_pkcs_sig, &ckm_sha256_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(ckm_sha256_rsa_pkcs_siglen, ckm_rsa_pkcs_siglen);


    assert_memory_equal(ckm_sha256_rsa_pkcs_sig, ckm_rsa_pkcs_sig,
            ckm_sha256_rsa_pkcs_siglen);

    rv = C_VerifyInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    rv = C_Verify(session, (CK_BYTE_PTR ) _data, sizeof(_data),
            ckm_sha256_rsa_pkcs_sig, ckm_sha256_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);
}

static void test_sign_verify_CKM_RSA_PKCS_5_2_returns(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = { { CKA_CLASS, &key_class, sizeof(key_class) }, {
            CKA_KEY_TYPE, &key_type, sizeof(key_type) }, };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    user_login(session);

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

    /*
     * Now that we have a key for sign, build up what we need to sign,
     * which is the ASN1 digest info for CKM_RSA_PKCS
     */
    CK_MECHANISM mech = { .mechanism =  CKM_RSA_PKCS };
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

    /* NULL size */
    CK_ULONG tmp = 42;
    rv = C_Sign(session, digest_info, sizeof(digest_info), NULL,
            &tmp);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(tmp, 256);

    /* CKR_BUFFER_TOO_SMALL */
    tmp = 42;
    rv = C_Sign(session, digest_info, sizeof(digest_info), ckm_rsa_pkcs_sig,
            &tmp);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(tmp, 256);

    /* OK */
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

    rv = C_VerifyInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    rv = C_Verify(session, (unsigned char *) _data, sizeof(_data),
            ckm_sha256_rsa_pkcs_sig, ckm_sha256_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);
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

    user_login(session);

    /* Find an RSA key */
    CK_ULONG count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /*
     * Now that we have a key for sign, build up what we need to sign,
     * which is the ASN1 digest info for CKM_RSA_PKCS
     */
    CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS };
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    /* 19 byte ASN1 header + sha512 64 byte size */
    CK_BYTE digest_info[19 + sizeof(_data_hash_sha512)] = {
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

    CK_BYTE ckm_rsa_pkcs_sig[4096];
    CK_ULONG ckm_rsa_pkcs_siglen = sizeof(ckm_rsa_pkcs_sig);

    rv = C_Sign(session, digest_info, sizeof(digest_info), ckm_rsa_pkcs_sig,
            &ckm_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);

    /*
     * OK now internally hash/sign the data via CKM_SHA512_RSA_PKCS
     */
    mech.mechanism = CKM_SHA512_RSA_PKCS;
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE ckm_sha512_rsa_pkcs_sig[4096];
    CK_ULONG ckm_sha512_rsa_pkcs_siglen = sizeof(ckm_rsa_pkcs_sig);

    rv = C_Sign(session, (CK_BYTE_PTR ) _data, sizeof(_data),
            ckm_sha512_rsa_pkcs_sig, &ckm_sha512_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(ckm_sha512_rsa_pkcs_siglen, ckm_rsa_pkcs_siglen);

    assert_memory_equal(ckm_sha512_rsa_pkcs_sig, ckm_rsa_pkcs_sig,
            ckm_sha512_rsa_pkcs_siglen);
}

static void test_sign_verify_CKM_ECDSA(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    user_login(session);

    get_keypair(session, CKK_EC, &pubkey, &privkey);

    /* verify that we can use it via a sign operation */
    CK_MECHANISM mech = { .mechanism = CKM_ECDSA };
    CK_RV rv = C_SignInit(session, &mech, privkey);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE sig[1024];

    /*
     * echo -n 'my foo msg' | openssl sha256 | cut -d' ' -f 2-2 | xxd -r -p | xxd -i
     */
    CK_BYTE sha256_msg_hash[] = {
        0xcd, 0xd8, 0x92, 0x1d, 0xf0, 0xcd, 0x29, 0xba, 0x4b, 0x8b, 0x87, 0x12,
        0x15, 0x07, 0x46, 0xdf, 0xb1, 0x91, 0x50, 0x81, 0xf7, 0xd4, 0x9b, 0xd5,
        0x67, 0x58, 0xae, 0x5a, 0xa3, 0x2e, 0x47, 0x0d
    };

    CK_ULONG siglen;

    /* Call C_Sign for size */
    rv = C_Sign(session, sha256_msg_hash, sizeof(sha256_msg_hash), NULL,
            &siglen);
    assert_int_equal(rv, CKR_OK);
    /* The signature comes back as DER encoded R + S parts of the signature.
     * R + S is 2 times the curve size in bytes (so 64 for P256) but we're not
     * returning that, but the DER encoded format that tools expect.
     * Since the length of DER encoding is dependend on the encoded value
     * (e.g. leading zero if negative), the output size is not stable.
     * Thus calling C_Sign for size must return the maximum length of the DER
     * encoded value, which is (2+1+keylength) * 2 + 2. So for P256 = 72
     * the actual signature size may be smaller.
     */
    assert_int_equal(siglen, 72);
    CK_ULONG tmp_len = siglen;

    rv = C_Sign(session, sha256_msg_hash, sizeof(sha256_msg_hash), sig,
            &siglen);
    assert_int_equal(rv, CKR_OK);
    /* the actual siglength may be smaller than the previously reported siglen */
    assert_in_range(siglen, 1, tmp_len);

    /* try the public key verification */
    rv = C_VerifyInit(session, &mech, pubkey);
    assert_int_equal(rv, CKR_OK);

    rv = C_Verify(session, sha256_msg_hash, sizeof(sha256_msg_hash),
            sig, siglen);
    assert_int_equal(rv, CKR_OK);
}

static void test_sign_verify_CKM_ECDSA_SHA1(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_EC;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
    };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    user_login(session);

    /* Find an EC key */
    CK_ULONG count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    CK_MECHANISM mech = { .mechanism = CKM_ECDSA_SHA1 };

    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE ckm_ecdsa_sha1_sig[4096];
    CK_ULONG ckm_ecdsa_sha1_siglen = 0;

    /* Call C_Sign for Size */
    rv = C_Sign(session, (CK_BYTE_PTR ) _data, sizeof(_data),
            NULL, &ckm_ecdsa_sha1_siglen);
    assert_int_equal(rv, CKR_OK);
    assert_int_not_equal(ckm_ecdsa_sha1_siglen, 0);

    CK_ULONG tmp_len = ckm_ecdsa_sha1_siglen;
    rv = C_Sign(session, (CK_BYTE_PTR ) _data, sizeof(_data),
            ckm_ecdsa_sha1_sig, &ckm_ecdsa_sha1_siglen);
    assert_int_equal(rv, CKR_OK);
    /* actual size must not be larger than previously indicated */
    assert_in_range(ckm_ecdsa_sha1_siglen, 1, tmp_len);

    rv = C_VerifyInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    rv = C_Verify(session, (CK_BYTE_PTR ) _data, sizeof(_data),
            ckm_ecdsa_sha1_sig, ckm_ecdsa_sha1_siglen);
    assert_int_equal(rv, CKR_OK);
}

static void test_double_sign_call_for_size_SHA256(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = { { CKA_CLASS, &key_class, sizeof(key_class) }, {
            CKA_KEY_TYPE, &key_type, sizeof(key_type) }, };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    user_login(session);

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

    /* initialize a signing operation */
    CK_MECHANISM mech = { .mechanism = CKM_SHA256_RSA_PKCS };
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE sig[4096];
    CK_ULONG siglen = 0;

    CK_BYTE_PTR msg=(unsigned char *)"my very cool message";

    /* get the size of the buffer for a sign */
    rv = C_Sign(session, msg, sizeof(msg), NULL,
            &siglen);
    assert_int_equal(rv, CKR_OK);
    assert_true(siglen > 0);

    /* Fail again on a size too small buffer CKR_BUFFER_TOO_SMALL case */
    CK_ULONG toosmallsiglen = siglen - 1;
    rv = C_Sign(session, msg, sizeof(msg), sig,
            &toosmallsiglen);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);

    rv = C_Sign(session, msg, sizeof(msg), sig,
            &siglen);
    assert_int_equal(rv, CKR_OK);

}

static void test_double_sign_call_for_size_SHA512(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = { { CKA_CLASS, &key_class, sizeof(key_class) }, {
            CKA_KEY_TYPE, &key_type, sizeof(key_type) }, };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    user_login(session);

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

    /* initialize a signing operation */
    CK_MECHANISM mech = { .mechanism = CKM_SHA512_RSA_PKCS };
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE sig[4096];
    CK_ULONG siglen = 0;

    CK_BYTE_PTR msg=(unsigned char *)"my very cool message";

    /* get the size of the buffer for a sign */
    rv = C_Sign(session, msg, sizeof(msg), NULL,
            &siglen);
    assert_int_equal(rv, CKR_OK);
    assert_true(siglen > 0);

    /* Fail again on a size too small buffer CKR_BUFFER_TOO_SMALL case */
    CK_ULONG toosmallsiglen = siglen - 1;
    rv = C_Sign(session, msg, sizeof(msg), sig,
            &toosmallsiglen);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);

    rv = C_Sign(session, msg, sizeof(msg), sig,
            &siglen);
    assert_int_equal(rv, CKR_OK);
}

static void test_double_sign_final_call_for_size_SHA256(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = { { CKA_CLASS, &key_class, sizeof(key_class) }, {
            CKA_KEY_TYPE, &key_type, sizeof(key_type) }, };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    user_login(session);

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

    /* initialize a signing operation */
    CK_MECHANISM mech = { .mechanism = CKM_SHA256_RSA_PKCS };
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE sig[4096];
    CK_BYTE_PTR msg=(unsigned char *)"my very cool message";

    rv = C_SignUpdate(session, msg, sizeof(msg));
    assert_int_equal(rv, CKR_OK);

    /* get the size of the buffer for a sign */
    CK_ULONG siglen = 0;
    rv = C_SignFinal(session, NULL, &siglen);
    assert_int_equal(rv, CKR_OK);

    /* Fail again on a size too small buffer CKR_BUFFER_TOO_SMALL case */
    CK_ULONG toosmallsiglen = siglen - 1;
    rv = C_SignFinal(session, sig,
            &toosmallsiglen);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);

    rv = C_SignFinal(session, sig, &siglen);
    assert_int_equal(rv, CKR_OK);
}

static void test_double_sign_final_call_for_size_SHA512(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = { { CKA_CLASS, &key_class, sizeof(key_class) }, {
            CKA_KEY_TYPE, &key_type, sizeof(key_type) }, };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    user_login(session);

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

    /* initialize a signing operation */
    CK_MECHANISM mech = { .mechanism = CKM_SHA512_RSA_PKCS };
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE sig[4096];
    CK_BYTE_PTR msg=(unsigned char *)"my very cool message";

    rv = C_SignUpdate(session, msg, sizeof(msg));
    assert_int_equal(rv, CKR_OK);

    /* get the size of the buffer for a sign */
    CK_ULONG siglen = 0;
    rv = C_SignFinal(session, NULL, &siglen);
    assert_int_equal(rv, CKR_OK);

    /* Fail again on a size too small buffer CKR_BUFFER_TOO_SMALL case */
    CK_ULONG toosmallsiglen = siglen - 1;
    rv = C_SignFinal(session, sig,
            &toosmallsiglen);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);

    rv = C_SignFinal(session, sig, &siglen);
    assert_int_equal(rv, CKR_OK);
}

static CK_ATTRIBUTE_PTR get_attr(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE_PTR attrs, CK_ULONG attr_len) {

    CK_ULONG i;
    for (i=0; i < attr_len; i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        if (a->type == type) {
            return a;
        }
    }

    return NULL;
}

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL && !defined(LIBRESSL_VERSION_NUMBER)) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L) /* OpenSSL 1.1.0 */
#define LIB_TPM2_OPENSSL_OPENSSL_PRE11
#endif

RSA *template_to_rsa_pub_key(CK_ATTRIBUTE_PTR attrs, CK_ULONG attr_len) {

    RSA *ssl_rsa_key = NULL;
    BIGNUM *e = NULL, *n = NULL;

    /* get the exponent */
    CK_ATTRIBUTE_PTR a = get_attr(CKA_PUBLIC_EXPONENT, attrs, attr_len);
    assert_non_null(a);

    e = BN_bin2bn((void*)a->pValue, a->ulValueLen, NULL);
    assert_non_null(e);

    /* get the modulus */
    a = get_attr(CKA_MODULUS, attrs, attr_len);
    assert_non_null(a);

    n = BN_bin2bn(a->pValue, a->ulValueLen,
                  NULL);
    assert_non_null(n);

    ssl_rsa_key = RSA_new();
    assert_non_null(ssl_rsa_key);

#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    ssl_rsa_key->e = e;
    ssl_rsa_key->n = n;
#else
    int rc = RSA_set0_key(ssl_rsa_key, n, e, NULL);
    assert_int_equal(rc, 1);
#endif

    return ssl_rsa_key;
}

static void verify(RSA *pub, CK_BYTE_PTR msg, CK_ULONG msg_len, CK_BYTE_PTR sig, CK_ULONG sig_len) {

    EVP_PKEY *pkey = EVP_PKEY_new();
    assert_non_null(pkey);

    int rc = EVP_PKEY_set1_RSA(pkey, pub);
    assert_int_equal(rc, 1);

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    const EVP_MD* md = EVP_get_digestbyname("SHA256");
    assert_non_null(md);

    rc = EVP_DigestInit_ex(ctx, md, NULL);
    assert_int_equal(rc, 1);

    rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
    assert_int_equal(rc, 1);

    rc = EVP_DigestVerifyUpdate(ctx, msg, msg_len);
    assert_int_equal(rc, 1);

    rc = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    assert_int_equal(rc, 1);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(ctx);
}

static void test_sign_verify_public(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_HANDLE priv_handle;
    CK_OBJECT_HANDLE pub_handle;

    user_login(session);

    get_keypair(session, CKK_RSA, &pub_handle, &priv_handle);

    /*
     * Now that we have a key for sign, build up what we need to sign,
     * which is the ASN1 digest info for CKM_RSA_PKCS
     */
    CK_MECHANISM mech = { .mechanism =  CKM_SHA256_RSA_PKCS };
    CK_RV rv = C_SignInit(session, &mech, priv_handle);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE msg[] = "my foo msg";
    CK_BYTE sig[1024];
    CK_ULONG siglen = sizeof(sig);

    rv = C_Sign(session, msg, sizeof(msg) - 1, sig,
            &siglen);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(siglen, 256);

    /* build an OSSL RSA key from parts */
    CK_BYTE _tmp_bufs[2][1024];
    CK_ATTRIBUTE attrs[] = {
        { .type = CKA_PUBLIC_EXPONENT, .ulValueLen = sizeof(_tmp_bufs[0]), .pValue = &_tmp_bufs[0] },
        { .type = CKA_MODULUS,         .ulValueLen = sizeof(_tmp_bufs[1]), .pValue = &_tmp_bufs[1] },
    };

    rv = C_GetAttributeValue(session, pub_handle, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    RSA *r = template_to_rsa_pub_key(attrs, ARRAY_LEN(attrs));
    assert_non_null(r);

    verify(r, msg, sizeof(msg) - 1, sig, siglen);
    RSA_free(r);
}

static void test_sign_verify_context_specific_good(void **state) {

    static CK_BBOOL _true = CK_TRUE;

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &key_class, sizeof(key_class)  },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_ALWAYS_AUTHENTICATE, &_true, sizeof(_true) },
    };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    user_login(session);

    /* Find an RSA key w/CKA_ALWAYS_AUTHENTICATE set */
    CK_ULONG count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_Logout(session);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* context specific require C_Login(USER) before */
    context_login_expects(session, CKR_USER_NOT_LOGGED_IN);

    user_login(session);

    CK_MECHANISM mech = { .mechanism =  CKM_SHA256_RSA_PKCS };
    /*
     * OK now internally hash/sign the data via CKM_SHA256_RSA_PKCS
     */
    rv = C_SignInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE ckm_sha256_rsa_pkcs_sig[4096];
    CK_ULONG ckm_sha256_rsa_pkcs_siglen = sizeof(ckm_sha256_rsa_pkcs_sig);

    /* this should fail with CKR_USER_NOT_LOGGED_IN */
    rv = C_Sign(session, (CK_BYTE_PTR ) _data, sizeof(_data),
            ckm_sha256_rsa_pkcs_sig, &ckm_sha256_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    /* bad pin should fail */
    context_login_bad_pin(session);

    /* finally logged in, should work */
    context_login(session);

    rv = C_Sign(session, (CK_BYTE_PTR ) _data, sizeof(_data),
            ckm_sha256_rsa_pkcs_sig, &ckm_sha256_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);

    rv = C_VerifyInit(session, &mech, objhandles[0]);
    assert_int_equal(rv, CKR_OK);

    /* this should fail */
    rv = C_Verify(session, (CK_BYTE_PTR ) _data, sizeof(_data),
            ckm_sha256_rsa_pkcs_sig, ckm_sha256_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    context_login(session);
    rv = C_Verify(session, (CK_BYTE_PTR ) _data, sizeof(_data),
            ckm_sha256_rsa_pkcs_sig, ckm_sha256_rsa_pkcs_siglen);
    assert_int_equal(rv, CKR_OK);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sign_verify_context_specific_good,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_verify_public,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_verify_CKM_RSA_PKCS_5_2_returns,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_double_sign_call_for_size_SHA512,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_double_sign_final_call_for_size_SHA512,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_double_sign_call_for_size_SHA256,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_double_sign_final_call_for_size_SHA256,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_verify_CKM_RSA_PKCS_sha256,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_verify_CKM_RSA_PKCS_sha512,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_verify_CKM_ECDSA_SHA1,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_verify_CKM_ECDSA,
            test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

