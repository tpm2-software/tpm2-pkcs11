/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2019, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#include <openssl/evp.h>
#include <openssl/rsa.h>
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

    ti->slot_id = slots[0];

    return ti;
}

static int test_setup(void **state) {

    test_info *ti = test_info_new();

    CK_RV rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &ti->handle);
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

static void test_rsa_keygen_missing_attributes(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_UTF8CHAR label[] = "minimum-rsa";

    CK_ATTRIBUTE pub[] = {
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_ENCRYPT, ck_true),
        ADD_ATTR_BASE(CKA_VERIFY, ck_true),
        ADD_ATTR_STR(CKA_LABEL, label),
    };

    CK_ATTRIBUTE priv[] = {
        ADD_ATTR_BASE(CKA_DECRYPT, ck_true),
        ADD_ATTR_BASE(CKA_SIGN, ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_STR(CKA_LABEL, label),
        ADD_ATTR_BASE(CKA_EXTRACTABLE, ck_false),
    };

    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    user_login(session);

    CK_RV rv = C_GenerateKeyPair (session,
            &mech,
            pub, ARRAY_LEN(pub),
            priv, ARRAY_LEN(priv),
            &pubkey, &privkey);
    assert_int_equal(rv, CKR_OK);

    /* verify that we can use it via an operation */
    mech.mechanism =  CKM_SHA256_RSA_PKCS;
    rv = C_SignInit(session, &mech, privkey);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE msg[] = "my foo msg";
    CK_BYTE sig[1024];
    CK_ULONG siglen = sizeof(sig);

    rv = C_Sign(session, msg, sizeof(msg) - 1, sig,
            &siglen);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(siglen, 256);

    /* try the public key verification */
    rv = C_VerifyInit(session, &mech, pubkey);
    assert_int_equal(rv, CKR_OK);

    rv = C_Verify(session, msg, sizeof(msg) - 1,
            sig, siglen);
    assert_int_equal(rv, CKR_OK);

    /* verify we can find it via pub templ */
    rv = C_FindObjectsInit(session, pub, ARRAY_LEN(pub));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE pub_handle_dup;
    CK_ULONG count = 0;
    rv = C_FindObjects(session, &pub_handle_dup, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* verify we can find it via priv templ */
    rv = C_FindObjectsInit(session, priv, ARRAY_LEN(priv));
    assert_int_equal(rv, CKR_OK);

    count = 0;
    CK_OBJECT_HANDLE priv_handle_dup;
    rv = C_FindObjects(session, &priv_handle_dup, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* verify missing attrs */
    verify_missing_pub_attrs_common(session, CKK_RSA, pub_handle_dup);
    verify_missing_pub_attrs_rsa(session, pub_handle_dup);

    verify_missing_priv_attrs_common(session, CKK_RSA, priv_handle_dup, CK_FALSE);
    verify_missing_priv_attrs_rsa(session, priv_handle_dup);
}
static void test_rsa_keygen_p11tool_templ(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 2048;
    CK_BYTE exp[] = { 0x00, 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR label[] = "p11-templ-key-label-rsa";

    CK_ATTRIBUTE pub[] = {
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_ENCRYPT, ck_true),
        ADD_ATTR_BASE(CKA_VERIFY, ck_true),
        ADD_ATTR_BASE(CKA_MODULUS_BITS, bits),
        ADD_ATTR_ARRAY(CKA_PUBLIC_EXPONENT, exp),
        ADD_ATTR_STR(CKA_LABEL, label)
    };

    CK_ATTRIBUTE priv[] = {
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_DECRYPT, ck_true),
        ADD_ATTR_BASE(CKA_SIGN, ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_STR(CKA_LABEL, label),
        ADD_ATTR_BASE(CKA_SENSITIVE, ck_false)
    };

    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    user_login(session);

    CK_RV rv = C_GenerateKeyPair (session,
            &mech,
            pub, ARRAY_LEN(pub),
            priv, ARRAY_LEN(priv),
            &pubkey, &privkey);
    assert_int_equal(rv, CKR_OK);

    /* verify that we can use it via an operation */
    mech.mechanism =  CKM_SHA256_RSA_PKCS;
    rv = C_SignInit(session, &mech, privkey);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE msg[] = "my foo msg";
    CK_BYTE sig[1024];
    CK_ULONG siglen = sizeof(sig);

    rv = C_Sign(session, msg, sizeof(msg) - 1, sig,
            &siglen);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(siglen, 256);

    /* try the public key verification */
    rv = C_VerifyInit(session, &mech, pubkey);
    assert_int_equal(rv, CKR_OK);

    rv = C_Verify(session, msg, sizeof(msg) - 1,
            sig, siglen);
    assert_int_equal(rv, CKR_OK);

    /* verify we can find it via pub templ */
    rv = C_FindObjectsInit(session, pub, ARRAY_LEN(pub));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE pub_handle_dup;
    CK_ULONG count = 0;
    rv = C_FindObjects(session, &pub_handle_dup, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* verify we can find it via priv templ */
    rv = C_FindObjectsInit(session, priv, ARRAY_LEN(priv));
    assert_int_equal(rv, CKR_OK);

    count = 0;
    CK_OBJECT_HANDLE priv_handle_dup;
    rv = C_FindObjects(session, &priv_handle_dup, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* verify missing attrs */
    verify_missing_pub_attrs_common(session, CKK_RSA, pub_handle_dup);
    verify_missing_pub_attrs_rsa(session, pub_handle_dup);

    verify_missing_priv_attrs_common(session, CKK_RSA, priv_handle_dup, CK_TRUE);
    verify_missing_priv_attrs_rsa(session, priv_handle_dup);
}

static void test_ecc_keygen_p11tool_templ(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";

    /*
     * DER-encoding of an ANSI X9.62 Parameters value
     *
     * Windows, surprisingly, had great documentation on how this works:
     * https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-object-identifier
     */
    CK_BYTE ec_params[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07
    };

    CK_ATTRIBUTE pub[] = {
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_VERIFY, ck_true),
        ADD_ATTR_ARRAY(CKA_EC_PARAMS, ec_params),
        ADD_ATTR_STR(CKA_LABEL, label)
    };

    CK_ATTRIBUTE priv[] = {
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_SIGN, ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_STR(CKA_LABEL, label),
        ADD_ATTR_BASE(CKA_SENSITIVE, ck_false)
    };

    CK_MECHANISM mech = {
        .mechanism = CKM_EC_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    user_login(session);

    CK_RV rv = C_GenerateKeyPair (session,
            &mech,
            pub, ARRAY_LEN(pub),
            priv, ARRAY_LEN(priv),
            &pubkey, &privkey);
    assert_int_equal(rv, CKR_OK);

    /* verify that we can use it via a sign operation */
    mech.mechanism =  CKM_ECDSA;
    rv = C_SignInit(session, &mech, privkey);
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

    CK_ULONG siglen = sizeof(sig);

    rv = C_Sign(session, sha256_msg_hash, sizeof(sha256_msg_hash), sig,
            &siglen);
    assert_int_equal(rv, CKR_OK);
    /*
     * Skip checking the siglen. This comes back as a DER encoded R + S portions of the signature.
     * R + S is 2 times the curve size in bytes (so 64 for P256) but we're not returning that, were
     * returning the DER encoded format that tools expect, in DER format which may cause leading
     * bytes to be dropped from, R + S, so the output size isn't stable. But it's definitely not 0.
     */
    assert_int_not_equal(siglen, 0);

    /* try the public key verification */
    rv = C_VerifyInit(session, &mech, pubkey);
    assert_int_equal(rv, CKR_OK);

    rv = C_Verify(session, sha256_msg_hash, sizeof(sha256_msg_hash),
            sig, siglen);
    assert_int_equal(rv, CKR_OK);

    /* verify we can find it via pub templ */
    rv = C_FindObjectsInit(session, pub, ARRAY_LEN(pub));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE pub_handle_dup;
    CK_ULONG count = 0;
    rv = C_FindObjects(session, &pub_handle_dup, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* verify we can find it via priv templ */
    rv = C_FindObjectsInit(session, priv, ARRAY_LEN(priv));
    assert_int_equal(rv, CKR_OK);

    count = 0;
    CK_OBJECT_HANDLE priv_handle_dup;
    rv = C_FindObjects(session, &priv_handle_dup, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* verify missing attrs */
    verify_missing_pub_attrs_common(session, CKK_EC, pub_handle_dup);
    verify_missing_priv_attrs_common(session, CKK_EC, priv_handle_dup, CK_TRUE);

    verify_missing_pub_attrs_ecc(session, pub_handle_dup);
    verify_missing_priv_attrs_ecc(session, priv_handle_dup);
}

static void test_destroy(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc-destroy";
    CK_UTF8CHAR label[] = "p11-templ-key-label-ecc-destroy";

    /*
     * DER-encoding of an ANSI X9.62 Parameters value
     *
     * Windows, surprisingly, had great documentation on how this works:
     * https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-object-identifier
     */
    CK_BYTE ec_params[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07
    };

    CK_ATTRIBUTE pub[] = {
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_VERIFY, ck_true),
        ADD_ATTR_ARRAY(CKA_EC_PARAMS, ec_params),
        ADD_ATTR_STR(CKA_LABEL, label)
    };

    CK_ATTRIBUTE priv[] = {
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_SIGN, ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_STR(CKA_LABEL, label),
        ADD_ATTR_BASE(CKA_SENSITIVE, ck_false)
    };

    CK_MECHANISM mech = {
        .mechanism = CKM_EC_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    user_login(session);

    CK_RV rv = C_GenerateKeyPair (session,
            &mech,
            pub, ARRAY_LEN(pub),
            priv, ARRAY_LEN(priv),
            &pubkey, &privkey);
    assert_int_equal(rv, CKR_OK);

    /* verify that if it's held by sign operation, it can't be deleted */
    mech.mechanism =  CKM_ECDSA;
    rv = C_SignInit(session, &mech, privkey);
    assert_int_equal(rv, CKR_OK);

    /* attempt failed destroy */
    rv = C_DestroyObject(session, privkey);
    assert_int_equal(rv, CKR_FUNCTION_FAILED);

    CK_BYTE sig[1024];

    /*
     * echo -n 'my foo msg' | openssl sha256 | cut -d' ' -f 2-2 | xxd -r -p | xxd -i
     */
    CK_BYTE sha256_msg_hash[] = {
        0xcd, 0xd8, 0x92, 0x1d, 0xf0, 0xcd, 0x29, 0xba, 0x4b, 0x8b, 0x87, 0x12,
        0x15, 0x07, 0x46, 0xdf, 0xb1, 0x91, 0x50, 0x81, 0xf7, 0xd4, 0x9b, 0xd5,
        0x67, 0x58, 0xae, 0x5a, 0xa3, 0x2e, 0x47, 0x0d
    };

    CK_ULONG siglen = sizeof(sig);

    /* finish sign to release the private key */
    rv = C_Sign(session, sha256_msg_hash, sizeof(sha256_msg_hash), sig,
            &siglen);
    assert_int_equal(rv, CKR_OK);

    /* attempt good destroy */
    rv = C_DestroyObject(session, privkey);
    assert_int_equal(rv, CKR_OK);

    /* verify gone */
    rv = C_FindObjectsInit(session, priv, ARRAY_LEN(priv));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG count = 0;
    CK_OBJECT_HANDLE tmp;
    rv = C_FindObjects(session, &tmp, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 0);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /*
     * PUBLIC BLOCK DESTROY AND CHECKS
     */

    /*
     * try the public key verification to lock the public portion of the object.
     * active count == 1
     */
    rv = C_VerifyInit(session, &mech, pubkey);
    assert_int_equal(rv, CKR_OK);

    /* attempt failed destroy */
    rv = C_DestroyObject(session, pubkey);
    assert_int_equal(rv, CKR_FUNCTION_FAILED);

    /* release verify active count == 1*/
    rv = C_Verify(session, sha256_msg_hash, sizeof(sha256_msg_hash),
            sig, siglen);
    assert_int_equal(rv, CKR_OK);

    /* attempt good destroy */
    rv = C_DestroyObject(session, pubkey);
    assert_int_equal(rv, CKR_OK);

    /* verify gone */
    rv = C_FindObjectsInit(session, pub, ARRAY_LEN(pub));
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjects(session, &tmp, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 0);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);
}


static void test_destroy_rsa_pkcs(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_UTF8CHAR label[] = "minimum-rsa";

    CK_ATTRIBUTE pub[] = {
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_ENCRYPT, ck_true),
        ADD_ATTR_BASE(CKA_VERIFY, ck_true),
        ADD_ATTR_STR(CKA_LABEL, label),
    };

    CK_ATTRIBUTE priv[] = {
        ADD_ATTR_BASE(CKA_DECRYPT, ck_true),
        ADD_ATTR_BASE(CKA_SIGN, ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_STR(CKA_LABEL, label),
        ADD_ATTR_BASE(CKA_EXTRACTABLE, ck_false),
    };

    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    user_login(session);

    CK_RV rv = C_GenerateKeyPair (session,
            &mech,
            pub, ARRAY_LEN(pub),
            priv, ARRAY_LEN(priv),
            &pubkey, &privkey);
    assert_int_equal(rv, CKR_OK);

    /* verify that if it's held by sign operation, it can't be deleted */
    mech.mechanism =  CKM_RSA_PKCS;
    rv = C_SignInit(session, &mech, privkey);
    assert_int_equal(rv, CKR_OK);

    /* attempt failed destroy */
    rv = C_DestroyObject(session, privkey);
    assert_int_equal(rv, CKR_FUNCTION_FAILED);

    CK_BYTE sha256_msg_hash[] = {
        0x30, 0x31, /* SÈQUENCE */
        0x30, 0x0D, /* SEQUENCE */
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, /* sha 256 */
        0x05, 0x00, /* NULL */
        0x04, 0x20, /* OCTET STRING, 32 bytes */
        0x12, 0x34, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, /* hash */
        0x12, 0x34, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    CK_BYTE sig[1024];
    CK_ULONG siglen = 0;
    /* call for size*/
    rv = C_Sign(session, sha256_msg_hash, sizeof(sha256_msg_hash), NULL,
            &siglen);
    assert_int_equal(rv, CKR_OK);
    rv = C_DestroyObject(session, privkey);
    assert_int_equal(rv, CKR_FUNCTION_FAILED);

    /* finish sign to release the private key */
    siglen = sizeof(sig);
    rv = C_Sign(session, sha256_msg_hash, sizeof(sha256_msg_hash), sig,
            &siglen);
    assert_int_equal(rv, CKR_OK);

    /* attempt good destroy */
    rv = C_DestroyObject(session, privkey);
    assert_int_equal(rv, CKR_OK);
    rv = C_DestroyObject(session, pubkey);
    assert_int_equal(rv, CKR_OK);

}

static void test_keygen_keytype(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BYTE id[] = "keytype_template_id";
    CK_ULONG bits = 2048;
    CK_BYTE exp[] = { 0x00, 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR label[] = "keytype_template_label";
    CK_KEY_TYPE keytype = CKK_EC;

    CK_ATTRIBUTE pub_rsa[] = {
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_ENCRYPT, ck_true),
        ADD_ATTR_BASE(CKA_VERIFY, ck_true),
        ADD_ATTR_BASE(CKA_MODULUS_BITS, bits),
        ADD_ATTR_ARRAY(CKA_PUBLIC_EXPONENT, exp),
        ADD_ATTR_STR(CKA_LABEL, label),
        /* deliberately wrong to CKK_EC */
        ADD_ATTR_BASE(CKA_KEY_TYPE, keytype),

    };

    CK_ATTRIBUTE priv_rsa[] = {
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_DECRYPT, ck_true),
        ADD_ATTR_BASE(CKA_SIGN, ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_STR(CKA_LABEL, label),
        ADD_ATTR_BASE(CKA_SENSITIVE, ck_false)
    };

    CK_MECHANISM mech_rsa = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    user_login(session);

    CK_RV rv = C_GenerateKeyPair (session,
            &mech_rsa,
            pub_rsa, ARRAY_LEN(pub_rsa),
            priv_rsa, ARRAY_LEN(priv_rsa),
            &pubkey, &privkey);
    assert_int_equal(rv, CKR_ATTRIBUTE_VALUE_INVALID);

    /* Test ECC Template */

    /*
     * DER-encoding of an ANSI X9.62 Parameters value
     *
     * Windows, surprisingly, had great documentation on how this works:
     * https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-object-identifier
     */
    CK_BYTE ec_params[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07
    };

    keytype = CKK_RSA;

    CK_ATTRIBUTE pub_ecc[] = {
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_VERIFY, ck_true),
        ADD_ATTR_ARRAY(CKA_EC_PARAMS, ec_params),
        ADD_ATTR_STR(CKA_LABEL, label),
        /* deliberately wrong to CKK_RSA */
        ADD_ATTR_BASE(CKA_KEY_TYPE, keytype),
    };

    CK_ATTRIBUTE priv_ecc[] = {
        ADD_ATTR_ARRAY(CKA_ID, id),
        ADD_ATTR_BASE(CKA_SIGN, ck_true),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_TOKEN,   ck_true),
        ADD_ATTR_STR(CKA_LABEL, label),
        ADD_ATTR_BASE(CKA_SENSITIVE, ck_false)
    };

    CK_MECHANISM mech_ecc = {
        .mechanism = CKM_EC_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };


    rv = C_GenerateKeyPair (session,
            &mech_ecc,
            pub_ecc, ARRAY_LEN(pub_ecc),
            priv_ecc, ARRAY_LEN(priv_ecc),
            &pubkey, &privkey);
    assert_int_equal(rv, CKR_ATTRIBUTE_VALUE_INVALID);

    /* Fixup Keytype to correct value CKK_EC */
    keytype = CKK_EC;
    rv = C_GenerateKeyPair (session,
            &mech_ecc,
            pub_ecc, ARRAY_LEN(pub_ecc),
            priv_ecc, ARRAY_LEN(priv_ecc),
            &pubkey, &privkey);
    assert_int_equal(rv, CKR_OK);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_destroy,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_destroy_rsa_pkcs,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ecc_keygen_p11tool_templ,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_rsa_keygen_p11tool_templ,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_rsa_keygen_missing_attributes,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keygen_keytype,
            test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
