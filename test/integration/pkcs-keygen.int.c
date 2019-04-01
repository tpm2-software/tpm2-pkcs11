/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2019, Intel Corporation
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

#define ADD_ATTR_BASE(t, x)  { .type = t,   .ulValueLen = sizeof(x),     .pValue = &x }
#define ADD_ATTR_ARRAY(t, x) { .type = t,   .ulValueLen = ARRAY_LEN(x),  .pValue = x }
#define ADD_ATTR_STR(t, x)   { .type = t,   .ulValueLen = sizeof(x) - 1, .pValue = x }

GENERIC_ATTR_TYPE_CONVERT(CK_BBOOL);
GENERIC_ATTR_TYPE_CONVERT(CK_ULONG);

static void verify_missing_rsa_pub_attrs(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {

    CK_BYTE tmp[4][256] = { 0 };

    /*
     * Skip checking shared values until bug:
     *   -https://github.com/tpm2-software/tpm2-pkcs11/issues/148
     * is resolved.
     */
    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_KEY_TYPE, tmp[0]),
            ADD_ATTR_ARRAY(CKA_CLASS,    tmp[1]),
            ADD_ATTR_ARRAY(CKA_MODULUS,  tmp[2]),
            ADD_ATTR_ARRAY(CKA_MODULUS_BITS,  tmp[3]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        case CKA_KEY_TYPE: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CKK_RSA);
        } break;
        case CKA_CLASS: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CKO_PUBLIC_KEY);
        } break;
        case CKA_MODULUS: {
            assert_int_not_equal(0, a->ulValueLen);
            assert_non_null(a->pValue);
        } break;
        case CKA_MODULUS_BITS: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, 2048);
        } break;
        default:
            assert_true(0);
        }
    }
}

static void verify_missing_rsa_priv_attrs(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {

    CK_BYTE tmp[5][256] = { 0 };

    /*
     * Skip checking shared values until bug:
     *   -https://github.com/tpm2-software/tpm2-pkcs11/issues/148
     * is resolved.
     */
    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_KEY_TYPE, tmp[0]),
            ADD_ATTR_ARRAY(CKA_CLASS, tmp[1]),
            ADD_ATTR_ARRAY(CKA_ALWAYS_SENSITIVE,  tmp[2]),
            ADD_ATTR_ARRAY(CKA_EXTRACTABLE,  tmp[3]),
            ADD_ATTR_ARRAY(CKA_NEVER_EXTRACTABLE,  tmp[4]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        case CKA_KEY_TYPE: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CKK_RSA);
        } break;
        case CKA_CLASS: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CKO_PRIVATE_KEY);
        } break;
        case CKA_ALWAYS_SENSITIVE: {
            CK_BBOOL v = CK_FALSE;
            rv = generic_CK_BBOOL(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CK_TRUE);
        } break;
        case CKA_EXTRACTABLE: {
            CK_BBOOL v = CK_TRUE;
            rv = generic_CK_BBOOL(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CK_FALSE);
        } break;
        case CKA_NEVER_EXTRACTABLE: {
            CK_BBOOL v = CK_FALSE;
            rv = generic_CK_BBOOL(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CK_TRUE);
        } break;
        default:
            assert_true(0);
        }
    }
}

static void test_rsa_keygen_p11tool_templ(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_TRUE;
    CK_BYTE id[] = "p11-templ-key-id";
    CK_ULONG bits = 2048;
    CK_BYTE exp[] = { 0x00, 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR label[] = "p11-templ-key-label";

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
    verify_missing_rsa_pub_attrs(session, pub_handle_dup);
    verify_missing_rsa_priv_attrs(session, priv_handle_dup);

}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_rsa_keygen_p11tool_templ,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
