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
#include <openssl/objects.h>

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

static void verify_missing_common_attrs_rsa(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {

    CK_BYTE tmp[3][256] = { 0 };

    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_MODULUS,  tmp[0]),
            ADD_ATTR_ARRAY(CKA_MODULUS_BITS,  tmp[1]),
            ADD_ATTR_ARRAY(CKA_PUBLIC_EXPONENT, tmp[2]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG count = 0;

    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        case CKA_MODULUS: {
            assert_int_not_equal(0, a->ulValueLen);
            assert_non_null(a->pValue);
            count++;
        } break;
        case CKA_MODULUS_BITS: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, 2048);
            count++;
        } break;
        case CKA_PUBLIC_EXPONENT:
            assert_int_not_equal(0, a->ulValueLen);
            assert_non_null(a->pValue);
            count++;
            break;
        default:
            assert_true(0);
        }
    }

    assert_int_equal(count, ARRAY_LEN(attrs));
}

static void verify_missing_priv_attrs_rsa(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {
    verify_missing_common_attrs_rsa(session, h);
}

static void verify_missing_pub_attrs_rsa(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {
    verify_missing_common_attrs_rsa(session, h);
}

static void test_ec_params(CK_ATTRIBUTE_PTR ecparams) {

    const unsigned char *p = ecparams->pValue;

    ASN1_OBJECT *a = d2i_ASN1_OBJECT(NULL, &p, ecparams->ulValueLen);
    assert_non_null(a);

    int nid = OBJ_obj2nid(a);
    ASN1_OBJECT_free(a);

    switch (nid) {
    case NID_X9_62_prime192v1:
    case NID_secp224r1:
    case NID_X9_62_prime256v1:
    case NID_secp384r1:
    case NID_secp521r1:
        break;
    default:
        fail_msg("Unsupported nid to tpm EC algorithm mapping, got nid: %d", nid);
    }
}

static void verify_missing_pub_attrs_ecc(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {

    CK_BYTE tmp[2][256] = { 0 };

    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_EC_PARAMS,  tmp[0]),
            ADD_ATTR_ARRAY(CKA_EC_POINT,    tmp[1]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG count = 0;
    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        /* TODO more robust checking here:
         *  - They match what was expected in generation.
         */
        case CKA_EC_PARAMS:
            test_ec_params(a);
            count++;
            break;
        case CKA_EC_POINT:
            // DER-encoding of ANSI X9.62 ECPoint value Q
            assert_int_not_equal(0, a->ulValueLen);
            assert_non_null(a->pValue);
            count++;
        break;
        default:
            assert_true(0);
        }
    }

    assert_int_equal(count, ARRAY_LEN(attrs));
}

static void verify_missing_priv_attrs_common(CK_SESSION_HANDLE session, CK_KEY_TYPE keytype, CK_OBJECT_HANDLE h) {

    CK_BYTE tmp[5][256] = { 0 };

    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_KEY_TYPE, tmp[0]),
            ADD_ATTR_ARRAY(CKA_CLASS, tmp[1]),
            ADD_ATTR_ARRAY(CKA_ALWAYS_SENSITIVE,  tmp[2]),
            ADD_ATTR_ARRAY(CKA_EXTRACTABLE,  tmp[3]),
            ADD_ATTR_ARRAY(CKA_NEVER_EXTRACTABLE,  tmp[4]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG count = 0;

    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        case CKA_KEY_TYPE: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, keytype);
            count++;
        } break;
        case CKA_CLASS: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CKO_PRIVATE_KEY);
            count++;
        } break;
        case CKA_ALWAYS_SENSITIVE: {
            CK_BBOOL v = CK_FALSE;
            rv = generic_CK_BBOOL(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CK_TRUE);
            count++;
        } break;
        case CKA_EXTRACTABLE: {
            CK_BBOOL v = CK_TRUE;
            rv = generic_CK_BBOOL(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CK_FALSE);
            count++;
        } break;
        case CKA_NEVER_EXTRACTABLE: {
            CK_BBOOL v = CK_FALSE;
            rv = generic_CK_BBOOL(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CK_TRUE);
            count++;
        } break;
        default:
            assert_true(0);
        }
    }

    assert_int_equal(count, ARRAY_LEN(attrs));
}

static void verify_missing_pub_attrs_common(CK_SESSION_HANDLE session, CK_KEY_TYPE keytype, CK_OBJECT_HANDLE h) {

    CK_BYTE tmp[2][256] = { 0 };

    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_KEY_TYPE, tmp[0]),
            ADD_ATTR_ARRAY(CKA_CLASS,    tmp[1]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG count = 0;
    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        case CKA_KEY_TYPE: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, keytype);
            count++;
        } break;
        case CKA_CLASS: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CKO_PUBLIC_KEY);
            count++;
        } break;
        default:
            assert_true(0);
        }
    }

    assert_int_equal(count, ARRAY_LEN(attrs));
}

static void test_rsa_keygen_p11tool_templ(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_TRUE;
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

    verify_missing_priv_attrs_common(session, CKK_RSA, priv_handle_dup);
    verify_missing_priv_attrs_rsa(session, priv_handle_dup);
}

static void test_ecc_keygen_p11tool_templ(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_TRUE;
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
    verify_missing_priv_attrs_common(session, CKK_EC, priv_handle_dup);
    verify_missing_pub_attrs_ecc(session, pub_handle_dup);
}

static void test_destroy(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_TRUE;
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

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_destroy,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ecc_keygen_p11tool_templ,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_rsa_keygen_p11tool_templ,
            test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
