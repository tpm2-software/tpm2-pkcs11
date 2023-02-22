/* SPDX-License-Identifier: BSD-2-Clause */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <assert.h>

#include "test.h"

#define ATTR(a, v, t) { a, &(t){v}, sizeof(t) }
#define ATTR_VAR(a, v, len) { a, v, len }

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
};

static test_info *test_info_new(void) {

    test_info *ti = calloc(1, sizeof(*ti));
    assert_non_null(ti);

    /* Get the slots */
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

static void gen_ecc_keypair(CK_SESSION_HANDLE session, CK_BYTE id,
                            CK_BYTE *curve, size_t curve_size,
                            uint8_t *pubkey, size_t *pubkey_len) {

    CK_MECHANISM mechanism = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pub_template[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_DERIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        /* */
        ATTR_VAR(CKA_EC_PARAMS, curve, curve_size),
    };
    CK_ATTRIBUTE priv_template[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_DERIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_DECRYPT, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        /* */
        ATTR(CKA_ID, id, CK_BYTE),
    };
    CK_ATTRIBUTE ec_point = { CKA_EC_POINT, NULL, 0 };
    CK_OBJECT_HANDLE private = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE public = CK_INVALID_HANDLE;
    CK_RV rv = CKR_GENERAL_ERROR;

    rv = C_GenerateKeyPair(session, & mechanism,
                           pub_template, ARRAY_LEN(pub_template),
                           priv_template, ARRAY_LEN(priv_template),
                           &public, &private);
    assert_int_equal(rv, CKR_OK);

    rv = C_GetAttributeValue(session, public, &ec_point, 1);
    assert_int_equal(rv, CKR_OK);

    assert(*pubkey_len >= ec_point.ulValueLen);
    ec_point.pValue = pubkey;

    rv = C_GetAttributeValue(session, public, &ec_point, 1);
    assert_int_equal(rv, CKR_OK);

    *pubkey_len = ec_point.ulValueLen;
}

static void gen_nistp256(CK_SESSION_HANDLE session, CK_BYTE id,
                         uint8_t* pubkey, size_t *pubkey_len) {
    CK_BYTE curve[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07
    };

    gen_ecc_keypair(session, id, curve, sizeof(curve), pubkey, pubkey_len);
}

static void ecdh1_derive(CK_SESSION_HANDLE session, CK_BYTE id,
                         uint8_t *pubkey, size_t pubkey_len,
                         uint8_t *secret, size_t secret_len) {

    CK_MECHANISM mechanism = { CKM_ECDH1_DERIVE, NULL, 0 };
    CK_ATTRIBUTE secret_template[] = {
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        /* */
        ATTR(CKA_VALUE_LEN, secret_len, CK_ULONG),
    };
    CK_ATTRIBUTE priv_template[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_DERIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_DECRYPT, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        /* */
        ATTR(CKA_ID, id, CK_BYTE),
    };
    CK_ATTRIBUTE derived_template[] = {
        ATTR_VAR(CKA_VALUE, secret, secret_len),
    };
    CK_ECDH1_DERIVE_PARAMS params = {
        .kdf = CKD_NULL,
        .ulSharedDataLen = 0,
        .pSharedData = secret,
        .ulPublicDataLen = 0,
        .pPublicData = NULL,
    };
    CK_OBJECT_HANDLE private = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_ULONG count = 0;

    /* Populate the mechanism, skip the DER header */
    mechanism.ulParameterLen = sizeof(params);
    mechanism.mechanism = CKM_ECDH1_DERIVE;
    mechanism.pParameter = &params;
    params.ulPublicDataLen = pubkey_len - 2;
    pubkey++;
    pubkey++;
    params.pPublicData = pubkey;

    /* Retrieve the private key */
    rv = C_FindObjectsInit(session, priv_template, ARRAY_LEN(priv_template));
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjects(session, &private, 2, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* Derive */
    rv = C_DeriveKey(session, &mechanism, private, secret_template,
                     ARRAY_LEN(secret_template), &derived);
    assert_int_equal(rv, CKR_OK);

    /* Get the secret */
    rv = C_GetAttributeValue(session, derived, derived_template,
                             ARRAY_LEN(derived_template));
    assert_int_equal(rv, CKR_OK);
}

static void test_ecc_derive_nist_p256_templ(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    /* NIST P-256: 32 bytes */
    struct {
        CK_BYTE shr[32];    /* Shared secret is the length of the key */
        CK_BYTE pub[70];    /* Allocate extra space for encoding      */
        size_t plen;
        CK_BYTE id;
    } key[] = {
        [0] = { .id = 0x00, .shr = { 0 }, .pub = { 0 }, .plen = 70 },
        [1] = { .id = 0x01, .shr = { 1 }, .pub = { 1 }, .plen = 70 },
    };

    user_login(session);

    gen_nistp256(session, key[0].id, key[0].pub, &key[0].plen);
    gen_nistp256(session, key[1].id, key[1].pub, &key[1].plen);

    ecdh1_derive(session, key[0].id, key[1].pub, key[1].plen, key[0].shr, 32);
    ecdh1_derive(session, key[1].id, key[0].pub, key[0].plen, key[1].shr, 32);

    assert(memcmp(key[0].shr, key[1].shr, 32) == 0);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ecc_derive_nist_p256_templ,
                                        test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
