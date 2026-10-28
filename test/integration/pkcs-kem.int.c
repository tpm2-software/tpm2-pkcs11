/* SPDX-License-Identifier: BSD-2-Clause */

#include <assert.h>

#include <openssl/evp.h>

#include "test.h"

/*
 * C_EncapsulateKey and C_DecapsulateKey, with CKM_RSA_PKCS_OAEP and CKM_ECDH1_DERIVE (not CKM_RSA_PKCS).
 * RSA encapsulates a secret from the TPM's RNG, encrypted with the public key; decapsulating is
 * unwrapping it. ECDH encapsulates with an ephemeral key pair, whose public point is the ciphertext.
 */

#define ATTR(a, v, t) { a, &(t){v}, sizeof(t) }
#define ATTR_VAR(a, v, len) { a, v, len }

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
};

static CK_SLOT_ID first_slot(void) {

    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_true(count > 0);

    return slots[0];
}

static int test_setup(void **state) {

    test_info *ti = calloc(1, sizeof(*ti));
    assert_non_null(ti);

    ti->slot_id = first_slot();

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

/* The number of objects the session sees */
static CK_ULONG count_objects(CK_SESSION_HANDLE session) {

    CK_RV rv = C_FindObjectsInit(session, NULL, 0);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG total = 0;
    for (;;) {
        CK_OBJECT_HANDLE found[64];
        CK_ULONG count = 0;
        rv = C_FindObjects(session, found, ARRAY_LEN(found), &count);
        assert_int_equal(rv, CKR_OK);
        if (!count) {
            break;
        }
        total += count;
    }

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    return total;
}

static CK_BBOOL get_bool(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type) {

    CK_BBOOL value = 0xff;
    CK_ATTRIBUTE a = { type, &value, sizeof(value) };
    CK_RV rv = C_GetAttributeValue(session, h, &a, 1);
    assert_int_equal(rv, CKR_OK);
    return value;
}

/* A session RSA key pair whose public key may encapsulate and private key decapsulate */
static void gen_rsa(CK_SESSION_HANDLE session, CK_BBOOL encapsulate, CK_BBOOL decapsulate,
        CK_BBOOL always_auth, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {

    /* a key pair that can neither sign, decrypt nor decapsulate is refused: give it CKA_SIGN */
    CK_BBOOL sign = !decapsulate;

    CK_ATTRIBUTE pub_templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_VERIFY, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_ENCAPSULATE, &encapsulate, sizeof(encapsulate)),
        ATTR(CKA_MODULUS_BITS, 2048, CK_ULONG),
    };
    CK_ATTRIBUTE priv_templ[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
        /* only decapsulate may ask for the TPM's decrypt attribute */
        ATTR_VAR(CKA_SIGN, &sign, sizeof(sign)),
        ATTR(CKA_DECRYPT, CK_FALSE, CK_BBOOL),
        ATTR_VAR(CKA_DECAPSULATE, &decapsulate, sizeof(decapsulate)),
        ATTR_VAR(CKA_ALWAYS_AUTHENTICATE, &always_auth, sizeof(always_auth)),
    };

    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_RV rv = C_GenerateKeyPair(session, &mech,
            pub_templ, ARRAY_LEN(pub_templ),
            priv_templ, ARRAY_LEN(priv_templ),
            pub, priv);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(get_bool(session, *pub, CKA_ENCAPSULATE), encapsulate);
    assert_int_equal(get_bool(session, *priv, CKA_DECAPSULATE), decapsulate);
}

static CK_BYTE p256[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

static CK_BYTE p384[] = {
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22
};

static CK_BYTE p521[] = {
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23
};

/* A session EC key pair whose public key may encapsulate and private key decapsulate, or derive */
static void gen_ec_curve(CK_SESSION_HANDLE session, CK_BYTE *curve, CK_ULONG curve_len,
        CK_BBOOL encapsulate, CK_BBOOL decapsulate, CK_BBOOL derive, CK_BBOOL always_auth,
        CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {

    CK_BBOOL sign = !decapsulate;

    CK_ATTRIBUTE pub_templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_VERIFY, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_ENCAPSULATE, &encapsulate, sizeof(encapsulate)),
        ATTR_VAR(CKA_EC_PARAMS, curve, curve_len),
    };
    CK_ATTRIBUTE priv_templ[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
        /* decapsulate may ask for the TPM's decrypt attribute, which ECDH needs, without derive */
        ATTR_VAR(CKA_SIGN, &sign, sizeof(sign)),
        ATTR_VAR(CKA_DERIVE, &derive, sizeof(derive)),
        ATTR_VAR(CKA_DECAPSULATE, &decapsulate, sizeof(decapsulate)),
        ATTR_VAR(CKA_ALWAYS_AUTHENTICATE, &always_auth, sizeof(always_auth)),
    };

    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_RV rv = C_GenerateKeyPair(session, &mech,
            pub_templ, ARRAY_LEN(pub_templ),
            priv_templ, ARRAY_LEN(priv_templ),
            pub, priv);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(get_bool(session, *pub, CKA_ENCAPSULATE), encapsulate);
    assert_int_equal(get_bool(session, *priv, CKA_DECAPSULATE), decapsulate);
    assert_int_equal(get_bool(session, *priv, CKA_DERIVE), derive);
}

/* A P-256 key pair, whose private key doesn't derive */
static void gen_ec(CK_SESSION_HANDLE session, CK_BBOOL encapsulate, CK_BBOOL decapsulate,
        CK_BBOOL always_auth, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {

    gen_ec_curve(session, p256, sizeof(p256), encapsulate, decapsulate, CK_FALSE, always_auth,
            pub, priv);
}

static CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
    .hashAlg = CKM_SHA256,
    .mgf = CKG_MGF1_SHA256,
    .source = CKZ_DATA_SPECIFIED,
    .pSourceData = NULL,
    .ulSourceDataLen = 0,
};

static CK_MECHANISM oaep = { CKM_RSA_PKCS_OAEP, &oaep_params, sizeof(oaep_params) };

static CK_ECDH1_DERIVE_PARAMS ecdh_params = {
    .kdf = CKD_NULL,
    .ulSharedDataLen = 0,
    .pSharedData = NULL,
    .ulPublicDataLen = 0,
    .pPublicData = NULL,
};

static CK_MECHANISM ecdh = { CKM_ECDH1_DERIVE, &ecdh_params, sizeof(ecdh_params) };

/* Encapsulates, with the §5.2 length query first, and checks the query made nothing */
static CK_ULONG encapsulate(CK_SESSION_HANDLE session, CK_MECHANISM *mech, CK_OBJECT_HANDLE pub,
        CK_ATTRIBUTE *templ, CK_ULONG count, CK_BYTE *ct, CK_ULONG ct_size, CK_OBJECT_HANDLE *key) {

    CK_ULONG before = count_objects(session);

    CK_ULONG len = 0;
    CK_OBJECT_HANDLE none = CK_INVALID_HANDLE;
    CK_RV rv = C_EncapsulateKey(session, mech, pub, templ, count, NULL, &len, &none);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(none, CK_INVALID_HANDLE);
    assert_true(len <= ct_size);
    assert_int_equal(count_objects(session), before);

    CK_ULONG got = ct_size;
    rv = C_EncapsulateKey(session, mech, pub, templ, count, ct, &got, key);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(got, len);
    assert_int_equal(count_objects(session), before + 1);

    return got;
}

static CK_ULONG get_value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h, CK_BYTE *value,
        CK_ULONG size) {

    CK_ATTRIBUTE a = { CKA_VALUE, value, size };
    CK_RV rv = C_GetAttributeValue(session, h, &a, 1);
    assert_int_equal(rv, CKR_OK);
    return a.ulValueLen;
}

/* What a key encapsulation makes has: it didn't stay in the token all along */
static void assert_kem_attrs(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {

    assert_int_equal(get_bool(session, h, CKA_LOCAL), CK_FALSE);
    assert_int_equal(get_bool(session, h, CKA_ALWAYS_SENSITIVE), CK_FALSE);
    assert_int_equal(get_bool(session, h, CKA_NEVER_EXTRACTABLE), CK_FALSE);
}

/* A readable generic secret of len bytes, or of the mechanism's length when len is 0 */
#define GENERIC_TEMPL(name, len) \
    CK_ATTRIBUTE name[] = { \
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS), \
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE), \
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL), \
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL), \
        ATTR(CKA_VALUE_LEN, len, CK_ULONG), \
    }

static void test_kem_rsa_oaep_roundtrip(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_SESSION_HANDLE session = ti->handle;
    CK_MECHANISM *mech = &oaep;

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(session, CK_TRUE, CK_TRUE, CK_FALSE, &pub, &priv);

    GENERIC_TEMPL(templ, 32);

    CK_BYTE ct[512];
    CK_OBJECT_HANDLE encapsulated = CK_INVALID_HANDLE;
    CK_ULONG ct_len = encapsulate(session, mech, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct),
            &encapsulated);
    assert_int_equal(ct_len, 256);

    CK_OBJECT_HANDLE decapsulated = CK_INVALID_HANDLE;
    CK_RV rv = C_DecapsulateKey(session, mech, priv, templ, ARRAY_LEN(templ), ct, ct_len,
            &decapsulated);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE a[64], b[64];
    assert_int_equal(get_value(session, encapsulated, a, sizeof(a)), 32);
    assert_int_equal(get_value(session, decapsulated, b, sizeof(b)), 32);
    assert_memory_equal(a, b, 32);

    /* a secret from the RNG, not zeros */
    CK_BYTE zero[32] = { 0 };
    assert_memory_not_equal(a, zero, 32);

    assert_int_equal(get_bool(session, encapsulated, CKA_EXTRACTABLE), CK_TRUE);
    assert_int_equal(get_bool(session, decapsulated, CKA_EXTRACTABLE), CK_TRUE);
    assert_kem_attrs(session, encapsulated);
    assert_kem_attrs(session, decapsulated);

    /* a second encapsulation is a new secret */
    CK_OBJECT_HANDLE again = CK_INVALID_HANDLE;
    encapsulate(session, mech, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct), &again);
    assert_int_equal(get_value(session, again, b, sizeof(b)), 32);
    assert_memory_not_equal(a, b, 32);
}

/* PKCS#1 v1.5 isn't offered, though PKCS#11 6.1.6 allows it: its decapsulation is a padding oracle */
static void test_kem_rsa_pkcs_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &pub, &priv);

    GENERIC_TEMPL(templ, 32);
    CK_BYTE ct[512];
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_ULONG ct_len = encapsulate(ti->handle, &oaep, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct), &h);

    CK_ULONG before = count_objects(ti->handle);
    CK_MECHANISM pkcs = { CKM_RSA_PKCS, NULL, 0 };
    CK_ULONG len = sizeof(ct);
    CK_OBJECT_HANDLE none = CK_INVALID_HANDLE;
    CK_RV rv = C_EncapsulateKey(ti->handle, &pkcs, pub, templ, ARRAY_LEN(templ), NULL, &len, &none);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);
    rv = C_EncapsulateKey(ti->handle, &pkcs, pub, templ, ARRAY_LEN(templ), ct, &len, &none);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);
    rv = C_DecapsulateKey(ti->handle, &pkcs, priv, templ, ARRAY_LEN(templ), ct, ct_len, &none);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);
    assert_int_equal(none, CK_INVALID_HANDLE);
    assert_int_equal(count_objects(ti->handle), before);
}

/* One block, CBC with a zero IV */
static void encrypt_block(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE aes, CK_BYTE ct[16]) {

    CK_BYTE zero_iv[16] = { 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC, zero_iv, sizeof(zero_iv) };
    CK_BYTE block[16] = "a block of text";

    CK_RV rv = C_EncryptInit(session, &cbc, aes);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG ct_len = 16;
    rv = C_Encrypt(session, block, sizeof(block), ct, &ct_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ct_len, 16);
}

static void test_kem_rsa_into_aes(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &pub, &priv);

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_VALUE_LEN, 32, CK_ULONG),
        ATTR(CKA_ENCRYPT, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };

    CK_BYTE ct[512];
    CK_OBJECT_HANDLE encapsulated = CK_INVALID_HANDLE;
    CK_ULONG ct_len = encapsulate(ti->handle, &oaep, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct),
            &encapsulated);

    CK_OBJECT_HANDLE decapsulated = CK_INVALID_HANDLE;
    CK_RV rv = C_DecapsulateKey(ti->handle, &oaep, priv, templ, ARRAY_LEN(templ), ct, ct_len,
            &decapsulated);
    assert_int_equal(rv, CKR_OK);

    /* in the TPM: unextractable, by the extractable-default rule */
    assert_int_equal(get_bool(ti->handle, encapsulated, CKA_EXTRACTABLE), CK_FALSE);
    assert_int_equal(get_bool(ti->handle, decapsulated, CKA_EXTRACTABLE), CK_FALSE);
    assert_kem_attrs(ti->handle, encapsulated);
    assert_kem_attrs(ti->handle, decapsulated);

    CK_BYTE a[16], b[16];
    encrypt_block(ti->handle, encapsulated, a);
    encrypt_block(ti->handle, decapsulated, b);
    assert_memory_equal(a, b, 16);

    /* an AES key is 16, 24 or 32 bytes */
    CK_ATTRIBUTE bad[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_VALUE_LEN, 20, CK_ULONG),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };
    CK_ULONG before = count_objects(ti->handle);
    CK_ULONG len = 0;
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    rv = C_EncapsulateKey(ti->handle, &oaep, pub, bad, ARRAY_LEN(bad), NULL, &len, &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_VALUE_INVALID);
    assert_int_equal(count_objects(ti->handle), before);
}

/* The Z ECDH gives for the private key and the ciphertext's point, by C_DeriveKey */
static void derive_z(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv, CK_BYTE *point,
        CK_ULONG point_len, CK_BYTE z[32]) {

    CK_ECDH1_DERIVE_PARAMS params = {
        .kdf = CKD_NULL,
        .ulPublicDataLen = point_len,
        .pPublicData = point,
    };
    CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    GENERIC_TEMPL(templ, 32);
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_RV rv = C_DeriveKey(session, &mech, priv, templ, ARRAY_LEN(templ), &derived);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(get_value(session, derived, z, 32), 32);
}

static void test_kem_ecdh_roundtrip(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    /* a key that also derives, so C_DeriveKey can check what decapsulating gives */
    CK_OBJECT_HANDLE pub, priv;
    gen_ec_curve(ti->handle, p256, sizeof(p256), CK_TRUE, CK_TRUE, CK_TRUE, CK_FALSE, &pub, &priv);

    /* without CKA_VALUE_LEN: the whole of Z */
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };

    CK_BYTE ct[256];
    CK_OBJECT_HANDLE encapsulated = CK_INVALID_HANDLE;
    CK_ULONG ct_len = encapsulate(ti->handle, &ecdh, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct),
            &encapsulated);

    /* the ephemeral point, uncompressed, in a DER OCTET STRING */
    assert_int_equal(ct_len, 67);
    assert_int_equal(ct[0], 0x04);
    assert_int_equal(ct[1], 65);
    assert_int_equal(ct[2], 0x04);

    CK_OBJECT_HANDLE decapsulated = CK_INVALID_HANDLE;
    CK_RV rv = C_DecapsulateKey(ti->handle, &ecdh, priv, templ, ARRAY_LEN(templ), ct, ct_len,
            &decapsulated);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE a[64], b[64];
    assert_int_equal(get_value(ti->handle, encapsulated, a, sizeof(a)), 32);
    assert_int_equal(get_value(ti->handle, decapsulated, b, sizeof(b)), 32);
    assert_memory_equal(a, b, 32);
    assert_kem_attrs(ti->handle, encapsulated);
    assert_kem_attrs(ti->handle, decapsulated);

    /* the raw point decapsulates too */
    rv = C_DecapsulateKey(ti->handle, &ecdh, priv, templ, ARRAY_LEN(templ), &ct[2], 65,
            &decapsulated);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(get_value(ti->handle, decapsulated, b, sizeof(b)), 32);
    assert_memory_equal(a, b, 32);

    /* it is the ECDH secret of the private key and the ephemeral point */
    CK_BYTE z[32];
    derive_z(ti->handle, priv, &ct[2], 65, z);
    assert_memory_equal(a, z, 32);

    /* CKA_VALUE_LEN truncates Z from its leading end (PKCS#11 6.3.17) */
    GENERIC_TEMPL(short_templ, 16);
    encapsulate(ti->handle, &ecdh, pub, short_templ, ARRAY_LEN(short_templ), ct, sizeof(ct),
            &encapsulated);
    rv = C_DecapsulateKey(ti->handle, &ecdh, priv, short_templ, ARRAY_LEN(short_templ), ct, 67,
            &decapsulated);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(get_value(ti->handle, encapsulated, a, sizeof(a)), 16);
    assert_int_equal(get_value(ti->handle, decapsulated, b, sizeof(b)), 16);
    assert_memory_equal(a, b, 16);
    derive_z(ti->handle, priv, &ct[2], 65, z);
    assert_memory_equal(a, &z[16], 16);

    /* into an AES key, which the two can encrypt with */
    CK_ATTRIBUTE aes_templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_ENCRYPT, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };
    encapsulate(ti->handle, &ecdh, pub, aes_templ, ARRAY_LEN(aes_templ), ct, sizeof(ct),
            &encapsulated);
    rv = C_DecapsulateKey(ti->handle, &ecdh, priv, aes_templ, ARRAY_LEN(aes_templ), ct, 67,
            &decapsulated);
    assert_int_equal(rv, CKR_OK);
    encrypt_block(ti->handle, encapsulated, a);
    encrypt_block(ti->handle, decapsulated, b);
    assert_memory_equal(a, b, 16);

    /* longer than Z */
    GENERIC_TEMPL(long_templ, 33);
    CK_ULONG len = 0;
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    rv = C_EncapsulateKey(ti->handle, &ecdh, pub, long_templ, ARRAY_LEN(long_templ), NULL, &len, &h);
    assert_int_equal(rv, CKR_KEY_SIZE_RANGE);
    rv = C_DecapsulateKey(ti->handle, &ecdh, priv, long_templ, ARRAY_LEN(long_templ), ct, 67, &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);

    /* a key made to decapsulate only has the TPM's decrypt attribute, but doesn't derive */
    CK_OBJECT_HANDLE kem_pub, kem_priv;
    gen_ec(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &kem_pub, &kem_priv);
    CK_ECDH1_DERIVE_PARAMS params = {
        .kdf = CKD_NULL,
        .ulPublicDataLen = 65,
        .pPublicData = &ct[2],
    };
    CK_MECHANISM derive_mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    CK_ULONG before = count_objects(ti->handle);
    rv = C_DeriveKey(ti->handle, &derive_mech, kem_priv, long_templ, ARRAY_LEN(long_templ), &h);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
    assert_int_equal(count_objects(ti->handle), before);
}

/* The private key labelled label, found in the session's token */
static CK_OBJECT_HANDLE find_private_key(CK_SESSION_HANDLE session, const char *label) {

    CK_OBJECT_CLASS clazz = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE templ[] = {
        { CKA_CLASS, &clazz, sizeof(clazz) },
        { CKA_LABEL, (void *)label, strlen(label) },
    };
    CK_RV rv = C_FindObjectsInit(session, templ, ARRAY_LEN(templ));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    rv = C_FindObjects(session, &h, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    return h;
}

/* A peer's public point, from a new P-256 key pair, to derive with */
static CK_ULONG peer_point(CK_SESSION_HANDLE session, CK_BYTE *point, CK_ULONG size) {

    CK_OBJECT_HANDLE peer_pub, peer_priv;
    gen_ec(session, CK_FALSE, CK_FALSE, CK_FALSE, &peer_pub, &peer_priv);
    CK_ATTRIBUTE a = { CKA_EC_POINT, point, size };
    CK_RV rv = C_GetAttributeValue(session, peer_pub, &a, 1);
    assert_int_equal(rv, CKR_OK);
    return a.ulValueLen;
}

/*
 * A key stored with CKA_DERIVE=false and no CKA_DECAPSULATE still derives, through the TPM's decrypt
 * attribute, as it always did: stores made before CKA_DERIVE was mapped hold EC keys so, as every EC
 * key's CKA_DERIVE defaulted to false. "ec-legacy-ecdh" is one: create_pkcs_store.sh made it with
 * tpm2_ptool, which gives it CKA_DERIVE=false (objects.py), knows no CKA_DECAPSULATE, and has
 * tpm2_create give it the TPM's decrypt attribute, and allowed it CKM_ECDH1_DERIVE.
 */
static void test_kem_legacy_ec_key_derives(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE legacy_priv = find_private_key(ti->handle, "ec-legacy-ecdh");
    assert_int_equal(get_bool(ti->handle, legacy_priv, CKA_DERIVE), CK_FALSE);
    CK_BBOOL b = CK_FALSE;
    CK_ATTRIBUTE decapsulate = { CKA_DECAPSULATE, &b, sizeof(b) };
    CK_RV rv = C_GetAttributeValue(ti->handle, legacy_priv, &decapsulate, 1);
    assert_int_equal(rv, CKR_ATTRIBUTE_TYPE_INVALID);

    CK_BYTE point[128];
    CK_ULONG point_len = peer_point(ti->handle, point, sizeof(point));
    CK_ECDH1_DERIVE_PARAMS params = {
        .kdf = CKD_NULL,
        .ulPublicDataLen = point_len,
        .pPublicData = point,
    };
    CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    GENERIC_TEMPL(templ, 32);
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    rv = C_DeriveKey(ti->handle, &mech, legacy_priv, templ, ARRAY_LEN(templ), &derived);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE z[32];
    assert_int_equal(get_value(ti->handle, derived, z, sizeof(z)), 32);
}

/* What C_DeriveKey gives for priv and a peer's point, with a readable template */
static CK_RV try_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv, CK_BYTE *point,
        CK_ULONG point_len) {

    CK_ECDH1_DERIVE_PARAMS params = {
        .kdf = CKD_NULL,
        .ulPublicDataLen = point_len,
        .pPublicData = point,
    };
    CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    GENERIC_TEMPL(templ, 32);
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ULONG before = count_objects(session);
    CK_RV rv = C_DeriveKey(session, &mech, priv, templ, ARRAY_LEN(templ), &derived);
    if (rv != CKR_OK) {
        assert_int_equal(count_objects(session), before);
    }
    return rv;
}

/*
 * A key made on this token has CKA_DECAPSULATE: its CKA_DERIVE=false is enforced, whatever its
 * CKA_DECAPSULATE is. A copy without CKA_DECAPSULATE, or the key with CKA_DECAPSULATE turned off,
 * doesn't derive the Z of a ciphertext the key decapsulated into an unextractable key.
 */
static void test_kem_decapsulate_off_doesnt_derive(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_ec(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &pub, &priv);

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };
    CK_BYTE ct[256];
    CK_OBJECT_HANDLE encapsulated = CK_INVALID_HANDLE;
    CK_ULONG ct_len = encapsulate(ti->handle, &ecdh, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct),
            &encapsulated);
    assert_int_equal(ct_len, 67);
    CK_OBJECT_HANDLE decapsulated = CK_INVALID_HANDLE;
    CK_RV rv = C_DecapsulateKey(ti->handle, &ecdh, priv, templ, ARRAY_LEN(templ), ct, ct_len,
            &decapsulated);
    assert_int_equal(rv, CKR_OK);

    /* a copy that can't decapsulate */
    CK_BBOOL ck_false = CK_FALSE;
    CK_ATTRIBUTE no_decapsulate = { CKA_DECAPSULATE, &ck_false, sizeof(ck_false) };
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    rv = C_CopyObject(ti->handle, priv, &no_decapsulate, 1, &copy);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(get_bool(ti->handle, copy, CKA_DECAPSULATE), CK_FALSE);
    assert_int_equal(get_bool(ti->handle, copy, CKA_DERIVE), CK_FALSE);
    rv = try_derive(ti->handle, copy, &ct[2], 65);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);

    /* the key still decapsulates */
    rv = C_DecapsulateKey(ti->handle, &ecdh, priv, templ, ARRAY_LEN(templ), ct, ct_len,
            &decapsulated);
    assert_int_equal(rv, CKR_OK);

    /* the key itself, once it can't decapsulate */
    rv = C_SetAttributeValue(ti->handle, priv, &no_decapsulate, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(get_bool(ti->handle, priv, CKA_DECAPSULATE), CK_FALSE);
    rv = try_derive(ti->handle, priv, &ct[2], 65);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);

    /* a key made to derive, with CKA_DERIVE turned off */
    CK_OBJECT_HANDLE dpub, dpriv;
    gen_ec_curve(ti->handle, p256, sizeof(p256), CK_FALSE, CK_FALSE, CK_TRUE, CK_FALSE,
            &dpub, &dpriv);
    assert_int_equal(try_derive(ti->handle, dpriv, &ct[2], 65), CKR_OK);
    CK_ATTRIBUTE no_derive = { CKA_DERIVE, &ck_false, sizeof(ck_false) };
    rv = C_SetAttributeValue(ti->handle, dpriv, &no_derive, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(try_derive(ti->handle, dpriv, &ct[2], 65), CKR_KEY_FUNCTION_NOT_PERMITTED);
}

/* The longer curves: P-521's point takes DER's long form (04 81 85 04 ...) */
static void test_kem_ecdh_curves(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    static const struct {
        CK_BYTE *curve;
        CK_ULONG curve_len;
        CK_ULONG field;
        CK_ULONG ct_len;
        CK_BYTE header[3];
        CK_ULONG header_len;
    } cases[] = {
        { p384, sizeof(p384), 48, 99,  { 0x04, 0x61 }, 2 },
        { p521, sizeof(p521), 66, 136, { 0x04, 0x81, 0x85 }, 3 },
    };

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };

    for (size_t i = 0; i < ARRAY_LEN(cases); i++) {
        CK_OBJECT_HANDLE pub, priv;
        gen_ec_curve(ti->handle, cases[i].curve, cases[i].curve_len, CK_TRUE, CK_TRUE, CK_FALSE,
                CK_FALSE, &pub, &priv);

        CK_BYTE ct[256];
        CK_OBJECT_HANDLE encapsulated = CK_INVALID_HANDLE;
        CK_ULONG ct_len = encapsulate(ti->handle, &ecdh, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct),
                &encapsulated);
        assert_int_equal(ct_len, cases[i].ct_len);
        assert_memory_equal(ct, cases[i].header, cases[i].header_len);
        assert_int_equal(ct[cases[i].header_len], 0x04);

        CK_OBJECT_HANDLE decapsulated = CK_INVALID_HANDLE;
        CK_RV rv = C_DecapsulateKey(ti->handle, &ecdh, priv, templ, ARRAY_LEN(templ), ct, ct_len,
                &decapsulated);
        assert_int_equal(rv, CKR_OK);

        CK_BYTE a[128], b[128];
        assert_int_equal(get_value(ti->handle, encapsulated, a, sizeof(a)), cases[i].field);
        assert_int_equal(get_value(ti->handle, decapsulated, b, sizeof(b)), cases[i].field);
        assert_memory_equal(a, b, cases[i].field);

        /* and the raw point */
        rv = C_DecapsulateKey(ti->handle, &ecdh, priv, templ, ARRAY_LEN(templ),
                &ct[cases[i].header_len], 2 * cases[i].field + 1, &decapsulated);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(get_value(ti->handle, decapsulated, b, sizeof(b)), cases[i].field);
        assert_memory_equal(a, b, cases[i].field);
    }
}

/* A key made to decapsulate only doesn't decrypt or unwrap, though it has the TPM's decrypt attribute */
static void test_kem_decapsulate_only_rsa(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &pub, &priv);
    assert_int_equal(get_bool(ti->handle, priv, CKA_DECRYPT), CK_FALSE);
    assert_int_equal(get_bool(ti->handle, priv, CKA_UNWRAP), CK_FALSE);

    CK_RV rv = C_DecryptInit(ti->handle, &oaep, priv);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);

    GENERIC_TEMPL(templ, 32);
    CK_BYTE ct[512];
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_ULONG ct_len = encapsulate(ti->handle, &oaep, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct), &h);

    CK_ULONG before = count_objects(ti->handle);
    CK_OBJECT_HANDLE none = CK_INVALID_HANDLE;
    rv = C_UnwrapKey(ti->handle, &oaep, priv, ct, ct_len, templ, ARRAY_LEN(templ), &none);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
    assert_int_equal(none, CK_INVALID_HANDLE);
    assert_int_equal(count_objects(ti->handle), before);
}

static void test_kem_ml_kem_invalid(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &pub, &priv);

    GENERIC_TEMPL(templ, 32);
    CK_BYTE ct[256] = { 0 };

    /* CKM_RSA_X_509 doesn't say how its k-byte secret becomes the key (see kem.c) */
    CK_MECHANISM_TYPE types[] = { CKM_ML_KEM, CKM_RSA_X_509, CKM_RSA_PKCS, CKM_AES_CBC_PAD, CKM_SHA256 };
    for (size_t i = 0; i < ARRAY_LEN(types); i++) {
        CK_MECHANISM mech = { types[i], NULL, 0 };
        CK_ULONG len = 0;
        CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
        CK_RV rv = C_EncapsulateKey(ti->handle, &mech, pub, templ, ARRAY_LEN(templ), NULL, &len, &h);
        assert_int_equal(rv, CKR_MECHANISM_INVALID);
        rv = C_DecapsulateKey(ti->handle, &mech, priv, templ, ARRAY_LEN(templ), ct, sizeof(ct), &h);
        assert_int_equal(rv, CKR_MECHANISM_INVALID);
    }
}

static void test_kem_needs_attr(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    GENERIC_TEMPL(templ, 32);
    CK_BYTE ct[256] = { 0 };
    CK_ULONG len = 0;
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, CK_FALSE, CK_FALSE, CK_FALSE, &pub, &priv);
    CK_RV rv = C_EncapsulateKey(ti->handle, &oaep, pub, templ, ARRAY_LEN(templ), NULL, &len, &h);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
    rv = C_DecapsulateKey(ti->handle, &oaep, priv, templ, ARRAY_LEN(templ), ct, sizeof(ct), &h);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);

    gen_ec(ti->handle, CK_FALSE, CK_FALSE, CK_FALSE, &pub, &priv);
    rv = C_EncapsulateKey(ti->handle, &ecdh, pub, templ, ARRAY_LEN(templ), NULL, &len, &h);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
    rv = C_DecapsulateKey(ti->handle, &ecdh, priv, templ, ARRAY_LEN(templ), ct, 67, &h);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);

    /* a key made before the attributes existed has neither */
    get_keypair(ti->handle, CKK_EC, &pub, &priv);
    rv = C_EncapsulateKey(ti->handle, &ecdh, pub, templ, ARRAY_LEN(templ), NULL, &len, &h);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
}

static void test_kem_key_type_inconsistent(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    GENERIC_TEMPL(templ, 32);
    CK_BYTE ct[256] = { 0 };
    CK_ULONG len = 0;
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;

    CK_OBJECT_HANDLE rsa_pub, rsa_priv, ec_pub, ec_priv;
    gen_rsa(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &rsa_pub, &rsa_priv);
    gen_ec(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &ec_pub, &ec_priv);

    CK_RV rv = C_EncapsulateKey(ti->handle, &oaep, ec_pub, templ, ARRAY_LEN(templ), NULL, &len, &h);
    assert_int_equal(rv, CKR_KEY_TYPE_INCONSISTENT);
    rv = C_EncapsulateKey(ti->handle, &ecdh, rsa_pub, templ, ARRAY_LEN(templ), NULL, &len, &h);
    assert_int_equal(rv, CKR_KEY_TYPE_INCONSISTENT);
    /* encapsulating takes the public key */
    rv = C_EncapsulateKey(ti->handle, &oaep, rsa_priv, templ, ARRAY_LEN(templ), NULL, &len, &h);
    assert_int_equal(rv, CKR_KEY_TYPE_INCONSISTENT);
    rv = C_EncapsulateKey(ti->handle, &oaep, CK_INVALID_HANDLE, templ, ARRAY_LEN(templ), NULL, &len, &h);
    assert_int_equal(rv, CKR_KEY_HANDLE_INVALID);

    rv = C_DecapsulateKey(ti->handle, &ecdh, rsa_priv, templ, ARRAY_LEN(templ), ct, 67, &h);
    assert_int_equal(rv, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
    rv = C_DecapsulateKey(ti->handle, &oaep, ec_priv, templ, ARRAY_LEN(templ), ct, sizeof(ct), &h);
    assert_int_equal(rv, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
    rv = C_DecapsulateKey(ti->handle, &ecdh, ec_pub, templ, ARRAY_LEN(templ), ct, 67, &h);
    assert_int_equal(rv, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
    rv = C_DecapsulateKey(ti->handle, &ecdh, CK_INVALID_HANDLE, templ, ARRAY_LEN(templ), ct, 67, &h);
    assert_int_equal(rv, CKR_UNWRAPPING_KEY_HANDLE_INVALID);
}

static void test_kem_length_query_creates_nothing(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE rsa_pub, rsa_priv, ec_pub, ec_priv;
    gen_rsa(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &rsa_pub, &rsa_priv);
    gen_ec(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &ec_pub, &ec_priv);

    GENERIC_TEMPL(templ, 32);
    CK_ULONG before = count_objects(ti->handle);

    static const struct {
        CK_MECHANISM *mech;
        CK_ULONG len;
    } cases[] = {
        { &oaep, 256 },
        { &ecdh, 67 },
    };

    for (size_t i = 0; i < ARRAY_LEN(cases); i++) {
        CK_OBJECT_HANDLE pub = cases[i].mech == &oaep ? rsa_pub : ec_pub;
        CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;

        CK_ULONG len = 0;
        CK_RV rv = C_EncapsulateKey(ti->handle, cases[i].mech, pub, templ, ARRAY_LEN(templ),
                NULL, &len, &h);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(len, cases[i].len);
        assert_int_equal(h, CK_INVALID_HANDLE);
        assert_int_equal(count_objects(ti->handle), before);

        CK_BYTE ct[16];
        len = sizeof(ct);
        rv = C_EncapsulateKey(ti->handle, cases[i].mech, pub, templ, ARRAY_LEN(templ),
                ct, &len, &h);
        assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
        assert_int_equal(len, cases[i].len);
        assert_int_equal(h, CK_INVALID_HANDLE);
        assert_int_equal(count_objects(ti->handle), before);
    }

    /* the template is checked before the length is given: RSA needs the secret's length */
    CK_ATTRIBUTE no_len[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };
    CK_ULONG len = 0;
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_EncapsulateKey(ti->handle, &oaep, rsa_pub, no_len, ARRAY_LEN(no_len), NULL, &len, &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCOMPLETE);

    /* longer than an OAEP message: 256 - 2 * 32 - 2 = 190 bytes */
    GENERIC_TEMPL(too_long, 191);
    rv = C_EncapsulateKey(ti->handle, &oaep, rsa_pub, too_long, ARRAY_LEN(too_long), NULL, &len, &h);
    assert_int_equal(rv, CKR_KEY_SIZE_RANGE);

    /* what only the token sets */
    CK_ATTRIBUTE local[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_VALUE_LEN, 32, CK_ULONG),
        ATTR(CKA_LOCAL, CK_TRUE, CK_BBOOL),
    };
    rv = C_EncapsulateKey(ti->handle, &ecdh, ec_pub, local, ARRAY_LEN(local), NULL, &len, &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(count_objects(ti->handle), before);
}

static void test_kem_corrupt_ciphertext(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &pub, &priv);

    GENERIC_TEMPL(templ, 32);
    CK_BYTE ct[512];
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_ULONG ct_len = encapsulate(ti->handle, &oaep, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct), &h);

    CK_ULONG before = count_objects(ti->handle);

    /* a good ciphertext the template can't take is refused as a bad one is: no oracle on it */
    CK_OBJECT_HANDLE none = CK_INVALID_HANDLE;
    GENERIC_TEMPL(other_len, 16);
    CK_RV rv = C_DecapsulateKey(ti->handle, &oaep, priv, other_len, ARRAY_LEN(other_len), ct, ct_len,
            &none);
    assert_int_equal(rv, CKR_WRAPPED_KEY_INVALID);

    ct[ct_len / 2] ^= 0x01;
    rv = C_DecapsulateKey(ti->handle, &oaep, priv, templ, ARRAY_LEN(templ), ct, ct_len, &none);
    assert_int_equal(rv, CKR_WRAPPED_KEY_INVALID);
    assert_int_equal(none, CK_INVALID_HANDLE);
    assert_int_equal(count_objects(ti->handle), before);

    rv = C_DecapsulateKey(ti->handle, &oaep, priv, templ, ARRAY_LEN(templ), ct, ct_len - 1, &none);
    assert_int_equal(rv, CKR_WRAPPED_KEY_LEN_RANGE);

    /* ECDH: a point that isn't on the curve, and one of the wrong length */
    CK_OBJECT_HANDLE ec_pub, ec_priv;
    gen_ec(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &ec_pub, &ec_priv);
    ct_len = encapsulate(ti->handle, &ecdh, ec_pub, templ, ARRAY_LEN(templ), ct, sizeof(ct), &h);
    before = count_objects(ti->handle);

    ct[ct_len - 1] ^= 0x01;
    rv = C_DecapsulateKey(ti->handle, &ecdh, ec_priv, templ, ARRAY_LEN(templ), ct, ct_len, &none);
    assert_int_equal(rv, CKR_WRAPPED_KEY_INVALID);
    assert_int_equal(none, CK_INVALID_HANDLE);

    rv = C_DecapsulateKey(ti->handle, &ecdh, ec_priv, templ, ARRAY_LEN(templ), ct, ct_len - 1, &none);
    assert_int_equal(rv, CKR_WRAPPED_KEY_LEN_RANGE);

    /* not a point: no 0x04 */
    ct[2] = 0x02;
    rv = C_DecapsulateKey(ti->handle, &ecdh, ec_priv, templ, ARRAY_LEN(templ), ct, ct_len, &none);
    assert_int_equal(rv, CKR_WRAPPED_KEY_INVALID);
    assert_int_equal(none, CK_INVALID_HANDLE);
    assert_int_equal(count_objects(ti->handle), before);
}

/* A R/O session can't make the key: it says so before anything is decrypted, whatever the ciphertext */
static void test_kem_read_only_session_first(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    GENERIC_TEMPL(templ, 32);
    CK_BYTE ct[512];
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;

    CK_OBJECT_HANDLE rsa_pub, rsa_priv, ec_pub, ec_priv;
    gen_rsa(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &rsa_pub, &rsa_priv);
    gen_ec(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &ec_pub, &ec_priv);
    CK_ULONG rsa_len = encapsulate(ti->handle, &oaep, rsa_pub, templ, ARRAY_LEN(templ), ct, sizeof(ct),
            &h);
    CK_BYTE ec_ct[67];
    CK_ULONG ec_len = encapsulate(ti->handle, &ecdh, ec_pub, templ, ARRAY_LEN(templ), ec_ct,
            sizeof(ec_ct), &h);
    ct[rsa_len / 2] ^= 0x01;
    ec_ct[ec_len - 1] ^= 0x01;

    CK_SESSION_HANDLE ro = CK_INVALID_HANDLE;
    CK_RV rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL, NULL, &ro);
    assert_int_equal(rv, CKR_OK);
    CK_ULONG before = count_objects(ro);

    CK_ATTRIBUTE token_templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_VALUE_LEN, 32, CK_ULONG),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
    };
    CK_OBJECT_HANDLE none = CK_INVALID_HANDLE;
    rv = C_DecapsulateKey(ro, &oaep, rsa_priv, token_templ, ARRAY_LEN(token_templ), ct, rsa_len, &none);
    assert_int_equal(rv, CKR_SESSION_READ_ONLY);
    rv = C_DecapsulateKey(ro, &ecdh, ec_priv, token_templ, ARRAY_LEN(token_templ), ec_ct, ec_len, &none);
    assert_int_equal(rv, CKR_SESSION_READ_ONLY);
    CK_ULONG len = sizeof(ct);
    rv = C_EncapsulateKey(ro, &oaep, rsa_pub, token_templ, ARRAY_LEN(token_templ), ct, &len, &none);
    assert_int_equal(rv, CKR_SESSION_READ_ONLY);
    assert_int_equal(none, CK_INVALID_HANDLE);
    assert_int_equal(count_objects(ro), before);
}

static void test_kem_ecdh_params(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_ec(ti->handle, CK_TRUE, CK_TRUE, CK_FALSE, &pub, &priv);

    GENERIC_TEMPL(templ, 32);
    CK_BYTE ct[67] = { 0 };
    CK_ULONG len = 0;
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;

    /* PKCS#11 6.3.17: pPublicData and ulPublicDataLen are NULL and 0 */
    CK_BYTE point[65] = { 0x04 };
    CK_ECDH1_DERIVE_PARAMS with_point = { .kdf = CKD_NULL, .ulPublicDataLen = sizeof(point),
            .pPublicData = point };
    CK_ECDH1_DERIVE_PARAMS with_len = { .kdf = CKD_NULL, .ulPublicDataLen = 65 };
    CK_ECDH1_DERIVE_PARAMS with_kdf = { .kdf = CKD_SHA256_KDF };

    CK_MECHANISM mechs[] = {
        { CKM_ECDH1_DERIVE, &with_point, sizeof(with_point) },
        { CKM_ECDH1_DERIVE, &with_len, sizeof(with_len) },
        { CKM_ECDH1_DERIVE, &with_kdf, sizeof(with_kdf) },
        { CKM_ECDH1_DERIVE, NULL, 0 },
        { CKM_ECDH1_DERIVE, &with_kdf, sizeof(with_kdf) - 1 },
    };

    for (size_t i = 0; i < ARRAY_LEN(mechs); i++) {
        CK_RV rv = C_EncapsulateKey(ti->handle, &mechs[i], pub, templ, ARRAY_LEN(templ),
                NULL, &len, &h);
        assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
        rv = C_DecapsulateKey(ti->handle, &mechs[i], priv, templ, ARRAY_LEN(templ),
                ct, sizeof(ct), &h);
        assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    }
}

/* Templates on the key aren't supported, as for wrapping: a key that has one is refused */
static void test_kem_templates_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_ATTRIBUTE inner[] = {
        ATTR(CKA_EXTRACTABLE, CK_FALSE, CK_BBOOL),
    };

    CK_ATTRIBUTE pub_templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_ENCAPSULATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_MODULUS_BITS, 2048, CK_ULONG),
        ATTR_VAR(CKA_ENCAPSULATE_TEMPLATE, inner, sizeof(inner)),
    };
    CK_ATTRIBUTE priv_templ[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_DECAPSULATE, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_DECAPSULATE_TEMPLATE, inner, sizeof(inner)),
    };

    CK_OBJECT_HANDLE pub, priv;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_RV rv = C_GenerateKeyPair(ti->handle, &mech,
            pub_templ, ARRAY_LEN(pub_templ),
            priv_templ, ARRAY_LEN(priv_templ),
            &pub, &priv);
    assert_int_equal(rv, CKR_OK);

    GENERIC_TEMPL(templ, 32);
    CK_ULONG before = count_objects(ti->handle);
    CK_ULONG len = 0;
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    rv = C_EncapsulateKey(ti->handle, &oaep, pub, templ, ARRAY_LEN(templ), NULL, &len, &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);

    CK_BYTE ct[256] = { 0 };
    rv = C_DecapsulateKey(ti->handle, &oaep, priv, templ, ARRAY_LEN(templ), ct, sizeof(ct), &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);
    assert_int_equal(count_objects(ti->handle), before);
}

/* A CKA_ALWAYS_AUTHENTICATE key needs a context-specific login, which C_DecapsulateKey can't have */
static void test_kem_always_authenticate_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    GENERIC_TEMPL(templ, 32);
    CK_BYTE ct[512];
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, CK_TRUE, CK_TRUE, CK_TRUE, &pub, &priv);
    CK_ULONG ct_len = encapsulate(ti->handle, &oaep, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct), &h);

    CK_ULONG before = count_objects(ti->handle);
    CK_RV rv = C_DecapsulateKey(ti->handle, &oaep, priv, templ, ARRAY_LEN(templ), ct, ct_len, &h);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);
    assert_int_equal(count_objects(ti->handle), before);

    gen_ec(ti->handle, CK_TRUE, CK_TRUE, CK_TRUE, &pub, &priv);
    ct_len = encapsulate(ti->handle, &ecdh, pub, templ, ARRAY_LEN(templ), ct, sizeof(ct), &h);
    before = count_objects(ti->handle);
    rv = C_DecapsulateKey(ti->handle, &ecdh, priv, templ, ARRAY_LEN(templ), ct, ct_len, &h);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    /* and there is no operation to log in for */
    context_login_expects(ti->handle, CKR_OPERATION_NOT_INITIALIZED);
    assert_int_equal(count_objects(ti->handle), before);
}

static void test_kem_mechinfo_flags(void **state) {

    test_info *ti = test_info_from_state(state);

    static const struct {
        CK_MECHANISM_TYPE type;
        bool kem;
    } cases[] = {
        { CKM_RSA_PKCS_OAEP, true },
        { CKM_RSA_PKCS, false },
        { CKM_ECDH1_DERIVE, true },
        { CKM_RSA_X_509, false },
        { CKM_AES_CBC_PAD, false },
    };

    for (size_t i = 0; i < ARRAY_LEN(cases); i++) {
        CK_MECHANISM_INFO info = { 0 };
        CK_RV rv = C_GetMechanismInfo(ti->slot_id, cases[i].type, &info);
        if (rv == CKR_MECHANISM_INVALID && !cases[i].kem) {
            continue;
        }
        assert_int_equal(rv, CKR_OK);
        CK_FLAGS flags = info.flags & (CKF_ENCAPSULATE | CKF_DECAPSULATE);
        assert_int_equal(flags, cases[i].kem ? (CKF_ENCAPSULATE | CKF_DECAPSULATE) : 0);
    }
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_kem_rsa_oaep_roundtrip,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_rsa_pkcs_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_rsa_into_aes,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_ecdh_roundtrip,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_ecdh_curves,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_legacy_ec_key_derives,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_decapsulate_off_doesnt_derive,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_decapsulate_only_rsa,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_ml_kem_invalid,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_needs_attr,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_key_type_inconsistent,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_length_query_creates_nothing,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_corrupt_ciphertext,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_ecdh_params,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_read_only_session_first,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_templates_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_always_authenticate_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kem_mechinfo_flags,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
