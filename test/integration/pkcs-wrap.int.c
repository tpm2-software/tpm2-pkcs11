/* SPDX-License-Identifier: BSD-2-Clause */

#include <assert.h>

#include <openssl/evp.h>

#include "test.h"

/*
 * C_WrapKey and C_UnwrapKey, with CKM_RSA_PKCS_OAEP and CKM_AES_CBC_PAD. Only a secret key whose value
 * the token holds on the host, with CKA_EXTRACTABLE=true, is wrapped. An unwrapped AES or HMAC key goes
 * into the TPM, unextractable; a generic secret stays a plain object, extractable by default.
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

/* C_Finalize then C_Initialize, so the objects come back from the store, and open a new session */
static void reload(test_info *ti) {

    CK_RV rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    rv = C_Initialize(NULL);
    assert_int_equal(rv, CKR_OK);

    ti->slot_id = first_slot();

    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &ti->handle);
    assert_int_equal(rv, CKR_OK);
}

static CK_OBJECT_HANDLE find_by_label(CK_SESSION_HANDLE session, CK_OBJECT_CLASS clazz,
        const char *label) {

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, clazz, CK_OBJECT_CLASS),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
    };

    CK_RV rv = C_FindObjectsInit(session, templ, ARRAY_LEN(templ));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE found[4] = { CK_INVALID_HANDLE };
    CK_ULONG count = 0;
    rv = C_FindObjects(session, found, ARRAY_LEN(found), &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(count, 1);
    return found[0];
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

/* An RSA key pair whose public key may wrap and private key unwrap */
static void gen_rsa(CK_SESSION_HANDLE session, const char *label, CK_BBOOL wrap, CK_BBOOL unwrap,
        CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {

    /* a key pair that can neither sign, decrypt nor unwrap is refused: give it CKA_SIGN */
    CK_BBOOL sign = !unwrap;

    CK_ATTRIBUTE pub_templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_ENCRYPT, CK_TRUE, CK_BBOOL),
        ATTR(CKA_VERIFY, CK_TRUE, CK_BBOOL),
        ATTR(CKA_WRAP, wrap, CK_BBOOL),
        ATTR(CKA_MODULUS_BITS, 2048, CK_ULONG),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
    };
    CK_ATTRIBUTE priv_templ[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
        /* only unwrap may ask for the TPM's decrypt attribute */
        ATTR_VAR(CKA_SIGN, &sign, sizeof(sign)),
        ATTR(CKA_DECRYPT, CK_FALSE, CK_BBOOL),
        ATTR(CKA_UNWRAP, unwrap, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
    };

    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_RV rv = C_GenerateKeyPair(session, &mech,
            pub_templ, ARRAY_LEN(pub_templ),
            priv_templ, ARRAY_LEN(priv_templ),
            pub, priv);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(get_bool(session, *pub, CKA_WRAP), wrap);
    assert_int_equal(get_bool(session, *priv, CKA_UNWRAP), unwrap);
}

/* A 256-bit AES key the TPM makes, which may wrap and unwrap */
static CK_OBJECT_HANDLE gen_aes(CK_SESSION_HANDLE session, const char *label, CK_BBOOL wrap,
        CK_BBOOL unwrap) {

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_VALUE_LEN, 32, CK_ULONG),
        /* only wrap and unwrap may ask the TPM to encrypt and decrypt */
        ATTR(CKA_ENCRYPT, CK_FALSE, CK_BBOOL),
        ATTR(CKA_DECRYPT, CK_FALSE, CK_BBOOL),
        ATTR(CKA_WRAP, wrap, CK_BBOOL),
        ATTR(CKA_UNWRAP, unwrap, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
    };

    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_GenerateKey(session, &mech, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(get_bool(session, h, CKA_WRAP), wrap);
    assert_int_equal(get_bool(session, h, CKA_UNWRAP), unwrap);

    return h;
}

/* A generic secret held as a plain object, its value readable */
static CK_OBJECT_HANDLE create_secret(CK_SESSION_HANDLE session, const char *label, CK_BBOOL sensitive,
        CK_BBOOL extractable, CK_BYTE *value, CK_ULONG value_len) {

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, sensitive, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, extractable, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
        ATTR_VAR(CKA_VALUE, value, value_len),
    };

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_CreateObject(session, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_OK);

    return h;
}

static void fill(CK_BYTE *buf, CK_ULONG len, CK_BYTE seed) {
    CK_ULONG i;
    for (i = 0; i < len; i++) {
        buf[i] = (CK_BYTE)(seed + 7 * i);
    }
}

static CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
    .hashAlg = CKM_SHA256,
    .mgf = CKG_MGF1_SHA256,
    .source = CKZ_DATA_SPECIFIED,
    .pSourceData = NULL,
    .ulSourceDataLen = 0,
};

static CK_MECHANISM oaep = { CKM_RSA_PKCS_OAEP, &oaep_params, sizeof(oaep_params) };

static CK_BYTE cbc_iv[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static CK_MECHANISM cbc_pad = { CKM_AES_CBC_PAD, cbc_iv, sizeof(cbc_iv) };

/* Wraps key, with the §5.2 length query first */
static CK_ULONG wrap(CK_SESSION_HANDLE session, CK_MECHANISM *mech, CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key, CK_BYTE *wrapped, CK_ULONG wrapped_size) {

    CK_ULONG len = 0;
    CK_RV rv = C_WrapKey(session, mech, wrapping_key, key, NULL, &len);
    assert_int_equal(rv, CKR_OK);
    assert_true(len <= wrapped_size);

    CK_ULONG got = wrapped_size;
    rv = C_WrapKey(session, mech, wrapping_key, key, wrapped, &got);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(got, len);

    return got;
}

static void assert_value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h, CK_BYTE *expected,
        CK_ULONG expected_len) {

    CK_BYTE value[128] = { 0 };
    CK_ATTRIBUTE a = { CKA_VALUE, value, sizeof(value) };
    CK_RV rv = C_GetAttributeValue(session, h, &a, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(a.ulValueLen, expected_len);
    assert_memory_equal(value, expected, expected_len);
}

/* What any key unwrapping makes has: it didn't stay in the token all along */
static void assert_unwrapped_attrs(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {

    assert_int_equal(get_bool(session, h, CKA_LOCAL), CK_FALSE);
    assert_int_equal(get_bool(session, h, CKA_ALWAYS_SENSITIVE), CK_FALSE);
    assert_int_equal(get_bool(session, h, CKA_NEVER_EXTRACTABLE), CK_FALSE);

    CK_BYTE id[64];
    CK_ATTRIBUTE a = { CKA_UNIQUE_ID, id, sizeof(id) };
    CK_RV rv = C_GetAttributeValue(session, h, &a, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(a.ulValueLen, 32);
}

static void test_wrap_unwrap_oaep_generic_secret(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "wrap-oaep-rsa", CK_TRUE, CK_TRUE, &pub, &priv);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x31);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "wrap-oaep-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));

    CK_BYTE wrapped[512];
    CK_ULONG wrapped_len = wrap(ti->handle, &oaep, pub, secret, wrapped, sizeof(wrapped));
    assert_int_equal(wrapped_len, 256);

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    CK_RV rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len,
            templ, ARRAY_LEN(templ), &unwrapped);
    assert_int_equal(rv, CKR_OK);

    assert_value(ti->handle, unwrapped, value, sizeof(value));
    assert_int_equal(get_bool(ti->handle, unwrapped, CKA_EXTRACTABLE), CK_TRUE);
    assert_unwrapped_attrs(ti->handle, unwrapped);

    /* and it can be wrapped in turn */
    wrapped_len = wrap(ti->handle, &oaep, pub, unwrapped, wrapped, sizeof(wrapped));
    assert_int_equal(wrapped_len, 256);
}

static void test_wrap_unwrap_aes_cbc_pad(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE aes = gen_aes(ti->handle, "wrap-cbc-aes", CK_TRUE, CK_TRUE);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x52);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "wrap-cbc-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));

    CK_BYTE wrapped[128];
    CK_ULONG wrapped_len = wrap(ti->handle, &cbc_pad, aes, secret, wrapped, sizeof(wrapped));
    /* 32 bytes, and a whole block of padding */
    assert_int_equal(wrapped_len, 48);

    /* no CKA_EXTRACTABLE nor CKA_SENSITIVE: a generic secret's value is the spec's default, readable */
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    CK_RV rv = C_UnwrapKey(ti->handle, &cbc_pad, aes, wrapped, wrapped_len,
            templ, ARRAY_LEN(templ), &unwrapped);
    assert_int_equal(rv, CKR_OK);

    assert_value(ti->handle, unwrapped, value, sizeof(value));
    assert_int_equal(get_bool(ti->handle, unwrapped, CKA_EXTRACTABLE), CK_TRUE);
    assert_unwrapped_attrs(ti->handle, unwrapped);

    /* C_EncryptInit still goes by CKA_ENCRYPT, not CKA_WRAP */
    rv = C_EncryptInit(ti->handle, &cbc_pad, aes);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
    rv = C_DecryptInit(ti->handle, &cbc_pad, aes);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
}

static void test_unwrap_into_aes_defaults_unextractable(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "unwrap-aes-rsa", CK_TRUE, CK_TRUE, &pub, &priv);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x93);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "unwrap-aes-secret", CK_TRUE, CK_TRUE,
            value, sizeof(value));

    CK_BYTE wrapped[512];
    CK_ULONG wrapped_len = wrap(ti->handle, &oaep, pub, secret, wrapped, sizeof(wrapped));

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_ENCRYPT, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    CK_RV rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len,
            templ, ARRAY_LEN(templ), &aes);
    assert_int_equal(rv, CKR_OK);

    /* in the TPM: unextractable, its value unreadable */
    assert_int_equal(get_bool(ti->handle, aes, CKA_EXTRACTABLE), CK_FALSE);
    assert_unwrapped_attrs(ti->handle, aes);

    CK_BYTE unread[64];
    CK_ATTRIBUTE a = { CKA_VALUE, unread, sizeof(unread) };
    rv = C_GetAttributeValue(ti->handle, aes, &a, 1);
    assert_int_equal(rv, CKR_ATTRIBUTE_SENSITIVE);

    /* it holds the unwrapped value: one block, CBC with a zero IV, as software AES gives it */
    CK_BYTE zero_iv[16] = { 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC, zero_iv, sizeof(zero_iv) };
    CK_BYTE block[16];
    fill(block, sizeof(block), 0x05);

    rv = C_EncryptInit(ti->handle, &cbc, aes);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE ct[16];
    CK_ULONG ct_len = sizeof(ct);
    rv = C_Encrypt(ti->handle, block, sizeof(block), ct, &ct_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(ct_len, 16);

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    assert_non_null(c);
    assert_int_equal(EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), NULL, value, zero_iv), 1);
    assert_int_equal(EVP_CIPHER_CTX_set_padding(c, 0), 1);
    CK_BYTE expected[32];
    int expected_len = 0;
    assert_int_equal(EVP_EncryptUpdate(c, expected, &expected_len, block, sizeof(block)), 1);
    EVP_CIPHER_CTX_free(c);
    assert_int_equal(expected_len, 16);

    assert_memory_equal(ct, expected, 16);
}

static void test_unwrap_into_extractable_aes_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "unwrap-xaes-rsa", CK_TRUE, CK_TRUE, &pub, &priv);

    CK_BYTE value[16];
    fill(value, sizeof(value), 0x11);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "unwrap-xaes-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));

    CK_BYTE wrapped[512];
    CK_ULONG wrapped_len = wrap(ti->handle, &oaep, pub, secret, wrapped, sizeof(wrapped));

    CK_ULONG before = count_objects(ti->handle);

    /* a key in the TPM can't be extractable */
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len,
            templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);

    /* nor can an HMAC key */
    templ[1] = (CK_ATTRIBUTE)ATTR(CKA_KEY_TYPE, CKK_SHA256_HMAC, CK_KEY_TYPE);
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len,
            templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);

    /* what only the token sets, and the value, which is what was wrapped */
    CK_ATTRIBUTE always[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_ALWAYS_SENSITIVE, CK_TRUE, CK_BBOOL),
    };
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len,
            always, ARRAY_LEN(always), &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    CK_ATTRIBUTE with_value[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
    };
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len,
            with_value, ARRAY_LEN(with_value), &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);

    /* a 16-byte value isn't a 32-byte key, nor a 20-byte AES key */
    CK_ATTRIBUTE len32[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_VALUE_LEN, 32, CK_ULONG),
    };
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len,
            len32, ARRAY_LEN(len32), &h);
    /* refused as one that doesn't decrypt: no telling good padding from bad */
    assert_int_equal(rv, CKR_WRAPPED_KEY_INVALID);

    assert_int_equal(count_objects(ti->handle), before);

    CK_BYTE value20[20];
    fill(value20, sizeof(value20), 0x20);
    CK_OBJECT_HANDLE secret20 = create_secret(ti->handle, "unwrap-xaes-secret20", CK_FALSE, CK_TRUE,
            value20, sizeof(value20));
    wrapped_len = wrap(ti->handle, &oaep, pub, secret20, wrapped, sizeof(wrapped));
    before = count_objects(ti->handle);

    CK_ATTRIBUTE aes20[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
    };
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len,
            aes20, ARRAY_LEN(aes20), &h);
    assert_int_equal(rv, CKR_WRAPPED_KEY_INVALID);

    /* a sensitive value held on the host isn't kept public, so in plain text in the store */
    CK_ATTRIBUTE public_sensitive[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_PRIVATE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
    };
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len,
            public_sensitive, ARRAY_LEN(public_sensitive), &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);

    /* only secret keys are unwrapped */
    CK_ATTRIBUTE private[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
    };
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len,
            private, ARRAY_LEN(private), &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);

    assert_int_equal(count_objects(ti->handle), before);
}

static void test_wrap_tpm_aes_unextractable(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "wrap-tpm-aes-rsa", CK_TRUE, CK_TRUE, &pub, &priv);

    /* in the TPM, the store holds no value for it */
    CK_OBJECT_HANDLE aes = gen_aes(ti->handle, "wrap-tpm-aes", CK_FALSE, CK_FALSE);

    CK_ULONG len = 0;
    CK_RV rv = C_WrapKey(ti->handle, &oaep, pub, aes, NULL, &len);
    assert_int_equal(rv, CKR_KEY_UNEXTRACTABLE);

    /* a host-held key with CKA_EXTRACTABLE=false */
    CK_BYTE value[32];
    fill(value, sizeof(value), 0x44);
    CK_OBJECT_HANDLE kept = create_secret(ti->handle, "wrap-unextractable", CK_FALSE, CK_FALSE,
            value, sizeof(value));
    rv = C_WrapKey(ti->handle, &oaep, pub, kept, NULL, &len);
    assert_int_equal(rv, CKR_KEY_UNEXTRACTABLE);

    /* an extractable key with no value held on the host */
    CK_OBJECT_HANDLE empty = create_secret(ti->handle, "wrap-empty", CK_FALSE, CK_TRUE, NULL, 0);
    rv = C_WrapKey(ti->handle, &oaep, pub, empty, NULL, &len);
    assert_int_equal(rv, CKR_KEY_UNEXTRACTABLE);

    /* a private key's value is the user's */
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "wrap-logged-out", CK_TRUE, CK_TRUE,
            value, sizeof(value));
    logout(ti->handle);
    rv = C_WrapKey(ti->handle, &oaep, pub, secret, NULL, &len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);
}

static void test_wrap_private_key_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE aes = gen_aes(ti->handle, "wrap-priv-aes", CK_TRUE, CK_TRUE);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "wrap-priv-rsa", CK_TRUE, CK_TRUE, &pub, &priv);

    CK_ULONG len = 0;
    CK_RV rv = C_WrapKey(ti->handle, &cbc_pad, aes, priv, NULL, &len);
    assert_int_equal(rv, CKR_KEY_NOT_WRAPPABLE);

    /* a public key isn't wrapped: it isn't a secret */
    rv = C_WrapKey(ti->handle, &cbc_pad, aes, pub, NULL, &len);
    assert_int_equal(rv, CKR_KEY_NOT_WRAPPABLE);

    /* nor is what isn't a key */
    CK_BYTE data_value[] = { 0x01, 0x02, 0x03 };
    CK_ATTRIBUTE data_templ[] = {
        ATTR(CKA_CLASS, CKO_DATA, CK_OBJECT_CLASS),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR_VAR(CKA_VALUE, data_value, sizeof(data_value)),
    };
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    rv = C_CreateObject(ti->handle, data_templ, ARRAY_LEN(data_templ), &data);
    assert_int_equal(rv, CKR_OK);
    rv = C_WrapKey(ti->handle, &cbc_pad, aes, data, NULL, &len);
    assert_int_equal(rv, CKR_KEY_HANDLE_INVALID);

    rv = C_WrapKey(ti->handle, &cbc_pad, aes, 0xdeadbeef, NULL, &len);
    assert_int_equal(rv, CKR_KEY_HANDLE_INVALID);

    /* a key that is only wrapped with a trusted key: the token has none */
    CK_BYTE value[16];
    fill(value, sizeof(value), 0x66);
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_WRAP_WITH_TRUSTED, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
    };
    CK_OBJECT_HANDLE trusted_only = CK_INVALID_HANDLE;
    rv = C_CreateObject(ti->handle, templ, ARRAY_LEN(templ), &trusted_only);
    assert_int_equal(rv, CKR_OK);

    rv = C_WrapKey(ti->handle, &cbc_pad, aes, trusted_only, NULL, &len);
    assert_int_equal(rv, CKR_KEY_NOT_WRAPPABLE);
}

static void test_wrap_needs_wrap_attr(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "wrap-noattr-rsa", CK_FALSE, CK_FALSE, &pub, &priv);
    CK_OBJECT_HANDLE aes = gen_aes(ti->handle, "wrap-noattr-aes", CK_FALSE, CK_FALSE);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x77);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "wrap-noattr-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));

    CK_ULONG len = 0;
    CK_RV rv = C_WrapKey(ti->handle, &oaep, pub, secret, NULL, &len);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
    rv = C_WrapKey(ti->handle, &cbc_pad, aes, secret, NULL, &len);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);

    CK_ULONG before = count_objects(ti->handle);
    CK_BYTE wrapped[256] = { 0 };
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, sizeof(wrapped), templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
    rv = C_UnwrapKey(ti->handle, &cbc_pad, aes, wrapped, 48, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
    assert_int_equal(count_objects(ti->handle), before);

    /* the right kind of key for the mechanism */
    CK_OBJECT_HANDLE wpub, wpriv;
    gen_rsa(ti->handle, "wrap-kind-rsa", CK_TRUE, CK_TRUE, &wpub, &wpriv);
    rv = C_WrapKey(ti->handle, &oaep, wpriv, secret, NULL, &len);
    assert_int_equal(rv, CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
    rv = C_WrapKey(ti->handle, &cbc_pad, wpub, secret, NULL, &len);
    assert_int_equal(rv, CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
    rv = C_UnwrapKey(ti->handle, &oaep, wpub, wrapped, sizeof(wrapped), templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);

    rv = C_WrapKey(ti->handle, &oaep, 0xdeadbeef, secret, NULL, &len);
    assert_int_equal(rv, CKR_WRAPPING_KEY_HANDLE_INVALID);
    rv = C_UnwrapKey(ti->handle, &oaep, 0xdeadbeef, wrapped, sizeof(wrapped), templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_UNWRAPPING_KEY_HANDLE_INVALID);

    /* only the two wrapping mechanisms */
    CK_MECHANISM cbc = { CKM_AES_CBC, cbc_iv, sizeof(cbc_iv) };
    CK_MECHANISM pkcs = { CKM_RSA_PKCS, NULL, 0 };
    rv = C_WrapKey(ti->handle, &cbc, aes, secret, NULL, &len);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);
    rv = C_WrapKey(ti->handle, &pkcs, wpub, secret, NULL, &len);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);
    rv = C_UnwrapKey(ti->handle, &pkcs, wpriv, wrapped, sizeof(wrapped), templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);

    /* a CBC IV is 16 bytes */
    CK_OBJECT_HANDLE waes = gen_aes(ti->handle, "wrap-kind-aes", CK_TRUE, CK_TRUE);
    CK_MECHANISM short_iv = { CKM_AES_CBC_PAD, cbc_iv, 8 };
    rv = C_WrapKey(ti->handle, &short_iv, waes, secret, NULL, &len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
}

static void test_unwrap_corrupt_creates_nothing(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "corrupt-rsa", CK_TRUE, CK_TRUE, &pub, &priv);
    CK_OBJECT_HANDLE aes = gen_aes(ti->handle, "corrupt-aes", CK_TRUE, CK_TRUE);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x88);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "corrupt-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));

    CK_BYTE wrapped[512];
    CK_ULONG wrapped_len = wrap(ti->handle, &oaep, pub, secret, wrapped, sizeof(wrapped));
    CK_BYTE cbc_wrapped[64];
    CK_ULONG cbc_wrapped_len = wrap(ti->handle, &cbc_pad, aes, secret, cbc_wrapped, sizeof(cbc_wrapped));
    assert_int_equal(cbc_wrapped_len, 48);

    CK_ULONG before = count_objects(ti->handle);

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;

    /* OAEP's decoding fails */
    wrapped[wrapped_len / 2] ^= 0x01;
    CK_RV rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_WRAPPED_KEY_INVALID);

    /* a template that can't be made is refused before anything is decrypted */
    CK_ATTRIBUTE unmakeable[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
    };
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len, unmakeable, ARRAY_LEN(unmakeable), &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);

    /* the last byte of the padding block becomes 0x11: the next to last block's last byte flips it */
    cbc_wrapped[31] ^= 0x01;
    rv = C_UnwrapKey(ti->handle, &cbc_pad, aes, cbc_wrapped, cbc_wrapped_len, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_WRAPPED_KEY_INVALID);
    cbc_wrapped[31] ^= 0x01;

    /* not whole blocks, nor the modulus' length */
    rv = C_UnwrapKey(ti->handle, &cbc_pad, aes, cbc_wrapped, cbc_wrapped_len - 1, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_WRAPPED_KEY_LEN_RANGE);
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len - 1, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_WRAPPED_KEY_LEN_RANGE);

    assert_int_equal(count_objects(ti->handle), before);

    /* and the AES key is as it was: its IV isn't carried over from the failed call */
    rv = C_UnwrapKey(ti->handle, &cbc_pad, aes, cbc_wrapped, cbc_wrapped_len, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_OK);
    assert_value(ti->handle, h, value, sizeof(value));

    /*
     * No padding oracle (Vaudenay): good padding with a value the template can't take, a 32-byte value
     * for a 16-byte key or an AES key of 32 bytes asked as 24, is refused as bad padding is.
     */
    before = count_objects(ti->handle);
    CK_ATTRIBUTE len16[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_VALUE_LEN, 16, CK_ULONG),
    };
    CK_ATTRIBUTE aes24[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_VALUE_LEN, 24, CK_ULONG),
    };
    CK_RV good_pad = C_UnwrapKey(ti->handle, &cbc_pad, aes, cbc_wrapped, cbc_wrapped_len,
            len16, ARRAY_LEN(len16), &h);
    CK_RV good_pad_aes = C_UnwrapKey(ti->handle, &cbc_pad, aes, cbc_wrapped, cbc_wrapped_len,
            aes24, ARRAY_LEN(aes24), &h);
    cbc_wrapped[31] ^= 0x01;
    CK_RV bad_pad = C_UnwrapKey(ti->handle, &cbc_pad, aes, cbc_wrapped, cbc_wrapped_len,
            len16, ARRAY_LEN(len16), &h);
    assert_int_equal(good_pad, CKR_WRAPPED_KEY_INVALID);
    assert_int_equal(good_pad_aes, CKR_WRAPPED_KEY_INVALID);
    assert_int_equal(bad_pad, CKR_WRAPPED_KEY_INVALID);

    /*
     * What the template alone can't be is refused before anything is decrypted, with its own code: the
     * ciphertext is still the bad one. An HMAC key doesn't encrypt; an AES key in the TPM isn't
     * readable.
     */
    CK_ATTRIBUTE hmac_encrypt[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_SHA256_HMAC, CK_KEY_TYPE),
        ATTR(CKA_ENCRYPT, CK_TRUE, CK_BBOOL),
    };
    CK_ATTRIBUTE aes_readable[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
    };
    rv = C_UnwrapKey(ti->handle, &cbc_pad, aes, cbc_wrapped, cbc_wrapped_len,
            hmac_encrypt, ARRAY_LEN(hmac_encrypt), &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_VALUE_INVALID);
    rv = C_UnwrapKey(ti->handle, &cbc_pad, aes, cbc_wrapped, cbc_wrapped_len,
            aes_readable, ARRAY_LEN(aes_readable), &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_VALUE_INVALID);
    assert_int_equal(count_objects(ti->handle), before);
}

static void test_wrap_length_query_no_side_effects(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE aes = gen_aes(ti->handle, "lenq-aes", CK_TRUE, CK_TRUE);

    CK_BYTE value[24];
    fill(value, sizeof(value), 0x99);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "lenq-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));

    CK_ULONG len1 = 0, len2 = 0;
    CK_RV rv = C_WrapKey(ti->handle, &cbc_pad, aes, secret, NULL, &len1);
    assert_int_equal(rv, CKR_OK);
    rv = C_WrapKey(ti->handle, &cbc_pad, aes, secret, NULL, &len2);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len1, 32);
    assert_int_equal(len2, len1);

    /* too small: the length, and nothing else */
    CK_BYTE wrapped[64];
    CK_ULONG small = len1 - 1;
    rv = C_WrapKey(ti->handle, &cbc_pad, aes, secret, wrapped, &small);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(small, len1);

    CK_ULONG got = sizeof(wrapped);
    rv = C_WrapKey(ti->handle, &cbc_pad, aes, secret, wrapped, &got);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(got, len1);

    /* each wrap starts from the mechanism's IV */
    CK_BYTE again[64];
    CK_ULONG again_len = sizeof(again);
    rv = C_WrapKey(ti->handle, &cbc_pad, aes, secret, again, &again_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(again_len, got);
    assert_memory_equal(again, wrapped, got);

    /* the session can still start an operation: wrapping didn't take its slot */
    CK_MECHANISM sha = { CKM_SHA256, NULL, 0 };
    rv = C_DigestInit(ti->handle, &sha);
    assert_int_equal(rv, CKR_OK);
    rv = C_WrapKey(ti->handle, &cbc_pad, aes, secret, again, &again_len);
    assert_int_equal(rv, CKR_OK);
    CK_BYTE digest[32];
    CK_ULONG digest_len = sizeof(digest);
    rv = C_Digest(ti->handle, value, sizeof(value), digest, &digest_len);
    assert_int_equal(rv, CKR_OK);
}

static void test_wrap_after_reload(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    gen_aes(ti->handle, "reload-wrap-aes", CK_TRUE, CK_TRUE);

    /* sensitive, but extractable: it may be wrapped, though its value can't be read */
    CK_BYTE value[32];
    fill(value, sizeof(value), 0xa5);
    create_secret(ti->handle, "reload-wrap-secret", CK_TRUE, CK_TRUE, value, sizeof(value));

    reload(ti);
    user_login(ti->handle);

    CK_OBJECT_HANDLE aes = find_by_label(ti->handle, CKO_SECRET_KEY, "reload-wrap-aes");
    CK_OBJECT_HANDLE secret = find_by_label(ti->handle, CKO_SECRET_KEY, "reload-wrap-secret");

    CK_BYTE unread[64];
    CK_ATTRIBUTE a = { CKA_VALUE, unread, sizeof(unread) };
    CK_RV rv = C_GetAttributeValue(ti->handle, secret, &a, 1);
    assert_int_equal(rv, CKR_ATTRIBUTE_SENSITIVE);

    CK_BYTE wrapped[64];
    CK_ULONG wrapped_len = wrap(ti->handle, &cbc_pad, aes, secret, wrapped, sizeof(wrapped));
    assert_int_equal(wrapped_len, 48);

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    rv = C_UnwrapKey(ti->handle, &cbc_pad, aes, wrapped, wrapped_len, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_OK);
    assert_value(ti->handle, h, value, sizeof(value));
}

/* An unwrapping key with CKA_UNWRAP_TEMPLATE, or a wrapping key with CKA_WRAP_TEMPLATE, is refused */
static void test_wrap_templates_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_ATTRIBUTE inner[] = {
        ATTR(CKA_EXTRACTABLE, CK_FALSE, CK_BBOOL),
    };

    CK_ATTRIBUTE pub_templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_WRAP, CK_TRUE, CK_BBOOL),
        ATTR(CKA_MODULUS_BITS, 2048, CK_ULONG),
        ATTR_VAR(CKA_WRAP_TEMPLATE, inner, sizeof(inner)),
    };
    CK_ATTRIBUTE priv_templ[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_UNWRAP, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_UNWRAP_TEMPLATE, inner, sizeof(inner)),
    };

    CK_OBJECT_HANDLE pub, priv;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_RV rv = C_GenerateKeyPair(ti->handle, &mech,
            pub_templ, ARRAY_LEN(pub_templ),
            priv_templ, ARRAY_LEN(priv_templ),
            &pub, &priv);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x12);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "templ-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));

    CK_ULONG len = 0;
    rv = C_WrapKey(ti->handle, &oaep, pub, secret, NULL, &len);
    assert_int_equal(rv, CKR_KEY_HANDLE_INVALID);

    CK_ULONG before = count_objects(ti->handle);
    CK_BYTE wrapped[256] = { 0 };
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, sizeof(wrapped), templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);
    assert_int_equal(count_objects(ti->handle), before);
}

static void test_mechinfo_wrap_flags(void **state) {

    test_info *ti = test_info_from_state(state);

    static const struct {
        CK_MECHANISM_TYPE type;
        bool wraps;
    } cases[] = {
        { CKM_RSA_PKCS_OAEP, true },
        { CKM_AES_CBC_PAD, true },
        { CKM_AES_CBC, false },
        { CKM_AES_ECB, false },
        { CKM_RSA_PKCS, false },
        { CKM_RSA_X_509, false },
    };

    for (size_t i = 0; i < ARRAY_LEN(cases); i++) {
        CK_MECHANISM_INFO info = { 0 };
        CK_RV rv = C_GetMechanismInfo(ti->slot_id, cases[i].type, &info);
        if (rv == CKR_MECHANISM_INVALID && !cases[i].wraps) {
            continue;
        }
        assert_int_equal(rv, CKR_OK);
        CK_FLAGS flags = info.flags & (CKF_WRAP | CKF_UNWRAP);
        assert_int_equal(flags, cases[i].wraps ? (CKF_WRAP | CKF_UNWRAP) : 0);
    }
}

/* EC keys have no wrapping mechanism: an EC key pair asking to wrap is made as before, and can't */
static void test_wrap_ec_key_type_inconsistent(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    get_keypair(ti->handle, CKK_EC, &pub, &priv);

    CK_OBJECT_HANDLE aes = gen_aes(ti->handle, "ec-wrap-aes", CK_TRUE, CK_TRUE);

    CK_ULONG len = 0;
    CK_RV rv = C_WrapKey(ti->handle, &cbc_pad, aes, priv, NULL, &len);
    assert_int_equal(rv, CKR_KEY_NOT_WRAPPABLE);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x3c);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "ec-wrap-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));
    rv = C_WrapKey(ti->handle, &oaep, pub, secret, NULL, &len);
    assert_int_equal(rv, CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
}

/* A CKA_ALWAYS_AUTHENTICATE key needs a context-specific login, which C_UnwrapKey can't have */
static void test_unwrap_always_authenticate_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_ATTRIBUTE pub_templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_WRAP, CK_TRUE, CK_BBOOL),
        ATTR(CKA_MODULUS_BITS, 2048, CK_ULONG),
    };
    CK_ATTRIBUTE priv_templ[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_UNWRAP, CK_TRUE, CK_BBOOL),
        ATTR(CKA_ALWAYS_AUTHENTICATE, CK_TRUE, CK_BBOOL),
    };

    CK_OBJECT_HANDLE pub, priv;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_RV rv = C_GenerateKeyPair(ti->handle, &mech,
            pub_templ, ARRAY_LEN(pub_templ),
            priv_templ, ARRAY_LEN(priv_templ),
            &pub, &priv);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x4d);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "always-auth-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));

    CK_BYTE wrapped[512];
    CK_ULONG wrapped_len = wrap(ti->handle, &oaep, pub, secret, wrapped, sizeof(wrapped));

    CK_ULONG before = count_objects(ti->handle);
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    /* and there is no operation to log in for */
    context_login_expects(ti->handle, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_UnwrapKey(ti->handle, &oaep, priv, wrapped, wrapped_len, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);
    assert_int_equal(count_objects(ti->handle), before);
}

/* A CKA_WRAP_WITH_TRUSTED key, created as test_wrap_private_key_refused does */
static CK_OBJECT_HANDLE create_trusted_only(CK_SESSION_HANDLE session) {

    CK_BYTE value[16];
    fill(value, sizeof(value), 0x6a);
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_WRAP_WITH_TRUSTED, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_CreateObject(session, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_OK);
    return h;
}

/*
 * Only the SO may set CKA_TRUSTED (PKCS#11 4.2, note 10), and an SO session can't create objects here: a user
 * who could make a trusted RSA public key of their own would wrap CKA_WRAP_WITH_TRUSTED keys with it.
 */
static void test_trusted_wrapping_key_bypass(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    /* the user's own modulus: any RSA public key's will do */
    CK_OBJECT_HANDLE kpub, kpriv;
    get_keypair(ti->handle, CKK_RSA, &kpub, &kpriv);
    CK_BYTE modulus[512];
    CK_BYTE exponent[16];
    CK_ATTRIBUTE parts[] = {
        { CKA_MODULUS, modulus, sizeof(modulus) },
        { CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent) },
    };
    CK_RV rv = C_GetAttributeValue(ti->handle, kpub, parts, ARRAY_LEN(parts));
    assert_int_equal(rv, CKR_OK);

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_WRAP, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TRUSTED, CK_TRUE, CK_BBOOL),
        parts[0],
        parts[1],
    };

    CK_OBJECT_HANDLE trusted_only = create_trusted_only(ti->handle);

    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    rv = C_CreateObject(ti->handle, templ, ARRAY_LEN(templ), &pub);
    if (rv == CKR_OK) {
        CK_ULONG len = 0;
        CK_RV wrv = C_WrapKey(ti->handle, &oaep, pub, trusted_only, NULL, &len);
        print_message("a user-made CKA_TRUSTED key was created; wrapping with it gave 0x%lx\n", wrv);
    }
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    /* untrusted, it's made, and doesn't wrap the key */
    templ[4] = (CK_ATTRIBUTE)ATTR(CKA_TRUSTED, CK_FALSE, CK_BBOOL);
    rv = C_CreateObject(ti->handle, templ, ARRAY_LEN(templ), &pub);
    assert_int_equal(rv, CKR_OK);
    CK_ULONG len = 0;
    rv = C_WrapKey(ti->handle, &oaep, pub, trusted_only, NULL, &len);
    assert_int_equal(rv, CKR_KEY_NOT_WRAPPABLE);
}

/* No template that makes an object may set CKA_TRUSTED=true; false is accepted */
static void test_trusted_refused_at_creation(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_ULONG before = count_objects(ti->handle);

    /* C_CreateObject */
    CK_BYTE value[32];
    fill(value, sizeof(value), 0x27);
    CK_ATTRIBUTE secret_templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TRUSTED, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_CreateObject(ti->handle, secret_templ, ARRAY_LEN(secret_templ), &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    /* C_GenerateKey */
    CK_ATTRIBUTE aes_templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_VALUE_LEN, 32, CK_ULONG),
        ATTR(CKA_WRAP, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TRUSTED, CK_TRUE, CK_BBOOL),
    };
    CK_MECHANISM aes_gen = { CKM_AES_KEY_GEN, NULL, 0 };
    rv = C_GenerateKey(ti->handle, &aes_gen, aes_templ, ARRAY_LEN(aes_templ), &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    /* C_GenerateKeyPair, either template */
    CK_ATTRIBUTE pub_templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_WRAP, CK_TRUE, CK_BBOOL),
        ATTR(CKA_MODULUS_BITS, 2048, CK_ULONG),
        ATTR(CKA_TRUSTED, CK_TRUE, CK_BBOOL),
    };
    CK_ATTRIBUTE priv_templ[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_UNWRAP, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TRUSTED, CK_TRUE, CK_BBOOL),
    };
    CK_MECHANISM rsa_gen = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE pub, priv;
    rv = C_GenerateKeyPair(ti->handle, &rsa_gen, pub_templ, ARRAY_LEN(pub_templ),
            priv_templ, ARRAY_LEN(priv_templ) - 1, &pub, &priv);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
    rv = C_GenerateKeyPair(ti->handle, &rsa_gen, pub_templ, ARRAY_LEN(pub_templ) - 1,
            priv_templ, ARRAY_LEN(priv_templ), &pub, &priv);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    assert_int_equal(count_objects(ti->handle), before);

    /* C_UnwrapKey */
    CK_OBJECT_HANDLE aes = gen_aes(ti->handle, "trusted-unwrap-aes", CK_TRUE, CK_TRUE);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "trusted-unwrap-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));
    CK_BYTE wrapped[64];
    CK_ULONG wrapped_len = wrap(ti->handle, &cbc_pad, aes, secret, wrapped, sizeof(wrapped));

    before = count_objects(ti->handle);
    CK_ATTRIBUTE unwrap_templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_TRUSTED, CK_TRUE, CK_BBOOL),
    };
    rv = C_UnwrapKey(ti->handle, &cbc_pad, aes, wrapped, wrapped_len,
            unwrap_templ, ARRAY_LEN(unwrap_templ), &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    /* C_CopyObject */
    CK_ATTRIBUTE copy_templ[] = {
        ATTR(CKA_TRUSTED, CK_TRUE, CK_BBOOL),
    };
    rv = C_CopyObject(ti->handle, secret, copy_templ, ARRAY_LEN(copy_templ), &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    assert_int_equal(count_objects(ti->handle), before);

    /* false is what every key is anyway */
    secret_templ[5] = (CK_ATTRIBUTE)ATTR(CKA_TRUSTED, CK_FALSE, CK_BBOOL);
    rv = C_CreateObject(ti->handle, secret_templ, ARRAY_LEN(secret_templ), &h);
    assert_int_equal(rv, CKR_OK);
    unwrap_templ[3] = (CK_ATTRIBUTE)ATTR(CKA_TRUSTED, CK_FALSE, CK_BBOOL);
    rv = C_UnwrapKey(ti->handle, &cbc_pad, aes, wrapped, wrapped_len,
            unwrap_templ, ARRAY_LEN(unwrap_templ), &h);
    assert_int_equal(rv, CKR_OK);
}

/* OAEP without its parameter, or with a bad one, on both sides */
static void test_oaep_bad_params(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "oaep-params-rsa", CK_TRUE, CK_TRUE, &pub, &priv);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x5e);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "oaep-params-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));

    CK_RSA_PKCS_OAEP_PARAMS bad_source = oaep_params;
    bad_source.source = 0x55;

    CK_MECHANISM bad[] = {
        { CKM_RSA_PKCS_OAEP, NULL, 0 },
        { CKM_RSA_PKCS_OAEP, NULL, sizeof(oaep_params) },
        { CKM_RSA_PKCS_OAEP, &oaep_params, sizeof(oaep_params) - 1 },
        { CKM_RSA_PKCS_OAEP, &bad_source, sizeof(bad_source) },
    };

    CK_ULONG before = count_objects(ti->handle);
    CK_BYTE wrapped[256] = { 0 };
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
    };

    for (size_t i = 0; i < ARRAY_LEN(bad); i++) {
        CK_ULONG len = 0;
        CK_RV rv = C_WrapKey(ti->handle, &bad[i], pub, secret, NULL, &len);
        assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

        len = sizeof(wrapped);
        rv = C_WrapKey(ti->handle, &bad[i], pub, secret, wrapped, &len);
        assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

        CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
        rv = C_UnwrapKey(ti->handle, &bad[i], priv, wrapped, sizeof(wrapped),
                templ, ARRAY_LEN(templ), &h);
        assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    }

    assert_int_equal(count_objects(ti->handle), before);
}

/*
 * The session's state is checked before anything is decrypted: a R/O session can't make the key, and
 * says so whatever the ciphertext, here a corrupt one.
 */
static void test_unwrap_read_only_session_first(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE aes = gen_aes(ti->handle, "ro-unwrap-aes", CK_TRUE, CK_TRUE);
    CK_BYTE value[32];
    fill(value, sizeof(value), 0x7e);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, "ro-unwrap-secret", CK_FALSE, CK_TRUE,
            value, sizeof(value));
    CK_BYTE wrapped[64];
    CK_ULONG wrapped_len = wrap(ti->handle, &cbc_pad, aes, secret, wrapped, sizeof(wrapped));
    wrapped[wrapped_len - 17] ^= 0x01;

    CK_SESSION_HANDLE ro = CK_INVALID_HANDLE;
    CK_RV rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL, NULL, &ro);
    assert_int_equal(rv, CKR_OK);
    CK_ULONG before = count_objects(ro);

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    rv = C_UnwrapKey(ro, &cbc_pad, aes, wrapped, wrapped_len, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_SESSION_READ_ONLY);
    assert_int_equal(h, CK_INVALID_HANDLE);
    assert_int_equal(count_objects(ro), before);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_wrap_unwrap_oaep_generic_secret,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wrap_unwrap_aes_cbc_pad,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unwrap_into_aes_defaults_unextractable,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unwrap_into_extractable_aes_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wrap_tpm_aes_unextractable,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wrap_private_key_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wrap_needs_wrap_attr,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unwrap_corrupt_creates_nothing,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wrap_length_query_no_side_effects,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wrap_after_reload,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wrap_templates_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_mechinfo_wrap_flags,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wrap_ec_key_type_inconsistent,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unwrap_always_authenticate_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_trusted_wrapping_key_bypass,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_trusted_refused_at_creation,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_oaep_bad_params,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unwrap_read_only_session_first,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
