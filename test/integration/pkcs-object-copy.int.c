/* SPDX-License-Identifier: BSD-2-Clause */

#include <assert.h>

#include "test.h"

/*
 * C_CopyObject, C_GetObjectSize and C_DigestKey. A copy is a store record of its own that shares the
 * original's TPM blobs, so destroying one leaves the other usable, and a session copy isn't stored.
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

/* the number of objects of the class with the label, and the first one in *h */
static CK_ULONG count_by_label(CK_SESSION_HANDLE session, CK_OBJECT_CLASS clazz, const char *label,
        CK_OBJECT_HANDLE *h) {

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

    if (h) {
        *h = found[0];
    }

    return count;
}

static CK_OBJECT_HANDLE find_by_label(CK_SESSION_HANDLE session, CK_OBJECT_CLASS clazz,
        const char *label) {

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    assert_int_equal(count_by_label(session, clazz, label, &h), 1);
    return h;
}

/* An RSA token key pair with the label; can_sign sets the private key's CKA_SIGN. */
static void gen_rsa(CK_SESSION_HANDLE session, const char *label, CK_BBOOL can_sign,
        CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {

    CK_ATTRIBUTE pub_templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_VERIFY, CK_TRUE, CK_BBOOL),
        ATTR(CKA_ENCRYPT, CK_TRUE, CK_BBOOL),
        ATTR(CKA_MODULUS_BITS, 2048, CK_ULONG),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
    };
    CK_ATTRIBUTE priv_templ[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_RSA, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SIGN, can_sign, CK_BBOOL),
        ATTR(CKA_DECRYPT, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
    };

    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_RV rv = C_GenerateKeyPair(session, &mech,
            pub_templ, ARRAY_LEN(pub_templ),
            priv_templ, ARRAY_LEN(priv_templ),
            pub, priv);
    assert_int_equal(rv, CKR_OK);
}

/* Signs a message with priv and checks the signature with pub */
static void sign_and_verify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub) {

    CK_MECHANISM mech = { CKM_SHA256_RSA_PKCS, NULL, 0 };
    CK_BYTE msg[] = "copy me";
    CK_BYTE sig[512];
    CK_ULONG sig_len = sizeof(sig);

    CK_RV rv = C_SignInit(session, &mech, priv);
    assert_int_equal(rv, CKR_OK);

    rv = C_Sign(session, msg, sizeof(msg) - 1, sig, &sig_len);
    assert_int_equal(rv, CKR_OK);

    rv = C_VerifyInit(session, &mech, pub);
    assert_int_equal(rv, CKR_OK);

    rv = C_Verify(session, msg, sizeof(msg) - 1, sig, sig_len);
    assert_int_equal(rv, CKR_OK);
}

/* A readable generic secret held as a plain object */
static CK_OBJECT_HANDLE create_readable_secret(CK_SESSION_HANDLE session, const char *label,
        CK_BBOOL token, CK_BBOOL sensitive, CK_BYTE *value, CK_ULONG value_len) {

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, token, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, sensitive, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
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
        buf[i] = (CK_BYTE)(seed + i);
    }
}

static void test_copy_label_and_sign(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "copy-sign";
    static const char copy_label[] = "copy-sign-copy";

    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, label, CK_TRUE, &pub, &priv);

    CK_ATTRIBUTE templ[] = {
        ATTR_VAR(CKA_LABEL, (void *)copy_label, sizeof(copy_label) - 1),
    };
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_RV rv = C_CopyObject(ti->handle, priv, templ, ARRAY_LEN(templ), &copy);
    assert_int_equal(rv, CKR_OK);
    assert_int_not_equal(copy, CK_INVALID_HANDLE);
    assert_int_not_equal(copy, priv);

    /* the copy has the new label, the original keeps its own */
    assert_int_equal(find_by_label(ti->handle, CKO_PRIVATE_KEY, copy_label), copy);
    assert_int_equal(find_by_label(ti->handle, CKO_PRIVATE_KEY, label), priv);

    sign_and_verify(ti->handle, priv, pub);
    sign_and_verify(ti->handle, copy, pub);
}

static void test_copy_cannot_widen(void **state) {

    test_info *ti = test_info_from_state(state);

    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "copy-narrow", CK_FALSE, &pub, &priv);

    CK_ATTRIBUTE sign[] = { ATTR(CKA_SIGN, CK_TRUE, CK_BBOOL) };
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_RV rv = C_CopyObject(ti->handle, priv, sign, ARRAY_LEN(sign), &copy);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    CK_ATTRIBUTE unsensitive[] = { ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL) };
    rv = C_CopyObject(ti->handle, priv, unsensitive, ARRAY_LEN(unsensitive), &copy);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    /* what a key is can't change: a different class or modulus is refused, the same one is fine */
    CK_ATTRIBUTE clazz[] = { ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS) };
    rv = C_CopyObject(ti->handle, priv, clazz, ARRAY_LEN(clazz), &copy);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    CK_ATTRIBUTE same_class[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_DECRYPT, CK_FALSE, CK_BBOOL),
    };
    rv = C_CopyObject(ti->handle, priv, same_class, ARRAY_LEN(same_class), &copy);
    assert_int_equal(rv, CKR_OK);

    CK_BBOOL decrypt = CK_TRUE;
    CK_ATTRIBUTE get = ADD_ATTR_BASE(CKA_DECRYPT, decrypt);
    rv = C_GetAttributeValue(ti->handle, copy, &get, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(decrypt, CK_FALSE);
}

static void test_copy_not_copyable(void **state) {

    test_info *ti = test_info_from_state(state);

    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "copy-not-copyable", CK_TRUE, &pub, &priv);

    CK_ATTRIBUTE off[] = { ATTR(CKA_COPYABLE, CK_FALSE, CK_BBOOL) };
    CK_RV rv = C_SetAttributeValue(ti->handle, priv, off, ARRAY_LEN(off));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    rv = C_CopyObject(ti->handle, priv, NULL, 0, &copy);
    assert_int_equal(rv, CKR_ACTION_PROHIBITED);

    /* once false, CKA_COPYABLE stays false */
    CK_ATTRIBUTE on[] = { ATTR(CKA_COPYABLE, CK_TRUE, CK_BBOOL) };
    rv = C_SetAttributeValue(ti->handle, priv, on, ARRAY_LEN(on));
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    /* a copy can be made not copyable */
    CK_OBJECT_HANDLE copy2 = CK_INVALID_HANDLE;
    rv = C_CopyObject(ti->handle, pub, off, ARRAY_LEN(off), &copy);
    assert_int_equal(rv, CKR_OK);
    rv = C_CopyObject(ti->handle, copy, NULL, 0, &copy2);
    assert_int_equal(rv, CKR_ACTION_PROHIBITED);

    rv = C_CopyObject(ti->handle, 0xdeadbeef, NULL, 0, &copy2);
    assert_int_equal(rv, CKR_OBJECT_HANDLE_INVALID);
    rv = C_CopyObject(ti->handle, pub, NULL, 0, NULL);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);
}

static void test_copy_survives_original_destroy(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "copy-orig";
    static const char copy_label[] = "copy-survivor";

    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, label, CK_TRUE, &pub, &priv);

    /* load the original in the TPM, so destroying it flushes a handle */
    sign_and_verify(ti->handle, priv, pub);

    CK_ATTRIBUTE templ[] = {
        ATTR_VAR(CKA_LABEL, (void *)copy_label, sizeof(copy_label) - 1),
    };
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_RV rv = C_CopyObject(ti->handle, priv, templ, ARRAY_LEN(templ), &copy);
    assert_int_equal(rv, CKR_OK);

    sign_and_verify(ti->handle, copy, pub);

    rv = C_DestroyObject(ti->handle, priv);
    assert_int_equal(rv, CKR_OK);

    /* still usable in this session */
    sign_and_verify(ti->handle, copy, pub);

    reload(ti);
    user_login(ti->handle);

    assert_int_equal(count_by_label(ti->handle, CKO_PRIVATE_KEY, label, NULL), 0);
    copy = find_by_label(ti->handle, CKO_PRIVATE_KEY, copy_label);
    pub = find_by_label(ti->handle, CKO_PUBLIC_KEY, label);

    sign_and_verify(ti->handle, copy, pub);
}

static void test_copy_session_object_not_persisted(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "copy-to-session";
    static const char copy_label[] = "copy-session";

    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, label, CK_TRUE, &pub, &priv);

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)copy_label, sizeof(copy_label) - 1),
    };
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_RV rv = C_CopyObject(ti->handle, priv, templ, ARRAY_LEN(templ), &copy);
    assert_int_equal(rv, CKR_OK);

    CK_BBOOL token = CK_TRUE;
    CK_ATTRIBUTE get = ADD_ATTR_BASE(CKA_TOKEN, token);
    rv = C_GetAttributeValue(ti->handle, copy, &get, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(token, CK_FALSE);

    sign_and_verify(ti->handle, copy, pub);

    /* a second session sees it while its session is open */
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &other);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count_by_label(other, CKO_PRIVATE_KEY, copy_label, NULL), 1);

    /* gone with its session; the original stays */
    rv = C_CloseSession(ti->handle);
    assert_int_equal(rv, CKR_OK);
    ti->handle = other;
    assert_int_equal(count_by_label(other, CKO_PRIVATE_KEY, copy_label, NULL), 0);
    assert_int_equal(count_by_label(other, CKO_PRIVATE_KEY, label, NULL), 1);

    /* and never stored */
    reload(ti);
    user_login(ti->handle);
    assert_int_equal(count_by_label(ti->handle, CKO_PRIVATE_KEY, copy_label, NULL), 0);
    assert_int_equal(count_by_label(ti->handle, CKO_PRIVATE_KEY, label, NULL), 1);
}

static void test_copy_secret_value(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "copy-secret-src";
    static const char token_label[] = "copy-secret-token";
    static const char public_label[] = "copy-secret-public";

    user_login(ti->handle);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x40);
    CK_OBJECT_HANDLE secret = create_readable_secret(ti->handle, label, CK_FALSE, CK_FALSE,
            value, sizeof(value));

    /* the value can't be changed by a copy */
    CK_BYTE other[32];
    fill(other, sizeof(other), 0x90);
    CK_ATTRIBUTE set_value[] = { ATTR_VAR(CKA_VALUE, other, sizeof(other)) };
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_RV rv = C_CopyObject(ti->handle, secret, set_value, ARRAY_LEN(set_value), &copy);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    /* a session secret copied to the token: its wrapped value is stored */
    CK_ATTRIBUTE to_token[] = {
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)token_label, sizeof(token_label) - 1),
    };
    rv = C_CopyObject(ti->handle, secret, to_token, ARRAY_LEN(to_token), &copy);
    assert_int_equal(rv, CKR_OK);

    /* a public copy holds the value as plain text */
    CK_ATTRIBUTE to_public[] = {
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_FALSE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)public_label, sizeof(public_label) - 1),
    };
    rv = C_CopyObject(ti->handle, secret, to_public, ARRAY_LEN(to_public), &copy);
    assert_int_equal(rv, CKR_OK);

    /* but a sensitive one isn't written out as plain text */
    CK_OBJECT_HANDLE sensitive = create_readable_secret(ti->handle, "copy-secret-sensitive",
            CK_FALSE, CK_TRUE, value, sizeof(value));
    rv = C_CopyObject(ti->handle, sensitive, to_public, ARRAY_LEN(to_public), &copy);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);

    reload(ti);

    /* the public copy is readable without login */
    CK_BYTE buf[64] = { 0 };
    CK_ATTRIBUTE get = ATTR_VAR(CKA_VALUE, buf, sizeof(buf));
    copy = find_by_label(ti->handle, CKO_SECRET_KEY, public_label);
    rv = C_GetAttributeValue(ti->handle, copy, &get, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(get.ulValueLen, sizeof(value));
    assert_memory_equal(buf, value, sizeof(value));

    user_login(ti->handle);

    memset(buf, 0, sizeof(buf));
    get.ulValueLen = sizeof(buf);
    copy = find_by_label(ti->handle, CKO_SECRET_KEY, token_label);
    rv = C_GetAttributeValue(ti->handle, copy, &get, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(get.ulValueLen, sizeof(value));
    assert_memory_equal(buf, value, sizeof(value));
}

static void test_object_size_positive(void **state) {

    test_info *ti = test_info_from_state(state);

    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "copy-size", CK_TRUE, &pub, &priv);

    CK_ULONG pub_size = 0;
    CK_RV rv = C_GetObjectSize(ti->handle, pub, &pub_size);
    assert_int_equal(rv, CKR_OK);
    assert_true(pub_size > 0);

    /* the private key also has its TPM private blob */
    CK_ULONG priv_size = 0;
    rv = C_GetObjectSize(ti->handle, priv, &priv_size);
    assert_int_equal(rv, CKR_OK);
    assert_true(priv_size > 0);

    rv = C_GetObjectSize(ti->handle, priv, NULL);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    rv = C_GetObjectSize(ti->handle, 0xdeadbeef, &priv_size);
    assert_int_equal(rv, CKR_OBJECT_HANDLE_INVALID);
}

static void test_digest_key_plain_secret(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "digest-key-secret";

    user_login(ti->handle);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x11);
    create_readable_secret(ti->handle, label, CK_TRUE, CK_FALSE, value, sizeof(value));

    /* after a reload, the value is only held wrapped */
    reload(ti);
    user_login(ti->handle);
    CK_OBJECT_HANDLE secret = find_by_label(ti->handle, CKO_SECRET_KEY, label);

    CK_MECHANISM mech = { CKM_SHA256, NULL, 0 };
    CK_BYTE expected[32];
    CK_ULONG expected_len = sizeof(expected);
    CK_RV rv = C_DigestInit(ti->handle, &mech);
    assert_int_equal(rv, CKR_OK);
    rv = C_Digest(ti->handle, value, sizeof(value), expected, &expected_len);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE got[32];
    CK_ULONG got_len = sizeof(got);
    rv = C_DigestInit(ti->handle, &mech);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestKey(ti->handle, secret);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestFinal(ti->handle, got, &got_len);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(got_len, expected_len);
    assert_memory_equal(got, expected, expected_len);

    /* interspersed with C_DigestUpdate */
    CK_BYTE prefix[] = "prefix";
    CK_BYTE both[sizeof(prefix) - 1 + sizeof(value)];
    memcpy(both, prefix, sizeof(prefix) - 1);
    memcpy(&both[sizeof(prefix) - 1], value, sizeof(value));

    expected_len = sizeof(expected);
    rv = C_DigestInit(ti->handle, &mech);
    assert_int_equal(rv, CKR_OK);
    rv = C_Digest(ti->handle, both, sizeof(both), expected, &expected_len);
    assert_int_equal(rv, CKR_OK);

    got_len = sizeof(got);
    rv = C_DigestInit(ti->handle, &mech);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestUpdate(ti->handle, prefix, sizeof(prefix) - 1);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestKey(ti->handle, secret);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestFinal(ti->handle, got, &got_len);
    assert_int_equal(rv, CKR_OK);
    assert_memory_equal(got, expected, expected_len);

    /* a sensitive key the host holds can still be digested */
    CK_OBJECT_HANDLE sensitive = create_readable_secret(ti->handle, "digest-key-sensitive",
            CK_FALSE, CK_TRUE, value, sizeof(value));
    got_len = sizeof(got);
    rv = C_DigestInit(ti->handle, &mech);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestKey(ti->handle, sensitive);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestFinal(ti->handle, got, &got_len);
    assert_int_equal(rv, CKR_OK);
}

static CK_OBJECT_HANDLE gen_aes(CK_SESSION_HANDLE session) {

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_VALUE_LEN, 16, CK_ULONG),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_ENCRYPT, CK_TRUE, CK_BBOOL),
        ATTR(CKA_DECRYPT, CK_TRUE, CK_BBOOL),
    };

    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_RV rv = C_GenerateKey(session, &mech, templ, ARRAY_LEN(templ), &key);
    assert_int_equal(rv, CKR_OK);

    return key;
}

static void test_digest_key_tpm_aes_indigestible(void **state) {

    test_info *ti = test_info_from_state(state);

    user_login(ti->handle);

    CK_OBJECT_HANDLE aes = gen_aes(ti->handle);

    CK_MECHANISM mech = { CKM_SHA256, NULL, 0 };
    CK_RV rv = C_DigestInit(ti->handle, &mech);
    assert_int_equal(rv, CKR_OK);

    rv = C_DigestKey(ti->handle, aes);
    assert_int_equal(rv, CKR_KEY_INDIGESTIBLE);

    /* the digest goes on */
    CK_BYTE msg[] = "abc";
    rv = C_DigestUpdate(ti->handle, msg, sizeof(msg) - 1);
    assert_int_equal(rv, CKR_OK);
    CK_BYTE got[32];
    CK_ULONG got_len = sizeof(got);
    rv = C_DigestFinal(ti->handle, got, &got_len);
    assert_int_equal(rv, CKR_OK);
}

static void test_digest_key_refusals(void **state) {

    test_info *ti = test_info_from_state(state);

    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    gen_rsa(ti->handle, "digest-key-rsa", CK_TRUE, &pub, &priv);

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x22);
    CK_OBJECT_HANDLE secret = create_readable_secret(ti->handle, "digest-key-refusals",
            CK_FALSE, CK_FALSE, value, sizeof(value));

    /* no digest started */
    CK_RV rv = C_DigestKey(ti->handle, secret);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    CK_MECHANISM mech = { CKM_SHA256, NULL, 0 };
    rv = C_DigestInit(ti->handle, &mech);
    assert_int_equal(rv, CKR_OK);

    /* only a secret key */
    rv = C_DigestKey(ti->handle, pub);
    assert_int_equal(rv, CKR_KEY_INDIGESTIBLE);
    rv = C_DigestKey(ti->handle, priv);
    assert_int_equal(rv, CKR_KEY_INDIGESTIBLE);

    rv = C_DigestKey(ti->handle, 0xdeadbeef);
    assert_int_equal(rv, CKR_KEY_HANDLE_INVALID);

    /*
     * A private key's value is the user's: after C_Logout the session is public, and C_DigestKey,
     * like every digest call, needs the user logged in. (So object_get_host_value() can't be reached
     * without the wrapping key; were it, its CKR_USER_NOT_LOGGED_IN would be returned as it is.)
     */
    logout(ti->handle);
    rv = C_DigestKey(ti->handle, secret);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_copy_label_and_sign,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_copy_cannot_widen,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_copy_not_copyable,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_copy_survives_original_destroy,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_copy_session_object_not_persisted,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_copy_secret_value,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_object_size_positive,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_digest_key_plain_secret,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_digest_key_tpm_aes_indigestible,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_digest_key_refusals,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
