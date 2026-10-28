/* SPDX-License-Identifier: BSD-2-Clause */

#include <assert.h>

#include "test.h"

/*
 * A private secret key held as a plain object (an ECDH-derived key, a readable generic secret)
 * must keep its CKA_VALUE in the store, wrapped as a private CKO_DATA object's is, so it's still
 * there once the library reloads.
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

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    rv = C_FindObjects(session, &h, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    return h;
}

/* Reads CKA_VALUE into buf, returning C_GetAttributeValue's rv and the length it gave */
static CK_RV read_value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h,
        CK_BYTE *buf, CK_ULONG buf_len, CK_ULONG *len) {

    CK_ATTRIBUTE value = ATTR_VAR(CKA_VALUE, buf, buf_len);
    CK_RV rv = C_GetAttributeValue(session, h, &value, 1);
    *len = value.ulValueLen;
    return rv;
}

static void gen_nistp256(CK_SESSION_HANDLE session, CK_BYTE id, CK_BYTE *point, CK_ULONG *point_len) {

    CK_BYTE curve[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07
    };

    CK_MECHANISM mechanism = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pub_template[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_DERIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_EC_PARAMS, curve, sizeof(curve)),
    };
    CK_ATTRIBUTE priv_template[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_DERIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_ID, id, CK_BYTE),
    };

    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_RV rv = C_GenerateKeyPair(session, &mechanism,
            pub_template, ARRAY_LEN(pub_template),
            priv_template, ARRAY_LEN(priv_template),
            &pub, &priv);
    assert_int_equal(rv, CKR_OK);

    CK_ATTRIBUTE ec_point = ATTR_VAR(CKA_EC_POINT, point, *point_len);
    rv = C_GetAttributeValue(session, pub, &ec_point, 1);
    assert_int_equal(rv, CKR_OK);
    *point_len = ec_point.ulValueLen;
}

static void test_derived_secret_survives_reload(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "persist-derived";

    user_login(ti->handle);

    /* two keys, so one's private half derives against the other's public point */
    CK_BYTE point_a[80];
    CK_ULONG point_a_len = sizeof(point_a);
    gen_nistp256(ti->handle, 0x51, point_a, &point_a_len);

    CK_BYTE point_b[80];
    CK_ULONG point_b_len = sizeof(point_b);
    gen_nistp256(ti->handle, 0x52, point_b, &point_b_len);

    CK_ATTRIBUTE priv_find[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_ID, 0x51, CK_BYTE),
    };
    CK_RV rv = C_FindObjectsInit(ti->handle, priv_find, ARRAY_LEN(priv_find));
    assert_int_equal(rv, CKR_OK);
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    rv = C_FindObjects(ti->handle, &priv, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);
    rv = C_FindObjectsFinal(ti->handle);
    assert_int_equal(rv, CKR_OK);

    /* the point is a DER OCTET STRING: skip its 2 byte header */
    CK_ECDH1_DERIVE_PARAMS params = {
        .kdf = CKD_NULL,
        .ulSharedDataLen = 0,
        .pSharedData = NULL,
        .ulPublicDataLen = point_b_len - 2,
        .pPublicData = &point_b[2],
    };
    CK_MECHANISM mechanism = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    CK_ATTRIBUTE secret_template[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_VALUE_LEN, 32, CK_ULONG),
        ATTR_VAR(CKA_LABEL, (void *)label, sizeof(label) - 1),
    };

    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    rv = C_DeriveKey(ti->handle, &mechanism, priv, secret_template,
            ARRAY_LEN(secret_template), &derived);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE v1[64] = { 0 };
    CK_ULONG len1 = 0;
    rv = read_value(ti->handle, derived, v1, sizeof(v1), &len1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len1, 32);

    reload(ti);
    user_login(ti->handle);

    derived = find_by_label(ti->handle, CKO_SECRET_KEY, label);

    CK_BYTE v2[64] = { 0 };
    CK_ULONG len2 = 0;
    rv = read_value(ti->handle, derived, v2, sizeof(v2), &len2);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(len1, len2);
    assert_memory_equal(v1, v2, len1);
}

static CK_OBJECT_HANDLE create_value_object(CK_SESSION_HANDLE session, CK_OBJECT_CLASS clazz,
        const char *label, CK_BYTE *value, CK_ULONG value_len) {

    CK_ATTRIBUTE secret_templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
        ATTR_VAR(CKA_VALUE, value, value_len),
    };
    CK_ATTRIBUTE data_templ[] = {
        ATTR(CKA_CLASS, CKO_DATA, CK_OBJECT_CLASS),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
        ATTR_VAR(CKA_VALUE, value, value_len),
    };

    bool is_secret = clazz == CKO_SECRET_KEY;
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_CreateObject(session,
            is_secret ? secret_templ : data_templ,
            is_secret ? ARRAY_LEN(secret_templ) : ARRAY_LEN(data_templ),
            &h);
    assert_int_equal(rv, CKR_OK);

    return h;
}

static void test_created_readable_secret_survives_reload(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "persist-created";

    CK_BYTE value[32];
    CK_ULONG i;
    for (i = 0; i < sizeof(value); i++) {
        value[i] = (CK_BYTE)(0xA0 ^ i);
    }

    user_login(ti->handle);

    CK_OBJECT_HANDLE h = create_value_object(ti->handle, CKO_SECRET_KEY, label, value, sizeof(value));

    CK_BYTE v1[64] = { 0 };
    CK_ULONG len1 = 0;
    CK_RV rv = read_value(ti->handle, h, v1, sizeof(v1), &len1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len1, sizeof(value));
    assert_memory_equal(v1, value, sizeof(value));

    reload(ti);
    user_login(ti->handle);

    h = find_by_label(ti->handle, CKO_SECRET_KEY, label);

    CK_BYTE v2[64] = { 0 };
    CK_ULONG len2 = 0;
    rv = read_value(ti->handle, h, v2, sizeof(v2), &len2);
    assert_int_equal(rv, CKR_OK);

    assert_int_equal(len1, len2);
    assert_memory_equal(v1, v2, len1);
}

/*
 * Once reloaded, the value is wrapped with the token's wrapping key, which is only unsealed at
 * login: before it, a secret key gives what a private CKO_DATA object gives, and the value after.
 */
static void test_secret_value_needs_login(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char secret_label[] = "persist-login-secret";
    static const char data_label[] = "persist-login-data";

    CK_BYTE value[32];
    CK_ULONG i;
    for (i = 0; i < sizeof(value); i++) {
        value[i] = (CK_BYTE)(0x5C ^ i);
    }

    user_login(ti->handle);
    create_value_object(ti->handle, CKO_SECRET_KEY, secret_label, value, sizeof(value));
    create_value_object(ti->handle, CKO_DATA, data_label, value, sizeof(value));

    reload(ti);

    /* a private object is only found once logged in: find them, then log out before reading */
    user_login(ti->handle);
    CK_OBJECT_HANDLE secret = find_by_label(ti->handle, CKO_SECRET_KEY, secret_label);
    CK_OBJECT_HANDLE data = find_by_label(ti->handle, CKO_DATA, data_label);
    logout(ti->handle);

    CK_BYTE buf[64] = { 0 };
    CK_ULONG data_len = 0;
    CK_RV data_rv = read_value(ti->handle, data, buf, sizeof(buf), &data_len);

    CK_ULONG secret_len = 0;
    memset(buf, 0, sizeof(buf));
    CK_RV secret_rv = read_value(ti->handle, secret, buf, sizeof(buf), &secret_len);

    /* nothing of the value comes out without the wrapping key */
    assert_int_equal(data_rv, CKR_OK);
    assert_true(data_len == 0 || data_len == CK_UNAVAILABLE_INFORMATION);
    assert_int_equal(secret_rv, data_rv);
    assert_int_equal(secret_len, data_len);

    user_login(ti->handle);

    memset(buf, 0, sizeof(buf));
    secret_len = 0;
    secret_rv = read_value(ti->handle, secret, buf, sizeof(buf), &secret_len);
    assert_int_equal(secret_rv, CKR_OK);
    assert_int_equal(secret_len, sizeof(value));
    assert_memory_equal(buf, value, sizeof(value));
}

/*
 * C_SetAttributeValue keeps the new value, not the one it replaces: what C_DeriveKey relies on,
 * and a private data object's value set again.
 */
static void test_set_value_survives_reload(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "persist-set-data";

    CK_BYTE first[32];
    CK_BYTE second[32];
    CK_ULONG i;
    for (i = 0; i < sizeof(first); i++) {
        first[i] = (CK_BYTE)(0x11 ^ i);
        second[i] = (CK_BYTE)(0xE7 ^ i);
    }

    user_login(ti->handle);
    CK_OBJECT_HANDLE h = create_value_object(ti->handle, CKO_DATA, label, first, sizeof(first));

    CK_ATTRIBUTE set = ATTR_VAR(CKA_VALUE, second, sizeof(second));
    CK_RV rv = C_SetAttributeValue(ti->handle, h, &set, 1);
    assert_int_equal(rv, CKR_OK);

    reload(ti);
    user_login(ti->handle);

    h = find_by_label(ti->handle, CKO_DATA, label);

    CK_BYTE buf[64] = { 0 };
    CK_ULONG len = 0;
    rv = read_value(ti->handle, h, buf, sizeof(buf), &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, sizeof(second));
    assert_memory_equal(buf, second, sizeof(second));
}

/* A generic secret held as a plain object, a session object, with the given CKA_SENSITIVE and CKA_EXTRACTABLE */
static CK_OBJECT_HANDLE create_secret(CK_SESSION_HANDLE session, const char *label,
        CK_BBOOL sensitive, CK_BBOOL extractable, CK_BYTE *value, CK_ULONG value_len) {

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_SENSITIVE, sensitive, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, extractable, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
        ATTR_VAR(CKA_VALUE, value, value_len),
    };

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_CreateObject(session, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_OK);

    return h;
}

/*
 * Asks for CKA_VALUE and CKA_LABEL together: the value can't be revealed, the label is still
 * filled, and the call says CKR_ATTRIBUTE_SENSITIVE (PKCS#11 3.2, C_GetAttributeValue).
 */
static void assert_value_hidden(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h, const char *label) {

    CK_BYTE value[64] = { 0 };
    char got_label[64] = { 0 };
    CK_ATTRIBUTE templ[] = {
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
        ATTR_VAR(CKA_LABEL, got_label, sizeof(got_label)),
    };

    CK_RV rv = C_GetAttributeValue(session, h, templ, ARRAY_LEN(templ));
    assert_int_equal(rv, CKR_ATTRIBUTE_SENSITIVE);
    assert_int_equal(templ[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);
    CK_BYTE zero[sizeof(value)] = { 0 };
    assert_memory_equal(value, zero, sizeof(value));

    assert_int_equal(templ[1].ulValueLen, strlen(label));
    assert_memory_equal(got_label, label, strlen(label));

    /* asking for the length alone is refused the same way */
    CK_ATTRIBUTE len_only = ATTR_VAR(CKA_VALUE, NULL, 0);
    rv = C_GetAttributeValue(session, h, &len_only, 1);
    assert_int_equal(rv, CKR_ATTRIBUTE_SENSITIVE);
    assert_int_equal(len_only.ulValueLen, CK_UNAVAILABLE_INFORMATION);
}

static void fill(CK_BYTE *buf, CK_ULONG len, CK_BYTE seed) {
    CK_ULONG i;
    for (i = 0; i < len; i++) {
        buf[i] = (CK_BYTE)(seed ^ i);
    }
}

static void test_sensitive_value_not_readable(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "sensitive-secret";

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x3A);

    user_login(ti->handle);
    CK_OBJECT_HANDLE h = create_secret(ti->handle, label, CK_TRUE, CK_TRUE, value, sizeof(value));

    assert_value_hidden(ti->handle, h, label);
}

static void test_unextractable_value_not_readable(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "unextractable-secret";

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x4B);

    user_login(ti->handle);
    CK_OBJECT_HANDLE h = create_secret(ti->handle, label, CK_FALSE, CK_FALSE, value, sizeof(value));

    assert_value_hidden(ti->handle, h, label);
}

static void test_readable_value_still_readable(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char label[] = "readable-secret";

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x5D);

    user_login(ti->handle);
    CK_OBJECT_HANDLE h = create_secret(ti->handle, label, CK_FALSE, CK_TRUE, value, sizeof(value));

    CK_BYTE buf[64] = { 0 };
    CK_ULONG len = 0;
    CK_RV rv = read_value(ti->handle, h, buf, sizeof(buf), &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, sizeof(value));
    assert_memory_equal(buf, value, sizeof(value));
}

/*
 * A value unwrapped while logged in doesn't outlive the login: once logged out, a data object and a
 * secret key that were read give what a private data object never read gives, and their value again
 * after the next login.
 */
static void test_value_dropped_on_logout(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char secret_label[] = "logout-secret";
    static const char data_label[] = "logout-data";
    static const char unread_label[] = "logout-unread";

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x6E);

    user_login(ti->handle);
    create_value_object(ti->handle, CKO_SECRET_KEY, secret_label, value, sizeof(value));
    create_value_object(ti->handle, CKO_DATA, data_label, value, sizeof(value));
    create_value_object(ti->handle, CKO_DATA, unread_label, value, sizeof(value));

    /* from the store, so nothing of the value is in memory until it's read */
    reload(ti);
    user_login(ti->handle);

    CK_OBJECT_HANDLE secret = find_by_label(ti->handle, CKO_SECRET_KEY, secret_label);
    CK_OBJECT_HANDLE data = find_by_label(ti->handle, CKO_DATA, data_label);
    CK_OBJECT_HANDLE unread = find_by_label(ti->handle, CKO_DATA, unread_label);

    CK_OBJECT_HANDLE read[] = { secret, data };
    CK_BYTE buf[64];
    CK_ULONG len = 0;
    CK_ULONG i;
    for (i = 0; i < ARRAY_LEN(read); i++) {
        memset(buf, 0, sizeof(buf));
        CK_RV rv = read_value(ti->handle, read[i], buf, sizeof(buf), &len);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(len, sizeof(value));
        assert_memory_equal(buf, value, sizeof(value));
    }

    logout(ti->handle);

    CK_ULONG unread_len = 0;
    memset(buf, 0, sizeof(buf));
    CK_RV unread_rv = read_value(ti->handle, unread, buf, sizeof(buf), &unread_len);
    assert_int_equal(unread_rv, CKR_OK);
    assert_true(unread_len == 0 || unread_len == CK_UNAVAILABLE_INFORMATION);

    for (i = 0; i < ARRAY_LEN(read); i++) {
        memset(buf, 0, sizeof(buf));
        CK_RV rv = read_value(ti->handle, read[i], buf, sizeof(buf), &len);
        assert_int_equal(rv, unread_rv);
        assert_int_equal(len, unread_len);
    }

    user_login(ti->handle);

    for (i = 0; i < ARRAY_LEN(read); i++) {
        memset(buf, 0, sizeof(buf));
        CK_RV rv = read_value(ti->handle, read[i], buf, sizeof(buf), &len);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(len, sizeof(value));
        assert_memory_equal(buf, value, sizeof(value));
    }
}

/* A key's value is what the key is: C_SetAttributeValue can't change it. A data object's it can. */
static void test_set_value_on_key_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    static const char secret_label[] = "set-value-secret";
    static const char data_label[] = "set-value-data";

    CK_BYTE value[32];
    CK_BYTE other[32];
    fill(value, sizeof(value), 0x7F);
    fill(other, sizeof(other), 0x80);

    user_login(ti->handle);
    CK_OBJECT_HANDLE secret = create_secret(ti->handle, secret_label, CK_FALSE, CK_TRUE,
            value, sizeof(value));
    CK_OBJECT_HANDLE data = create_value_object(ti->handle, CKO_DATA, data_label,
            value, sizeof(value));

    CK_ATTRIBUTE set = ATTR_VAR(CKA_VALUE, other, sizeof(other));
    CK_RV rv = C_SetAttributeValue(ti->handle, secret, &set, 1);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    /* unchanged */
    CK_BYTE buf[64] = { 0 };
    CK_ULONG len = 0;
    rv = read_value(ti->handle, secret, buf, sizeof(buf), &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, sizeof(value));
    assert_memory_equal(buf, value, sizeof(value));

    rv = C_SetAttributeValue(ti->handle, data, &set, 1);
    assert_int_equal(rv, CKR_OK);

    memset(buf, 0, sizeof(buf));
    rv = read_value(ti->handle, data, buf, sizeof(buf), &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, sizeof(other));
    assert_memory_equal(buf, other, sizeof(other));
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

/* What C_CreateObject gives for a generic secret held on the host */
static CK_RV create_public_secret(CK_SESSION_HANDLE session, CK_BBOOL is_private, CK_BBOOL sensitive,
        CK_BBOOL extractable, CK_OBJECT_HANDLE *h) {

    CK_BYTE value[32];
    fill(value, sizeof(value), 0x91);

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR_VAR(CKA_PRIVATE, &is_private, sizeof(is_private)),
        ATTR_VAR(CKA_SENSITIVE, &sensitive, sizeof(sensitive)),
        ATTR_VAR(CKA_EXTRACTABLE, &extractable, sizeof(extractable)),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
    };

    *h = CK_INVALID_HANDLE;
    return C_CreateObject(session, templ, ARRAY_LEN(templ), h);
}

/*
 * A public object's value is kept in plain text in the store: a secret held on the host that is
 * sensitive or unextractable isn't public, whether C_CreateObject or C_DeriveKey makes it, or
 * C_SetAttributeValue or a copy would make it so.
 */
static void test_public_secret_is_readable(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_ULONG before = count_objects(ti->handle);

    /* C_CreateObject: an extractable generic secret stays on the host */
    CK_OBJECT_HANDLE h;
    CK_RV rv = create_public_secret(ti->handle, CK_FALSE, CK_TRUE, CK_TRUE, &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);
    /* and one that isn't sensitive */
    rv = create_public_secret(ti->handle, CK_FALSE, CK_FALSE, CK_FALSE, &h);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);
    assert_int_equal(count_objects(ti->handle), before);

    /* C_DeriveKey */
    CK_BYTE point_a[80];
    CK_ULONG point_a_len = sizeof(point_a);
    gen_nistp256(ti->handle, 0x61, point_a, &point_a_len);
    CK_BYTE point_b[80];
    CK_ULONG point_b_len = sizeof(point_b);
    gen_nistp256(ti->handle, 0x62, point_b, &point_b_len);

    CK_ATTRIBUTE priv_find[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_ID, 0x61, CK_BYTE),
    };
    rv = C_FindObjectsInit(ti->handle, priv_find, ARRAY_LEN(priv_find));
    assert_int_equal(rv, CKR_OK);
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    rv = C_FindObjects(ti->handle, &priv, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);
    rv = C_FindObjectsFinal(ti->handle);
    assert_int_equal(rv, CKR_OK);

    CK_ECDH1_DERIVE_PARAMS params = {
        .kdf = CKD_NULL,
        .ulPublicDataLen = point_b_len - 2,
        .pPublicData = &point_b[2],
    };
    CK_MECHANISM mechanism = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    CK_ATTRIBUTE derive_templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_PRIVATE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    };
    before = count_objects(ti->handle);
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    rv = C_DeriveKey(ti->handle, &mechanism, priv, derive_templ, ARRAY_LEN(derive_templ), &derived);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);
    assert_int_equal(count_objects(ti->handle), before);

    /* C_SetAttributeValue: a public readable secret stays readable */
    rv = create_public_secret(ti->handle, CK_FALSE, CK_FALSE, CK_TRUE, &h);
    assert_int_equal(rv, CKR_OK);
    CK_BBOOL ck_true = CK_TRUE, ck_false = CK_FALSE;
    CK_ATTRIBUTE sensitive = ATTR_VAR(CKA_SENSITIVE, &ck_true, sizeof(ck_true));
    CK_ATTRIBUTE unextractable = ATTR_VAR(CKA_EXTRACTABLE, &ck_false, sizeof(ck_false));
    rv = C_SetAttributeValue(ti->handle, h, &sensitive, 1);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
    rv = C_SetAttributeValue(ti->handle, h, &unextractable, 1);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    CK_BYTE buf[64];
    CK_ULONG len = 0;
    rv = read_value(ti->handle, h, buf, sizeof(buf), &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 32);

    /* a copy that stays public, and one made private, which may be sensitive */
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    rv = C_CopyObject(ti->handle, h, &sensitive, 1, &copy);
    assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);
    CK_ATTRIBUTE private_sensitive[] = {
        ATTR_VAR(CKA_PRIVATE, &ck_true, sizeof(ck_true)),
        ATTR_VAR(CKA_SENSITIVE, &ck_true, sizeof(ck_true)),
    };
    rv = C_CopyObject(ti->handle, h, private_sensitive, ARRAY_LEN(private_sensitive), &copy);
    assert_int_equal(rv, CKR_OK);
    rv = read_value(ti->handle, copy, buf, sizeof(buf), &len);
    assert_int_equal(rv, CKR_ATTRIBUTE_SENSITIVE);

    /* a private one may become sensitive and unextractable */
    rv = create_public_secret(ti->handle, CK_TRUE, CK_FALSE, CK_TRUE, &h);
    assert_int_equal(rv, CKR_OK);
    rv = C_SetAttributeValue(ti->handle, h, &sensitive, 1);
    assert_int_equal(rv, CKR_OK);
    rv = C_SetAttributeValue(ti->handle, h, &unextractable, 1);
    assert_int_equal(rv, CKR_OK);
    rv = read_value(ti->handle, h, buf, sizeof(buf), &len);
    assert_int_equal(rv, CKR_ATTRIBUTE_SENSITIVE);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_derived_secret_survives_reload,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_created_readable_secret_survives_reload,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_secret_value_needs_login,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_value_survives_reload,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sensitive_value_not_readable,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unextractable_value_not_readable,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_readable_value_still_readable,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_value_dropped_on_logout,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_value_on_key_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_public_secret_is_readable,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
