/* SPDX-License-Identifier: BSD-2-Clause */

#include <assert.h>
#include <ctype.h>

#include "test.h"

/*
 * CKA_UNIQUE_ID (PKCS#11 3.2 4.4.1): the token gives every object one when it's made, by any function, and
 * a copy a new one; no template may give it, and it can't be changed. An object already in the store
 * without one, as every tpm2_ptool object is, gets one when it's loaded, and keeps it across reloads.
 * CKA_DESTROYABLE=false makes C_DestroyObject fail with CKR_ACTION_PROHIBITED (5.7.3).
 */

#define ATTR(a, v, t) { a, &(t){v}, sizeof(t) }
#define ATTR_VAR(a, v, len) { a, v, len }

/* 16 bytes, hex-encoded */
#define UNIQUE_ID_LEN 32

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

/* the objects matching templ, the first one in *h */
static CK_ULONG count_matching(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR templ, CK_ULONG n,
        CK_OBJECT_HANDLE *h) {

    CK_RV rv = C_FindObjectsInit(session, templ, n);
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE found[8] = { CK_INVALID_HANDLE };
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

static CK_ULONG count_by_label(CK_SESSION_HANDLE session, const char *label, CK_OBJECT_HANDLE *h) {

    CK_ATTRIBUTE templ[] = {
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
    };

    return count_matching(session, templ, ARRAY_LEN(templ), h);
}

static CK_ULONG count_by_unique_id(CK_SESSION_HANDLE session, const char *id, CK_OBJECT_HANDLE *h) {

    CK_ATTRIBUTE templ[] = {
        ATTR_VAR(CKA_UNIQUE_ID, (void *)id, strlen(id)),
    };

    return count_matching(session, templ, ARRAY_LEN(templ), h);
}

/* the object's CKA_UNIQUE_ID, which must be 32 hex characters, NUL-terminated in id */
static void get_unique_id(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h, char id[UNIQUE_ID_LEN + 1]) {

    CK_ATTRIBUTE a = { CKA_UNIQUE_ID, NULL, 0 };
    CK_RV rv = C_GetAttributeValue(session, h, &a, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(a.ulValueLen, UNIQUE_ID_LEN);

    memset(id, 0, UNIQUE_ID_LEN + 1);
    a.pValue = id;
    rv = C_GetAttributeValue(session, h, &a, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(a.ulValueLen, UNIQUE_ID_LEN);

    size_t i;
    for (i = 0; i < UNIQUE_ID_LEN; i++) {
        assert_true(isxdigit((unsigned char)id[i]));
    }
}

static CK_RV create_data(CK_SESSION_HANDLE session, const char *label, CK_BBOOL token,
        CK_ATTRIBUTE_PTR extra, CK_OBJECT_HANDLE *h) {

    static CK_BYTE value[] = "some data";
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_DATA, CK_OBJECT_CLASS),
        ATTR(CKA_TOKEN, token, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
        ATTR_VAR(CKA_VALUE, value, sizeof(value) - 1),
        { 0 },
    };

    CK_ULONG n = ARRAY_LEN(templ) - 1;
    if (extra) {
        templ[n++] = *extra;
    }

    *h = CK_INVALID_HANDLE;
    return C_CreateObject(session, templ, n, h);
}

/* An AES key imported to the TPM through C_CreateObject */
static CK_RV create_aes(CK_SESSION_HANDLE session, const char *label, CK_OBJECT_HANDLE *h) {

    CK_BYTE value[32] = { 0x11 };
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_AES, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
    };

    return C_CreateObject(session, templ, ARRAY_LEN(templ), h);
}

static CK_RV gen_aes(CK_SESSION_HANDLE session, const char *label, CK_ATTRIBUTE_PTR extra,
        CK_OBJECT_HANDLE *h) {

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_VALUE_LEN, 32, CK_ULONG),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
        { 0 },
    };

    CK_ULONG n = ARRAY_LEN(templ) - 1;
    if (extra) {
        templ[n++] = *extra;
    }

    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0 };
    return C_GenerateKey(session, &mech, templ, n, h);
}

/* An EC P-256 token key pair that can derive; pub_extra and priv_extra go in each template */
static CK_RV gen_ec(CK_SESSION_HANDLE session, const char *label, CK_ATTRIBUTE_PTR pub_extra,
        CK_ATTRIBUTE_PTR priv_extra, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {

    static CK_BYTE p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    CK_ATTRIBUTE pub_templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_VERIFY, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_EC_PARAMS, p256, sizeof(p256)),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
        { 0 },
    };
    CK_ATTRIBUTE priv_templ[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SIGN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_DERIVE, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, strlen(label)),
        { 0 },
    };

    CK_ULONG npub = ARRAY_LEN(pub_templ) - 1;
    CK_ULONG npriv = ARRAY_LEN(priv_templ) - 1;
    if (pub_extra) {
        pub_templ[npub++] = *pub_extra;
    }
    if (priv_extra) {
        priv_templ[npriv++] = *priv_extra;
    }

    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    return C_GenerateKeyPair(session, &mech, pub_templ, npub, priv_templ, npriv, pub, priv);
}

/* ECDH with the key pair's own public point; extra goes in the secret's template */
static CK_RV derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv,
        CK_ATTRIBUTE_PTR extra, CK_OBJECT_HANDLE *secret) {

    CK_BYTE point[80];
    CK_ATTRIBUTE ec_point = { CKA_EC_POINT, point, sizeof(point) };
    CK_RV rv = C_GetAttributeValue(session, pub, &ec_point, 1);
    assert_int_equal(rv, CKR_OK);
    assert_true(ec_point.ulValueLen > 2);

    /* skip the DER OCTET STRING header */
    CK_ECDH1_DERIVE_PARAMS params = {
        .kdf = CKD_NULL,
        .pPublicData = &point[2],
        .ulPublicDataLen = ec_point.ulValueLen - 2,
    };
    CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_VALUE_LEN, 32, CK_ULONG),
        { 0 },
    };

    CK_ULONG n = ARRAY_LEN(templ) - 1;
    if (extra) {
        templ[n++] = *extra;
    }

    return C_DeriveKey(session, &mech, priv, templ, n, secret);
}

static void test_unique_id_on_create(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE s = ti->handle;

    user_login(s);

    CK_OBJECT_HANDLE h[7];
    CK_RV rv = create_data(s, "uid-data", CK_TRUE, NULL, &h[0]);
    assert_int_equal(rv, CKR_OK);

    rv = create_data(s, "uid-session-data", CK_FALSE, NULL, &h[1]);
    assert_int_equal(rv, CKR_OK);

    rv = create_aes(s, "uid-aes-import", &h[2]);
    assert_int_equal(rv, CKR_OK);

    rv = gen_aes(s, "uid-aes-gen", NULL, &h[3]);
    assert_int_equal(rv, CKR_OK);

    rv = gen_ec(s, "uid-ec", NULL, NULL, &h[4], &h[5]);
    assert_int_equal(rv, CKR_OK);

    rv = derive(s, h[4], h[5], NULL, &h[6]);
    assert_int_equal(rv, CKR_OK);

    char ids[ARRAY_LEN(h)][UNIQUE_ID_LEN + 1];
    size_t i, j;
    for (i = 0; i < ARRAY_LEN(h); i++) {
        get_unique_id(s, h[i], ids[i]);
        for (j = 0; j < i; j++) {
            assert_string_not_equal(ids[i], ids[j]);
        }
    }
}

static void test_unique_id_template_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE s = ti->handle;

    user_login(s);

    static char given[] = "00112233445566778899aabbccddeeff";
    CK_ATTRIBUTE uid = ATTR_VAR(CKA_UNIQUE_ID, given, sizeof(given) - 1);

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = create_data(s, "uid-refused", CK_TRUE, &uid, &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(count_by_label(s, "uid-refused", NULL), 0);

    rv = create_data(s, "uid-refused", CK_FALSE, &uid, &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(count_by_label(s, "uid-refused", NULL), 0);

    rv = gen_aes(s, "uid-refused", &uid, &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(count_by_label(s, "uid-refused", NULL), 0);

    CK_OBJECT_HANDLE pub, priv;
    rv = gen_ec(s, "uid-refused", &uid, NULL, &pub, &priv);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
    rv = gen_ec(s, "uid-refused", NULL, &uid, &pub, &priv);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(count_by_label(s, "uid-refused", NULL), 0);

    rv = gen_ec(s, "uid-derive", NULL, NULL, &pub, &priv);
    assert_int_equal(rv, CKR_OK);
    rv = derive(s, pub, priv, &uid, &h);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    /* nothing was made with the given ID */
    assert_int_equal(count_by_unique_id(s, given, NULL), 0);
}

static void test_unique_id_copy_is_new(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE s = ti->handle;

    user_login(s);

    CK_OBJECT_HANDLE orig;
    CK_RV rv = create_data(s, "uid-copy", CK_TRUE, NULL, &orig);
    assert_int_equal(rv, CKR_OK);

    char orig_id[UNIQUE_ID_LEN + 1];
    get_unique_id(s, orig, orig_id);

    /* not even the value it already has */
    CK_ATTRIBUTE same = ATTR_VAR(CKA_UNIQUE_ID, orig_id, UNIQUE_ID_LEN);
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    rv = C_CopyObject(s, orig, &same, 1, &copy);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(count_by_label(s, "uid-copy", NULL), 1);

    rv = C_CopyObject(s, orig, NULL, 0, &copy);
    assert_int_equal(rv, CKR_OK);

    CK_ATTRIBUTE session_copy[] = { ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL) };
    CK_OBJECT_HANDLE copy2 = CK_INVALID_HANDLE;
    rv = C_CopyObject(s, orig, session_copy, ARRAY_LEN(session_copy), &copy2);
    assert_int_equal(rv, CKR_OK);

    char copy_id[UNIQUE_ID_LEN + 1], copy2_id[UNIQUE_ID_LEN + 1], again[UNIQUE_ID_LEN + 1];
    get_unique_id(s, copy, copy_id);
    get_unique_id(s, copy2, copy2_id);
    get_unique_id(s, orig, again);

    assert_string_not_equal(copy_id, orig_id);
    assert_string_not_equal(copy2_id, orig_id);
    assert_string_not_equal(copy2_id, copy_id);
    assert_string_equal(again, orig_id);

    CK_OBJECT_HANDLE h;
    assert_int_equal(count_by_unique_id(s, orig_id, &h), 1);
    assert_int_equal(h, orig);
    assert_int_equal(count_by_unique_id(s, copy_id, &h), 1);
    assert_int_equal(h, copy);

    /* the token copy keeps its own after a reload */
    reload(ti);
    user_login(ti->handle);
    assert_int_equal(count_by_unique_id(ti->handle, copy_id, &h), 1);
    get_unique_id(ti->handle, h, again);
    assert_string_equal(again, copy_id);
    assert_int_equal(count_by_unique_id(ti->handle, orig_id, NULL), 1);
}

static void test_unique_id_stable_across_reload(void **state) {

    test_info *ti = test_info_from_state(state);

    user_login(ti->handle);

    CK_OBJECT_HANDLE data, key, pub, priv;
    CK_RV rv = create_data(ti->handle, "uid-reload", CK_TRUE, NULL, &data);
    assert_int_equal(rv, CKR_OK);
    rv = gen_aes(ti->handle, "uid-reload-aes", NULL, &key);
    assert_int_equal(rv, CKR_OK);
    rv = gen_ec(ti->handle, "uid-reload-ec", NULL, NULL, &pub, &priv);
    assert_int_equal(rv, CKR_OK);

    char data_id[UNIQUE_ID_LEN + 1], key_id[UNIQUE_ID_LEN + 1];
    char pub_id[UNIQUE_ID_LEN + 1], priv_id[UNIQUE_ID_LEN + 1];
    get_unique_id(ti->handle, data, data_id);
    get_unique_id(ti->handle, key, key_id);
    get_unique_id(ti->handle, pub, pub_id);
    get_unique_id(ti->handle, priv, priv_id);

    reload(ti);
    user_login(ti->handle);

    const char *ids[] = { data_id, key_id, pub_id, priv_id };
    const char *labels[] = { "uid-reload", "uid-reload-aes", "uid-reload-ec", "uid-reload-ec" };
    size_t i;
    for (i = 0; i < ARRAY_LEN(ids); i++) {
        CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
        assert_int_equal(count_by_unique_id(ti->handle, ids[i], &h), 1);

        char again[UNIQUE_ID_LEN + 1];
        get_unique_id(ti->handle, h, again);
        assert_string_equal(again, ids[i]);

        char label[32] = { 0 };
        CK_ATTRIBUTE a = { CKA_LABEL, label, sizeof(label) - 1 };
        rv = C_GetAttributeValue(ti->handle, h, &a, 1);
        assert_int_equal(rv, CKR_OK);
        assert_string_equal(label, labels[i]);
    }
}

/* "mykeylabel" is an AES key that create_pkcs_store.sh made with tpm2_ptool, which knows no CKA_UNIQUE_ID */
static void test_unique_id_ptool_object(void **state) {

    test_info *ti = test_info_from_state(state);

    user_login(ti->handle);

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    assert_int_equal(count_by_label(ti->handle, "mykeylabel", &h), 1);

    char id[UNIQUE_ID_LEN + 1];
    get_unique_id(ti->handle, h, id);

    /* every object in the token has one, all different */
    CK_OBJECT_HANDLE all[64];
    CK_ULONG count = 0;
    CK_RV rv = C_FindObjectsInit(ti->handle, NULL, 0);
    assert_int_equal(rv, CKR_OK);
    rv = C_FindObjects(ti->handle, all, ARRAY_LEN(all), &count);
    assert_int_equal(rv, CKR_OK);
    rv = C_FindObjectsFinal(ti->handle);
    assert_int_equal(rv, CKR_OK);
    assert_true(count > 1);

    char ids[ARRAY_LEN(all)][UNIQUE_ID_LEN + 1];
    CK_ULONG i, j;
    for (i = 0; i < count; i++) {
        get_unique_id(ti->handle, all[i], ids[i]);
        for (j = 0; j < i; j++) {
            assert_string_not_equal(ids[i], ids[j]);
        }
    }

    /* it was written to the store: a reload gives the same one */
    reload(ti);
    user_login(ti->handle);

    assert_int_equal(count_by_label(ti->handle, "mykeylabel", &h), 1);
    char again[UNIQUE_ID_LEN + 1];
    get_unique_id(ti->handle, h, again);
    assert_string_equal(again, id);

    CK_OBJECT_HANDLE by_id = CK_INVALID_HANDLE;
    assert_int_equal(count_by_unique_id(ti->handle, id, &by_id), 1);
    assert_int_equal(by_id, h);

    /* and it still works */
    CK_BYTE iv[16] = { 0 };
    CK_MECHANISM mech = { CKM_AES_CBC, iv, sizeof(iv) };
    rv = C_EncryptInit(ti->handle, &mech, h);
    assert_int_equal(rv, CKR_OK);
    CK_BYTE plain[16] = { 0 }, cipher[16];
    CK_ULONG cipher_len = sizeof(cipher);
    rv = C_Encrypt(ti->handle, plain, sizeof(plain), cipher, &cipher_len);
    assert_int_equal(rv, CKR_OK);
}

static void test_unique_id_find(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE s = ti->handle;

    user_login(s);

    CK_OBJECT_HANDLE a, b;
    CK_RV rv = create_data(s, "uid-find", CK_TRUE, NULL, &a);
    assert_int_equal(rv, CKR_OK);
    rv = create_data(s, "uid-find", CK_FALSE, NULL, &b);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count_by_label(s, "uid-find", NULL), 2);

    char id_a[UNIQUE_ID_LEN + 1], id_b[UNIQUE_ID_LEN + 1];
    get_unique_id(s, a, id_a);
    get_unique_id(s, b, id_b);

    CK_OBJECT_HANDLE h;
    assert_int_equal(count_by_unique_id(s, id_a, &h), 1);
    assert_int_equal(h, a);
    assert_int_equal(count_by_unique_id(s, id_b, &h), 1);
    assert_int_equal(h, b);

    /* with the other attributes too */
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_DATA, CK_OBJECT_CLASS),
        ATTR_VAR(CKA_LABEL, "uid-find", 8),
        ATTR_VAR(CKA_UNIQUE_ID, id_b, UNIQUE_ID_LEN),
    };
    assert_int_equal(count_matching(s, templ, ARRAY_LEN(templ), &h), 1);
    assert_int_equal(h, b);

    assert_int_equal(count_by_unique_id(s, "ffffffffffffffffffffffffffffffff", NULL), 0);
    /* a prefix isn't a match */
    char prefix[UNIQUE_ID_LEN];
    memcpy(prefix, id_a, UNIQUE_ID_LEN - 1);
    prefix[UNIQUE_ID_LEN - 1] = '\0';
    assert_int_equal(count_by_unique_id(s, prefix, NULL), 0);
}

static void test_unique_id_set_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE s = ti->handle;

    user_login(s);

    CK_OBJECT_HANDLE h;
    CK_RV rv = create_data(s, "uid-set", CK_TRUE, NULL, &h);
    assert_int_equal(rv, CKR_OK);

    char id[UNIQUE_ID_LEN + 1];
    get_unique_id(s, h, id);

    static char other[] = "00112233445566778899aabbccddeeff";
    CK_ATTRIBUTE set = ATTR_VAR(CKA_UNIQUE_ID, other, sizeof(other) - 1);
    rv = C_SetAttributeValue(s, h, &set, 1);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    CK_ATTRIBUTE same = ATTR_VAR(CKA_UNIQUE_ID, id, UNIQUE_ID_LEN);
    rv = C_SetAttributeValue(s, h, &same, 1);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    char again[UNIQUE_ID_LEN + 1];
    get_unique_id(s, h, again);
    assert_string_equal(again, id);
}

static void test_destroy_not_destroyable(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE s = ti->handle;

    user_login(s);

    CK_OBJECT_HANDLE h;
    CK_RV rv = create_data(s, "uid-keep", CK_TRUE, NULL, &h);
    assert_int_equal(rv, CKR_OK);

    CK_ATTRIBUTE off = ATTR(CKA_DESTROYABLE, CK_FALSE, CK_BBOOL);
    rv = C_SetAttributeValue(s, h, &off, 1);
    assert_int_equal(rv, CKR_OK);

    rv = C_DestroyObject(s, h);
    assert_int_equal(rv, CKR_ACTION_PROHIBITED);
    assert_int_equal(count_by_label(s, "uid-keep", NULL), 1);

    /* made not destroyable: a session object, and an AES key in the TPM */
    CK_OBJECT_HANDLE sh;
    rv = create_data(s, "uid-keep-session", CK_FALSE, &off, &sh);
    assert_int_equal(rv, CKR_OK);
    rv = C_DestroyObject(s, sh);
    assert_int_equal(rv, CKR_ACTION_PROHIBITED);
    assert_int_equal(count_by_label(s, "uid-keep-session", NULL), 1);

    CK_OBJECT_HANDLE k;
    rv = gen_aes(s, "uid-keep-aes", &off, &k);
    assert_int_equal(rv, CKR_OK);
    rv = C_DestroyObject(s, k);
    assert_int_equal(rv, CKR_ACTION_PROHIBITED);

    /* still there after a reload, and still not destroyable */
    reload(ti);
    user_login(ti->handle);
    assert_int_equal(count_by_label(ti->handle, "uid-keep", &h), 1);
    rv = C_DestroyObject(ti->handle, h);
    assert_int_equal(rv, CKR_ACTION_PROHIBITED);
    assert_int_equal(count_by_label(ti->handle, "uid-keep-aes", &k), 1);
    rv = C_DestroyObject(ti->handle, k);
    assert_int_equal(rv, CKR_ACTION_PROHIBITED);

    /* an object without the attribute, or with it true, can be */
    rv = create_data(ti->handle, "uid-gone", CK_TRUE, NULL, &h);
    assert_int_equal(rv, CKR_OK);
    rv = C_DestroyObject(ti->handle, h);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count_by_label(ti->handle, "uid-gone", NULL), 0);

    CK_ATTRIBUTE on = ATTR(CKA_DESTROYABLE, CK_TRUE, CK_BBOOL);
    rv = create_data(ti->handle, "uid-gone", CK_FALSE, &on, &h);
    assert_int_equal(rv, CKR_OK);
    rv = C_DestroyObject(ti->handle, h);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count_by_label(ti->handle, "uid-gone", NULL), 0);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_unique_id_on_create,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unique_id_template_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unique_id_copy_is_new,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unique_id_stable_across_reload,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unique_id_ptool_object,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unique_id_find,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unique_id_set_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_destroy_not_destroyable,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
