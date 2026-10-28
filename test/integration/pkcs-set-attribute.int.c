/* SPDX-License-Identifier: BSD-2-Clause */

#include <assert.h>

#include "test.h"

/*
 * What C_SetAttributeValue may change (PKCS#11 3.2 4.1.2, 5.7.6, and the attribute tables of chapter 4
 * with their footnote 8): the label and the reference attributes, key usages only off, CKA_SENSITIVE only
 * on, CKA_EXTRACTABLE and CKA_COPYABLE only off. The rest is read-only, and an attribute the object's class
 * doesn't have is invalid. A copy can't widen a key either.
 */

#define ATTR(a, v, t) { a, &(t){v}, sizeof(t) }
#define ATTR_VAR(a, v, len) { a, v, len }

/* src/lib/attrs.h */
#ifndef CKA_TPM2_PUB_BLOB
#define CKA_TPM2_PUB_BLOB (CKA_VENDOR_DEFINED|0x0F000000UL|0x2UL)
#endif

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

    user_login(ti->handle);

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

/* A session NIST P-256 key pair; always_auth sets the private key's CKA_ALWAYS_AUTHENTICATE. */
static void gen_ec(CK_SESSION_HANDLE session, CK_BBOOL always_auth,
        CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {

    static CK_BYTE p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

    CK_ATTRIBUTE pub_templ[] = {
        ATTR(CKA_CLASS, CKO_PUBLIC_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_VERIFY, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_EC_PARAMS, p256, sizeof(p256)),
    };
    CK_ATTRIBUTE priv_templ[] = {
        ATTR(CKA_CLASS, CKO_PRIVATE_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_EC, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_TRUE, CK_BBOOL),
        ATTR(CKA_SIGN, CK_TRUE, CK_BBOOL),
        ATTR(CKA_ALWAYS_AUTHENTICATE, always_auth, CK_BBOOL),
    };

    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_RV rv = C_GenerateKeyPair(session, &mech,
            pub_templ, ARRAY_LEN(pub_templ),
            priv_templ, ARRAY_LEN(priv_templ),
            pub, priv);
    assert_int_equal(rv, CKR_OK);
}

/* A private session data object */
static CK_OBJECT_HANDLE create_data(CK_SESSION_HANDLE session) {

    static CK_BYTE value[] = { 0xd1, 0xd2, 0xd3, 0xd4 };
    static const char label[] = "set-attr-data";

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_DATA, CK_OBJECT_CLASS),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_PRIVATE, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_LABEL, (void *)label, sizeof(label) - 1),
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
    };

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_CreateObject(session, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_OK);

    return h;
}

/* A session generic secret, readable */
static CK_OBJECT_HANDLE create_secret(CK_SESSION_HANDLE session) {

    static CK_BYTE value[] = { 0x5e, 0xc2, 0xe7, 0x01, 0x02, 0x03, 0x04, 0x05,
                               0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d };

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_CLASS),
        ATTR(CKA_KEY_TYPE, CKK_GENERIC_SECRET, CK_KEY_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR(CKA_SENSITIVE, CK_FALSE, CK_BBOOL),
        ATTR(CKA_EXTRACTABLE, CK_TRUE, CK_BBOOL),
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
    };

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_CreateObject(session, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_OK);

    return h;
}

/* A session X.509 certificate; its bytes aren't parsed */
static CK_OBJECT_HANDLE create_cert(CK_SESSION_HANDLE session) {

    static CK_BYTE subject[] = { 0x30, 0x00 };
    static CK_BYTE value[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };

    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_CERTIFICATE, CK_OBJECT_CLASS),
        ATTR(CKA_CERTIFICATE_TYPE, CKC_X_509, CK_CERTIFICATE_TYPE),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR_VAR(CKA_SUBJECT, subject, sizeof(subject)),
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
    };

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = C_CreateObject(session, templ, ARRAY_LEN(templ), &h);
    assert_int_equal(rv, CKR_OK);

    return h;
}

static CK_RV set_bool(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type, CK_BBOOL v) {
    CK_ATTRIBUTE t = ATTR(type, v, CK_BBOOL);
    return C_SetAttributeValue(session, h, &t, 1);
}

static CK_BBOOL get_bool(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type) {
    CK_BBOOL v = 0xAA;
    CK_ATTRIBUTE t = ATTR_VAR(type, &v, sizeof(v));
    CK_RV rv = C_GetAttributeValue(session, h, &t, 1);
    assert_int_equal(rv, CKR_OK);
    return v;
}

static CK_RV set_ulong(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type, CK_ULONG v) {
    CK_ATTRIBUTE t = ATTR(type, v, CK_ULONG);
    return C_SetAttributeValue(session, h, &t, 1);
}

static CK_ULONG get_ulong(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type) {
    CK_ULONG v = 0;
    CK_ATTRIBUTE t = ATTR_VAR(type, &v, sizeof(v));
    CK_RV rv = C_GetAttributeValue(session, h, &t, 1);
    assert_int_equal(rv, CKR_OK);
    return v;
}

static void assert_bytes(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type,
        const void *expected, CK_ULONG len) {
    CK_BYTE buf[64] = { 0 };
    CK_ATTRIBUTE t = ATTR_VAR(type, buf, sizeof(buf));
    CK_RV rv = C_GetAttributeValue(session, h, &t, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(t.ulValueLen, len);
    assert_memory_equal(buf, expected, len);
}

/* CKA_PRIVATE, CKA_TOKEN and CKA_MODIFIABLE only change in a copy (Table 19, 4.1.3) */
static void test_set_private_read_only(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE data = create_data(ti->handle);

    assert_int_equal(set_bool(ti->handle, data, CKA_PRIVATE, CK_FALSE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_bool(ti->handle, data, CKA_PRIVATE), CK_TRUE);

    assert_int_equal(set_bool(ti->handle, data, CKA_TOKEN, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_bool(ti->handle, data, CKA_TOKEN), CK_FALSE);

    assert_int_equal(set_bool(ti->handle, data, CKA_MODIFIABLE, CK_FALSE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_bool(ti->handle, data, CKA_MODIFIABLE), CK_TRUE);

    /* the value it already has is refused all the same */
    assert_int_equal(set_bool(ti->handle, data, CKA_PRIVATE, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);

    /* and a refused entry leaves the others of the template unapplied */
    static const char label[] = "set-attr-new-label";
    CK_ATTRIBUTE both[] = {
        ATTR_VAR(CKA_LABEL, (void *)label, sizeof(label) - 1),
        ATTR(CKA_PRIVATE, CK_FALSE, CK_BBOOL),
    };
    CK_RV rv = C_SetAttributeValue(ti->handle, data, both, ARRAY_LEN(both));
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
    assert_bytes(ti->handle, data, CKA_LABEL, "set-attr-data", strlen("set-attr-data"));
}

static void test_set_class_read_only(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE data = create_data(ti->handle);
    assert_int_equal(set_ulong(ti->handle, data, CKA_CLASS, CKO_SECRET_KEY), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_ulong(ti->handle, data, CKA_CLASS, CKO_DATA), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_ulong(ti->handle, data, CKA_CLASS), CKO_DATA);

    CK_OBJECT_HANDLE pub, priv;
    gen_ec(ti->handle, CK_FALSE, &pub, &priv);
    assert_int_equal(set_ulong(ti->handle, pub, CKA_CLASS, CKO_PRIVATE_KEY), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_ulong(ti->handle, priv, CKA_CLASS, CKO_SECRET_KEY), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_ulong(ti->handle, priv, CKA_CLASS), CKO_PRIVATE_KEY);
}

static void test_set_key_type_read_only(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE pub, priv;
    gen_ec(ti->handle, CK_FALSE, &pub, &priv);
    assert_int_equal(set_ulong(ti->handle, priv, CKA_KEY_TYPE, CKK_RSA), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_ulong(ti->handle, pub, CKA_KEY_TYPE, CKK_RSA), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_ulong(ti->handle, priv, CKA_KEY_TYPE), CKK_EC);

    CK_OBJECT_HANDLE secret = create_secret(ti->handle);
    assert_int_equal(set_ulong(ti->handle, secret, CKA_KEY_TYPE, CKK_AES), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_ulong(ti->handle, secret, CKA_KEY_TYPE), CKK_GENERIC_SECRET);

    /* nor the other attributes the token sets */
    assert_int_equal(set_bool(ti->handle, priv, CKA_LOCAL, CK_FALSE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_bool(ti->handle, priv, CKA_ALWAYS_SENSITIVE, CK_FALSE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_bool(ti->handle, priv, CKA_NEVER_EXTRACTABLE, CK_FALSE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_ulong(ti->handle, priv, CKA_KEY_GEN_MECHANISM, CKM_RSA_PKCS_KEY_PAIR_GEN),
            CKR_ATTRIBUTE_READ_ONLY);

    CK_MECHANISM_TYPE mechs[] = { CKM_ECDSA };
    CK_ATTRIBUTE allowed = ATTR_VAR(CKA_ALLOWED_MECHANISMS, mechs, sizeof(mechs));
    assert_int_equal(C_SetAttributeValue(ti->handle, priv, &allowed, 1), CKR_ATTRIBUTE_READ_ONLY);

    /* the key material */
    CK_BYTE point[] = { 0x04, 0x41, 0x04 };
    CK_ATTRIBUTE ec_point = ATTR_VAR(CKA_EC_POINT, point, sizeof(point));
    assert_int_equal(C_SetAttributeValue(ti->handle, pub, &ec_point, 1), CKR_ATTRIBUTE_READ_ONLY);
    CK_BYTE p384[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
    CK_ATTRIBUTE params = ATTR_VAR(CKA_EC_PARAMS, p384, sizeof(p384));
    assert_int_equal(C_SetAttributeValue(ti->handle, priv, &params, 1), CKR_ATTRIBUTE_READ_ONLY);

    /* CKA_UNIQUE_ID MUST NOT be modified (4.4.1) */
    CK_BYTE uid[] = "1234";
    CK_ATTRIBUTE unique = ATTR_VAR(CKA_UNIQUE_ID, uid, sizeof(uid) - 1);
    assert_int_equal(C_SetAttributeValue(ti->handle, secret, &unique, 1), CKR_ATTRIBUTE_READ_ONLY);
}

/* The TPM's data: the blobs, the wrapped auth, the serialized handle. Any vendor attribute. */
static void test_set_vendor_attr_read_only(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE pub, priv;
    gen_ec(ti->handle, CK_FALSE, &pub, &priv);

    CK_BYTE blob[] = { 0x00, 0x01, 0x02, 0x03 };
    CK_ATTRIBUTE t = ATTR_VAR(CKA_TPM2_PUB_BLOB, blob, sizeof(blob));
    assert_int_equal(C_SetAttributeValue(ti->handle, priv, &t, 1), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(C_SetAttributeValue(ti->handle, pub, &t, 1), CKR_ATTRIBUTE_READ_ONLY);

    CK_OBJECT_HANDLE data = create_data(ti->handle);
    CK_ATTRIBUTE other = ATTR_VAR(CKA_VENDOR_DEFINED + 0x1234, blob, sizeof(blob));
    assert_int_equal(C_SetAttributeValue(ti->handle, data, &other, 1), CKR_ATTRIBUTE_READ_ONLY);

    /* the key still signs */
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
    CK_RV rv = C_SignInit(ti->handle, &mech, priv);
    assert_int_equal(rv, CKR_OK);
    CK_BYTE digest[32] = { 0x42 };
    CK_BYTE sig[128];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_Sign(ti->handle, digest, sizeof(digest), sig, &sig_len);
    assert_int_equal(rv, CKR_OK);
}

/* Turning it off would widen the key, and on, it isn't a key the TPM was told to guard so */
static void test_set_always_authenticate_read_only(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE pub, priv;
    gen_ec(ti->handle, CK_TRUE, &pub, &priv);
    assert_int_equal(set_bool(ti->handle, priv, CKA_ALWAYS_AUTHENTICATE, CK_FALSE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_bool(ti->handle, priv, CKA_ALWAYS_AUTHENTICATE), CK_TRUE);

    CK_OBJECT_HANDLE pub2, priv2;
    gen_ec(ti->handle, CK_FALSE, &pub2, &priv2);
    assert_int_equal(set_bool(ti->handle, priv2, CKA_ALWAYS_AUTHENTICATE, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_bool(ti->handle, priv2, CKA_ALWAYS_AUTHENTICATE), CK_FALSE);
}

/* A public key's usages only narrow, like a private key's */
static void test_set_public_key_usage_cannot_widen(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE pub, priv;
    gen_ec(ti->handle, CK_FALSE, &pub, &priv);

    assert_int_equal(get_bool(ti->handle, pub, CKA_VERIFY), CK_TRUE);
    assert_int_equal(set_bool(ti->handle, pub, CKA_VERIFY, CK_FALSE), CKR_OK);
    assert_int_equal(get_bool(ti->handle, pub, CKA_VERIFY), CK_FALSE);
    assert_int_equal(set_bool(ti->handle, pub, CKA_VERIFY, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_bool(ti->handle, pub, CKA_VERIFY), CK_FALSE);

    assert_int_equal(set_bool(ti->handle, pub, CKA_WRAP, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_bool(ti->handle, pub, CKA_ENCRYPT, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_bool(ti->handle, pub, CKA_DERIVE, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);

    /* a private key's usage attribute isn't a public key's */
    assert_int_equal(set_bool(ti->handle, pub, CKA_SIGN, CK_FALSE), CKR_ATTRIBUTE_TYPE_INVALID);
    assert_int_equal(set_bool(ti->handle, priv, CKA_VERIFY, CK_FALSE), CKR_ATTRIBUTE_TYPE_INVALID);
}

static void test_set_label_and_id_ok(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE pub, priv;
    gen_ec(ti->handle, CK_FALSE, &pub, &priv);

    static const char label[] = "set-attr-key";
    CK_BYTE id[] = { 0x1d, 0x2d };
    CK_BYTE subject[] = { 0x30, 0x00 };
    CK_DATE start = { { '2', '0', '2', '6' }, { '0', '1' }, { '0', '1' } };
    CK_DATE end = { { '2', '0', '2', '7' }, { '1', '2' }, { '3', '1' } };
    CK_ATTRIBUTE templ[] = {
        ATTR_VAR(CKA_LABEL, (void *)label, sizeof(label) - 1),
        ATTR_VAR(CKA_ID, id, sizeof(id)),
        ATTR_VAR(CKA_SUBJECT, subject, sizeof(subject)),
        ATTR_VAR(CKA_START_DATE, &start, sizeof(start)),
        ATTR_VAR(CKA_END_DATE, &end, sizeof(end)),
    };

    CK_OBJECT_HANDLE keys[] = { pub, priv, create_secret(ti->handle) };
    CK_ULONG i;
    for (i = 0; i < ARRAY_LEN(keys); i++) {
        /* a secret key has no CKA_SUBJECT */
        CK_ULONG count = i == 2 ? 2 : ARRAY_LEN(templ);
        CK_RV rv = C_SetAttributeValue(ti->handle, keys[i], templ, count);
        assert_int_equal(rv, CKR_OK);
        if (i == 2) {
            rv = C_SetAttributeValue(ti->handle, keys[i], &templ[3], 2);
            assert_int_equal(rv, CKR_OK);
        }

        assert_bytes(ti->handle, keys[i], CKA_LABEL, label, sizeof(label) - 1);
        assert_bytes(ti->handle, keys[i], CKA_ID, id, sizeof(id));
        assert_bytes(ti->handle, keys[i], CKA_START_DATE, &start, sizeof(start));
        assert_bytes(ti->handle, keys[i], CKA_END_DATE, &end, sizeof(end));
        if (i < 2) {
            assert_bytes(ti->handle, keys[i], CKA_SUBJECT, subject, sizeof(subject));
        }
    }

    assert_int_equal(C_SetAttributeValue(ti->handle, keys[2], &templ[2], 1), CKR_ATTRIBUTE_TYPE_INVALID);

    /* a bad date */
    CK_BYTE short_date[] = { '2', '0' };
    CK_ATTRIBUTE bad = ATTR_VAR(CKA_START_DATE, short_date, sizeof(short_date));
    assert_int_equal(C_SetAttributeValue(ti->handle, priv, &bad, 1), CKR_ATTRIBUTE_VALUE_INVALID);

    /* the key still signs */
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
    CK_RV rv = C_SignInit(ti->handle, &mech, priv);
    assert_int_equal(rv, CKR_OK);
    CK_BYTE digest[32] = { 0x42 };
    CK_BYTE sig[128];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_Sign(ti->handle, digest, sizeof(digest), sig, &sig_len);
    assert_int_equal(rv, CKR_OK);
}

static void test_set_data_value_ok(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE data = create_data(ti->handle);

    CK_BYTE value[] = { 0xa1, 0xa2, 0xa3 };
    static const char app[] = "set-attr-app";
    CK_BYTE oid[] = { 0x06, 0x03, 0x2a, 0x03, 0x04 };
    CK_ATTRIBUTE templ[] = {
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
        ATTR_VAR(CKA_APPLICATION, (void *)app, sizeof(app) - 1),
        ATTR_VAR(CKA_OBJECT_ID, oid, sizeof(oid)),
    };
    CK_RV rv = C_SetAttributeValue(ti->handle, data, templ, ARRAY_LEN(templ));
    assert_int_equal(rv, CKR_OK);

    assert_bytes(ti->handle, data, CKA_VALUE, value, sizeof(value));
    assert_bytes(ti->handle, data, CKA_APPLICATION, app, sizeof(app) - 1);
    assert_bytes(ti->handle, data, CKA_OBJECT_ID, oid, sizeof(oid));
}

static void test_set_key_attr_on_data_invalid(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE data = create_data(ti->handle);
    assert_int_equal(set_bool(ti->handle, data, CKA_SIGN, CK_FALSE), CKR_ATTRIBUTE_TYPE_INVALID);
    assert_int_equal(set_bool(ti->handle, data, CKA_SENSITIVE, CK_TRUE), CKR_ATTRIBUTE_TYPE_INVALID);
    assert_int_equal(set_ulong(ti->handle, data, CKA_KEY_TYPE, CKK_AES), CKR_ATTRIBUTE_TYPE_INVALID);

    CK_BYTE id[] = { 0x01 };
    CK_ATTRIBUTE t = ATTR_VAR(CKA_ID, id, sizeof(id));
    assert_int_equal(C_SetAttributeValue(ti->handle, data, &t, 1), CKR_ATTRIBUTE_TYPE_INVALID);

    /* nor a data object's attribute on a key */
    CK_OBJECT_HANDLE secret = create_secret(ti->handle);
    static const char app[] = "app";
    CK_ATTRIBUTE a = ATTR_VAR(CKA_APPLICATION, (void *)app, sizeof(app) - 1);
    assert_int_equal(C_SetAttributeValue(ti->handle, secret, &a, 1), CKR_ATTRIBUTE_TYPE_INVALID);
}

/* An X.509 certificate's CKA_ID, CKA_ISSUER and CKA_SERIAL_NUMBER, and nothing else (Table 22) */
static void test_set_cert_attrs(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE cert = create_cert(ti->handle);

    CK_BYTE id[] = { 0xc1 };
    CK_BYTE issuer[] = { 0x30, 0x02, 0x31, 0x00 };
    CK_BYTE serial[] = { 0x02, 0x01, 0x07 };
    static const char label[] = "set-attr-cert";
    CK_ATTRIBUTE templ[] = {
        ATTR_VAR(CKA_ID, id, sizeof(id)),
        ATTR_VAR(CKA_ISSUER, issuer, sizeof(issuer)),
        ATTR_VAR(CKA_SERIAL_NUMBER, serial, sizeof(serial)),
        ATTR_VAR(CKA_LABEL, (void *)label, sizeof(label) - 1),
    };
    CK_RV rv = C_SetAttributeValue(ti->handle, cert, templ, ARRAY_LEN(templ));
    assert_int_equal(rv, CKR_OK);
    assert_bytes(ti->handle, cert, CKA_SERIAL_NUMBER, serial, sizeof(serial));

    CK_BYTE subject[] = { 0x30, 0x02, 0x31, 0x00 };
    CK_ATTRIBUTE s = ATTR_VAR(CKA_SUBJECT, subject, sizeof(subject));
    assert_int_equal(C_SetAttributeValue(ti->handle, cert, &s, 1), CKR_ATTRIBUTE_READ_ONLY);

    CK_BYTE value[] = { 0x30, 0x00 };
    CK_ATTRIBUTE v = ATTR_VAR(CKA_VALUE, value, sizeof(value));
    assert_int_equal(C_SetAttributeValue(ti->handle, cert, &v, 1), CKR_ATTRIBUTE_READ_ONLY);

    static const char url[] = "http://example.invalid/c";
    CK_ATTRIBUTE u = ATTR_VAR(CKA_URL, (void *)url, sizeof(url) - 1);
    assert_int_equal(C_SetAttributeValue(ti->handle, cert, &u, 1), CKR_ATTRIBUTE_READ_ONLY);

    assert_int_equal(set_bool(ti->handle, cert, CKA_TRUSTED, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_ulong(ti->handle, cert, CKA_CERTIFICATE_TYPE, CKC_WTLS), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_bool(ti->handle, cert, CKA_SIGN, CK_FALSE), CKR_ATTRIBUTE_TYPE_INVALID);
}

/* One-way attributes of any object, and a secret key's */
static void test_set_one_way(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE data = create_data(ti->handle);
    assert_int_equal(set_bool(ti->handle, data, CKA_DESTROYABLE, CK_FALSE), CKR_OK);
    assert_int_equal(set_bool(ti->handle, data, CKA_DESTROYABLE, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(get_bool(ti->handle, data, CKA_DESTROYABLE), CK_FALSE);
    assert_int_equal(set_bool(ti->handle, data, CKA_COPYABLE, CK_FALSE), CKR_OK);
    assert_int_equal(set_bool(ti->handle, data, CKA_COPYABLE, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);

    CK_OBJECT_HANDLE secret = create_secret(ti->handle);
    assert_int_equal(set_bool(ti->handle, secret, CKA_SIGN, CK_FALSE), CKR_OK);
    assert_int_equal(set_bool(ti->handle, secret, CKA_SIGN, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_bool(ti->handle, secret, CKA_SENSITIVE, CK_TRUE), CKR_OK);
    assert_int_equal(set_bool(ti->handle, secret, CKA_SENSITIVE, CK_FALSE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_bool(ti->handle, secret, CKA_EXTRACTABLE, CK_FALSE), CKR_OK);
    assert_int_equal(set_bool(ti->handle, secret, CKA_EXTRACTABLE, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_bool(ti->handle, secret, CKA_WRAP_WITH_TRUSTED, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);
    assert_int_equal(set_bool(ti->handle, secret, CKA_TRUSTED, CK_TRUE), CKR_ATTRIBUTE_READ_ONLY);

    /* a bool that isn't one */
    CK_ULONG wide = 0;
    CK_ATTRIBUTE t = ATTR_VAR(CKA_SIGN, &wide, sizeof(wide));
    assert_int_equal(C_SetAttributeValue(ti->handle, secret, &t, 1), CKR_ATTRIBUTE_VALUE_INVALID);
}

/* A copy narrows a public key's usages too, never widens them */
static void test_copy_public_key_cannot_widen(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_OBJECT_HANDLE pub, priv;
    gen_ec(ti->handle, CK_FALSE, &pub, &priv);

    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_ATTRIBUTE wrap = ATTR(CKA_WRAP, CK_TRUE, CK_BBOOL);
    CK_RV rv = C_CopyObject(ti->handle, pub, &wrap, 1, &copy);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    CK_ATTRIBUTE off = ATTR(CKA_VERIFY, CK_FALSE, CK_BBOOL);
    rv = C_CopyObject(ti->handle, pub, &off, 1, &copy);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(get_bool(ti->handle, copy, CKA_VERIFY), CK_FALSE);

    CK_OBJECT_HANDLE copy2 = CK_INVALID_HANDLE;
    CK_ATTRIBUTE on = ATTR(CKA_VERIFY, CK_TRUE, CK_BBOOL);
    rv = C_CopyObject(ti->handle, copy, &on, 1, &copy2);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);

    /* nor CKA_ALWAYS_AUTHENTICATE of a private key */
    CK_ATTRIBUTE aa = ATTR(CKA_ALWAYS_AUTHENTICATE, CK_TRUE, CK_BBOOL);
    rv = C_CopyObject(ti->handle, priv, &aa, 1, &copy2);
    assert_int_equal(rv, CKR_ATTRIBUTE_READ_ONLY);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_set_private_read_only,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_class_read_only,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_key_type_read_only,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_vendor_attr_read_only,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_always_authenticate_read_only,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_public_key_usage_cannot_widen,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_label_and_id_ok,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_data_value_ok,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_key_attr_on_data_invalid,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_cert_attrs,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_one_way,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_copy_public_key_cannot_widen,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
