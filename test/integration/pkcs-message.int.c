/* SPDX-License-Identifier: BSD-2-Clause */

#include "test.h"

/*
 * Message-based signing and verification (S32 5.14, 5.16): one C_MessageSignInit, or
 * C_MessageVerifyInit, holds the key for any number of messages, each signed in one part with
 * C_SignMessage or in several with C_SignMessageBegin and C_SignMessageNext, until
 * C_MessageSignFinal. No mechanism takes a per-message parameter.
 */

#define ATTR(a, v, t) { a, &(t){v}, sizeof(t) }
#define ATTR_VAR(a, v, len) { a, v, len }

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
    /* a session P-256 key pair, which a test may destroy */
    CK_OBJECT_HANDLE pub;
    CK_OBJECT_HANDLE priv;
};

static CK_BYTE p256[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

static CK_BYTE msg1[] = "the first message";
static CK_BYTE msg2[] = "a second, longer message than the first";
static CK_BYTE msg3[] = "3";

static CK_MECHANISM ecdsa_sha256 = { CKM_ECDSA_SHA256, NULL, 0 };

static void gen_ec(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {

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
    };

    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_RV rv = C_GenerateKeyPair(session, &mech,
            pub_templ, ARRAY_LEN(pub_templ),
            priv_templ, ARRAY_LEN(priv_templ),
            pub, priv);
    assert_int_equal(rv, CKR_OK);
}

/* Finds the one key of the class and type with CKA_ALWAYS_AUTHENTICATE set. */
static CK_OBJECT_HANDLE find_always_auth(CK_SESSION_HANDLE session, CK_OBJECT_CLASS clazz,
        CK_KEY_TYPE type) {

    CK_BBOOL _true = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &clazz, sizeof(clazz) },
        { CKA_KEY_TYPE, &type, sizeof(type) },
        { CKA_ALWAYS_AUTHENTICATE, &_true, sizeof(_true) },
    };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
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

static int test_setup(void **state) {

    test_info *ti = calloc(1, sizeof(*ti));
    assert_non_null(ti);

    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_true(count > 0);
    ti->slot_id = slots[0];

    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &ti->handle);
    assert_int_equal(rv, CKR_OK);

    user_login(ti->handle);

    gen_ec(ti->handle, &ti->pub, &ti->priv);

    *state = ti;

    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_Logout(ti->handle);
    assert_int_equal(rv, CKR_OK);

    /* the session keys go with the session */
    rv = C_CloseAllSessions(ti->slot_id);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

/* C_Verify of a signature over data, as made by a message-based signature */
static void verify_expects(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE pub,
        CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR sig, CK_ULONG sig_len, CK_RV expected) {

    CK_RV rv = C_VerifyInit(session, mech, pub);
    assert_int_equal(rv, CKR_OK);

    rv = C_Verify(session, data, data_len, sig, sig_len);
    assert_int_equal(rv, expected);
}

/* One C_SignMessage of data, which C_Verify must accept. */
static void sign_message_verified(test_info *ti, CK_MECHANISM_PTR mech, CK_BYTE_PTR data,
        CK_ULONG data_len) {

    CK_BYTE sig[256];
    CK_ULONG sig_len = sizeof(sig);
    CK_RV rv = C_SignMessage(ti->handle, NULL, 0, data, data_len, sig, &sig_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(sig_len, 64);

    /* a second session, for the message-based process holds this one */
    CK_SESSION_HANDLE other;
    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL, NULL, &other);
    assert_int_equal(rv, CKR_OK);

    verify_expects(other, mech, ti->pub, data, data_len, sig, sig_len, CKR_OK);

    rv = C_CloseSession(other);
    assert_int_equal(rv, CKR_OK);
}

static void test_sign_message_three_messages(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_MessageSignInit(ti->handle, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OK);

    sign_message_verified(ti, &ecdsa_sha256, msg1, sizeof(msg1));
    sign_message_verified(ti, &ecdsa_sha256, msg2, sizeof(msg2));
    sign_message_verified(ti, &ecdsa_sha256, msg3, sizeof(msg3));

    rv = C_MessageSignFinal(ti->handle);
    assert_int_equal(rv, CKR_OK);

    /* the process is over */
    CK_BYTE sig[256];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_SignMessage(ti->handle, NULL, 0, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_MessageSignFinal(ti->handle);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
}

/*
 * Begin, two parts with a NULL pulSignatureLen, and a last one with it: the signature is over the
 * three parts, for a mechanism that hashes (CKM_ECDSA_SHA256) and one that collects (CKM_ECDSA).
 */
static void sign_multipart(test_info *ti, CK_MECHANISM_PTR mech, CK_BYTE_PTR data, CK_ULONG data_len) {

    assert_true(data_len >= 3);
    CK_ULONG third = data_len / 3;

    CK_RV rv = C_MessageSignInit(ti->handle, mech, ti->priv);
    assert_int_equal(rv, CKR_OK);

    /* twice, for the process goes on after a message */
    int i;
    for (i = 0; i < 2; i++) {
        rv = C_SignMessageBegin(ti->handle, NULL, 0);
        assert_int_equal(rv, CKR_OK);

        rv = C_SignMessageNext(ti->handle, NULL, 0, data, third, NULL, NULL);
        assert_int_equal(rv, CKR_OK);

        rv = C_SignMessageNext(ti->handle, NULL, 0, data + third, third, NULL, NULL);
        assert_int_equal(rv, CKR_OK);

        CK_BYTE sig[256];
        CK_ULONG sig_len = sizeof(sig);
        rv = C_SignMessageNext(ti->handle, NULL, 0, data + 2 * third, data_len - 2 * third,
                sig, &sig_len);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(sig_len, 64);

        /* the message is over */
        rv = C_SignMessageNext(ti->handle, NULL, 0, data, data_len, NULL, NULL);
        assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

        CK_SESSION_HANDLE other;
        rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL, NULL, &other);
        assert_int_equal(rv, CKR_OK);
        verify_expects(other, mech, ti->pub, data, data_len, sig, sig_len, CKR_OK);
        rv = C_CloseSession(other);
        assert_int_equal(rv, CKR_OK);
    }

    rv = C_MessageSignFinal(ti->handle);
    assert_int_equal(rv, CKR_OK);
}

static void test_sign_message_multipart(void **state) {

    test_info *ti = test_info_from_state(state);

    sign_multipart(ti, &ecdsa_sha256, msg2, sizeof(msg2));

    /* raw ECDSA signs what it's given, here a SHA-256 sized value */
    CK_BYTE hash[32];
    memset(hash, 0xa5, sizeof(hash));
    CK_MECHANISM ecdsa = { CKM_ECDSA, NULL, 0 };
    sign_multipart(ti, &ecdsa, hash, sizeof(hash));
}

static void test_verify_message_roundtrip(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    /* signatures of msg1 and msg2 */
    CK_BYTE sig1[256];
    CK_ULONG sig1_len = sizeof(sig1);
    CK_BYTE sig2[256];
    CK_ULONG sig2_len = sizeof(sig2);

    CK_RV rv = C_MessageSignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OK);
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), sig1, &sig1_len);
    assert_int_equal(rv, CKR_OK);
    rv = C_SignMessage(session, NULL, 0, msg2, sizeof(msg2), sig2, &sig2_len);
    assert_int_equal(rv, CKR_OK);
    rv = C_MessageSignFinal(session);
    assert_int_equal(rv, CKR_OK);

    rv = C_MessageVerifyInit(session, &ecdsa_sha256, ti->pub);
    assert_int_equal(rv, CKR_OK);

    rv = C_VerifyMessage(session, NULL, 0, msg1, sizeof(msg1), sig1, sig1_len);
    assert_int_equal(rv, CKR_OK);

    /* a bad signature ends that message, not the process */
    rv = C_VerifyMessage(session, NULL, 0, msg1, sizeof(msg1), sig2, sig2_len);
    assert_int_equal(rv, CKR_SIGNATURE_INVALID);

    rv = C_VerifyMessage(session, NULL, 0, msg2, sizeof(msg2), sig2, sig2_len);
    assert_int_equal(rv, CKR_OK);

    /* in parts: a NULL pSignature means more parts follow */
    rv = C_VerifyMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_OK);
    rv = C_VerifyMessageNext(session, NULL, 0, msg2, 5, NULL, 0);
    assert_int_equal(rv, CKR_OK);
    rv = C_VerifyMessageNext(session, NULL, 0, msg2 + 5, sizeof(msg2) - 5, sig2, sig2_len);
    assert_int_equal(rv, CKR_OK);

    /* a bad one in parts ends the message, and the next is verified */
    rv = C_VerifyMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_OK);
    rv = C_VerifyMessageNext(session, NULL, 0, msg2, sizeof(msg2), sig1, sig1_len);
    assert_int_equal(rv, CKR_SIGNATURE_INVALID);
    rv = C_VerifyMessageNext(session, NULL, 0, msg2, sizeof(msg2), NULL, 0);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_VerifyMessage(session, NULL, 0, msg1, sizeof(msg1), sig1, sig1_len);
    assert_int_equal(rv, CKR_OK);

    /* inside a begun message, the single-part call is refused */
    rv = C_VerifyMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_OK);
    rv = C_VerifyMessage(session, NULL, 0, msg1, sizeof(msg1), sig1, sig1_len);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);
    rv = C_VerifyMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);
    rv = C_VerifyMessageNext(session, NULL, 0, msg1, sizeof(msg1), sig1, sig1_len);
    assert_int_equal(rv, CKR_OK);

    rv = C_MessageVerifyFinal(session);
    assert_int_equal(rv, CKR_OK);

    rv = C_VerifyMessage(session, NULL, 0, msg1, sizeof(msg1), sig1, sig1_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
}

static void test_sign_message_param_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BYTE param[16] = { 0 };
    CK_BYTE sig[256];
    CK_ULONG sig_len = sizeof(sig);

    CK_RV rv = C_MessageSignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OK);

    rv = C_SignMessage(session, param, sizeof(param), msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    /* a length without a parameter is no better */
    rv = C_SignMessage(session, NULL, 1, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    rv = C_SignMessageBegin(session, param, sizeof(param));
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    rv = C_SignMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_OK);

    /* a refused part ends the message */
    rv = C_SignMessageNext(session, param, sizeof(param), msg1, sizeof(msg1), NULL, NULL);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    rv = C_SignMessageNext(session, NULL, 0, msg1, sizeof(msg1), NULL, NULL);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* and the process goes on */
    sign_message_verified(ti, &ecdsa_sha256, msg1, sizeof(msg1));

    rv = C_MessageSignFinal(session);
    assert_int_equal(rv, CKR_OK);

    rv = C_MessageVerifyInit(session, &ecdsa_sha256, ti->pub);
    assert_int_equal(rv, CKR_OK);

    rv = C_VerifyMessage(session, param, sizeof(param), msg1, sizeof(msg1), sig, sig_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    rv = C_VerifyMessageBegin(session, param, sizeof(param));
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    rv = C_MessageVerifyFinal(session);
    assert_int_equal(rv, CKR_OK);
}

/* S32 5.2: a length query, or too small a buffer, keeps the message for the real call */
static void test_sign_message_length_query(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_RV rv = C_MessageSignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG sig_len = 0;
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), NULL, &sig_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(sig_len, 64);

    CK_BYTE sig[64];
    sig_len = 10;
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(sig_len, 64);

    /* the data was fed once: the signature is msg1's */
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(sig_len, 64);

    CK_SESSION_HANDLE other;
    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL, NULL, &other);
    assert_int_equal(rv, CKR_OK);
    verify_expects(other, &ecdsa_sha256, ti->pub, msg1, sizeof(msg1), sig, sig_len, CKR_OK);

    /* the last part, queried, is given again: the message is over the parts once each */
    rv = C_SignMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_OK);
    rv = C_SignMessageNext(session, NULL, 0, msg2, 4, NULL, NULL);
    assert_int_equal(rv, CKR_OK);

    sig_len = 0;
    rv = C_SignMessageNext(session, NULL, 0, msg2 + 4, sizeof(msg2) - 4, NULL, &sig_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(sig_len, 64);

    sig_len = 1;
    rv = C_SignMessageNext(session, NULL, 0, msg2 + 4, sizeof(msg2) - 4, sig, &sig_len);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(sig_len, 64);

    rv = C_SignMessageNext(session, NULL, 0, msg2 + 4, sizeof(msg2) - 4, sig, &sig_len);
    assert_int_equal(rv, CKR_OK);
    verify_expects(other, &ecdsa_sha256, ti->pub, msg2, sizeof(msg2), sig, sig_len, CKR_OK);

    rv = C_CloseSession(other);
    assert_int_equal(rv, CKR_OK);

    rv = C_MessageSignFinal(session);
    assert_int_equal(rv, CKR_OK);
}

/* Message signing pairs with nothing: no other operation starts beside it */
static void test_sign_message_blocks_sign_init(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_RV rv = C_MessageSignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OK);

    rv = C_SignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);

    rv = C_MessageSignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);

    rv = C_MessageVerifyInit(session, &ecdsa_sha256, ti->pub);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);

    CK_MECHANISM sha256 = { CKM_SHA256, NULL, 0 };
    rv = C_DigestInit(session, &sha256);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);

    /* still signing */
    sign_message_verified(ti, &ecdsa_sha256, msg1, sizeof(msg1));

    /* a NULL mechanism ends the process, and lets the key go */
    rv = C_MessageSignInit(session, NULL, ti->priv);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE sig[64];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_SignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OK);
    rv = C_Sign(session, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_OK);

    /* and the other way round */
    rv = C_MessageVerifyInit(session, &ecdsa_sha256, ti->pub);
    assert_int_equal(rv, CKR_OK);
    rv = C_VerifyInit(session, &ecdsa_sha256, ti->pub);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);
    rv = C_MessageVerifyInit(session, NULL, ti->pub);
    assert_int_equal(rv, CKR_OK);
    rv = C_VerifyMessage(session, NULL, 0, msg1, sizeof(msg1), sig, sig_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
}

static void test_mechinfo_message_flags(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_FLAGS msg = CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY;
    CK_FLAGS want = msg | CKF_MULTI_MESSAGE;

    /* multi-part mechanisms: in one part or several */
    CK_MECHANISM_TYPE multi[] = { CKM_ECDSA_SHA256, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS,
            CKM_SHA256_HMAC };
    CK_MECHANISM_INFO info;
    CK_RV rv;
    size_t i;
    for (i = 0; i < ARRAY_LEN(multi); i++) {
        rv = C_GetMechanismInfo(ti->slot_id, multi[i], &info);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(info.flags & want, want);
    }

    /* the S32 tables' single-part only mechanisms: message-based, but not with C_*MessageBegin */
    CK_MECHANISM_TYPE single[] = { CKM_ECDSA, CKM_RSA_PKCS, CKM_RSA_X_509, CKM_RSA_PKCS_PSS };
    for (i = 0; i < ARRAY_LEN(single); i++) {
        rv = C_GetMechanismInfo(ti->slot_id, single[i], &info);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(info.flags & want, msg);
    }

    /* no message-based encryption */
    rv = C_GetMechanismInfo(ti->slot_id, CKM_AES_CBC, &info);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(info.flags & (want | CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT), 0);
}

static void test_session_cancel_message_sign(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_RV rv = C_MessageSignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OK);

    rv = C_SignMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_OK);

    /* the key is held */
    rv = C_DestroyObject(session, ti->priv);
    assert_int_equal(rv, CKR_FUNCTION_FAILED);

    /* another kind is left be */
    rv = C_SessionCancel(session, CKF_SIGN | CKF_MESSAGE_VERIFY);
    assert_int_equal(rv, CKR_OK);
    rv = C_SignMessageNext(session, NULL, 0, msg1, sizeof(msg1), NULL, NULL);
    assert_int_equal(rv, CKR_OK);

    rv = C_SessionCancel(session, CKF_MESSAGE_SIGN);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE sig[64];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_MessageVerifyInit(session, &ecdsa_sha256, ti->pub);
    assert_int_equal(rv, CKR_OK);
    rv = C_SessionCancel(session, CKF_MESSAGE_VERIFY);
    assert_int_equal(rv, CKR_OK);
    rv = C_VerifyMessage(session, NULL, 0, msg1, sizeof(msg1), sig, sig_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* both keys were let go */
    rv = C_DestroyObject(session, ti->priv);
    assert_int_equal(rv, CKR_OK);
    rv = C_DestroyObject(session, ti->pub);
    assert_int_equal(rv, CKR_OK);
}

/* The process holds its key until C_MessageSignFinal or the session closes */
static void test_message_releases_key(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_RV rv = C_MessageSignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OK);

    sign_message_verified(ti, &ecdsa_sha256, msg1, sizeof(msg1));

    /* between messages too */
    rv = C_DestroyObject(session, ti->priv);
    assert_int_equal(rv, CKR_FUNCTION_FAILED);

    /* a failed message doesn't let it go either */
    rv = C_SignMessage(session, NULL, 0, NULL, 5, NULL, NULL);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);
    rv = C_DestroyObject(session, ti->priv);
    assert_int_equal(rv, CKR_FUNCTION_FAILED);

    /* C_MessageSignFinal in the middle of a message ends both */
    rv = C_SignMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_OK);
    rv = C_MessageSignFinal(session);
    assert_int_equal(rv, CKR_OK);

    rv = C_DestroyObject(session, ti->priv);
    assert_int_equal(rv, CKR_OK);

    /* closing the session lets the verify key go */
    CK_SESSION_HANDLE other;
    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL, NULL, &other);
    assert_int_equal(rv, CKR_OK);
    rv = C_MessageVerifyInit(other, &ecdsa_sha256, ti->pub);
    assert_int_equal(rv, CKR_OK);
    rv = C_VerifyMessageBegin(other, NULL, 0);
    assert_int_equal(rv, CKR_OK);

    rv = C_DestroyObject(session, ti->pub);
    assert_int_equal(rv, CKR_FUNCTION_FAILED);

    rv = C_CloseSession(other);
    assert_int_equal(rv, CKR_OK);

    rv = C_DestroyObject(session, ti->pub);
    assert_int_equal(rv, CKR_OK);
}

/* C_MessageSignInit validates as C_SignInit does */
static void test_message_init_validates(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    /* an RSA mechanism, an EC key */
    CK_MECHANISM pss = { CKM_SHA256_RSA_PKCS_PSS, NULL, 0 };
    CK_RV expected = C_SignInit(session, &pss, ti->priv);
    assert_int_not_equal(expected, CKR_OK);
    CK_RV rv = C_MessageSignInit(session, &pss, ti->priv);
    assert_int_equal(rv, expected);

    expected = C_VerifyInit(session, &pss, ti->pub);
    assert_int_not_equal(expected, CKR_OK);
    rv = C_MessageVerifyInit(session, &pss, ti->pub);
    assert_int_equal(rv, expected);

    rv = C_MessageSignInit(session, &ecdsa_sha256, CK_INVALID_HANDLE);
    assert_int_equal(rv, CKR_KEY_HANDLE_INVALID);

    /* nothing was left started, nor any key held */
    rv = C_SignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OK);
    rv = C_SignInit(session, NULL, ti->priv);
    assert_int_equal(rv, CKR_OK);
    rv = C_DestroyObject(session, ti->priv);
    assert_int_equal(rv, CKR_OK);

    /* no message process to end */
    rv = C_MessageSignFinal(session);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    rv = C_MessageVerifyFinal(session);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    rv = C_SignMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
}

/* An init refused once the handle is found isn't left holding it: the object can be destroyed */
static void test_message_init_releases_non_key(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BYTE value[] = "not a key";
    CK_ATTRIBUTE templ[] = {
        ATTR(CKA_CLASS, CKO_DATA, CK_OBJECT_CLASS),
        ATTR(CKA_TOKEN, CK_FALSE, CK_BBOOL),
        ATTR_VAR(CKA_VALUE, value, sizeof(value)),
    };
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    CK_RV rv = C_CreateObject(session, templ, ARRAY_LEN(templ), &data);
    assert_int_equal(rv, CKR_OK);

    rv = C_MessageSignInit(session, &ecdsa_sha256, data);
    assert_int_equal(rv, CKR_KEY_HANDLE_INVALID);
    rv = C_SignInit(session, &ecdsa_sha256, data);
    assert_int_equal(rv, CKR_KEY_HANDLE_INVALID);

    rv = C_DestroyObject(session, data);
    assert_int_equal(rv, CKR_OK);
}

/*
 * C_Logout ends every operation of the token (S32 5.6.10): a message process doesn't sign with a key
 * the logout flushed from the TPM, and lets the key go.
 */
static void test_logout_ends_message_sign(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_RV rv = C_MessageSignInit(session, &ecdsa_sha256, ti->priv);
    assert_int_equal(rv, CKR_OK);
    sign_message_verified(ti, &ecdsa_sha256, msg1, sizeof(msg1));

    /* and an operation of another session of the token */
    CK_SESSION_HANDLE other;
    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL, NULL, &other);
    assert_int_equal(rv, CKR_OK);
    rv = C_MessageVerifyInit(other, &ecdsa_sha256, ti->pub);
    assert_int_equal(rv, CKR_OK);
    rv = C_VerifyMessageBegin(other, NULL, 0);
    assert_int_equal(rv, CKR_OK);

    rv = C_Logout(session);
    assert_int_equal(rv, CKR_OK);
    user_login(session);

    CK_BYTE sig[64];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    rv = C_MessageSignFinal(session);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    rv = C_VerifyMessageNext(other, NULL, 0, msg1, sizeof(msg1), NULL, 0);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_DestroyObject(session, ti->priv);
    assert_int_equal(rv, CKR_OK);
    rv = C_DestroyObject(session, ti->pub);
    assert_int_equal(rv, CKR_OK);

    rv = C_CloseSession(other);
    assert_int_equal(rv, CKR_OK);
}

/*
 * A CKA_ALWAYS_AUTHENTICATE key wants its context-specific login for each message, and waiting for
 * it keeps the message.
 */
static void test_sign_message_always_authenticate(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_HANDLE rsa = find_always_auth(session, CKO_PRIVATE_KEY, CKK_RSA);
    CK_MECHANISM mech = { CKM_SHA256_RSA_PKCS, NULL, 0 };

    CK_RV rv = C_MessageSignInit(session, &mech, rsa);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE sig[512];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    context_login(session);

    /* a length query isn't a message */
    CK_ULONG query_len = 0;
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), NULL, &query_len);
    assert_int_equal(rv, CKR_OK);

    sig_len = sizeof(sig);
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(sig_len, query_len);

    /* the next message wants a login of its own */
    sig_len = sizeof(sig);
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    rv = C_SignMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    context_login(session);

    rv = C_SignMessageBegin(session, NULL, 0);
    assert_int_equal(rv, CKR_OK);
    rv = C_SignMessageNext(session, NULL, 0, msg1, 3, NULL, NULL);
    assert_int_equal(rv, CKR_OK);
    sig_len = sizeof(sig);
    rv = C_SignMessageNext(session, NULL, 0, msg1 + 3, sizeof(msg1) - 3, sig, &sig_len);
    assert_int_equal(rv, CKR_OK);

    sig_len = sizeof(sig);
    rv = C_SignMessage(session, NULL, 0, msg1, sizeof(msg1), sig, &sig_len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    rv = C_MessageSignFinal(session);
    assert_int_equal(rv, CKR_OK);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sign_message_three_messages,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_message_multipart,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_verify_message_roundtrip,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_message_param_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_message_length_query,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_message_blocks_sign_init,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_mechinfo_message_flags,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_session_cancel_message_sign,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_message_releases_key,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_message_init_validates,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_message_always_authenticate,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_message_init_releases_non_key,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_logout_ends_message_sign,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
