/* SPDX-License-Identifier: BSD-2-Clause */

#include "test.h"

/*
 * A session holds up to two operations, when they are one of the four pairs PKCS#11 allows
 * (UG32 4.1): digest and encrypt, decrypt and digest, sign and encrypt, decrypt and verify.
 */

typedef enum dual_op dual_op;
enum dual_op {
    op_digest,
    op_encrypt,
    op_decrypt,
    op_sign,
    op_verify,
};

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
    CK_OBJECT_HANDLE aes;
    CK_OBJECT_HANDLE rsa_priv;
    CK_OBJECT_HANDLE rsa_pub;
    /* the AES-CBC ciphertext and RSA signature of plaintext, made in test_setup */
    CK_BYTE ciphertext[32];
    CK_BYTE signature[512];
    CK_ULONG signature_len;
};

static CK_BYTE plaintext[] = {
    'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
};

static CK_BYTE iv[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
};

static CK_MECHANISM aes_mech = { CKM_AES_CBC, iv, sizeof(iv) };
static CK_MECHANISM rsa_mech = { CKM_SHA256_RSA_PKCS, NULL, 0 };
static CK_MECHANISM digest_mech = { CKM_SHA256, NULL, 0 };

static CK_OBJECT_HANDLE generate_aes(CK_SESSION_HANDLE session) {

    CK_OBJECT_CLASS clazz = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_AES;
    CK_ULONG value_len = 16;
    CK_BBOOL _true = CK_TRUE;
    CK_BBOOL _false = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &clazz, sizeof(clazz) },
        { CKA_KEY_TYPE, &type, sizeof(type) },
        { CKA_VALUE_LEN, &value_len, sizeof(value_len) },
        { CKA_TOKEN, &_false, sizeof(_false) },
        { CKA_ENCRYPT, &_true, sizeof(_true) },
        { CKA_DECRYPT, &_true, sizeof(_true) },
    };

    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_RV rv = C_GenerateKey(session, &mech, tmpl, ARRAY_LEN(tmpl), &key);
    assert_int_equal(rv, CKR_OK);

    return key;
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

    get_keypair(ti->handle, CKK_RSA, &ti->rsa_pub, &ti->rsa_priv);
    ti->aes = generate_aes(ti->handle);

    /* what the operations of the tests check their results against */
    rv = C_EncryptInit(ti->handle, &aes_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);
    CK_ULONG len = sizeof(ti->ciphertext);
    rv = C_Encrypt(ti->handle, plaintext, sizeof(plaintext), ti->ciphertext, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, sizeof(ti->ciphertext));

    rv = C_SignInit(ti->handle, &rsa_mech, ti->rsa_priv);
    assert_int_equal(rv, CKR_OK);
    ti->signature_len = sizeof(ti->signature);
    rv = C_Sign(ti->handle, plaintext, sizeof(plaintext), ti->signature, &ti->signature_len);
    assert_int_equal(rv, CKR_OK);

    *state = ti;

    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_Logout(ti->handle);
    assert_int_equal(rv, CKR_OK);

    /* the session AES key goes with the session */
    rv = C_CloseAllSessions(ti->slot_id);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

static const char *op_name(dual_op op) {

    static const char *names[] = { "digest", "encrypt", "decrypt", "sign", "verify" };
    return names[op];
}

static CK_RV op_init(test_info *ti, CK_SESSION_HANDLE session, dual_op op) {

    switch (op) {
    case op_digest:
        return C_DigestInit(session, &digest_mech);
    case op_encrypt:
        return C_EncryptInit(session, &aes_mech, ti->aes);
    case op_decrypt:
        return C_DecryptInit(session, &aes_mech, ti->aes);
    case op_sign:
        return C_SignInit(session, &rsa_mech, ti->rsa_priv);
    case op_verify:
        return C_VerifyInit(session, &rsa_mech, ti->rsa_pub);
    }

    fail_msg("unknown operation %d", op);
    return CKR_GENERAL_ERROR;
}

/* Runs the operation op_init started, single-part, and checks its result. */
static void op_run(test_info *ti, CK_SESSION_HANDLE session, dual_op op) {

    CK_BYTE out[512];
    CK_ULONG out_len = sizeof(out);
    CK_RV rv = CKR_GENERAL_ERROR;

    switch (op) {
    case op_digest:
        rv = C_Digest(session, plaintext, sizeof(plaintext), out, &out_len);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(out_len, 32);
        break;
    case op_encrypt:
        rv = C_Encrypt(session, plaintext, sizeof(plaintext), out, &out_len);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(out_len, sizeof(ti->ciphertext));
        assert_memory_equal(out, ti->ciphertext, out_len);
        break;
    case op_decrypt:
        rv = C_Decrypt(session, ti->ciphertext, sizeof(ti->ciphertext), out, &out_len);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(out_len, sizeof(plaintext));
        assert_memory_equal(out, plaintext, out_len);
        break;
    case op_sign:
        rv = C_Sign(session, plaintext, sizeof(plaintext), out, &out_len);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(out_len, ti->signature_len);
        break;
    case op_verify:
        rv = C_Verify(session, plaintext, sizeof(plaintext), ti->signature, ti->signature_len);
        assert_int_equal(rv, CKR_OK);
        break;
    }
}

static void test_dual_pairs_can_start(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    static const dual_op pairs[][2] = {
        { op_digest, op_encrypt },
        { op_decrypt, op_digest },
        { op_sign, op_encrypt },
        { op_decrypt, op_verify },
    };

    size_t i;
    for (i = 0; i < ARRAY_LEN(pairs); i++) {
        unsigned order;
        for (order = 0; order < 2; order++) {
            dual_op first = pairs[i][order];
            dual_op second = pairs[i][1 - order];

            CK_RV rv = op_init(ti, session, first);
            assert_int_equal(rv, CKR_OK);

            rv = op_init(ti, session, second);
            if (rv != CKR_OK) {
                fail_msg("%s after %s: 0x%lx", op_name(second), op_name(first), rv);
            }

            /* each finds its own operation, and ending one leaves the other */
            op_run(ti, session, first);
            op_run(ti, session, second);
        }
    }
}

static void test_dual_non_pair_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    static const dual_op non_pairs[][2] = {
        { op_sign, op_verify },
        { op_encrypt, op_decrypt },
        { op_digest, op_sign },
    };

    size_t i;
    for (i = 0; i < ARRAY_LEN(non_pairs); i++) {
        dual_op first = non_pairs[i][0];
        dual_op second = non_pairs[i][1];

        CK_RV rv = op_init(ti, session, first);
        assert_int_equal(rv, CKR_OK);

        rv = op_init(ti, session, second);
        if (rv != CKR_OPERATION_ACTIVE) {
            fail_msg("%s after %s: 0x%lx", op_name(second), op_name(first), rv);
        }

        op_run(ti, session, first);
    }

    /* a find needs the session to itself */
    CK_OBJECT_CLASS clazz = CKO_SECRET_KEY;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &clazz, sizeof(clazz) },
    };
    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    rv = op_init(ti, session, op_encrypt);
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);

    CK_OBJECT_HANDLE h[4];
    CK_ULONG count = 0;
    rv = C_FindObjects(session, h, ARRAY_LEN(h), &count);
    assert_int_equal(rv, CKR_OK);
    assert_true(count > 0);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* and nothing may start a find beside an operation */
    rv = op_init(ti, session, op_encrypt);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OPERATION_ACTIVE);

    op_run(ti, session, op_encrypt);
}

static void test_dual_token_flag(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_TOKEN_INFO info;
    CK_RV rv = C_GetTokenInfo(ti->slot_id, &info);
    assert_int_equal(rv, CKR_OK);
    assert_true(info.flags & CKF_DUAL_CRYPTO_OPERATIONS);
}

static void test_dual_cancel_one(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_RV rv = op_init(ti, session, op_digest);
    assert_int_equal(rv, CKR_OK);

    rv = op_init(ti, session, op_encrypt);
    assert_int_equal(rv, CKR_OK);

    rv = C_DigestUpdate(session, plaintext, sizeof(plaintext));
    assert_int_equal(rv, CKR_OK);

    rv = C_SessionCancel(session, CKF_ENCRYPT);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE out[64];
    CK_ULONG out_len = sizeof(out);
    rv = C_DigestFinal(session, out, &out_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(out_len, 32);

    out_len = sizeof(out);
    rv = C_EncryptUpdate(session, plaintext, sizeof(plaintext), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* and the encrypt key was let go: it starts again */
    rv = op_init(ti, session, op_encrypt);
    assert_int_equal(rv, CKR_OK);
    op_run(ti, session, op_encrypt);
}

static void test_dual_close_session_releases_both(void **state) {

    test_info *ti = test_info_from_state(state);

    /* another session, as closing the first would destroy its session AES key */
    CK_SESSION_HANDLE session;
    CK_RV rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    assert_int_equal(rv, CKR_OK);

    rv = op_init(ti, session, op_sign);
    assert_int_equal(rv, CKR_OK);

    rv = op_init(ti, session, op_encrypt);
    assert_int_equal(rv, CKR_OK);

    rv = C_CloseSession(session);
    assert_int_equal(rv, CKR_OK);

    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    assert_int_equal(rv, CKR_OK);

    rv = op_init(ti, session, op_sign);
    assert_int_equal(rv, CKR_OK);
    op_run(ti, session, op_sign);

    rv = op_init(ti, session, op_encrypt);
    assert_int_equal(rv, CKR_OK);
    op_run(ti, session, op_encrypt);

    rv = C_CloseSession(session);
    assert_int_equal(rv, CKR_OK);
}

/* C_Sign or C_Encrypt of plaintext, which the session's operation was started for */
static void sign_expects(CK_SESSION_HANDLE session, CK_RV expected) {

    CK_BYTE sig[512];
    CK_ULONG sig_len = sizeof(sig);
    CK_RV rv = C_Sign(session, plaintext, sizeof(plaintext), sig, &sig_len);
    assert_int_equal(rv, expected);
}

static void encrypt_expects(CK_SESSION_HANDLE session, CK_RV expected) {

    CK_BYTE out[64];
    CK_ULONG out_len = sizeof(out);
    CK_RV rv = C_Encrypt(session, plaintext, sizeof(plaintext), out, &out_len);
    assert_int_equal(rv, expected);
    if (expected == CKR_OK) {
        assert_int_equal(out_len, sizeof(plaintext));
    }
}

/*
 * As test_sign_verify_context_specific_good, with an encryption beside the signature: a key with
 * CKA_ALWAYS_AUTHENTICATE keeps its operation while it waits for C_Login(CKU_CONTEXT_SPECIFIC). A
 * login authenticates one key (PKCS#11 3.2 4.9), that of the operation started first which waits
 * for one; a second always-authenticate key needs a second login.
 */
static void test_dual_context_specific(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_HANDLE rsa = find_always_auth(session, CKO_PRIVATE_KEY, CKK_RSA);
    CK_OBJECT_HANDLE aes = find_always_auth(session, CKO_SECRET_KEY, CKK_AES);

    /* a context-specific login needs an operation with a key */
    CK_RV rv = op_init(ti, session, op_digest);
    assert_int_equal(rv, CKR_OK);
    context_login_expects(session, CKR_OPERATION_NOT_INITIALIZED);
    op_run(ti, session, op_digest);

    /* the always-authenticate signing key, beside the plain session AES key */
    rv = C_SignInit(session, &rsa_mech, rsa);
    assert_int_equal(rv, CKR_OK);

    rv = op_init(ti, session, op_encrypt);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE sig[512];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_Sign(session, plaintext, sizeof(plaintext), sig, &sig_len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    /* the encryption goes on meanwhile */
    CK_BYTE out[64];
    CK_ULONG out_len = sizeof(out);
    rv = C_EncryptUpdate(session, plaintext, sizeof(plaintext), out, &out_len);
    assert_int_equal(rv, CKR_OK);

    context_login(session);

    sig_len = sizeof(sig);
    rv = C_Sign(session, plaintext, sizeof(plaintext), sig, &sig_len);
    assert_int_equal(rv, CKR_OK);

    /* with no always-authenticate key waiting, a context-specific login still succeeds */
    context_login(session);

    CK_ULONG last_len = sizeof(out) - out_len;
    rv = C_EncryptFinal(session, &out[out_len], &last_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(out_len + last_len, sizeof(ti->ciphertext));
    assert_memory_equal(out, ti->ciphertext, sizeof(ti->ciphertext));

    /* both keys always-authenticate: each login authenticates one, the older operation's first */
    rv = C_SignInit(session, &rsa_mech, rsa);
    assert_int_equal(rv, CKR_OK);

    rv = C_EncryptInit(session, &aes_mech, aes);
    assert_int_equal(rv, CKR_OK);

    sign_expects(session, CKR_USER_NOT_LOGGED_IN);
    encrypt_expects(session, CKR_USER_NOT_LOGGED_IN);

    context_login(session);

    sign_expects(session, CKR_OK);
    encrypt_expects(session, CKR_USER_NOT_LOGGED_IN);

    context_login(session);

    encrypt_expects(session, CKR_OK);

    /* the other way round */
    rv = C_EncryptInit(session, &aes_mech, aes);
    assert_int_equal(rv, CKR_OK);

    rv = C_SignInit(session, &rsa_mech, rsa);
    assert_int_equal(rv, CKR_OK);

    context_login(session);

    sign_expects(session, CKR_USER_NOT_LOGGED_IN);
    encrypt_expects(session, CKR_OK);

    context_login(session);

    sign_expects(session, CKR_OK);

    /* the order is that of the operations still active: once the digest ends, encrypt is the older */
    rv = op_init(ti, session, op_digest);
    assert_int_equal(rv, CKR_OK);

    rv = C_EncryptInit(session, &aes_mech, aes);
    assert_int_equal(rv, CKR_OK);

    op_run(ti, session, op_digest);

    rv = C_SignInit(session, &rsa_mech, rsa);
    assert_int_equal(rv, CKR_OK);

    context_login(session);

    sign_expects(session, CKR_USER_NOT_LOGGED_IN);
    encrypt_expects(session, CKR_OK);

    context_login(session);

    sign_expects(session, CKR_OK);

    /* and the login ended with the operations */
    rv = C_SignInit(session, &rsa_mech, rsa);
    assert_int_equal(rv, CKR_OK);

    sign_expects(session, CKR_USER_NOT_LOGGED_IN);

    rv = C_SessionCancel(session, CKF_SIGN);
    assert_int_equal(rv, CKR_OK);
}

/*
 * The dual functions (S32 5.17): each is the composition of the two halves' updates. The tests check
 * them against the separate single-part operations over the same data.
 */

/* 40 bytes: CBC-PAD makes it 3 blocks, the last of which only C_DecryptFinal returns */
static CK_BYTE pad_plaintext[] = {
    'a', ' ', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't', ' ', 'o', 'f', ' ', 'f',
    'o', 'r', 't', 'y', ' ', 'b', 'y', 't', 'e', 's', ',', ' ', 'n', 'o', 't', ' ',
    'a', ' ', 'b', 'l', 'o', 'c', 'k', '!',
};

static CK_MECHANISM aes_pad_mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };

/* the uneven parts the multi-part tests feed pad_plaintext in */
static const CK_ULONG pad_parts[] = { 5, 20, 15 };

static void separate_digest(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len,
        CK_BYTE digest[32]) {

    CK_RV rv = C_DigestInit(session, &digest_mech);
    assert_int_equal(rv, CKR_OK);
    CK_ULONG len = 32;
    rv = C_Digest(session, data, data_len, digest, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 32);
}

/* C_Encrypt of pad_plaintext with AES-CBC-PAD: 48 bytes */
static void separate_pad_encrypt(test_info *ti, CK_SESSION_HANDLE session, CK_BYTE ct[48]) {

    CK_RV rv = C_EncryptInit(session, &aes_pad_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);
    CK_ULONG len = 48;
    rv = C_Encrypt(session, pad_plaintext, sizeof(pad_plaintext), ct, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 48);
}

static void separate_sign(test_info *ti, CK_SESSION_HANDLE session, CK_BYTE_PTR data,
        CK_ULONG data_len, CK_BYTE_PTR sig, CK_ULONG_PTR sig_len) {

    CK_RV rv = C_SignInit(session, &rsa_mech, ti->rsa_priv);
    assert_int_equal(rv, CKR_OK);
    rv = C_Sign(session, data, data_len, sig, sig_len);
    assert_int_equal(rv, CKR_OK);
}

typedef CK_RV (*encrypt_side_fn)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

/* feeds pad_plaintext in pad_parts to an encrypt-side dual function, then ends the encryption */
static void encrypt_side_parts(CK_SESSION_HANDLE session, encrypt_side_fn fn, CK_BYTE ct[48]) {

    CK_ULONG off = 0;
    CK_ULONG in = 0;
    size_t i;
    for (i = 0; i < ARRAY_LEN(pad_parts); i++) {
        CK_ULONG len = 48 - off;
        CK_RV rv = fn(session, &pad_plaintext[in], pad_parts[i], &ct[off], &len);
        assert_int_equal(rv, CKR_OK);
        off += len;
        in += pad_parts[i];
    }
    assert_int_equal(in, sizeof(pad_plaintext));

    CK_ULONG len = 48 - off;
    CK_RV rv = C_EncryptFinal(session, &ct[off], &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(off + len, 48);
}

static void test_digest_encrypt_matches_separate(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BYTE want_ct[48], want_md[32];
    separate_pad_encrypt(ti, session, want_ct);
    separate_digest(session, pad_plaintext, sizeof(pad_plaintext), want_md);

    CK_RV rv = C_DigestInit(session, &digest_mech);
    assert_int_equal(rv, CKR_OK);
    rv = C_EncryptInit(session, &aes_pad_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE ct[48];
    encrypt_side_parts(session, C_DigestEncryptUpdate, ct);
    assert_memory_equal(ct, want_ct, sizeof(ct));

    CK_BYTE md[32];
    CK_ULONG md_len = sizeof(md);
    rv = C_DigestFinal(session, md, &md_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(md_len, sizeof(md));
    assert_memory_equal(md, want_md, sizeof(md));
}

static void test_sign_encrypt_matches_separate(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BYTE want_ct[48];
    separate_pad_encrypt(ti, session, want_ct);
    CK_BYTE want_sig[512];
    CK_ULONG want_sig_len = sizeof(want_sig);
    separate_sign(ti, session, pad_plaintext, sizeof(pad_plaintext), want_sig, &want_sig_len);

    CK_RV rv = C_SignInit(session, &rsa_mech, ti->rsa_priv);
    assert_int_equal(rv, CKR_OK);
    rv = C_EncryptInit(session, &aes_pad_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE ct[48];
    encrypt_side_parts(session, C_SignEncryptUpdate, ct);
    assert_memory_equal(ct, want_ct, sizeof(ct));

    CK_BYTE sig[512];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_SignFinal(session, sig, &sig_len);
    assert_int_equal(rv, CKR_OK);

    /* RSA PKCS#1 v1.5 is deterministic */
    assert_int_equal(sig_len, want_sig_len);
    assert_memory_equal(sig, want_sig, sig_len);

    rv = C_VerifyInit(session, &rsa_mech, ti->rsa_pub);
    assert_int_equal(rv, CKR_OK);
    rv = C_Verify(session, pad_plaintext, sizeof(pad_plaintext), sig, sig_len);
    assert_int_equal(rv, CKR_OK);
}

static void test_decrypt_digest_cbc_pad_last_block(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BYTE ct[48], want_md[32];
    separate_pad_encrypt(ti, session, ct);
    separate_digest(session, pad_plaintext, sizeof(pad_plaintext), want_md);

    CK_RV rv = C_DecryptInit(session, &aes_pad_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestInit(session, &digest_mech);
    assert_int_equal(rv, CKR_OK);

    /* a block at a time: CBC-PAD holds the last block it has back, as it may be the padding */
    static const CK_ULONG returned[] = { 0, 16, 16 };
    CK_BYTE pt[48];
    CK_ULONG off = 0;
    size_t i;
    for (i = 0; i < 3; i++) {
        /* a length query, which returns nothing, before each */
        CK_ULONG len = 0;
        rv = C_DecryptDigestUpdate(session, &ct[i * 16], 16, NULL, &len);
        assert_int_equal(rv, CKR_OK);
        assert_true(len >= returned[i]);

        len = sizeof(pt) - off;
        rv = C_DecryptDigestUpdate(session, &ct[i * 16], 16, &pt[off], &len);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(len, returned[i]);
        off += len;
    }

    /*
     * the last 8 bytes of plaintext come only now, and aren't passed to the digest (S32 5.17.2):
     * the application does that
     */
    CK_ULONG len = 0;
    rv = C_DecryptFinal(session, NULL, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 8);

    len = 4;
    rv = C_DecryptFinal(session, &pt[off], &len);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(len, 8);

    len = sizeof(pt) - off;
    rv = C_DecryptFinal(session, &pt[off], &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 8);

    rv = C_DigestUpdate(session, &pt[off], len);
    assert_int_equal(rv, CKR_OK);
    off += len;

    assert_int_equal(off, sizeof(pad_plaintext));
    assert_memory_equal(pt, pad_plaintext, sizeof(pad_plaintext));

    CK_BYTE md[32];
    CK_ULONG md_len = sizeof(md);
    rv = C_DigestFinal(session, md, &md_len);
    assert_int_equal(rv, CKR_OK);
    assert_memory_equal(md, want_md, sizeof(md));
}

/* decrypt-verifies ct in parts, and returns C_VerifyFinal's verdict on sig */
static CK_RV decrypt_verify_parts(test_info *ti, CK_SESSION_HANDLE session, CK_BYTE ct[48],
        CK_BYTE_PTR sig, CK_ULONG sig_len) {

    CK_RV rv = C_VerifyInit(session, &rsa_mech, ti->rsa_pub);
    assert_int_equal(rv, CKR_OK);
    rv = C_DecryptInit(session, &aes_pad_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);

    static const CK_ULONG parts[] = { 7, 25, 16 };
    CK_BYTE pt[48];
    CK_ULONG off = 0, in = 0;
    size_t i;
    for (i = 0; i < ARRAY_LEN(parts); i++) {
        CK_ULONG len = sizeof(pt) - off;
        rv = C_DecryptVerifyUpdate(session, &ct[in], parts[i], &pt[off], &len);
        assert_int_equal(rv, CKR_OK);
        off += len;
        in += parts[i];
    }

    /* C_DecryptFinal's plaintext isn't passed on (S32 5.17.2): the application does that */
    CK_ULONG len = sizeof(pt) - off;
    rv = C_DecryptFinal(session, &pt[off], &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 8);

    rv = C_VerifyUpdate(session, &pt[off], len);
    assert_int_equal(rv, CKR_OK);
    off += len;

    assert_int_equal(off, sizeof(pad_plaintext));
    assert_memory_equal(pt, pad_plaintext, sizeof(pad_plaintext));

    return C_VerifyFinal(session, sig, sig_len);
}

static void test_decrypt_verify_matches_separate(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BYTE ct[48];
    separate_pad_encrypt(ti, session, ct);
    CK_BYTE sig[512];
    CK_ULONG sig_len = sizeof(sig);
    separate_sign(ti, session, pad_plaintext, sizeof(pad_plaintext), sig, &sig_len);

    CK_RV rv = decrypt_verify_parts(ti, session, ct, sig, sig_len);
    assert_int_equal(rv, CKR_OK);

    /* and the verification is of what was decrypted: another signature fails */
    rv = decrypt_verify_parts(ti, session, ct, ti->signature, ti->signature_len);
    assert_int_equal(rv, CKR_SIGNATURE_INVALID);
}

static void test_dual_requires_both(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BYTE out[64];
    CK_ULONG out_len;

    /* only an encryption: neither encrypt-side function touches it */
    CK_RV rv = op_init(ti, session, op_encrypt);
    assert_int_equal(rv, CKR_OK);
    out_len = sizeof(out);
    rv = C_DigestEncryptUpdate(session, plaintext, sizeof(plaintext), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    out_len = sizeof(out);
    rv = C_SignEncryptUpdate(session, plaintext, sizeof(plaintext), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    /* single-part still, so not updated */
    op_run(ti, session, op_encrypt);

    /* only a decryption */
    rv = op_init(ti, session, op_decrypt);
    assert_int_equal(rv, CKR_OK);
    out_len = sizeof(out);
    rv = C_DecryptDigestUpdate(session, ti->ciphertext, sizeof(ti->ciphertext), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    out_len = sizeof(out);
    rv = C_DecryptVerifyUpdate(session, ti->ciphertext, sizeof(ti->ciphertext), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    op_run(ti, session, op_decrypt);

    /* only the other half */
    rv = op_init(ti, session, op_digest);
    assert_int_equal(rv, CKR_OK);
    out_len = sizeof(out);
    rv = C_DigestEncryptUpdate(session, plaintext, sizeof(plaintext), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    out_len = sizeof(out);
    rv = C_DecryptDigestUpdate(session, ti->ciphertext, sizeof(ti->ciphertext), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    op_run(ti, session, op_digest);

    rv = op_init(ti, session, op_sign);
    assert_int_equal(rv, CKR_OK);
    out_len = sizeof(out);
    rv = C_SignEncryptUpdate(session, plaintext, sizeof(plaintext), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    op_run(ti, session, op_sign);

    rv = op_init(ti, session, op_verify);
    assert_int_equal(rv, CKR_OK);
    out_len = sizeof(out);
    rv = C_DecryptVerifyUpdate(session, ti->ciphertext, sizeof(ti->ciphertext), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    op_run(ti, session, op_verify);

    /* with no operation at all */
    out_len = sizeof(out);
    rv = C_DigestEncryptUpdate(session, plaintext, sizeof(plaintext), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
}

static void test_dual_length_query_feeds_nothing(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BYTE want_ct[48], want_md[32];
    separate_pad_encrypt(ti, session, want_ct);
    separate_digest(session, pad_plaintext, sizeof(pad_plaintext), want_md);

    CK_RV rv = C_DigestInit(session, &digest_mech);
    assert_int_equal(rv, CKR_OK);
    rv = C_EncryptInit(session, &aes_pad_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);

    /* 20 bytes: one block out, 4 held for the next */
    CK_ULONG len = 0;
    rv = C_DigestEncryptUpdate(session, pad_plaintext, 20, NULL, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 16);

    /* a buffer too small neither */
    CK_BYTE ct[48];
    len = 8;
    rv = C_DigestEncryptUpdate(session, pad_plaintext, 20, ct, &len);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(len, 16);

    len = sizeof(ct);
    rv = C_DigestEncryptUpdate(session, pad_plaintext, 20, ct, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 16);
    CK_ULONG off = len;

    len = sizeof(ct) - off;
    rv = C_DigestEncryptUpdate(session, &pad_plaintext[20], sizeof(pad_plaintext) - 20, &ct[off], &len);
    assert_int_equal(rv, CKR_OK);
    off += len;

    len = sizeof(ct) - off;
    rv = C_EncryptFinal(session, &ct[off], &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(off + len, sizeof(ct));
    assert_memory_equal(ct, want_ct, sizeof(ct));

    CK_BYTE md[32];
    CK_ULONG md_len = sizeof(md);
    rv = C_DigestFinal(session, md, &md_len);
    assert_int_equal(rv, CKR_OK);
    assert_memory_equal(md, want_md, sizeof(md));

    /* the same for a signature */
    CK_BYTE want_sig[512];
    CK_ULONG want_sig_len = sizeof(want_sig);
    separate_sign(ti, session, pad_plaintext, sizeof(pad_plaintext), want_sig, &want_sig_len);

    rv = C_SignInit(session, &rsa_mech, ti->rsa_priv);
    assert_int_equal(rv, CKR_OK);
    rv = C_EncryptInit(session, &aes_pad_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);

    len = 0;
    rv = C_SignEncryptUpdate(session, pad_plaintext, sizeof(pad_plaintext), NULL, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 32);

    len = sizeof(ct);
    rv = C_SignEncryptUpdate(session, pad_plaintext, sizeof(pad_plaintext), ct, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 32);
    off = len;

    len = sizeof(ct) - off;
    rv = C_EncryptFinal(session, &ct[off], &len);
    assert_int_equal(rv, CKR_OK);
    assert_memory_equal(ct, want_ct, sizeof(ct));

    CK_BYTE sig[512];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_SignFinal(session, sig, &sig_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(sig_len, want_sig_len);
    assert_memory_equal(sig, want_sig, sig_len);
}

/* An error in either half ends both operations. */
static void test_dual_failure_cancels_both(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_RSA_PKCS_OAEP_PARAMS params = {
        .hashAlg = CKM_SHA256, .mgf = CKG_MGF1_SHA256, .source = CKZ_DATA_SPECIFIED,
    };
    CK_MECHANISM oaep = { CKM_RSA_PKCS_OAEP, &params, sizeof(params) };

    CK_RV rv = C_DecryptInit(session, &oaep, ti->rsa_priv);
    assert_int_equal(rv, CKR_OK);
    rv = op_init(ti, session, op_verify);
    assert_int_equal(rv, CKR_OK);

    /* not an OAEP ciphertext: the TPM refuses it */
    CK_BYTE bad[256] = { 0 };
    bad[255] = 1;
    CK_BYTE out[256];
    CK_ULONG out_len = sizeof(out);
    rv = C_DecryptVerifyUpdate(session, bad, sizeof(bad), out, &out_len);
    assert_int_not_equal(rv, CKR_OK);
    assert_int_not_equal(rv, CKR_BUFFER_TOO_SMALL);

    rv = C_VerifyFinal(session, ti->signature, ti->signature_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
    out_len = sizeof(out);
    rv = C_DecryptFinal(session, out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* and both keys were let go */
    rv = op_init(ti, session, op_verify);
    assert_int_equal(rv, CKR_OK);
    op_run(ti, session, op_verify);
}

/*
 * A key waiting for its context-specific login (CKR_USER_NOT_LOGGED_IN) keeps both operations, and
 * neither half takes the data: the call is made again after the login.
 */
static void test_dual_context_specific_keeps_both(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_OBJECT_HANDLE rsa = find_always_auth(session, CKO_PRIVATE_KEY, CKK_RSA);
    CK_OBJECT_HANDLE aes = find_always_auth(session, CKO_SECRET_KEY, CKK_AES);

    /* digest beside an always-authenticate encryption key */
    CK_BYTE want_md[32];
    separate_digest(session, plaintext, sizeof(plaintext), want_md);

    CK_RV rv = C_DigestInit(session, &digest_mech);
    assert_int_equal(rv, CKR_OK);
    rv = C_EncryptInit(session, &aes_mech, aes);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE ct[64];
    CK_ULONG len = sizeof(ct);
    rv = C_DigestEncryptUpdate(session, plaintext, sizeof(plaintext), ct, &len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    context_login(session);

    len = sizeof(ct);
    rv = C_DigestEncryptUpdate(session, plaintext, sizeof(plaintext), ct, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, sizeof(plaintext));

    CK_ULONG last = sizeof(ct) - len;
    rv = C_EncryptFinal(session, &ct[len], &last);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(last, 0);
    CK_BYTE aes_ct[sizeof(plaintext)];
    memcpy(aes_ct, ct, sizeof(aes_ct));

    CK_BYTE md[32];
    CK_ULONG md_len = sizeof(md);
    rv = C_DigestFinal(session, md, &md_len);
    assert_int_equal(rv, CKR_OK);
    assert_memory_equal(md, want_md, sizeof(md));

    /* an always-authenticate signing key beside a plain encryption: the encryption waits too */
    rv = C_SignInit(session, &rsa_mech, rsa);
    assert_int_equal(rv, CKR_OK);
    rv = op_init(ti, session, op_encrypt);
    assert_int_equal(rv, CKR_OK);

    len = sizeof(ct);
    rv = C_SignEncryptUpdate(session, plaintext, sizeof(plaintext), ct, &len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    context_login(session);

    len = sizeof(ct);
    rv = C_SignEncryptUpdate(session, plaintext, sizeof(plaintext), ct, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, sizeof(plaintext));

    last = sizeof(ct) - len;
    rv = C_EncryptFinal(session, &ct[len], &last);
    assert_int_equal(rv, CKR_OK);
    assert_memory_equal(ct, ti->ciphertext, sizeof(ti->ciphertext));

    CK_BYTE sig[512];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_SignFinal(session, sig, &sig_len);
    assert_int_equal(rv, CKR_OK);

    /* an always-authenticate decryption key beside a digest: the digest isn't fed before it may */
    rv = C_DecryptInit(session, &aes_mech, aes);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestInit(session, &digest_mech);
    assert_int_equal(rv, CKR_OK);

    /* what the always-authenticate key encrypted above */
    CK_BYTE pt[64];
    len = sizeof(pt);
    rv = C_DecryptDigestUpdate(session, aes_ct, sizeof(aes_ct), pt, &len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    context_login(session);

    len = sizeof(pt);
    rv = C_DecryptDigestUpdate(session, aes_ct, sizeof(aes_ct), pt, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, sizeof(plaintext));
    assert_memory_equal(pt, plaintext, sizeof(plaintext));

    last = sizeof(pt) - len;
    rv = C_DecryptFinal(session, &pt[len], &last);
    assert_int_equal(rv, CKR_OK);

    md_len = sizeof(md);
    rv = C_DigestFinal(session, md, &md_len);
    assert_int_equal(rv, CKR_OK);
    assert_memory_equal(md, want_md, sizeof(md));
}

/* Plain C_DecryptUpdate/C_DecryptFinal beside a digest don't feed it: only the dual function does. */
static void test_dual_plain_decrypt_feeds_nothing(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BYTE ct[48], want_md[32];
    separate_pad_encrypt(ti, session, ct);
    separate_digest(session, plaintext, sizeof(plaintext), want_md);

    CK_RV rv = C_DecryptInit(session, &aes_pad_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestInit(session, &digest_mech);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE pt[48];
    CK_ULONG len = sizeof(pt);
    rv = C_DecryptUpdate(session, ct, sizeof(ct), pt, &len);
    assert_int_equal(rv, CKR_OK);
    CK_ULONG last = sizeof(pt) - len;
    rv = C_DecryptFinal(session, &pt[len], &last);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len + last, sizeof(pad_plaintext));

    rv = C_DigestUpdate(session, plaintext, sizeof(plaintext));
    assert_int_equal(rv, CKR_OK);
    CK_BYTE md[32];
    CK_ULONG md_len = sizeof(md);
    rv = C_DigestFinal(session, md, &md_len);
    assert_int_equal(rv, CKR_OK);
    assert_memory_equal(md, want_md, sizeof(md));
}

/*
 * S32 5.17.2: the decryption and the digest are linked only through C_DecryptDigestUpdate, so the
 * plaintext C_DecryptFinal returns isn't digested unless the application passes it on.
 */
static void test_decrypt_final_not_fed(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    CK_BYTE ct[48];
    separate_pad_encrypt(ti, session, ct);

    CK_RV rv = C_DecryptInit(session, &aes_pad_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);
    rv = C_DigestInit(session, &digest_mech);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE pt[48];
    CK_ULONG len = sizeof(pt);
    rv = C_DecryptDigestUpdate(session, ct, sizeof(ct), pt, &len);
    assert_int_equal(rv, CKR_OK);
    /* the last block, which may be padding, is held back */
    assert_int_equal(len, 32);
    CK_ULONG updated = len;

    len = sizeof(pt) - updated;
    rv = C_DecryptFinal(session, &pt[updated], &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(updated + len, sizeof(pad_plaintext));
    assert_memory_equal(pt, pad_plaintext, sizeof(pad_plaintext));

    /* the digest is of what the update returned alone */
    CK_BYTE want_md[32];
    CK_BYTE md[32];
    CK_ULONG md_len = sizeof(md);
    rv = C_DigestFinal(session, md, &md_len);
    assert_int_equal(rv, CKR_OK);

    separate_digest(session, pad_plaintext, updated, want_md);
    assert_memory_equal(md, want_md, sizeof(md));
}

/* A C_DecryptFinal length query that finds bad padding fails, with the padding's error. */
static void test_decrypt_final_bad_padding_query(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    /* plaintext, AES-CBC encrypted without a pad: its last byte, 'l', is no PKCS#7 pad */
    CK_RV rv = C_DecryptInit(session, &aes_pad_mech, ti->aes);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE pt[32];
    CK_ULONG len = sizeof(pt);
    rv = C_DecryptUpdate(session, ti->ciphertext, sizeof(ti->ciphertext), pt, &len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(len, 16);

    len = 0;
    rv = C_DecryptFinal(session, NULL, &len);
    assert_int_equal(rv, CKR_ENCRYPTED_DATA_INVALID);

    /* an error ends the operation, as for any C_DecryptFinal */
    len = sizeof(pt);
    rv = C_DecryptFinal(session, pt, &len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* and the key was let go */
    rv = op_init(ti, session, op_decrypt);
    assert_int_equal(rv, CKR_OK);
    op_run(ti, session, op_decrypt);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_dual_pairs_can_start,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dual_non_pair_refused,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dual_token_flag,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dual_cancel_one,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dual_close_session_releases_both,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dual_context_specific,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_digest_encrypt_matches_separate,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sign_encrypt_matches_separate,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_decrypt_digest_cbc_pad_last_block,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_decrypt_verify_matches_separate,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dual_requires_both,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dual_length_query_feeds_nothing,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dual_failure_cancels_both,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dual_context_specific_keeps_both,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dual_plain_decrypt_feeds_nothing,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_decrypt_final_not_fed,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_decrypt_final_bad_padding_query,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
