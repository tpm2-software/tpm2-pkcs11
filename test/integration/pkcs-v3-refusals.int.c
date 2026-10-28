/* SPDX-License-Identifier: BSD-2-Clause */

#include <pthread.h>
#include <time.h>

#include "test.h"

/*
 * The functions the token answers with a refusal the standard defines, rather than
 * CKR_FUNCTION_NOT_SUPPORTED: message-based encryption (S32 5.9, 5.11) and authenticated wrapping
 * (5.18.6, 5.18.7), which take no mechanism the token has; asynchronous sessions (5.6.1, 5.21); the
 * operation state (5.6.6, 5.6.7); the legacy parallel functions (5.20); and slot events (5.5.4), of
 * which there are none. Each still checks the library is initialized and the session handle.
 */

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
};

static CK_MECHANISM aes_gcm = { CKM_AES_GCM, NULL, 0 };

/* A session handle no session has */
#define BAD_SESSION ((CK_SESSION_HANDLE)0xdeadbeef)

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

    *state = ti;

    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_Logout(ti->handle);
    assert_int_equal(rv, CKR_OK);

    rv = C_CloseAllSessions(ti->slot_id);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

/* The first AES key of the store, which the setup script makes */
static CK_OBJECT_HANDLE find_aes(CK_SESSION_HANDLE session) {

    CK_OBJECT_CLASS clazz = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &clazz, sizeof(clazz) },
        { CKA_KEY_TYPE, &type, sizeof(type) },
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

static void test_message_encrypt_init_mechanism_invalid(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_OBJECT_HANDLE aes = find_aes(ti->handle);

    /* not even AES-GCM, with an AES key: no mechanism has CKF_MESSAGE_ENCRYPT or CKF_MESSAGE_DECRYPT */
    CK_RV rv = C_MessageEncryptInit(ti->handle, &aes_gcm, aes);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);

    rv = C_MessageDecryptInit(ti->handle, &aes_gcm, aes);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);

    CK_MECHANISM cbc = { CKM_AES_CBC_PAD, NULL, 0 };
    rv = C_MessageEncryptInit(ti->handle, &cbc, aes);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);

    /* a NULL mechanism ends a process there isn't */
    rv = C_MessageEncryptInit(ti->handle, NULL, aes);
    assert_int_equal(rv, CKR_OK);

    rv = C_MessageDecryptInit(ti->handle, NULL, aes);
    assert_int_equal(rv, CKR_OK);

    rv = C_MessageEncryptInit(BAD_SESSION, &aes_gcm, aes);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);

    rv = C_MessageDecryptInit(BAD_SESSION, NULL, aes);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_encrypt_message_not_initialized(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE s = ti->handle;

    CK_BYTE in[16] = { 0 };
    CK_BYTE out[64];
    CK_ULONG out_len = sizeof(out);

    CK_RV rv = C_EncryptMessage(s, NULL, 0, NULL, 0, in, sizeof(in), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_EncryptMessageBegin(s, NULL, 0, NULL, 0);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    out_len = sizeof(out);
    rv = C_EncryptMessageNext(s, NULL, 0, in, sizeof(in), out, &out_len, CKF_END_OF_MESSAGE);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_MessageEncryptFinal(s);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    out_len = sizeof(out);
    rv = C_DecryptMessage(s, NULL, 0, NULL, 0, in, sizeof(in), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_DecryptMessageBegin(s, NULL, 0, NULL, 0);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    out_len = sizeof(out);
    rv = C_DecryptMessageNext(s, NULL, 0, in, sizeof(in), out, &out_len, CKF_END_OF_MESSAGE);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_MessageDecryptFinal(s);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* the session handle is checked first */
    rv = C_MessageEncryptFinal(BAD_SESSION);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);

    rv = C_DecryptMessageBegin(BAD_SESSION, NULL, 0, NULL, 0);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_wrap_key_authenticated_mechanism_invalid(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_OBJECT_HANDLE aes = find_aes(ti->handle);

    CK_BYTE ad[] = "associated data";
    CK_BYTE wrapped[128];
    CK_ULONG wrapped_len = sizeof(wrapped);

    CK_RV rv = C_WrapKeyAuthenticated(ti->handle, &aes_gcm, aes, aes, ad, sizeof(ad),
            wrapped, &wrapped_len);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);

    CK_OBJECT_CLASS clazz = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE templ[] = {
        { CKA_CLASS, &clazz, sizeof(clazz) },
        { CKA_KEY_TYPE, &type, sizeof(type) },
    };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    memset(wrapped, 0x5a, sizeof(wrapped));
    rv = C_UnwrapKeyAuthenticated(ti->handle, &aes_gcm, aes, wrapped, 48, templ, ARRAY_LEN(templ),
            ad, sizeof(ad), &key);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);
    assert_int_equal(key, CK_INVALID_HANDLE);

    /* no mechanism at all */
    wrapped_len = sizeof(wrapped);
    rv = C_WrapKeyAuthenticated(ti->handle, NULL, aes, aes, NULL, 0, wrapped, &wrapped_len);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    rv = C_UnwrapKeyAuthenticated(ti->handle, NULL, aes, wrapped, 48, templ, ARRAY_LEN(templ),
            NULL, 0, &key);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    rv = C_WrapKeyAuthenticated(BAD_SESSION, &aes_gcm, aes, aes, NULL, 0, wrapped, &wrapped_len);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_open_session_async_not_supported(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_SESSION_HANDLE s = CK_INVALID_HANDLE;
    CK_RV rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION | CKF_ASYNC_SESSION, NULL, NULL, &s);
    assert_int_equal(rv, CKR_SESSION_ASYNC_NOT_SUPPORTED);
    assert_int_equal(s, CK_INVALID_HANDLE);

    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION | CKF_ASYNC_SESSION,
            NULL, NULL, &s);
    assert_int_equal(rv, CKR_SESSION_ASYNC_NOT_SUPPORTED);
    assert_int_equal(s, CK_INVALID_HANDLE);

    /* the serial flag is still wanted first */
    rv = C_OpenSession(ti->slot_id, CKF_ASYNC_SESSION, NULL, NULL, &s);
    assert_int_equal(rv, CKR_SESSION_PARALLEL_NOT_SUPPORTED);
}

static void test_token_info_no_async_flag(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_TOKEN_INFO info;
    CK_RV rv = C_GetTokenInfo(ti->slot_id, &info);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(info.flags & CKF_ASYNC_SESSION_SUPPORTED, 0);
}

static void test_async_get_id_not_initialized(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_ULONG id = 0;
    CK_RV rv = C_AsyncGetID(ti->handle, (CK_UTF8CHAR_PTR)"C_SignFinal", &id);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_AsyncGetID(ti->handle, NULL, &id);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    rv = C_AsyncGetID(ti->handle, (CK_UTF8CHAR_PTR)"C_SignFinal", NULL);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    rv = C_AsyncGetID(BAD_SESSION, (CK_UTF8CHAR_PTR)"C_SignFinal", &id);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_async_complete_not_initialized(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_ASYNC_DATA result = { 0 };
    CK_RV rv = C_AsyncComplete(ti->handle, (CK_UTF8CHAR_PTR)"C_SignFinal", &result);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* the standard's example passes no result */
    rv = C_AsyncComplete(ti->handle, (CK_UTF8CHAR_PTR)"C_SignInit", NULL);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_AsyncComplete(ti->handle, NULL, &result);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    rv = C_AsyncComplete(BAD_SESSION, (CK_UTF8CHAR_PTR)"C_SignFinal", &result);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_async_join_saved_state_invalid(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_BYTE data[64];
    CK_RV rv = C_AsyncJoin(ti->handle, (CK_UTF8CHAR_PTR)"C_SignFinal", 1, data, sizeof(data));
    assert_int_equal(rv, CKR_SAVED_STATE_INVALID);

    rv = C_AsyncJoin(ti->handle, NULL, 1, data, sizeof(data));
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    rv = C_AsyncJoin(BAD_SESSION, (CK_UTF8CHAR_PTR)"C_SignFinal", 1, data, sizeof(data));
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_get_operation_state_not_initialized(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_ULONG len = 0;
    CK_RV rv = C_GetOperationState(ti->handle, NULL, &len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* an object search isn't a cryptographic operation */
    CK_OBJECT_CLASS clazz = CKO_SECRET_KEY;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &clazz, sizeof(clazz) },
    };
    rv = C_FindObjectsInit(ti->handle, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    rv = C_GetOperationState(ti->handle, NULL, &len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_FindObjectsFinal(ti->handle);
    assert_int_equal(rv, CKR_OK);

    rv = C_GetOperationState(ti->handle, NULL, NULL);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    rv = C_GetOperationState(BAD_SESSION, NULL, &len);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_get_operation_state_unsaveable(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_MECHANISM sha256 = { CKM_SHA256, NULL, 0 };
    CK_RV rv = C_DigestInit(ti->handle, &sha256);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE part[] = "some data";
    rv = C_DigestUpdate(ti->handle, part, sizeof(part));
    assert_int_equal(rv, CKR_OK);

    /* the length query too: no state is ever given out */
    CK_ULONG len = 0;
    rv = C_GetOperationState(ti->handle, NULL, &len);
    assert_int_equal(rv, CKR_STATE_UNSAVEABLE);

    CK_BYTE buf[512];
    len = sizeof(buf);
    rv = C_GetOperationState(ti->handle, buf, &len);
    assert_int_equal(rv, CKR_STATE_UNSAVEABLE);

    /* the digest goes on */
    CK_BYTE digest[32];
    CK_ULONG digest_len = sizeof(digest);
    rv = C_DigestFinal(ti->handle, digest, &digest_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(digest_len, 32);
}

/* A session key pair, the private key with CKA_SIGN and sign_recover as CKA_SIGN_RECOVER */
static void gen_session_keypair(CK_SESSION_HANDLE session, CK_MECHANISM_TYPE gen,
        CK_ATTRIBUTE_PTR pub_extra, CK_ULONG pub_extra_count, CK_BBOOL sign_recover,
        CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    CK_ATTRIBUTE pub_templ[4] = {
        ADD_ATTR_BASE(CKA_TOKEN, ck_false),
        ADD_ATTR_BASE(CKA_VERIFY, ck_true),
    };
    CK_ULONG pub_count = 2;
    CK_ULONG i;
    for (i = 0; i < pub_extra_count; i++) {
        pub_templ[pub_count++] = pub_extra[i];
    }

    CK_ATTRIBUTE priv_templ[] = {
        ADD_ATTR_BASE(CKA_TOKEN, ck_false),
        ADD_ATTR_BASE(CKA_PRIVATE, ck_true),
        ADD_ATTR_BASE(CKA_SIGN, ck_true),
        ADD_ATTR_BASE(CKA_SIGN_RECOVER, sign_recover),
    };

    CK_MECHANISM mech = { gen, NULL, 0 };
    CK_RV rv = C_GenerateKeyPair(session, &mech, pub_templ, pub_count,
            priv_templ, ARRAY_LEN(priv_templ), pub, priv);
    assert_int_equal(rv, CKR_OK);
}

static void test_get_operation_state_sign_unsaveable(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_BYTE p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    CK_ATTRIBUTE ec_params[] = {
        { CKA_EC_PARAMS, p256, sizeof(p256) },
    };
    CK_OBJECT_HANDLE pub, priv;
    gen_session_keypair(ti->handle, CKM_EC_KEY_PAIR_GEN, ec_params, ARRAY_LEN(ec_params), CK_FALSE,
            &pub, &priv);

    CK_MECHANISM ecdsa_sha256 = { CKM_ECDSA_SHA256, NULL, 0 };
    CK_RV rv = C_SignInit(ti->handle, &ecdsa_sha256, priv);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG len = 0;
    rv = C_GetOperationState(ti->handle, NULL, &len);
    assert_int_equal(rv, CKR_STATE_UNSAVEABLE);

    /* the signature goes on */
    CK_BYTE data[] = "some data";
    CK_BYTE sig[128];
    CK_ULONG sig_len = sizeof(sig);
    rv = C_Sign(ti->handle, data, sizeof(data), sig, &sig_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(sig_len, 64);
}

/* Signing with message recovery isn't an operation S32 5.6.6 saves a state for. */
static void test_get_operation_state_sign_recover_not_initialized(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_ULONG bits = 2048;
    CK_ATTRIBUTE rsa_bits[] = {
        ADD_ATTR_BASE(CKA_MODULUS_BITS, bits),
    };
    CK_OBJECT_HANDLE pub, priv;
    gen_session_keypair(ti->handle, CKM_RSA_PKCS_KEY_PAIR_GEN, rsa_bits, ARRAY_LEN(rsa_bits), CK_TRUE,
            &pub, &priv);

    CK_MECHANISM rsa_pkcs = { CKM_RSA_PKCS, NULL, 0 };
    CK_RV rv = C_SignRecoverInit(ti->handle, &rsa_pkcs, priv);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG len = 0;
    rv = C_GetOperationState(ti->handle, NULL, &len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* end it */
    rv = C_SignRecoverInit(ti->handle, NULL, priv);
    assert_int_equal(rv, CKR_OK);
}

static void test_set_operation_state_invalid(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_BYTE saved[64];
    memset(saved, 0xa5, sizeof(saved));
    CK_RV rv = C_SetOperationState(ti->handle, saved, sizeof(saved), CK_INVALID_HANDLE,
            CK_INVALID_HANDLE);
    assert_int_equal(rv, CKR_SAVED_STATE_INVALID);

    rv = C_SetOperationState(ti->handle, NULL, 0, CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    rv = C_SetOperationState(BAD_SESSION, saved, sizeof(saved), CK_INVALID_HANDLE,
            CK_INVALID_HANDLE);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_get_function_status_not_parallel(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_GetFunctionStatus(ti->handle);
    assert_int_equal(rv, CKR_FUNCTION_NOT_PARALLEL);

    rv = C_GetFunctionStatus(BAD_SESSION);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_cancel_function_not_parallel(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_CancelFunction(ti->handle);
    assert_int_equal(rv, CKR_FUNCTION_NOT_PARALLEL);

    rv = C_CancelFunction(BAD_SESSION);
    assert_int_equal(rv, CKR_SESSION_HANDLE_INVALID);
}

static void test_wait_for_slot_event_dont_block_no_event(void **state) {
    UNUSED(state);

    CK_SLOT_ID slot = 0;
    CK_RV rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL);
    assert_int_equal(rv, CKR_NO_EVENT);

    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, NULL, NULL);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);

    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, &slot);
    assert_int_equal(rv, CKR_ARGUMENTS_BAD);
}

/* A thread blocked in C_WaitForSlotEvent, and what it returned */
typedef struct waiter waiter;
struct waiter {
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool done;
    CK_RV rv;
};

static void *wait_thread(void *arg) {

    waiter *w = (waiter *)arg;

    CK_SLOT_ID slot = 0;
    CK_RV rv = C_WaitForSlotEvent(0, &slot, NULL);

    pthread_mutex_lock(&w->mutex);
    w->rv = rv;
    w->done = true;
    pthread_cond_signal(&w->cond);
    pthread_mutex_unlock(&w->mutex);

    return NULL;
}

static void waiter_start(waiter *w) {

    memset(w, 0, sizeof(*w));
    assert_int_equal(pthread_mutex_init(&w->mutex, NULL), 0);
    assert_int_equal(pthread_cond_init(&w->cond, NULL), 0);
    assert_int_equal(pthread_create(&w->thread, NULL, wait_thread, w), 0);
}

/* Whether the waiter returned within ms milliseconds */
static bool waiter_returned_within(waiter *w, long ms) {

    /* no assert here: the caller asserts once the thread is joined */
    struct timespec deadline = { 0 };
    (void)clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += ms / 1000;
    deadline.tv_nsec += (ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&w->mutex);
    while (!w->done) {
        if (pthread_cond_timedwait(&w->cond, &w->mutex, &deadline)) {
            break;
        }
    }
    bool done = w->done;
    pthread_mutex_unlock(&w->mutex);

    return done;
}

static void waiter_join(waiter *w) {

    assert_int_equal(pthread_join(w->thread, NULL), 0);
    pthread_cond_destroy(&w->cond);
    pthread_mutex_destroy(&w->mutex);
}

/*
 * The waiter: static, for a thread that outlives a failed test must not write into a dead stack
 * frame.
 */
static waiter the_waiter;

/*
 * Blocks a waiter, finalizes, and checks it returned CKR_CRYPTOKI_NOT_INITIALIZED. Nothing is
 * asserted until C_Finalize was called and the thread joined, so a failure leaves no thread blocked;
 * one C_Finalize didn't wake can't be joined, and is detached.
 */
static void wait_then_finalize(void) {

    waiter_start(&the_waiter);

    /* no event ever comes: it blocks */
    bool returned_early = waiter_returned_within(&the_waiter, 200);

    CK_RV rv = C_Finalize(NULL);

    bool woken = waiter_returned_within(&the_waiter, 5000);
    if (woken) {
        waiter_join(&the_waiter);
    } else {
        pthread_detach(the_waiter.thread);
    }

    assert_false(returned_early);
    assert_int_equal(rv, CKR_OK);
    assert_true(woken);
    assert_int_equal(the_waiter.rv, CKR_CRYPTOKI_NOT_INITIALIZED);
}

static void test_wait_for_slot_event_wakes_on_finalize(void **state) {

    wait_then_finalize();

    /* finalized: the call says so at once */
    CK_SLOT_ID slot = 0;
    CK_RV rv = C_WaitForSlotEvent(0, &slot, NULL);
    assert_int_equal(rv, CKR_CRYPTOKI_NOT_INITIALIZED);

    /* initialized again, a new wait blocks until the next C_Finalize */
    rv = group_setup_locking(state);
    assert_int_equal(rv, 0);

    wait_then_finalize();

    /* for the group teardown */
    rv = group_setup_locking(state);
    assert_int_equal(rv, 0);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_message_encrypt_init_mechanism_invalid,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_encrypt_message_not_initialized,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wrap_key_authenticated_mechanism_invalid,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_open_session_async_not_supported,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_token_info_no_async_flag,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_async_get_id_not_initialized,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_async_complete_not_initialized,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_async_join_saved_state_invalid,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_operation_state_not_initialized,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_operation_state_unsaveable,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_operation_state_sign_unsaveable,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_operation_state_sign_recover_not_initialized,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_set_operation_state_invalid,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_function_status_not_parallel,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_cancel_function_not_parallel,
                test_setup, test_teardown),
        cmocka_unit_test(test_wait_for_slot_event_dont_block_no_event),
        /* last: it finalizes and initializes the library again */
        cmocka_unit_test(test_wait_for_slot_event_wakes_on_finalize),
    };

    /* with locking, for one test calls from a second thread */
    return cmocka_run_group_tests(tests, group_setup_locking, group_teardown);
}
