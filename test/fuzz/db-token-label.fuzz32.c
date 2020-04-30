/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"

#include <stdbool.h>
#include <stdlib.h>

#include <sqlite3.h>

#include "db.h"
#include "token.h"
#include "pkcs11.h"

#include "wrap_tpm.h"

static const uint8_t *_data;
static size_t _size;

static sqlite3 *_db;
static token _token;

/* hidden api */
extern CK_RV db_init_new(sqlite3 *db);
extern void db_debug_set_db(sqlite3 *db);

/* overriding weak symbol, like wrap */
CK_RV db_new(sqlite3 **db) {

    *db = _db;
    return CKR_OK;
}

/* overriding weak symbol, like wrap */
void db_get_label(token *t, sqlite3_stmt *stmt, int iCol) {
    UNUSED(stmt);
    UNUSED(iCol);

    /* FUZZ DATA */
    memcpy(t->label, _data, _size);
}

static int setup(void **state) {
    UNUSED(state);

    set_default_tpm();

    int rc = sqlite3_open(":memory:", &_db);
    assert_int_equal(rc, SQLITE_OK);

    CK_RV rv = db_init_new(_db);
    assert_int_equal(rv, CKR_OK);

    db_debug_set_db(_db);

    unsigned int pid = 0;
    twist blob = twist_new("aabbccdd");
    rv = db_add_primary(blob, &pid);
    twist_free(blob);
    assert_int_equal(rv, CKR_OK);

    /* create and add a dummy token */
    memcpy(_token.label, "foo", 3);
    _token.pid = pid;

    _token.config.is_initialized = true;

    _token.esysdb.sealobject.sopriv = twist_new("sopriv");
    assert_non_null(_token.esysdb.sealobject.sopriv);

    _token.esysdb.sealobject.soauthsalt = twist_new("soauthsalt");
    assert_non_null(_token.esysdb.sealobject.soauthsalt);

    _token.esysdb.sealobject.sopub = twist_new("sopub");
    assert_non_null(_token.esysdb.sealobject.sopub);

    _token.esysdb.sealobject.userauthsalt = twist_new("userauthsalt");
    assert_non_null(_token.esysdb.sealobject.userauthsalt);

    rv = db_add_token(&_token);
    assert_int_equal(rv, CKR_OK);

    setenv("TPM2_PKCS11_STORE", ":memory:", 1);

    rv = C_Initialize(NULL);
    assert_int_equal(rv, CKR_OK);

    return 0;
}

static int teardown(void **state) {
    UNUSED(state);

    set_default_tpm();

    CK_RV rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    token_free(&_token);

    return 0;
}

static void test(void **state) {
    UNUSED(state);

    /* nothing to do, setup and teardown do it */
    CK_SLOT_ID slot_ids[2];
    CK_ULONG cnt = ARRAY_LEN(slot_ids);
    CK_RV rv = C_GetSlotList(true, slot_ids, &cnt);
    assert_int_equal(rv, CKR_OK);

    CK_TOKEN_INFO info;
    /* FUZZ TARGET */
    rv = C_GetTokenInfo(slot_ids[0], &info);
    assert_int_equal(rv, CKR_OK);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    if (size > 32) {
        LOGE("SIZE BIGGER THAN 32");
        return 0;
    }

    _size = size;
    _data = data;

    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(test, setup, teardown),
    };

    cmocka_run_group_tests(tests, NULL, NULL);
    return 0;
}
