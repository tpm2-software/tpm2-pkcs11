/* SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>

#include <sqlite3.h>

#include "db.h"
#include "object.h"
#include "twist.h"
#include "utils.h"

#define BAD_PTR ((void *)0xDEADBEEF)

typedef struct will_return_data will_return_data;
struct will_return_data {
	union {
		int rc;
		void *data;
		bool rcb;
		CK_RV rv;
	};
};

static int tobject_setup(void **state) {

	tobject *t = __real_tobject_new();
	assert_non_null(t);
	t->id = 42;
	*state = t;
	return 0;
}

int __wrap_sqlite3_column_bytes(sqlite3 *stmt, int i) {
	UNUSED(stmt);
	UNUSED(i);

	will_return_data *d = mock_type(will_return_data *);
	return d->rc;
}

void *__wrap_sqlite3_column_blob(sqlite3 *stmt, int i) {
	UNUSED(stmt);
	UNUSED(i);

	will_return_data *d = mock_type(will_return_data *);
	return d->data;
}

int __wrap_sqlite3_data_count(sqlite3 *stmt) {
	UNUSED(stmt);

	will_return_data *d = mock_type(will_return_data *);
	return d->rc;
}

const char *__wrap_sqlite3_column_name(sqlite3 *stmt, int i) {
	UNUSED(stmt);
	UNUSED(i);

	will_return_data *d = mock_type(will_return_data *);
	return d->data;
}

const unsigned char *__wrap_sqlite3_column_text(sqlite3_stmt *stmt, int i) {
	UNUSED(stmt);
	UNUSED(i);

	will_return_data *d = mock_type(will_return_data *);
	return d->data;
}

/* Override WEAK symbol */
twist twistbin_new(const void *data, size_t len) {
	UNUSED(data);
	UNUSED(len);

	will_return_data *d = mock_type(will_return_data *);
	return d->data;
}

/* weak override */
tobject *tobject_new(void) {

	will_return_data *d = mock_type(will_return_data *);
	return d->data;
}

/* weak override */
bool parse_attributes_from_string(const unsigned char *yaml, size_t size,
        attr_list **attrs) {
	UNUSED(yaml);
	UNUSED(size);
	UNUSED(attrs);

	will_return_data *d = mock_type(will_return_data *);
	return d->rcb;
}

/* weak override */
WEAK CK_RV object_init_from_attrs(tobject *tobj) {
	UNUSED(tobj);

	will_return_data *d = mock_type(will_return_data *);
	return d->rv;
}

static void test_db_get_blob_col_bytes_0(void **state) {
    (void) state;

    will_return_data d = {
    		.rc = 0
    };

    will_return(__wrap_sqlite3_column_bytes, &d);

    twist blob = NULL;
    int rc = get_blob(BAD_PTR, 0, &blob);
    assert_int_equal(rc, SQLITE_ERROR);
}

static void test_db_get_blob_null_col_bytes_0(void **state) {
    (void) state;

    will_return_data d = {
    		.rc = 0
    };

    will_return(__wrap_sqlite3_column_bytes, &d);

    twist blob = NULL;
    int rc = get_blob_null(BAD_PTR, 0, &blob);
    assert_int_equal(rc, SQLITE_OK);
}

static void test_db_get_blob_alloc_fail(void **state) {
    (void) state;

    will_return_data d[] = {
		{ .rc = 32 },
		{ .data = "This is 32 bytes, that's cool!!" },
		{ .data = NULL },
    };

    will_return(__wrap_sqlite3_column_bytes, &d[0]);
    will_return(__wrap_sqlite3_column_blob, &d[1]);
    will_return(twistbin_new, &d[2]);

    twist blob = NULL;
    int rc = get_blob(BAD_PTR, 0, &blob);
    assert_int_equal(rc, SQLITE_ERROR);
}

static void db_tobject_new_tobject_alloc_fail(void **state) {
    (void) state;

    will_return_data d = {
		.data = NULL,
    };

    will_return(tobject_new, &d);

    tobject *t = db_tobject_new(BAD_PTR);
    assert_null(t);
}

static void db_tobject_new_tobject_sqlite3_column_unknown_fail(void **state) {
    (void) state;

    will_return_data d[] = {
		{ .data = *state },    /* tobject_new */
		{ .rc = 1 },           /* sqlite3_data_count */
		{ .data = "unknown" }, /* sqlite3_column_name */
    };

    will_return(tobject_new,                 &d[0]);
    will_return(__wrap_sqlite3_data_count,   &d[1]);
    will_return(__wrap_sqlite3_column_name,  &d[2]);

    tobject *t = db_tobject_new(BAD_PTR);
    assert_null(t);
}

static void db_tobject_new_tobject_sqlite3_column_text_fail(void **state) {
    (void) state;

    will_return_data d[] = {
		{ .data = *state },  /* tobject_new */
		{ .rc = 1 },         /* sqlite3_data_count */
		{ .data = "attrs" }, /* sqlite3_column_name */
		{ .rc = 0 },         /* sqlite3_column_bytes */
		{ .data = NULL },    /* sqlite3_column_text */
    };

    will_return(tobject_new,                 &d[0]);
    will_return(__wrap_sqlite3_data_count,   &d[1]);
    will_return(__wrap_sqlite3_column_name,  &d[2]);
    will_return(__wrap_sqlite3_column_bytes, &d[3]);
    will_return(__wrap_sqlite3_column_text,  &d[4]);

    tobject *t = db_tobject_new(BAD_PTR);
    assert_null(t);
}

static void db_tobject_new_tobject_sqlite3_attrs_text_fail(void **state) {
    (void) state;

    will_return_data d[] = {
		{ .data = *state },  /* tobject_new */
		{ .rc = 1 },         /* sqlite3_data_count */
		{ .data = "attrs" }, /* sqlite3_column_name */
		{ .rc = 4 },         /* sqlite3_column_bytes */
		{ .data = "bad" },   /* sqlite3_column_text */
		{ .rcb = false },    /* parse_attributes_from_string */
    };

    will_return(tobject_new,                  &d[0]);
    will_return(__wrap_sqlite3_data_count,    &d[1]);
    will_return(__wrap_sqlite3_column_name,   &d[2]);
    will_return(__wrap_sqlite3_column_bytes,  &d[3]);
    will_return(__wrap_sqlite3_column_text,   &d[4]);
    will_return(parse_attributes_from_string, &d[5]);

    tobject *t = db_tobject_new(BAD_PTR);
    assert_null(t);
}

static void db_tobject_new_tobject_object_init_from_attrs_fail(void **state) {
    (void) state;

    will_return_data d[] = {
		{ .data = *state },         /* tobject_new */
		{ .rc = 1 },                /* sqlite3_data_count */
		{ .data = "attrs" },        /* sqlite3_column_name */
		{ .rc = 3 },                /* sqlite3_column_bytes */
		{ .data = "good" },         /* sqlite3_column_text */
		{ .rcb = true },            /* parse_attributes_from_string */
		{ .rv = CKR_GENERAL_ERROR } /* object_init_from_attrs */
    };

    will_return(tobject_new,                  &d[0]);
    will_return(__wrap_sqlite3_data_count,    &d[1]);
    will_return(__wrap_sqlite3_column_name,   &d[2]);
    will_return(__wrap_sqlite3_column_bytes,  &d[3]);
    will_return(__wrap_sqlite3_column_text,   &d[4]);
    will_return(parse_attributes_from_string, &d[5]);
    will_return(object_init_from_attrs,       &d[6]);

    tobject *t = db_tobject_new(BAD_PTR);
    assert_null(t);
}

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_db_get_blob_col_bytes_0),
		cmocka_unit_test(test_db_get_blob_null_col_bytes_0),
		cmocka_unit_test(test_db_get_blob_alloc_fail),
		cmocka_unit_test(db_tobject_new_tobject_alloc_fail),
		cmocka_unit_test_setup(
			db_tobject_new_tobject_sqlite3_column_unknown_fail,
			tobject_setup),
		cmocka_unit_test_setup(
			db_tobject_new_tobject_sqlite3_column_text_fail,
			tobject_setup),
		cmocka_unit_test_setup(
			db_tobject_new_tobject_sqlite3_attrs_text_fail,
			tobject_setup),
		cmocka_unit_test_setup(
			db_tobject_new_tobject_object_init_from_attrs_fail,
			tobject_setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
