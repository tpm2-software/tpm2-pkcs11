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
#include "debug.h"
#include "object.h"
#include "twist.h"
#include "utils.h"

#define BAD_PTR ((void *)0xDEADBEEF)

typedef struct will_return_data will_return_data;
struct will_return_data {
    bool call_real;
    token t;
	union {
		int rc;
		void *data;
		bool rcb;
		CK_RV rv;
		sqlite3_int64 u64;
	};
};

static int tobject_setup(void **state) {

    will_return_data d = { .call_real = true };
    will_return(__wrap_calloc, &d);

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

int __wrap_sqlite3_column_int(sqlite3_stmt *stmt, int i) {
	UNUSED(stmt);
	UNUSED(i);

	will_return_data *d = mock_type(will_return_data *);
	return d->rc;
}

int __wrap_sqlite3_finalize(sqlite3_stmt *pStmt) {
    UNUSED(pStmt);

	will_return_data *d = mock_type(will_return_data *);
	return d->rc;
}

int __wrap_sqlite3_prepare_v2(sqlite3 *db,
  const char *zSql,
  int nByte,
  sqlite3_stmt **ppStmt,
  const char **pzTail
) {
	UNUSED(db);
	UNUSED(zSql);
	UNUSED(nByte);
	UNUSED(ppStmt);
	UNUSED(pzTail);

	will_return_data *d = mock_type(will_return_data *);
	if (d->rc == SQLITE_OK) {
		*ppStmt = (sqlite3_stmt *)0xBADCC0DE;
	}
	return d->rc;
}

int __wrap_sqlite3_bind_int(sqlite3_stmt *pStmt, int iCol, int value) {
	UNUSED(pStmt);
	UNUSED(iCol);
	UNUSED(value);

	will_return_data *d = mock_type(will_return_data *);
	return d->rc;
}

int __wrap_sqlite3_bind_text(sqlite3_stmt *pStmt, int iCol, const char *text, int len, void(*fnp)(void *data)) {
	UNUSED(pStmt);
	UNUSED(iCol);
	UNUSED(text);
	UNUSED(len);
	UNUSED(fnp);

	will_return_data *d = mock_type(will_return_data *);
	return d->rc;
}

int __wrap_sqlite3_bind_blob(sqlite3_stmt *pStmt, int iCol, const void *data, int len, void(*fnp)(void *data)) {
    UNUSED(pStmt);
    UNUSED(iCol);
    UNUSED(data);
    UNUSED(len);
    UNUSED(fnp);

    will_return_data *d = mock_type(will_return_data *);
    return d->rc;
}

int __wrap_sqlite3_step(sqlite3_stmt *pStmt) {
	UNUSED(pStmt);

	will_return_data *d = mock_type(will_return_data *);
	return d->rc;
}

const char *__wrap_sqlite3_errmsg(sqlite3 *db) {
	UNUSED(db);
	return "FAKE ERROR MESSAGE";
}

char *__real_strdup(const char *s);
char *__wrap_strdup(const char *s) {
	UNUSED(s);

	will_return_data *d = mock_type(will_return_data *);
	if (d->call_real) {
	    return __real_strdup(s);
	}

	return d->data;
}

void *__real_calloc(size_t nmemb, size_t size);
void *__wrap_calloc(size_t nmemb, size_t size) {

    will_return_data *d = mock_type(will_return_data *);
    if (d->call_real) {
        return __real_calloc(nmemb, size);
    }

    return d->data;
}

int __real_sqlite3_exec(
    sqlite3 *db,                               /* An open database */
    const char *sql,                           /* SQL to be evaluated */
    int (*callback)(void*,int,char**,char**),  /* Callback function */
    void *,                                    /* 1st argument to callback */
    char **errmsg                              /* Error msg written here */
);
int __wrap_sqlite3_exec(
    sqlite3 *db,
    const char *sql,
    int (*callback)(void*,int,char**,char**),
    void *arg,
    char **errmsg
) {
    will_return_data *d = mock_type(will_return_data *);
    if (d->call_real) {
        return __real_sqlite3_exec(db, sql, callback, arg, errmsg);
    }

    return d->rc;
}

sqlite3_int64 __wrap_sqlite3_last_insert_rowid(sqlite3 *db) {
    UNUSED(db);

    will_return_data *d = mock_type(will_return_data *);
    return d->u64;
}

/* Override WEAK symbol */
twist __real_twistbin_new(const void *data, size_t size);
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
tobject *db_tobject_new(sqlite3_stmt *stmt) {

    will_return_data *d = mock_type(will_return_data *);
    if (d->call_real) {
        return __real_db_tobject_new(stmt);
    }
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

/* weak override */
char *emit_pobject_to_conf_string(pobject_config *config) {
	UNUSED(config);

	will_return_data *d = mock_type(will_return_data *);
	return d->data;
}

/* weak override */
bool tpm_deserialize_handle(tpm_ctx *ctx, twist handle_blob,
        uint32_t *handle, uint32_t *tpm_handle) {
    UNUSED(ctx);
    UNUSED(handle_blob);
    UNUSED(handle);

    if (tpm_handle) {
        *tpm_handle = 42;
    }

    will_return_data *d = mock_type(will_return_data *);
    return d->rcb;
}

/* weak overide */
CK_RV token_add_tobject_last(token *tok, tobject *t) {
    UNUSED(tok);
    UNUSED(t);

    will_return_data *d = mock_type(will_return_data *);
    return d->rv;
}

/* weak override */
CK_RV tpm_create_transient_primary_from_template(tpm_ctx *tpm,
        const char *template_name, twist pobj_auth,
        uint32_t *primary_handle) {
    UNUSED(tpm);
    UNUSED(template_name);
    UNUSED(pobj_auth);
    UNUSED(primary_handle);

    will_return_data *d = mock_type(will_return_data *);
    return d->rv;
}

/* weak override */
CK_RV token_min_init(token *t) {

    will_return_data *d = mock_type(will_return_data *);
    *t = d->t;
    return d->rv;
}

/* weak override */
int init_pobject(unsigned pid, pobject *pobj, tpm_ctx *tpm) {

    will_return_data *d = mock_type(will_return_data *);
    if (d->call_real) {
        return __real_init_pobject(pid, pobj, tpm);
    }
    return d->rc;
}

/* weak override */
int init_sealobjects(unsigned tokid, sealobject *sealobj) {

    will_return_data *d = mock_type(will_return_data *);
    if (d->call_real) {
        return __real_init_sealobjects(tokid, sealobj);
    }
    return d->rc;
}

/* weak override */
int init_tobjects(token *tok) {

    will_return_data *d = mock_type(will_return_data *);
    if (d->call_real) {
        return __real_init_tobjects(tok);
    }
    return d->rc;
}

/* weak override */
char *emit_attributes_to_string(attr_list *attrs) {
    UNUSED(attrs);
    will_return_data *d = mock_type(will_return_data *);
    return d->data;
}

/* weak override */
char *emit_config_to_string(token *tok) {
    UNUSED(tok);
    will_return_data *d = mock_type(will_return_data *);
    return d->data;
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

    will_return_data d[] = {
        { .call_real = true },  /* db_tobject_new call real */
		{ .data = NULL      }  /* tobject_new fail */
    };

    will_return(db_tobject_new, &d[0]);
    will_return(tobject_new, &d[1]);

    tobject *t = db_tobject_new(BAD_PTR);
    assert_null(t);
}

static void db_tobject_new_tobject_sqlite3_column_unknown_fail(void **state) {
    (void) state;

    will_return_data d[] = {
        { .call_real = true }, /* db_tobject_new call real */
		{ .data = *state },    /* tobject_new */
		{ .rc = 1 },           /* sqlite3_data_count */
		{ .data = "unknown" }, /* sqlite3_column_name */
    };

    will_return(db_tobject_new,              &d[0]);
    will_return(tobject_new,                 &d[1]);
    will_return(__wrap_sqlite3_data_count,   &d[2]);
    will_return(__wrap_sqlite3_column_name,  &d[3]);

    tobject *t = db_tobject_new(BAD_PTR);
    assert_null(t);
}

static void db_tobject_new_tobject_sqlite3_column_text_fail(void **state) {
    (void) state;

    will_return_data d[] = {
        { .call_real = true }, /* db_tobject_new call real */
		{ .data = *state },    /* tobject_new */
		{ .rc = 1 },           /* sqlite3_data_count */
		{ .data = "attrs" },   /* sqlite3_column_name */
		{ .rc = 0 },           /* sqlite3_column_bytes */
		{ .data = NULL },      /* sqlite3_column_text */
    };

    will_return(db_tobject_new,              &d[0]);
    will_return(tobject_new,                 &d[1]);
    will_return(__wrap_sqlite3_data_count,   &d[2]);
    will_return(__wrap_sqlite3_column_name,  &d[3]);
    will_return(__wrap_sqlite3_column_bytes, &d[4]);
    will_return(__wrap_sqlite3_column_text,  &d[5]);

    tobject *t = db_tobject_new(BAD_PTR);
    assert_null(t);
}

static void db_tobject_new_tobject_sqlite3_attrs_text_fail(void **state) {
    (void) state;

    will_return_data d[] = {
        { .call_real = true }, /* db_tobject_new call real */
		{ .data = *state },    /* tobject_new */
		{ .rc = 1 },           /* sqlite3_data_count */
		{ .data = "attrs" },   /* sqlite3_column_name */
		{ .rc = 4 },           /* sqlite3_column_bytes */
		{ .data = "bad" },     /* sqlite3_column_text */
		{ .rcb = false },      /* parse_attributes_from_string */
    };

    will_return(db_tobject_new,               &d[0]);
    will_return(tobject_new,                  &d[1]);
    will_return(__wrap_sqlite3_data_count,    &d[2]);
    will_return(__wrap_sqlite3_column_name,   &d[3]);
    will_return(__wrap_sqlite3_column_bytes,  &d[4]);
    will_return(__wrap_sqlite3_column_text,   &d[5]);
    will_return(parse_attributes_from_string, &d[6]);

    tobject *t = db_tobject_new(BAD_PTR);
    assert_null(t);
}

static void db_tobject_new_tobject_object_init_from_attrs_fail(void **state) {
    (void) state;

    will_return_data d[] = {
        { .call_real = true },      /* db_tobject_new call real */
		{ .data = *state },         /* tobject_new */
		{ .rc = 1 },                /* sqlite3_data_count */
		{ .data = "attrs" },        /* sqlite3_column_name */
		{ .rc = 3 },                /* sqlite3_column_bytes */
		{ .data = "good" },         /* sqlite3_column_text */
		{ .rcb = true },            /* parse_attributes_from_string */
		{ .rv = CKR_GENERAL_ERROR } /* object_init_from_attrs */
    };

    will_return(db_tobject_new,               &d[0]);
    will_return(tobject_new,                  &d[1]);
    will_return(__wrap_sqlite3_data_count,    &d[2]);
    will_return(__wrap_sqlite3_column_name,   &d[3]);
    will_return(__wrap_sqlite3_column_bytes,  &d[4]);
    will_return(__wrap_sqlite3_column_text,   &d[5]);
    will_return(parse_attributes_from_string, &d[6]);
    will_return(object_init_from_attrs,       &d[7]);

    tobject *t = db_tobject_new(BAD_PTR);
    assert_null(t);
}

static void init_pobject_v3_from_stmt_sqlite3_column_text_fail(void **state) {
    (void) state;

    will_return_data d[] = {
		{ .rc = 42 },               /* sqlite3_column_int */
		{ .data = NULL },           /* sqlite3_column_text */
    };

    will_return(__wrap_sqlite3_column_int,    &d[0]);
    will_return(__wrap_sqlite3_column_text,   &d[1]);

    pobject_v3 pobj = { 0 };

    int rc = init_pobject_v3_from_stmt(BAD_PTR, &pobj);
    assert_int_equal(rc, SQLITE_ERROR);
}

static void init_pobject_v3_from_stmt_strdup_fail(void **state) {
    (void) state;

    will_return_data d[] = {
		{ .rc = 42 },               /* sqlite3_column_int */
		{ .data = "o" },            /* sqlite3_column_text */
		{ .data = NULL },           /* strdup */
    };

    will_return(__wrap_sqlite3_column_int,    &d[0]);
    will_return(__wrap_sqlite3_column_text,   &d[1]);
    will_return(__wrap_strdup,                &d[2]);

    pobject_v3 pobj = { 0 };

    int rc = init_pobject_v3_from_stmt(BAD_PTR, &pobj);
    assert_int_equal(rc, SQLITE_ERROR);
}

static void init_pobject_v3_from_stmt__get_blob_fail(void **state) {
    (void) state;

    char *x = __real_strdup("o");
    assert_non_null(x);

    will_return_data d[] = {
		{ .rc = 42 },       /* sqlite3_column_int */
		{ .data = "o" },    /* sqlite3_column_text */
		{ .data = x },      /* strdup */
		{ .rc = 4   },      /* _get_blob --> sqlite3_column_bytes */
		{ .data = "data" }, /* _get_blob --> sqlite3_column_blob */
		{ .data = NULL },   /* twistbin_new */
    };

    will_return(__wrap_sqlite3_column_int,    &d[0]);
    will_return(__wrap_sqlite3_column_text,   &d[1]);
    will_return(__wrap_strdup,                &d[2]);
    will_return(__wrap_sqlite3_column_bytes,  &d[3]);
    will_return(__wrap_sqlite3_column_blob,   &d[4]);
    will_return(twistbin_new,                 &d[5]);

    pobject_v3 pobj = { 0 };

    int rc = init_pobject_v3_from_stmt(BAD_PTR, &pobj);
    assert_int_equal(rc, SQLITE_ERROR);
}

static void init_pobject_v3_from_stmt_sqlite3_column_text2_fail(void **state) {
    (void) state;

    char *x = __real_strdup("o");
    assert_non_null(x);

    twist t = __real_twistbin_new("data", 4);
    assert_non_null(t);

    will_return_data d[] = {
		{ .rc = 42 },          /* sqlite3_column_int */
		{ .data = "o" },       /* sqlite3_column_text */
		{ .data = x },         /* strdup */
		{ .rc = 4   },         /* _get_blob --> sqlite3_column_bytes */
		{ .data = "data" },    /* _get_blob --> sqlite3_column_blob */
		{ .data = (void *)t }, /* twistbin_new */
		{ .data = NULL },      /* sqlite3_column_text */
    };

    will_return(__wrap_sqlite3_column_int,    &d[0]);
    will_return(__wrap_sqlite3_column_text,   &d[1]);
    will_return(__wrap_strdup,                &d[2]);
    will_return(__wrap_sqlite3_column_bytes,  &d[3]);
    will_return(__wrap_sqlite3_column_blob,   &d[4]);
    will_return(twistbin_new,                 &d[5]);
    will_return(__wrap_sqlite3_column_text,   &d[6]);

    pobject_v3 pobj = { 0 };

    int rc = init_pobject_v3_from_stmt(BAD_PTR, &pobj);
    assert_int_equal(rc, SQLITE_ERROR);
}

static void init_pobject_v3_from_stmt_strdup2_fail(void **state) {
    (void) state;

    char *x = __real_strdup("o");
    assert_non_null(x);

    twist t = __real_twistbin_new("data", 4);
    assert_non_null(t);

    will_return_data d[] = {
		{ .rc = 42 },              /* sqlite3_column_int */
		{ .data = "o" },           /* sqlite3_column_text */
		{ .data = x },             /* strdup */
		{ .rc = 4   },             /* _get_blob --> sqlite3_column_bytes */
		{ .data = "data" },        /* _get_blob --> sqlite3_column_blob */
		{ .data = (void *)t },     /* twistbin_new */
		{ .data = "foo:bar:baz" }, /* sqlite3_column_text */
		{ .data = NULL },          /* strdup */
    };

    will_return(__wrap_sqlite3_column_int,    &d[0]);
    will_return(__wrap_sqlite3_column_text,   &d[1]);
    will_return(__wrap_strdup,                &d[2]);
    will_return(__wrap_sqlite3_column_bytes,  &d[3]);
    will_return(__wrap_sqlite3_column_blob,   &d[4]);
    will_return(twistbin_new,                 &d[5]);
    will_return(__wrap_sqlite3_column_text,   &d[6]);
    will_return(__wrap_strdup,                &d[7]);

    pobject_v3 pobj = { 0 };

    int rc = init_pobject_v3_from_stmt(BAD_PTR, &pobj);
    assert_int_equal(rc, SQLITE_ERROR);
}

static void init_tobjects_sqlite3_prepare_v2_fail(void **state) {
	UNUSED(state);

    will_return_data d[] = {
		{ .rc = SQLITE_ERROR },    /* sqlite3_prepare_v2 */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);

	int rc = __real_init_tobjects((token *)0xDEADBEEF);
	assert_int_not_equal(rc, SQLITE_OK);

}

static void init_tobjects_sqlite3_bind_int(void **state) {
	UNUSED(state);

	token t = {
		.id = 42
	};

    will_return_data d[] = {
		{ .rc = SQLITE_OK    },    /* sqlite3_prepare_v2 */
		{ .rc = SQLITE_ERROR },    /* sqlite3_bind_int */
		{ .rc = SQLITE_OK },       /* sqlite3_finalize */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);
    will_return(__wrap_sqlite3_bind_int  , &d[1]);
    will_return(__wrap_sqlite3_finalize,   &d[2]);

	int rc = __real_init_tobjects(&t);
	assert_int_not_equal(rc, SQLITE_OK);
}

static void init_tobjects_db_tobject_new_fail(void **state) {
    UNUSED(state);

    token t = {
        .id = 42
    };

    will_return_data d[] = {
        { .rc = SQLITE_OK  }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK  }, /* sqlite3_bind_int */
        { .rc = SQLITE_ROW }, /* sqlite3_step */
        { .data = NULL     }, /* db_tobject_new */
        { .rc = SQLITE_OK  }, /* sqlite3_finalize */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);
    will_return(__wrap_sqlite3_bind_int,   &d[1]);
    will_return(__wrap_sqlite3_step,       &d[2]);
    will_return(db_tobject_new,            &d[3]);
    will_return(__wrap_sqlite3_finalize,   &d[4]);

    int rc = __real_init_tobjects(&t);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void init_tobjects_token_add_tobject_last_fail(void **state) {

    token t = {
        .id = 42
    };

    will_return_data d[] = {
        { .rc = SQLITE_OK       }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK       }, /* sqlite3_bind_int */
        { .rc = SQLITE_ROW      }, /* sqlite3_step */
        { .data = *state        }, /* db_tobject_new call real */
        { .rv = CKR_HOST_MEMORY }, /* token_add_tobject_last */
        { .rc = SQLITE_OK       }, /* sqlite3_finalize */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);
    will_return(__wrap_sqlite3_bind_int,   &d[1]);
    will_return(__wrap_sqlite3_step,       &d[2]);
    will_return(db_tobject_new,            &d[3]);
    will_return(token_add_tobject_last,    &d[4]);
    will_return(__wrap_sqlite3_finalize,   &d[5]);

    int rc = __real_init_tobjects(&t);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_convert_pobject_v3_to_v4_emit_pobject_to_conf_string_fail(void **state) {
	UNUSED(state);

	pobject_v4 new_pobj = { 0 };

	pobject_v3 old_pobj = {
		.id = 42,
		.hierarchy = "o",
		.objauth = "foobarauth"
	};

    will_return_data d[] = {
		{ .data = NULL },    /* emit_pobject_to_conf_string */
    };

    will_return(emit_pobject_to_conf_string, &d[0]);

	CK_RV rv = convert_pobject_v3_to_v4(&old_pobj, &new_pobj);
	assert_int_equal(rv, CKR_HOST_MEMORY);
}

static void test_db_add_pobject_v4_sqlite3_prepare_v2_fail(void **state) {
	UNUSED(state);

    will_return_data d[] = {
		{ .rc = SQLITE_ERROR }, /* sqlite3_prepare_v2 */
		{ .rc = SQLITE_ERROR }  /* sqlite3_finalize (error for warning) */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);
    will_return(__wrap_sqlite3_finalize, &d[1]);

    pobject_v4 new_pobj = {
		.id = 1234,
		.config = "YAML CONFIG YEAH",
		.hierarchy = "o",
		.objauth = "foobarauth"
    };

	CK_RV rv = db_add_pobject_v4((sqlite3 *)0xDEADBEEF, &new_pobj);
	assert_int_not_equal(rv, CKR_OK);
}

static void test_db_add_pobject_v4_sqlite3_step_fail(void **state) {
	UNUSED(state);

    will_return_data d[] = {
		{ .rc = SQLITE_OK },       /* sqlite3_prepare_v2 */
		{ .rc = SQLITE_OK },       /* sqlite3_bind_int */
		{ .rc = SQLITE_OK },       /* sqlite3_bind_text */
		{ .rc = SQLITE_OK },       /* sqlite3_bind_text */
		{ .rc = SQLITE_OK },       /* sqlite3_bind_text */
		{ .rc = SQLITE_ERROR },    /* sqlite3_step */
		{ .rc = SQLITE_OK },       /* sqlite3_finalize */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);
    will_return(__wrap_sqlite3_bind_int,   &d[1]);
    will_return(__wrap_sqlite3_bind_text,  &d[2]);
    will_return(__wrap_sqlite3_bind_text,  &d[3]);
    will_return(__wrap_sqlite3_bind_text,  &d[4]);
    will_return(__wrap_sqlite3_step,       &d[5]);
    will_return(__wrap_sqlite3_finalize,   &d[6]);

    pobject_v4 new_pobj = {
		.id = 1234,
		.config = "YAML CONFIG YEAH",
		.hierarchy = "o",
		.objauth = "foobarauth"
    };

	CK_RV rv = db_add_pobject_v4((sqlite3 *)0xDEADBEEF, &new_pobj);
	assert_int_not_equal(rv, CKR_OK);
}

static void test_init_pobject_from_stmt_parse_pobject_config_from_string_fail(void **state) {
    UNUSED(state);

    pobject pobj = {0};

    const char *yaml_config = "really bad yaml";

    will_return_data d[] = {
        { .rc = strlen(yaml_config)   }, /* sqlite3_column_bytes */
        { .data = (void *)yaml_config }, /* sqlite3_column_text */
    };

    will_return(__wrap_sqlite3_column_bytes, &d[0]);
    will_return(__wrap_sqlite3_column_text,  &d[1]);

    int rc = init_pobject_from_stmt((sqlite3_stmt *)0xBADDCAFE, (tpm_ctx *)0xBADCC0DE, &pobj);
    pobject_free(&pobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_pobject_from_stmt_not_transient_no_blob_fail(void **state) {
    UNUSED(state);

    pobject pobj = {0};

    /*
     * convert text to C string easily:
     *   - https://tomeko.net/online_tools/cpp_text_escape.php?lang=en
     */
    const char *yaml_config =
        "---\n"
        "!!map {\n"
        "  ? !!str \"transient\"\n"
        "  : !!bool \"false\",\n"
        "}\n";

    will_return_data d[] = {
        { .rc = strlen(yaml_config)   }, /* sqlite3_column_bytes */
        { .data = (void *)yaml_config }, /* sqlite3_column_text */
    };

    will_return(__wrap_sqlite3_column_bytes, &d[0]);
    will_return(__wrap_sqlite3_column_text,  &d[1]);

    int rc = init_pobject_from_stmt((sqlite3_stmt *)0xBADDCAFE, (tpm_ctx *)0xBADCC0DE, &pobj);
    pobject_free(&pobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_pobject_from_stmt_tpm_deserialize_handle_fail(void **state) {
    UNUSED(state);

    pobject pobj = {0};

    /*
     * convert text to C string easily:
     *   - https://tomeko.net/online_tools/cpp_text_escape.php?lang=en
     */
    const char *yaml_config =
        "---\n"
        "!!map {\n"
        "  ? !!str \"esys-tr\"\n"
        "  : !!str \"810000000022000b7ddf69cda75fe70a5114890cb571af4b67667887b51640de9833d0ad7ae1fe9400000001011a0001000b00030072000000060080004300100800000000000100bbfeca8f754e03dce6bee3b5ba7536c0c7241cb84ae1401b9573ca88ea2c2caeaa7a462b9e8578719a7b8e5cd72f8790e2745833d87f89586fe3fc3ff09edc154519361a1a6676247b423ee6d39419ede7946ee3778b75c558464cbd1305382ec7fb2674986ad924ee5198dfcd32d29b0b9161ed9c7dc9bf935d10562870b7a192d40b2c1b4b255df08fb9ce6489ce9ca11ba85fedf09107316aa18442b2eeb6249cb495ed6b9de9421ebbb1313f2616b60045351253be475ddb712dc1f593e98950b52c90ddad7590556564f3725eccebeb0b0f409c83e81d6e8163054312d01f5551f53ebecbef6b5a58bce6df206837b5af27ae6c3983fecd5a003f115159\",\n"
        "  ? !!str \"transient\"\n"
        "  : !!bool \"false\",\n"
        "}";

    will_return_data d[] = {
        { .rc = strlen(yaml_config)   }, /* sqlite3_column_bytes */
        { .data = (void *)yaml_config }, /* sqlite3_column_text */
        { .rcb = false                }, /* tpm_deserialize_handle */
    };

    will_return(__wrap_sqlite3_column_bytes, &d[0]);
    will_return(__wrap_sqlite3_column_text,  &d[1]);
    will_return(tpm_deserialize_handle,      &d[2]);

    int rc = init_pobject_from_stmt((sqlite3_stmt *)0xBADDCAFE, (tpm_ctx *)0xBADCC0DE, &pobj);
    pobject_free(&pobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_pobject_from_stmt_tpm_create_transient_primary_from_template_fail(void **state) {
    UNUSED(state);

    pobject pobj = {0};

    /*
     * convert text to C string easily:
     *   - https://tomeko.net/online_tools/cpp_text_escape.php?lang=en
     */
    const char *yaml_config =
        "---\n"
        "!!map {\n"
        "  ? !!str \"template-name\"\n"
        "  : !!str \"tpm2-tools-default\",\n"
        "  ? !!str \"transient\"\n"
        "  : !!bool \"true\",\n"
        "}\n";

    will_return_data d[] = {
        { .call_real = true           }, /* strdup */
        { .rc = strlen(yaml_config)   }, /* sqlite3_column_bytes */
        { .data = (void *)yaml_config }, /* sqlite3_column_text */
        { .data = "fakeauth"          }, /* sqlite3_column_text */
        { .rc = SQLITE_DONE           }, /* sqlite3_step */
        { .rv = CKR_GENERAL_ERROR     }, /* tpm_create_transient_primary_from_template */
    };

    will_return_always(__wrap_strdup,                       &d[0]);
    will_return(__wrap_sqlite3_column_bytes,                &d[1]);
    will_return(__wrap_sqlite3_column_text,                 &d[2]);
    will_return(__wrap_sqlite3_column_text,                 &d[3]);
    will_return(__wrap_sqlite3_step,                        &d[4]);
    will_return(tpm_create_transient_primary_from_template, &d[5]);

    int rc = init_pobject_from_stmt((sqlite3_stmt *)0xBADDCAFE, (tpm_ctx *)0xBADCC0DE, &pobj);
    pobject_free(&pobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_pobject_from_stmt_missing_template_name_fail(void **state) {
    UNUSED(state);

    pobject pobj = {0};

    /*
     * convert text to C string easily:
     *   - https://tomeko.net/online_tools/cpp_text_escape.php?lang=en
     */
    const char *yaml_config =
        "---\n"
        "!!map {\n"
       "  ? !!str \"transient\"\n"
        "  : !!bool \"true\",\n"
        "}";

    will_return_data d[] = {
        { .rc = strlen(yaml_config)   }, /* sqlite3_column_bytes */
        { .data = (void *)yaml_config }, /* sqlite3_column_text */
    };

    will_return(__wrap_sqlite3_column_bytes, &d[0]);
    will_return(__wrap_sqlite3_column_text,  &d[1]);

    int rc = init_pobject_from_stmt((sqlite3_stmt *)0xBADDCAFE, (tpm_ctx *)0xBADCC0DE, &pobj);
    pobject_free(&pobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_pobject_from_stmt_twist_new_fail(void **state) {
    UNUSED(state);

    pobject pobj = {0};

    /*
     * convert text to C string easily:
     *   - https://tomeko.net/online_tools/cpp_text_escape.php?lang=en
     */
    const char *yaml_config =
        "---\n"
        "!!map {\n"
        "  ? !!str \"esys-tr\"\n"
        "  : !!str \"810000000022000b7ddf69cda75fe70a5114890cb571af4b67667887b51640de9833d0ad7ae1fe9400000001011a0001000b00030072000000060080004300100800000000000100bbfeca8f754e03dce6bee3b5ba7536c0c7241cb84ae1401b9573ca88ea2c2caeaa7a462b9e8578719a7b8e5cd72f8790e2745833d87f89586fe3fc3ff09edc154519361a1a6676247b423ee6d39419ede7946ee3778b75c558464cbd1305382ec7fb2674986ad924ee5198dfcd32d29b0b9161ed9c7dc9bf935d10562870b7a192d40b2c1b4b255df08fb9ce6489ce9ca11ba85fedf09107316aa18442b2eeb6249cb495ed6b9de9421ebbb1313f2616b60045351253be475ddb712dc1f593e98950b52c90ddad7590556564f3725eccebeb0b0f409c83e81d6e8163054312d01f5551f53ebecbef6b5a58bce6df206837b5af27ae6c3983fecd5a003f115159\",\n"
        "  ? !!str \"transient\"\n"
        "  : !!bool \"false\",\n"
        "}";

    will_return_data d[] = {
        { .rc = strlen(yaml_config)   }, /* sqlite3_column_bytes */
        { .data = (void *)yaml_config }, /* sqlite3_column_text */
        { .rcb = true                 }, /* tpm_deserialize_handle */
        { .data = NULL                }, /* sqlite3_column_text */
    };

    will_return(__wrap_sqlite3_column_bytes, &d[0]);
    will_return(__wrap_sqlite3_column_text,  &d[1]);
    will_return(tpm_deserialize_handle,      &d[2]);
    will_return(__wrap_sqlite3_column_text,  &d[3]);

    int rc = init_pobject_from_stmt((sqlite3_stmt *)0xBADDCAFE, (tpm_ctx *)0xBADCC0DE, &pobj);
    pobject_free(&pobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_pobject_from_stmt_sqlite_step_fail(void **state) {
    UNUSED(state);

    pobject pobj = {0};

    /*
     * convert text to C string easily:
     *   - https://tomeko.net/online_tools/cpp_text_escape.php?lang=en
     */
    const char *yaml_config =
        "---\n"
        "!!map {\n"
        "  ? !!str \"esys-tr\"\n"
        "  : !!str \"810000000022000b7ddf69cda75fe70a5114890cb571af4b67667887b51640de9833d0ad7ae1fe9400000001011a0001000b00030072000000060080004300100800000000000100bbfeca8f754e03dce6bee3b5ba7536c0c7241cb84ae1401b9573ca88ea2c2caeaa7a462b9e8578719a7b8e5cd72f8790e2745833d87f89586fe3fc3ff09edc154519361a1a6676247b423ee6d39419ede7946ee3778b75c558464cbd1305382ec7fb2674986ad924ee5198dfcd32d29b0b9161ed9c7dc9bf935d10562870b7a192d40b2c1b4b255df08fb9ce6489ce9ca11ba85fedf09107316aa18442b2eeb6249cb495ed6b9de9421ebbb1313f2616b60045351253be475ddb712dc1f593e98950b52c90ddad7590556564f3725eccebeb0b0f409c83e81d6e8163054312d01f5551f53ebecbef6b5a58bce6df206837b5af27ae6c3983fecd5a003f115159\",\n"
        "  ? !!str \"transient\"\n"
        "  : !!bool \"false\",\n"
        "}";

    will_return_data d[] = {
        { .rc = strlen(yaml_config)   }, /* sqlite3_column_bytes */
        { .data = (void *)yaml_config }, /* sqlite3_column_text */
        { .rcb = true                 }, /* tpm_deserialize_handle */
        { .data = "fake auth data"    }, /* sqlite3_column_text */
        { .rc = SQLITE_ERROR          }  /* sqlite3_step */
    };

    will_return(__wrap_sqlite3_column_bytes, &d[0]);
    will_return(__wrap_sqlite3_column_text,  &d[1]);
    will_return(tpm_deserialize_handle,      &d[2]);
    will_return(__wrap_sqlite3_column_text,  &d[3]);
    will_return(__wrap_sqlite3_step,         &d[4]);

    int rc = init_pobject_from_stmt((sqlite3_stmt *)0xBADDCAFE, (tpm_ctx *)0xBADCC0DE, &pobj);
    pobject_free(&pobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_pobject_sqlite_prepare_v2_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .rc = SQLITE_ERROR          }, /* sqlite3_prepare_v2 */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);

    int rc = __real_init_pobject(1, NULL, NULL);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_pobject_sqlite_bind_int_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .rc = SQLITE_OK          }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ERROR       }, /* sqlite3_bind_int */
        { .rc = SQLITE_OK          }, /* sqlite3_finalize */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);
    will_return(__wrap_sqlite3_bind_int,   &d[1]);
    will_return(__wrap_sqlite3_finalize,   &d[2]);

    int rc = __real_init_pobject(1, NULL, NULL);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_pobject_sqlite_step_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .rc = SQLITE_OK          }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK          }, /* sqlite3_bind_int */
        { .rc = SQLITE_ERROR       }, /* sqlite3_step */
        { .rc = SQLITE_OK          }, /* sqlite3_finalize */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);
    will_return(__wrap_sqlite3_bind_int,   &d[1]);
    will_return(__wrap_sqlite3_step,       &d[2]);
    will_return(__wrap_sqlite3_finalize,   &d[3]);

    int rc = __real_init_pobject(1, NULL, NULL);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_sealobjects_sqlite3_prepare_v2_fail(void **state) {
    UNUSED(state);

    sealobject sobj = { 0 };

    will_return_data d[] = {
        { .rc = SQLITE_ERROR          }, /* sqlite3_prepare_v2 */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);

    int rc = __real_init_sealobjects(42, &sobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_sealobjects_sqlite3_bind_int_fail(void **state) {
    UNUSED(state);

    sealobject sobj = { 0 };

    will_return_data d[] = {
        { .rc = SQLITE_OK       }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ERROR    }, /* sqlite3_bind_int */
        { .rc = SQLITE_OK          }, /* sqlite3_finalize */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);
    will_return(__wrap_sqlite3_bind_int,   &d[1]);
    will_return(__wrap_sqlite3_finalize,   &d[2]);

    int rc = __real_init_sealobjects(42, &sobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_sealobjects_sqlite3_step_fail(void **state) {
    UNUSED(state);

    sealobject sobj = { 0 };

    will_return_data d[] = {
        { .rc = SQLITE_OK          }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK          }, /* sqlite3_bind_int */
        { .rc = SQLITE_ERROR       }, /* sqlite3_step */
        { .rc = SQLITE_OK          }, /* sqlite3_finalize */
    };

    will_return(__wrap_sqlite3_prepare_v2, &d[0]);
    will_return(__wrap_sqlite3_bind_int,   &d[1]);
    will_return(__wrap_sqlite3_step,       &d[2]);
    will_return(__wrap_sqlite3_finalize,   &d[3]);

    int rc = __real_init_sealobjects(42, &sobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_init_sealobjects_bad_col_name_fail(void **state) {
    UNUSED(state);

    sealobject sobj = { 0 };

    will_return_data d[] = {
        { .rc = SQLITE_OK          }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK          }, /* sqlite3_bind_int */
        { .rc = SQLITE_ROW         }, /* sqlite3_step */
        { .rc = 1                  }, /* sqlite3_data_count */
        { .data = "bad col name"   }, /* sqlite3_column_name */
        { .rc = SQLITE_OK          }, /* sqlite3_finalize */
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);
    will_return(__wrap_sqlite3_bind_int,    &d[1]);
    will_return(__wrap_sqlite3_step,        &d[2]);
    will_return(__wrap_sqlite3_data_count,  &d[3]);
    will_return(__wrap_sqlite3_column_name, &d[4]);
    will_return(__wrap_sqlite3_finalize,    &d[5]);

    int rc = __real_init_sealobjects(42, &sobj);
    assert_int_not_equal(rc, SQLITE_OK);
}

static void test_db_get_tokens_calloc_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .data = NULL        }, /* calloc */
    };

    will_return(__wrap_calloc,  &d[0]);

    size_t len = 0;
    token *t = NULL;

    CK_RV rv = db_get_tokens(&t, &len);
    assert_int_equal(rv, CKR_HOST_MEMORY);
}

static void test_db_get_tokens_sqlite3_prepare_v2_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .call_real = true           }, /* calloc */
        { .rc = SQLITE_ERROR          }, /* sqlite3_prepare_v2 */
    };

    will_return(__wrap_calloc,              &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,  &d[1]);

    CK_RV rv = db_get_tokens(NULL, NULL);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_get_tokens_token_overcount_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .call_real = true           }, /* calloc */
        { .rc = SQLITE_OK             }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ROW            }, /* sqlite3_step */
        { .rc = 0                     }, /* sqlite3_data_count (no per token data)*/
        { .rv = CKR_OK                }, /* token_min_init */
        { .rc = SQLITE_OK             }, /* init_pobject */
        { .rc = SQLITE_OK             }, /* sqlite3_finalize */
    };

    will_return_always(__wrap_calloc,              &d[0]);
    will_return_always(__wrap_sqlite3_prepare_v2,  &d[1]);
    will_return_always(__wrap_sqlite3_step,        &d[2]);
    will_return_always(__wrap_sqlite3_data_count,  &d[3]);
    will_return_always(token_min_init,             &d[4]);
    will_return_always(init_pobject,               &d[5]);
    will_return(__wrap_sqlite3_finalize,           &d[6]);

    CK_RV rv = db_get_tokens(NULL, NULL);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_get_tokens_init_seal_objects_fail(void **state) {
    UNUSED(state);

    token t = {
        .config = {
            .is_initialized = true
        }
    };

    will_return_data d[] = {
        { .call_real = true           }, /* calloc */
        { .rc = SQLITE_OK             }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ROW            }, /* sqlite3_step */
        { .rc = 0                     }, /* sqlite3_data_count (no per token data)*/
        { .rv = CKR_OK, .t = t        }, /* token_min_init */
        { .rc = SQLITE_OK             }, /* init_pobject */
        { .rc = SQLITE_ERROR          }, /* init_sealobjects */
        { .rc = SQLITE_OK             }, /* sqlite3_finalize */
    };

    will_return(__wrap_calloc,              &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,  &d[1]);
    will_return(__wrap_sqlite3_step,        &d[2]);
    will_return(__wrap_sqlite3_data_count,  &d[3]);
    will_return(token_min_init,             &d[4]);
    will_return(init_pobject,               &d[5]);
    will_return(init_sealobjects,           &d[6]);
    will_return(__wrap_sqlite3_finalize,    &d[7]);

    CK_RV rv = db_get_tokens(NULL, NULL);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_get_tokens_token_min_init_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .call_real = true           }, /* calloc */
        { .rc = SQLITE_OK             }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ROW            }, /* sqlite3_step */
        { .rc = 0                     }, /* sqlite3_data_count (no per token data)*/
        { .rv = CKR_GENERAL_ERROR     }, /* token_min_init */
        { .rc = SQLITE_OK             }, /* sqlite3_finalize */
    };

    will_return(__wrap_calloc,              &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,  &d[1]);
    will_return(__wrap_sqlite3_step,        &d[2]);
    will_return(__wrap_sqlite3_data_count,  &d[3]);
    will_return(token_min_init,             &d[4]);
    will_return(__wrap_sqlite3_finalize,    &d[5]);

    CK_RV rv = db_get_tokens(NULL, NULL);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_get_tokens_init_pobjects_fail(void **state) {
    UNUSED(state);

    token t = {
        .config = {
            .is_initialized = true
        }
    };

    will_return_data d[] = {
        { .call_real = true           }, /* calloc */
        { .rc = SQLITE_OK             }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ROW            }, /* sqlite3_step */
        { .rc = 0                     }, /* sqlite3_data_count (no per token data)*/
        { .rv = CKR_OK, .t = t        }, /* token_min_init */
        { .rc = SQLITE_ERROR          }, /* init_pobject */
        { .rc = SQLITE_OK             }, /* sqlite3_finalize */
    };

    will_return(__wrap_calloc,              &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,  &d[1]);
    will_return(__wrap_sqlite3_step,        &d[2]);
    will_return(__wrap_sqlite3_data_count,  &d[3]);
    will_return(token_min_init,             &d[4]);
    will_return(init_pobject,               &d[5]);
    will_return(__wrap_sqlite3_finalize,    &d[6]);

    CK_RV rv = db_get_tokens(NULL, NULL);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_get_tokens_init_tobjects_fail(void **state) {
    UNUSED(state);

    token t = {
        .config = {
            .is_initialized = true
        }
    };

    will_return_data d[] = {
        { .call_real = true           }, /* calloc */
        { .rc = SQLITE_OK             }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ROW            }, /* sqlite3_step */
        { .rc = 0                     }, /* sqlite3_data_count (no per token data)*/
        { .rv = CKR_OK, .t = t        }, /* token_min_init */
        { .rc = SQLITE_OK             }, /* init_pobject */
        { .rc = SQLITE_OK             }, /* init_sealobjects */
        { .rc = SQLITE_ERROR          }, /* init_tobjects */
        { .rc = SQLITE_OK             }, /* sqlite3_finalize */
    };

    will_return(__wrap_calloc,              &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,  &d[1]);
    will_return(__wrap_sqlite3_step,        &d[2]);
    will_return(__wrap_sqlite3_data_count,  &d[3]);
    will_return(token_min_init,             &d[4]);
    will_return(init_pobject,               &d[5]);
    will_return(init_sealobjects,           &d[6]);
    will_return(init_tobjects,              &d[7]);
    will_return(__wrap_sqlite3_finalize,    &d[8]);

    CK_RV rv = db_get_tokens(NULL, NULL);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_get_tokens_config_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .call_real = true           }, /* calloc */
        { .rc = SQLITE_OK             }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ROW            }, /* sqlite3_step */
        { .data = "config"            }, /* sqlite3_column_name*/
        { .rc = 1                     }, /* sqlite3_data_count */
        { .rc = 0                     }, /* sqlite3_column_bytes */
        { .data = NULL                }, /* sqlite3_column_text */
        { .rc = SQLITE_OK             }, /* sqlite3_finalize */
    };

    will_return(__wrap_calloc,                &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,    &d[1]);
    will_return(__wrap_sqlite3_step,          &d[2]);
    will_return(__wrap_sqlite3_column_name,   &d[3]);
    will_return(__wrap_sqlite3_data_count,    &d[4]);
    will_return(__wrap_sqlite3_column_bytes,  &d[5]);
    will_return(__wrap_sqlite3_column_text,   &d[6]);
    will_return(__wrap_sqlite3_finalize,      &d[7]);

    CK_RV rv = db_get_tokens(NULL, NULL);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_get_tokens_parse_token_config_from_string_fail(void **state) {
    UNUSED(state);

    const char *yaml_data = "bad yaml";

    will_return_data d[] = {
        { .call_real = true           }, /* calloc */
        { .rc = SQLITE_OK             }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ROW            }, /* sqlite3_step */
        { .rc = 1                     }, /* sqlite3_data_count */
        { .data = "config"            }, /* sqlite3_column_name*/
        { .rc = strlen(yaml_data)     }, /* sqlite3_column_bytes */
        { .data = (void *)yaml_data   }, /* sqlite3_column_text */
        { .rc = SQLITE_OK             }, /* sqlite3_finalize */
    };

    will_return(__wrap_calloc,                &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,    &d[1]);
    will_return(__wrap_sqlite3_step,          &d[2]);
    will_return(__wrap_sqlite3_data_count,    &d[3]);
    will_return(__wrap_sqlite3_column_name,   &d[4]);
    will_return(__wrap_sqlite3_column_bytes,  &d[5]);
    will_return(__wrap_sqlite3_column_text,   &d[6]);
    will_return(__wrap_sqlite3_finalize,      &d[7]);

    CK_RV rv = db_get_tokens(NULL, NULL);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_get_tokens_parse_token_unknown_key_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .call_real = true           }, /* calloc */
        { .rc = SQLITE_OK             }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ROW            }, /* sqlite3_step */
        { .rc = 1                     }, /* sqlite3_data_count */
        { .data = "unknown"           }, /* sqlite3_column_name*/
        { .rc = SQLITE_OK             }, /* sqlite3_finalize */
    };

    will_return(__wrap_calloc,                &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,    &d[1]);
    will_return(__wrap_sqlite3_step,          &d[2]);
    will_return(__wrap_sqlite3_data_count,    &d[3]);
    will_return(__wrap_sqlite3_column_name,   &d[4]);
    will_return(__wrap_sqlite3_finalize,      &d[5]);

    CK_RV rv = db_get_tokens(NULL, NULL);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_for_pinchange_sqlite3_prepare_v2_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .rc = SQLITE_ERROR             }, /* sqlite3_prepare_v2 */
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);

    CK_RV rv = db_update_for_pinchange(
            NULL,
            true,
            NULL,
            (twist)0xDEADBEEF,
            (twist)0xDEADBEEF);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_for_pinchange_start_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .rc = SQLITE_OK    }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ERROR }, /* sqlite3_exec (BEGIN TRANSACTION) */
        { .rc = SQLITE_OK    }, /* sqlite3_finalize */
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);
    will_return(__wrap_sqlite3_exec,        &d[1]);
    will_return(__wrap_sqlite3_finalize,    &d[2]);

    CK_RV rv = db_update_for_pinchange(
            NULL,
            true,
            NULL,
            (twist)0xDEADBEEF,
            (twist)0xDEADBEEF);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_for_pinchange_sqlite3_bind_text_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .rc = SQLITE_OK                }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (BEGIN TRANSACTION)*/
        { .rc = SQLITE_ERROR             }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (ROLLBACK)*/
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);
    will_return(__wrap_sqlite3_exec,        &d[1]);
    will_return(__wrap_sqlite3_bind_text,   &d[2]);
    will_return(__wrap_sqlite3_finalize,    &d[3]);
    will_return(__wrap_sqlite3_exec,        &d[4]);

    CK_RV rv = db_update_for_pinchange(
            NULL,
            true,
            NULL,
            (twist)0xDEADBEEF,
            (twist)0xDEADBEEF);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_for_pinchange_sqlite3_bind_private_blob_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .rc = SQLITE_OK                }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (BEGIN TRANSACTION)*/
        { .rc = SQLITE_OK                }, /* sqlite3_bind_text */
        { .rc = SQLITE_ERROR             }, /* sqlite3_bind_blob */
        { .rc = SQLITE_OK                }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (ROLLBACK)*/
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);
    will_return(__wrap_sqlite3_exec,        &d[1]);
    will_return(__wrap_sqlite3_bind_text,   &d[2]);
    will_return(__wrap_sqlite3_bind_blob,   &d[3]);
    will_return(__wrap_sqlite3_finalize,    &d[4]);
    will_return(__wrap_sqlite3_exec,        &d[5]);

    twist twist_data  = twist_new("pubdata");
    assert_non_null(twist_data);

    CK_RV rv = db_update_for_pinchange(
            NULL,
            true,
            NULL,
            twist_data,
            twist_data);
    twist_free(twist_data);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_for_pinchange_sqlite3_bind_public_blob_fail(void **state) {
    UNUSED(state);

    will_return_data d[] = {
        { .rc = SQLITE_OK                }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (BEGIN TRANSACTION)*/
        { .rc = SQLITE_OK                }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_blob 1 */
        { .rc = SQLITE_ERROR             }, /* sqlite3_bind_blob 2 */
        { .rc = SQLITE_OK                }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (ROLLBACK)*/
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);
    will_return(__wrap_sqlite3_exec,        &d[1]);
    will_return(__wrap_sqlite3_bind_text,   &d[2]);
    will_return(__wrap_sqlite3_bind_blob,   &d[3]);
    will_return(__wrap_sqlite3_bind_blob,   &d[4]);
    will_return(__wrap_sqlite3_finalize,    &d[5]);
    will_return(__wrap_sqlite3_exec,        &d[6]);

    twist twist_data  = twist_new("pubdata");
    assert_non_null(twist_data);

    CK_RV rv = db_update_for_pinchange(
            NULL,
            true,
            NULL,
            twist_data,
            twist_data);
    twist_free(twist_data);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_for_pinchange_sqlite3_bind_int_fail(void **state) {
    UNUSED(state);

    token t = { .id = 76 };

    will_return_data d[] = {
        { .rc = SQLITE_OK                }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (BEGIN TRANSACTION)*/
        { .rc = SQLITE_OK                }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_blob 1 */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_blob 2 */
        { .rc = SQLITE_ERROR             }, /* sqlite3_bind_int */
        { .rc = SQLITE_OK                }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (ROLLBACK)*/
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);
    will_return(__wrap_sqlite3_exec,        &d[1]);
    will_return(__wrap_sqlite3_bind_text,   &d[2]);
    will_return(__wrap_sqlite3_bind_blob,   &d[3]);
    will_return(__wrap_sqlite3_bind_blob,   &d[4]);
    will_return(__wrap_sqlite3_bind_int,    &d[5]);
    will_return(__wrap_sqlite3_finalize,    &d[6]);
    will_return(__wrap_sqlite3_exec,        &d[7]);

    twist twist_data  = twist_new("pubdata");
    assert_non_null(twist_data);

    CK_RV rv = db_update_for_pinchange(
            &t,
            true,
            NULL,
            twist_data,
            twist_data);
    twist_free(twist_data);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_for_pinchange_sqlite3_step_fail(void **state) {
    UNUSED(state);

    token t = { .id = 76 };

    will_return_data d[] = {
        { .rc = SQLITE_OK                }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (BEGIN TRANSACTION)*/
        { .rc = SQLITE_OK                }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_blob 1 */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_blob 2 */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_int */
        { .rc = SQLITE_ERROR             }, /* sqlite3_step */
        { .rc = SQLITE_OK                }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (ROLLBACK)*/
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);
    will_return(__wrap_sqlite3_exec,        &d[1]);
    will_return(__wrap_sqlite3_bind_text,   &d[2]);
    will_return(__wrap_sqlite3_bind_blob,   &d[3]);
    will_return(__wrap_sqlite3_bind_blob,   &d[4]);
    will_return(__wrap_sqlite3_bind_int,    &d[5]);
    will_return(__wrap_sqlite3_step,        &d[6]);
    will_return(__wrap_sqlite3_finalize,    &d[7]);
    will_return(__wrap_sqlite3_exec,        &d[8]);

    twist twist_data  = twist_new("pubdata");
    assert_non_null(twist_data);

    CK_RV rv = db_update_for_pinchange(
            &t,
            true,
            NULL,
            twist_data,
            twist_data);
    twist_free(twist_data);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_for_pinchange_sqlite3_finalize_fail(void **state) {
    UNUSED(state);

    token t = { .id = 76 };

    will_return_data d[] = {
        { .rc = SQLITE_OK                }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (BEGIN TRANSACTION)*/
        { .rc = SQLITE_OK                }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_blob 1 */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_blob 2 */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_int */
        { .rc = SQLITE_DONE              }, /* sqlite3_step */
        { .rc = SQLITE_ERROR             }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (ROLLBACK)*/
    };

    will_return(__wrap_sqlite3_prepare_v2,        &d[0]);
    will_return(__wrap_sqlite3_exec,              &d[1]);
    will_return(__wrap_sqlite3_bind_text,         &d[2]);
    will_return(__wrap_sqlite3_bind_blob,         &d[3]);
    will_return(__wrap_sqlite3_bind_blob,         &d[4]);
    will_return(__wrap_sqlite3_bind_int,          &d[5]);
    will_return(__wrap_sqlite3_step,              &d[6]);
    will_return(__wrap_sqlite3_finalize,          &d[7]);
    will_return(__wrap_sqlite3_exec,              &d[8]);

    twist twist_data  = twist_new("pubdata");
    assert_non_null(twist_data);

    CK_RV rv = db_update_for_pinchange(
            &t,
            true,
            NULL,
            twist_data,
            twist_data);
    twist_free(twist_data);
    /* Finalize is just a warning */
    assert_int_equal(rv, CKR_OK);
}

static void test_db_update_for_pinchange_commit_fail(void **state) {
    UNUSED(state);

    token t = { .id = 76 };

    will_return_data d[] = {
        { .rc = SQLITE_OK                }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                }, /* sqlite3_exec (BEGIN TRANSACTION)*/
        { .rc = SQLITE_OK                }, /* sqlite3_bind_blob 1 */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_blob 2 */
        { .rc = SQLITE_OK                }, /* sqlite3_bind_int */
        { .rc = SQLITE_OK                }, /* sqlite3_step */
        { .rc = SQLITE_OK                }, /* sqlite3_finalize */
        { .rc = SQLITE_ERROR             }, /* sqlite3_exec (ROLLBACK)*/
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);
    will_return(__wrap_sqlite3_exec,        &d[1]);
    will_return(__wrap_sqlite3_bind_text,   &d[2]);
    will_return(__wrap_sqlite3_bind_blob,   &d[3]);
    will_return(__wrap_sqlite3_bind_blob,   &d[4]);
    will_return(__wrap_sqlite3_bind_int,    &d[5]);
    will_return(__wrap_sqlite3_step,        &d[6]);
    will_return(__wrap_sqlite3_finalize,    &d[7]);
    will_return(__wrap_sqlite3_exec,        &d[8]);

    twist twist_data  = twist_new("pubdata");
    assert_non_null(twist_data);

    CK_RV rv = db_update_for_pinchange(
            &t,
            true,
            NULL,
            twist_data,
            twist_data);
    twist_free(twist_data);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_add_new_object_emit_attributes_to_string_fail(void **state) {
    UNUSED(state);

    token t = { .id = 76 };
    tobject tobj = { 0 };

    will_return_data d[] = {
        { .data = NULL                }, /* emit_attributes_to_string */
    };

    will_return(emit_attributes_to_string,        &d[0]);

    CK_RV rv = db_add_new_object(&t, &tobj);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_add_new_object_sqlite3_prepare_v2_fail(void **state) {
    UNUSED(state);

    token t = { .id = 76 };
    tobject tobj = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("attrs in yaml") }, /* emit_attributes_to_string */
        { .rc = SQLITE_ERROR                     }, /* sqlite3_prepare_v2 */
    };

    assert_non_null(d[0].data);

    will_return(emit_attributes_to_string,  &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,  &d[1]);

    CK_RV rv = db_add_new_object(&t, &tobj);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_add_new_object_sqlite_step_fail(void **state) {
    UNUSED(state);

    token t = { .id = 76 };
    tobject tobj = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("attrs in yaml") }, /* emit_attributes_to_string */
        { .rc = SQLITE_OK                        }, /* sqlite_exec (BEGIN TRANSACTION) */
        { .rc = SQLITE_OK                        }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                        }, /* sqlite3_bind_int */
        { .rc = SQLITE_OK                        }, /* sqlite3_bind_text */
        { .rc = SQLITE_ERROR                     }, /* sqlite3_step */
        { .rc = SQLITE_OK                        }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                        }, /* sqlite_exec (ROLLBACK) */
    };

    assert_non_null(d[0].data);

    will_return(emit_attributes_to_string,  &d[0]);
    will_return(__wrap_sqlite3_exec,        &d[1]);
    will_return(__wrap_sqlite3_prepare_v2,  &d[2]);
    will_return(__wrap_sqlite3_bind_int,    &d[3]);
    will_return(__wrap_sqlite3_bind_text,   &d[4]);
    will_return(__wrap_sqlite3_step,        &d[5]);
    will_return(__wrap_sqlite3_finalize,    &d[6]);
    will_return(__wrap_sqlite3_exec,        &d[7]);

    CK_RV rv = db_add_new_object(&t, &tobj);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_add_new_object_sqlite3_last_insert_rowid_fail(void **state) {
    UNUSED(state);

    token t = { .id = 76 };
    tobject tobj = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("attrs in yaml") }, /* emit_attributes_to_string */
        { .rc = SQLITE_OK                        }, /* sqlite_exec (BEGIN TRANSACTION) */
        { .rc = SQLITE_OK                        }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                        }, /* sqlite3_bind_int */
        { .rc = SQLITE_OK                        }, /* sqlite3_bind_text */
        { .rc = SQLITE_DONE                      }, /* sqlite3_step */
        { .u64 = 0                               }, /* sqlite3_last_insert_rowid */
        { .rc = SQLITE_ERROR                     }, /* sqlite3_finalize (force warning) */
        { .rc = SQLITE_OK                        }, /* sqlite_exec (ROLLBACK) */
    };

    assert_non_null(d[0].data);

    will_return(emit_attributes_to_string,        &d[0]);
    will_return(__wrap_sqlite3_exec,              &d[1]);
    will_return(__wrap_sqlite3_prepare_v2,        &d[2]);
    will_return(__wrap_sqlite3_bind_int,          &d[3]);
    will_return(__wrap_sqlite3_bind_text,         &d[4]);
    will_return(__wrap_sqlite3_step,              &d[5]);
    will_return(__wrap_sqlite3_last_insert_rowid, &d[6]);
    will_return(__wrap_sqlite3_finalize,          &d[7]);
    will_return(__wrap_sqlite3_exec,              &d[8]);

    CK_RV rv = db_add_new_object(&t, &tobj);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_delete_object_sqlite3_prepare_v2_fail(void **state) {
    UNUSED(state);

    tobject tobj = { 0 };

    will_return_data d[] = {
        { .rc = SQLITE_ERROR }, /* sqlite3_prepare_v2 */
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);

    CK_RV rv = db_delete_object(&tobj);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_delete_object_sqlite3_bind_int_fail(void **state) {
    UNUSED(state);

    tobject tobj = { 0 };

    will_return_data d[] = {
        { .rc = SQLITE_OK                        }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                        }, /* sqlite_exec (BEGIN TRANSACTION) */
        { .rc = SQLITE_ERROR                     }, /* sqlite3_bind_int */
        { .rc = SQLITE_OK                        }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                        }, /* sqlite_exec (ROLLBACK) */
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);
    will_return(__wrap_sqlite3_exec,        &d[1]);
    will_return(__wrap_sqlite3_bind_int,    &d[2]);
    will_return(__wrap_sqlite3_finalize,    &d[3]);
    will_return(__wrap_sqlite3_exec,        &d[4]);

    CK_RV rv = db_delete_object(&tobj);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_delete_object_sqlite3_step_fail(void **state) {
    UNUSED(state);

    tobject tobj = { 0 };

    will_return_data d[] = {
        { .rc = SQLITE_OK                        }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                        }, /* sqlite_exec (BEGIN TRANSACTION) */
        { .rc = SQLITE_OK                        }, /* sqlite3_bind_int */
        { .rc = SQLITE_ERROR                     }, /* sqlite3_step */
        { .rc = SQLITE_ERROR                     }, /* sqlite3_finalize (force warning) */
        { .rc = SQLITE_OK                        }, /* sqlite_exec (ROLLBACK) */
    };

    will_return(__wrap_sqlite3_prepare_v2,  &d[0]);
    will_return(__wrap_sqlite3_exec,        &d[1]);
    will_return(__wrap_sqlite3_bind_int,    &d[2]);
    will_return(__wrap_sqlite3_step,        &d[3]);
    will_return(__wrap_sqlite3_finalize,    &d[4]);
    will_return(__wrap_sqlite3_exec,        &d[5]);

    CK_RV rv = db_delete_object(&tobj);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_db_add_primary_emit_pobject_to_conf_string_fail(void **state) {
    UNUSED(state);

    unsigned pid = 0;
    pobject pobj = { 0 };

    will_return_data d[] = {
        { .data = NULL       }, /* emit_pobject_to_conf_string */
    };

    will_return(emit_pobject_to_conf_string, &d[0]);

    CK_RV rv = db_add_primary(&pobj, &pid);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_db_add_primary_sqlite3_prepare_v2_fail(void **state) {
    UNUSED(state);

    unsigned pid = 0;
    pobject pobj = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("foobar") }, /* emit_pobject_to_conf_string */
        { .rc = SQLITE_ERROR }, /* sqlite3_prepare_v2 */
    };

    will_return(emit_pobject_to_conf_string, &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,   &d[1]);

    CK_RV rv = db_add_primary(&pobj, &pid);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_db_add_primary_sqlite3_bind_text_fail(void **state) {
    UNUSED(state);

    unsigned pid = 0;
    pobject pobj = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("foobar") }, /* emit_pobject_to_conf_string */
        { .rc = SQLITE_OK    }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK    }, /* sqlite_exec (BEGIN TRANSACTION) */
        { .rc = SQLITE_ERROR }, /* sqlite3_bind_text */
        { .rc = SQLITE_ERROR }, /* sqlite3_finalize (force warning) */
        { .rc = SQLITE_OK    }, /* sqlite_exec (ROLLBACK) */
    };

    will_return(emit_pobject_to_conf_string, &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,   &d[1]);
    will_return(__wrap_sqlite3_exec,         &d[2]);
    will_return(__wrap_sqlite3_bind_text,    &d[3]);
    will_return(__wrap_sqlite3_finalize,     &d[4]);
    will_return(__wrap_sqlite3_exec,         &d[5]);

    CK_RV rv = db_add_primary(&pobj, &pid);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_db_add_primary_sqlite3_bind_text_2_fail(void **state) {
    UNUSED(state);

    unsigned pid = 0;
    pobject pobj = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("foobar") }, /* emit_pobject_to_conf_string */
        { .rc = SQLITE_OK                 }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                 }, /* sqlite_exec (BEGIN TRANSACTION) */
        { .rc = SQLITE_OK                 }, /* sqlite3_bind_text */
        { .rc = SQLITE_ERROR              }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                 }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                 }, /* sqlite_exec (ROLLBACK) */
    };

    assert_non_null(d[0].data);

    will_return(emit_pobject_to_conf_string, &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,   &d[1]);
    will_return(__wrap_sqlite3_exec,         &d[2]);
    will_return(__wrap_sqlite3_bind_text,    &d[3]);
    will_return(__wrap_sqlite3_bind_text,    &d[4]);
    will_return(__wrap_sqlite3_finalize,     &d[5]);
    will_return(__wrap_sqlite3_exec,         &d[6]);

    CK_RV rv = db_add_primary(&pobj, &pid);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_db_add_primary_sqlite3_bind_text_3_fail(void **state) {
    UNUSED(state);

    unsigned pid = 0;
    pobject pobj = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("foobar") }, /* emit_pobject_to_conf_string */
        { .rc = SQLITE_OK                 }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                 }, /* sqlite_exec (BEGIN TRANSACTION) */
        { .rc = SQLITE_OK                 }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                 }, /* sqlite3_bind_text */
        { .rc = SQLITE_ERROR              }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                 }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                 }, /* sqlite_exec (ROLLBACK) */
    };

    assert_non_null(d[0].data);

    will_return(emit_pobject_to_conf_string, &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,   &d[1]);
    will_return(__wrap_sqlite3_exec,         &d[2]);
    will_return(__wrap_sqlite3_bind_text,    &d[3]);
    will_return(__wrap_sqlite3_bind_text,    &d[4]);
    will_return(__wrap_sqlite3_bind_text,    &d[5]);
    will_return(__wrap_sqlite3_finalize,     &d[6]);
    will_return(__wrap_sqlite3_exec,         &d[7]);

    CK_RV rv = db_add_primary(&pobj, &pid);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_db_add_primary_sqlite3_step_fail(void **state) {
    UNUSED(state);

    unsigned pid = 0;
    pobject pobj = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("foobar") }, /* emit_pobject_to_conf_string */
        { .rc = SQLITE_OK                 }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                 }, /* sqlite_exec (BEGIN TRANSACTION) */
        { .rc = SQLITE_OK                 }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                 }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                 }, /* sqlite3_bind_text */
        { .rc = SQLITE_ERROR              }, /* sqlite3_step */
        { .rc = SQLITE_OK                 }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                 }, /* sqlite_exec (BEGIN TRANSACTION) */
    };

    assert_non_null(d[0].data);

    will_return(emit_pobject_to_conf_string, &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,   &d[1]);
    will_return(__wrap_sqlite3_exec,         &d[2]);
    will_return(__wrap_sqlite3_bind_text,    &d[3]);
    will_return(__wrap_sqlite3_bind_text,    &d[4]);
    will_return(__wrap_sqlite3_bind_text,    &d[5]);
    will_return(__wrap_sqlite3_step,         &d[6]);
    will_return(__wrap_sqlite3_finalize,     &d[7]);
    will_return(__wrap_sqlite3_exec,         &d[8]);
    CK_RV rv = db_add_primary(&pobj, &pid);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_db_add_primary_sqlite3_last_insert_rowid_fail(void **state) {
    UNUSED(state);

    unsigned pid = 0;
    pobject pobj = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("foobar") }, /* emit_pobject_to_conf_string */
        { .rc = SQLITE_OK                 }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                 }, /* sqlite_exec (BEGIN TRANSACTION) */
        { .rc = SQLITE_OK                 }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                 }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                 }, /* sqlite3_bind_text */
        { .rc = SQLITE_DONE               }, /* sqlite3_step */
        { .u64 = 0                        }, /* sqlite3_last_insert_rowid */
        { .rc = SQLITE_OK                 }, /* sqlite3_finalize */
        { .rc = SQLITE_OK                 }, /* sqlite_exec (ROLLBACK) */
    };

    assert_non_null(d[0].data);

    will_return(emit_pobject_to_conf_string,      &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,        &d[1]);
    will_return(__wrap_sqlite3_exec,              &d[2]);
    will_return(__wrap_sqlite3_bind_text,         &d[3]);
    will_return(__wrap_sqlite3_bind_text,         &d[4]);
    will_return(__wrap_sqlite3_bind_text,         &d[5]);
    will_return(__wrap_sqlite3_step,              &d[6]);
    will_return(__wrap_sqlite3_last_insert_rowid, &d[7]);
    will_return(__wrap_sqlite3_finalize,          &d[8]);
    will_return(__wrap_sqlite3_exec,              &d[9]);

    CK_RV rv = db_add_primary(&pobj, &pid);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_token_config_emit_config_to_string_fail(void **state) {
    UNUSED(state);

    token tok = { 0 };

    will_return_data d[] = {
        { .data = NULL }, /* emit_config_to_string */
    };

    will_return(emit_config_to_string,      &d[0]);

    CK_RV rv = db_update_token_config(&tok);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_token_sqlite3_prepare_v2_fail(void **state) {
    UNUSED(state);

    token tok = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("foobar") }, /* emit_config_to_string */
        { .rc = SQLITE_ERROR              }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                 }, /* sqlite3_finalize */
    };

    assert_non_null(d[0].data);

    will_return(emit_config_to_string,      &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,  &d[1]);
    will_return(__wrap_sqlite3_finalize,    &d[2]);

    CK_RV rv = db_update_token_config(&tok);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_token_sqlite3_bind_text_fail(void **state) {
    UNUSED(state);

    token tok = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("foobar") }, /* emit_config_to_string */
        { .rc = SQLITE_OK                 }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_ERROR              }, /* sqlite3_bind_text */
        { .rc = SQLITE_OK                 }, /* sqlite3_finalize */
    };

    assert_non_null(d[0].data);

    will_return(emit_config_to_string,      &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,  &d[1]);
    will_return(__wrap_sqlite3_bind_text,   &d[2]);
    will_return(__wrap_sqlite3_finalize,    &d[3]);

    CK_RV rv = db_update_token_config(&tok);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
}

static void test_db_update_token_sqlite3_bind_int_fail(void **state) {
    UNUSED(state);

    token tok = { 0 };

    will_return_data d[] = {
        { .data = __real_strdup("foobar") }, /* emit_config_to_string */
        { .rc = SQLITE_OK                 }, /* sqlite3_prepare_v2 */
        { .rc = SQLITE_OK                 }, /* sqlite3_bind_text */
        { .rc = SQLITE_ERROR              }, /* sqlite3_bind_int */
        { .rc = SQLITE_OK                 }, /* sqlite3_finalize */
    };

    assert_non_null(d[0].data);

    will_return(emit_config_to_string,      &d[0]);
    will_return(__wrap_sqlite3_prepare_v2,  &d[1]);
    will_return(__wrap_sqlite3_bind_text,   &d[2]);
    will_return(__wrap_sqlite3_bind_int,    &d[3]);
    will_return(__wrap_sqlite3_finalize,    &d[4]);

    CK_RV rv = db_update_token_config(&tok);
    assert_int_equal(rv, CKR_GENERAL_ERROR);
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
		cmocka_unit_test(init_tobjects_db_tobject_new_fail),
		cmocka_unit_test(init_pobject_v3_from_stmt_sqlite3_column_text_fail),
		cmocka_unit_test(init_pobject_v3_from_stmt_strdup_fail),
		cmocka_unit_test(init_pobject_v3_from_stmt__get_blob_fail),
		cmocka_unit_test(init_pobject_v3_from_stmt_sqlite3_column_text2_fail),
		cmocka_unit_test(init_pobject_v3_from_stmt_strdup2_fail),
		cmocka_unit_test(init_tobjects_sqlite3_prepare_v2_fail),
		cmocka_unit_test(init_tobjects_sqlite3_bind_int),
		cmocka_unit_test_setup(init_tobjects_token_add_tobject_last_fail,
            tobject_setup),
		cmocka_unit_test(test_convert_pobject_v3_to_v4_emit_pobject_to_conf_string_fail),
		cmocka_unit_test(test_db_add_pobject_v4_sqlite3_prepare_v2_fail),
		cmocka_unit_test(test_db_add_pobject_v4_sqlite3_step_fail),
		cmocka_unit_test(test_init_pobject_from_stmt_parse_pobject_config_from_string_fail),
		cmocka_unit_test(test_init_pobject_from_stmt_not_transient_no_blob_fail),
		cmocka_unit_test(test_init_pobject_from_stmt_tpm_deserialize_handle_fail),
		cmocka_unit_test(test_init_pobject_from_stmt_tpm_create_transient_primary_from_template_fail),
		cmocka_unit_test(test_init_pobject_from_stmt_missing_template_name_fail),
        cmocka_unit_test(test_init_pobject_from_stmt_twist_new_fail),
        cmocka_unit_test(test_init_pobject_from_stmt_sqlite_step_fail),
        cmocka_unit_test(test_init_pobject_sqlite_prepare_v2_fail),
        cmocka_unit_test(test_init_pobject_sqlite_bind_int_fail),
        cmocka_unit_test(test_init_pobject_sqlite_step_fail),
        cmocka_unit_test(test_init_sealobjects_sqlite3_prepare_v2_fail),
        cmocka_unit_test(test_init_sealobjects_sqlite3_bind_int_fail),
        cmocka_unit_test(test_init_sealobjects_sqlite3_step_fail),
        cmocka_unit_test(test_init_sealobjects_bad_col_name_fail),
        cmocka_unit_test(test_db_get_tokens_calloc_fail),
        cmocka_unit_test(test_db_get_tokens_sqlite3_prepare_v2_fail),
        cmocka_unit_test(test_db_get_tokens_token_overcount_fail),
        cmocka_unit_test(test_db_get_tokens_token_min_init_fail),
        cmocka_unit_test(test_db_get_tokens_init_pobjects_fail),
        cmocka_unit_test(test_db_get_tokens_init_seal_objects_fail),
        cmocka_unit_test(test_db_get_tokens_init_tobjects_fail),
        cmocka_unit_test(test_db_get_tokens_config_fail),
        cmocka_unit_test(test_db_get_tokens_parse_token_config_from_string_fail),
        cmocka_unit_test(test_db_get_tokens_parse_token_unknown_key_fail),
        cmocka_unit_test(test_db_update_for_pinchange_sqlite3_prepare_v2_fail),
        cmocka_unit_test(test_db_update_for_pinchange_start_fail),
        cmocka_unit_test(test_db_update_for_pinchange_sqlite3_bind_text_fail),
        cmocka_unit_test(test_db_update_for_pinchange_sqlite3_bind_private_blob_fail),
        cmocka_unit_test(test_db_update_for_pinchange_sqlite3_bind_public_blob_fail),
        cmocka_unit_test(test_db_update_for_pinchange_sqlite3_bind_int_fail),
        cmocka_unit_test(test_db_update_for_pinchange_sqlite3_step_fail),
        cmocka_unit_test(test_db_update_for_pinchange_sqlite3_finalize_fail),
        cmocka_unit_test(test_db_update_for_pinchange_commit_fail),
        cmocka_unit_test(test_db_add_new_object_emit_attributes_to_string_fail),
        cmocka_unit_test(test_db_add_new_object_sqlite3_prepare_v2_fail),
        cmocka_unit_test(test_db_add_new_object_sqlite_step_fail),
        cmocka_unit_test(test_db_add_new_object_sqlite3_last_insert_rowid_fail),
        cmocka_unit_test(test_db_delete_object_sqlite3_prepare_v2_fail),
        cmocka_unit_test(test_db_delete_object_sqlite3_bind_int_fail),
        cmocka_unit_test(test_db_delete_object_sqlite3_step_fail),
        cmocka_unit_test(test_db_db_add_primary_emit_pobject_to_conf_string_fail),
        cmocka_unit_test(test_db_db_add_primary_sqlite3_prepare_v2_fail),
        cmocka_unit_test(test_db_db_add_primary_sqlite3_bind_text_fail),
        cmocka_unit_test(test_db_db_add_primary_sqlite3_bind_text_2_fail),
        cmocka_unit_test(test_db_db_add_primary_sqlite3_bind_text_3_fail),
        cmocka_unit_test(test_db_db_add_primary_sqlite3_step_fail),
        cmocka_unit_test(test_db_db_add_primary_sqlite3_last_insert_rowid_fail),
        cmocka_unit_test(test_db_update_token_config_emit_config_to_string_fail),
        cmocka_unit_test(test_db_update_token_sqlite3_prepare_v2_fail),
        cmocka_unit_test(test_db_update_token_sqlite3_bind_text_fail),
        cmocka_unit_test(test_db_update_token_sqlite3_bind_int_fail),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
