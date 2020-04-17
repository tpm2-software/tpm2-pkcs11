/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>

#include <linux/limits.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sqlite3.h>

#include "db.h"
#include "emitter.h"
#include "log.h"
#include "mutex.h"
#include "object.h"
#include "parser.h"
#include "session_table.h"
#include "token.h"
#include "tpm.h"
#include "twist.h"
#include "utils.h"

#include <openssl/evp.h>

#ifndef TPM2_PKCS11_STORE_DIR
#define TPM2_PKCS11_STORE_DIR "/etc/tpm2_pkcs11"
#endif

#define DB_VERSION 3

#define goto_oom(x, l) if (!x) { LOGE("oom"); goto l; }
#define goto_error(x, l) if (x) { goto l; }

static struct {
    sqlite3 *db;
} global;

static int _get_blob(sqlite3_stmt *stmt, int i, bool can_be_null, twist *blob) {

    int size = sqlite3_column_bytes(stmt, i);
    if (size < 0) {
        return 1;
    }

    if (size == 0) {
        return can_be_null ? 0 : 1;
    }

    const void *data = sqlite3_column_blob(stmt, i);
    *blob = twistbin_new(data, size);
    if (!*blob) {
        LOGE("oom");
        return 1;
    }

    return 0;
}

static int get_blob_null(sqlite3_stmt *stmt, int i, twist *blob) {

    return _get_blob(stmt, i, true, blob);
}

static int get_blob(sqlite3_stmt *stmt, int i, twist *blob) {

    return _get_blob(stmt, i, false, blob);
}

typedef struct token_get_cb_ud token_get_cb_ud;
struct token_get_cb_ud {
    size_t offset;
    size_t len;
    token *tokens;
};

static tobject *db_tobject_new(sqlite3_stmt *stmt) {

    tobject *tobj = tobject_new();
    if (!tobj) {
        LOGE("oom");
        return NULL;
    }

    int i;
    int col_count = sqlite3_data_count(stmt);
    for (i=0; i < col_count; i++) {
        const char *name = sqlite3_column_name(stmt, i);

        if (!strcmp(name, "id")) {
            tobj->id = sqlite3_column_int(stmt, i);

        } else if (!strcmp(name, "tokid")) {
            // Ignore sid we don't need it as token has that data.
        } else if (!strcmp(name, "attrs")) {

            int bytes = sqlite3_column_bytes(stmt, i);
            const unsigned char *attrs = sqlite3_column_text(stmt, i);
            if (!attrs || !bytes) {
                LOGE("tobject does not have attributes");
                goto error;
            }

            bool res = parse_attributes_from_string(attrs, bytes,
                    &tobj->attrs);
            if (!res) {
                LOGE("Could not parse DB attrs, got: \"%s\"", attrs);
                goto error;
            }
        } else {
            LOGE("Unknown row, got: %s", name);
            goto error;
        }
    }

    assert(tobj->id);

    CK_RV rv = object_init_from_attrs(tobj);
    if (rv != CKR_OK) {
        LOGE("Object initialization failed");
        goto error;
    }

    return tobj;

error:
    tobject_free(tobj);
    return NULL;
}

int init_tobjects(token *tok) {

    const char *sql =
            "SELECT * FROM tobjects WHERE tokid=?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot prepare tobject query: %s\n", sqlite3_errmsg(global.db));
        return rc;
    }

    rc = sqlite3_bind_int(stmt, 1, tok->id);
    if (rc != SQLITE_OK) {
        LOGE("Cannot bind tobject tokid: %s\n", sqlite3_errmsg(global.db));
        goto error;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {

        tobject *insert = db_tobject_new(stmt);
        if (!insert) {
            LOGE("Failed to initialize tobject from db");
            goto error;
        }

        CK_RV rv = token_add_tobject_last(tok, insert);
        if (rv != CKR_OK) {
            goto error;
        }
    }

    rc = SQLITE_OK;

error:
    sqlite3_finalize(stmt);
    return rc;
}

static int init_pobject(unsigned pid, pobject *pobj, tpm_ctx *tpm) {

    const char *sql =
            "SELECT handle,objauth FROM pobjects WHERE id=?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot prepare sobject query: %s\n", sqlite3_errmsg(global.db));
        return rc;
    }

    rc = sqlite3_bind_int(stmt, 1, pid);
    if (rc != SQLITE_OK) {
        LOGE("Cannot bind pobject id: %s\n", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        LOGE("stepping in pobjects, got: %s\n", sqlite3_errstr(rc));
        goto error;
    }

    twist blob = NULL;
    rc = _get_blob(stmt, 0, false, &blob);
    if (rc != SQLITE_OK) {
        LOGE("Cannot get ESYS_TR handle blob %s\n", sqlite3_errmsg(global.db));
        goto error;
    }


    bool res = tpm_deserialize_handle(tpm, blob, &pobj->handle);
    twist_free(blob);
    if (!res) {
        /* just set a general error as rc could be success right now */
        rc = SQLITE_ERROR;
        goto error;
    }

    pobj->objauth = twist_new((char *)sqlite3_column_text(stmt, 1));
    goto_oom(pobj->objauth, error);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOGE("stepping in pobjects, got: %s\n", sqlite3_errstr(rc));
        goto error;
    }

    rc = SQLITE_OK;

error:
    sqlite3_finalize(stmt);

    return rc;
}

CK_RV db_init_pobject(unsigned pid, pobject *pobj, tpm_ctx *tpm) {
    int rc = init_pobject(pid, pobj, tpm);
    return rc == SQLITE_OK ? CKR_OK : CKR_GENERAL_ERROR;
}

static int init_sealobjects(unsigned tokid, sealobject *sealobj) {

    const char *sql =
            "SELECT * FROM sealobjects WHERE tokid=?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot prepare sealobject query: %s\n", sqlite3_errmsg(global.db));
        return rc;
    }

    rc = sqlite3_bind_int(stmt, 1, tokid);
    if (rc != SQLITE_OK) {
        LOGE("Cannot bind tokid: %s\n", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        LOGE("stepping in sealobjects, got: %s\n", sqlite3_errstr(rc));
        goto error;
    }

    int i;
    int col_count = sqlite3_data_count(stmt);
    for (i=0; i < col_count; i++) {
        const char *name = sqlite3_column_name(stmt, i);

        if (!strcmp(name, "id")) {
            // pass
        } else if (!strcmp(name, "userauthsalt")) {
            const char *x = (const char *)sqlite3_column_text(stmt, i);
            if (x) {
                sealobj->userauthsalt = twist_new(x);
                goto_oom(sealobj->userauthsalt, error);
            }
        } else if (!strcmp(name, "userpriv")) {
            goto_error(get_blob_null(stmt, i, &sealobj->userpriv), error);
        } else if (!strcmp(name, "userpub")) {
            goto_error(get_blob_null(stmt, i, &sealobj->userpub), error);
        } else if (!strcmp(name, "soauthsalt")) {
            sealobj->soauthsalt = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sealobj->soauthsalt, error);
        } else if (!strcmp(name, "sopriv")) {
            goto_error(get_blob(stmt, i, &sealobj->sopriv), error);
        } else if (!strcmp(name, "sopub")) {
            goto_error(get_blob(stmt, i, &sealobj->sopub), error);
        } else if (!strcmp(name, "tokid")) {
            // pass
        } else {
            LOGE("Unknown token: %s", name);
            goto error;
        }
    }

    rc = SQLITE_OK;

error:
    sqlite3_finalize(stmt);

    return rc;
}

CK_RV db_get_tokens(token **tok, size_t *len) {

    size_t cnt = 0;

    token *tmp = calloc(MAX_TOKEN_CNT, sizeof(token));
    if (!tmp) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    const char *sql =
            "SELECT * FROM tokens";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(tmp);
        LOGE("Cannot prepare tobject query: %s\n", sqlite3_errmsg(global.db));
        return rc;
    }

    bool has_uninit_token = false;
    size_t row = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {

        if (cnt >= MAX_TOKEN_CNT) {
            LOGE("Too many tokens, must have less than %d", MAX_TOKEN_CNT);
            goto error;
        }

        token *t = &tmp[row++];
        int col_count = sqlite3_data_count(stmt);

        int i;
        for (i=0; i < col_count; i++) {
            const char *name = sqlite3_column_name(stmt, i);

            if (!strcmp(name, "id")) {
                t->id = sqlite3_column_int(stmt, i);

            } else if(!strcmp(name, "pid")) {
                t->pid = sqlite3_column_int(stmt, i);

            } else if (!strcmp(name, "label")) {
                snprintf((char *)t->label, sizeof(t->label), "%s",
                        sqlite3_column_text(stmt, i));

            } else if (!strcmp(name, "config")) {
                int bytes = sqlite3_column_bytes(stmt, i);
                const unsigned char *config = sqlite3_column_text(stmt, i);
                if (!config || !i) {
                    LOGE("Expected token config to contain config data");
                    goto error;
                }
                bool result = parse_token_config_from_string(config, bytes, &t->config);
                if (!result) {
                    LOGE("Could not parse token config, got: \"%s\"", config);
                    goto error;
                }

            } else {
                LOGE("Unknown key: %s", name);
                goto error;
            }
        } /* done with sql key value search */

        CK_RV rv = token_min_init(t);
        if (rv != CKR_OK) {
            goto error;
        }

        /* tokens in the DB store already have an associated primary object */
        int rc = init_pobject(t->pid, &t->pobject, t->tctx);
        if (rc != SQLITE_OK) {
            goto error;
        }

        if (!t->config.is_initialized) {
            has_uninit_token = true;
            LOGV("skipping further initialization of token tid: %u", t->id);
            continue;
        }

        rc = init_sealobjects(t->id, &t->sealobject);
        if (rc != SQLITE_OK) {
            goto error;
        }

        rc = init_tobjects(t);
        if (rc != SQLITE_OK) {
            goto error;
        }

        /* token initialized, bump cnt */
        cnt++;
    }

    /* if their was no unitialized token in the db, add it */
    if (!has_uninit_token) {
        if (cnt >= MAX_TOKEN_CNT) {
            LOGE("Too many tokens, must have less than %d", MAX_TOKEN_CNT);
            goto error;
        }

        token *t = &tmp[cnt++];
        t->id = cnt;
        CK_RV rv = token_min_init(t);
        if (rv != CKR_OK) {
            goto error;
        }
    }

    *tok = tmp;
    *len = cnt;
    sqlite3_finalize(stmt);

    return CKR_OK;

error:
    token_free_list(tmp, cnt);
    sqlite3_finalize(stmt);
    return CKR_GENERAL_ERROR;

}

static int start(void) {
    int rc = sqlite3_exec(global.db, "BEGIN TRANSACTION", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        LOGE("%s", sqlite3_errmsg(global.db));
    }
    return rc;
}

static int commit(void) {
    return sqlite3_exec(global.db, "COMMIT", NULL, NULL, NULL);
}

static int rollback(void) {
    return sqlite3_exec(global.db, "ROLLBACK", NULL, NULL, NULL);
}

#define gotobinderror(rc, msg) if (rc) { LOGE("cannot bind "msg); goto error; }

CK_RV db_update_for_pinchange(
        token *tok,
        bool is_so,

        /* new seal object auth metadata */
        twist newauthsalthex,

        /* private and public blobs */
        twist newprivblob,
        twist newpubblob) {

    sqlite3_stmt *stmt = NULL;

    int rc = start();
    if (rc != SQLITE_OK) {
        return CKR_GENERAL_ERROR;
    }

    char *sql = NULL;
    /* so update statements */
    if (is_so) {
        if (newpubblob) {
            sql = "UPDATE sealobjects SET"
                     " soauthsalt=?,"           /* index: 1 */
                     " sopriv=?,"               /* index: 2 */
                     " sopub=?"                 /* index: 3 */
                     " WHERE tokid=?";          /* index: 4 */
        } else {
            sql = "UPDATE sealobjects SET"
                 " soauthsalt=?,"           /* index: 1 */
                 " sopriv=?"                /* index: 2 */
                 " WHERE tokid=?";          /* index: 3 */
        }
    /* user */
    } else {
        if (newpubblob) {
            sql = "UPDATE sealobjects SET"
                     " userauthsalt=?,"           /* index: 1 */
                     " userpriv=?,"               /* index: 2 */
                     " userpub=?"                 /* index: 3 */
                     " WHERE tokid=?" ;           /* index: 4 */
        } else {
            sql = "UPDATE sealobjects SET"
                 " userauthsalt=?,"           /* index: 1 */
                 " userpriv=?"                /* index: 2 */
                 " WHERE tokid=?";            /* index: 3 */
        }
    }

    /*
     * Prepare statements
     */
    rc = sqlite3_prepare(global.db, sql, -1, &stmt, NULL);
    if (rc) {
        LOGE("Could not prepare statement: \"%s\" error: \"%s\"",
        sql, sqlite3_errmsg(global.db));
        goto error;
    }

    /* bind values */
    /* sealobjects */

    int index = 1;
    rc = sqlite3_bind_text(stmt, index++, newauthsalthex, -1, SQLITE_STATIC);
    gotobinderror(rc, "newauthsalthex");

    rc = sqlite3_bind_blob(stmt, index++, newprivblob, twist_len(newprivblob), SQLITE_STATIC);
    gotobinderror(rc, "newprivblob");

    if (newpubblob) {
        rc = sqlite3_bind_blob(stmt, index++, newpubblob, twist_len(newpubblob), SQLITE_STATIC);
        gotobinderror(rc, "newpubblob");
    }

    rc = sqlite3_bind_int(stmt,  index++, tok->id);
    gotobinderror(rc, "tokid");

    /*
     * Everything is bound, fire off the sql statements
     */
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOGE("Could not execute stmt");
        goto error;
    }

    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        LOGE("Could not finalize stmt");
        goto error;
    }

    rc = commit();
    if (rc != SQLITE_OK) {
        goto error;
    }

    return CKR_OK;

error:

    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        LOGW("Could not finalize stmt");
    }

    rollback();
    return CKR_GENERAL_ERROR;
}

CK_RV db_add_new_object(token *tok, tobject *tobj) {

    CK_RV rv = CKR_GENERAL_ERROR;

    sqlite3_stmt *stmt = NULL;

    char *attrs = emit_attributes_to_string(tobj->attrs);
    if (!attrs) {
        return CKR_GENERAL_ERROR;
    }

    const char *sql =
          "INSERT INTO tobjects ("
            "tokid, "     // index: 1 type: INT
            "attrs"       // index: 2 type: TEXT (JSON)
          ") VALUES ("
            "?,?"
          ");";

    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("%s", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = start();
    if (rc != SQLITE_OK) {
        goto error;
    }

    rc = sqlite3_bind_int(stmt, 1, tok->id);
    gotobinderror(rc, "tokid");

    rc = sqlite3_bind_text(stmt, 2, attrs, -1, SQLITE_STATIC);
    gotobinderror(rc, "attrs");

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOGE("step error: %s", sqlite3_errmsg(global.db));
        goto error;
    }

    sqlite3_int64 id = sqlite3_last_insert_rowid(global.db);
    if (id == 0) {
        LOGE("Could not get id: %s", sqlite3_errmsg(global.db));
        goto error;
    }

    if (id > UINT_MAX) {
        LOGE("id is larger than unsigned int, got: %lld", id);
        goto error;
    }

    tobject_set_id(tobj, (unsigned)id);

    rc = sqlite3_finalize(stmt);
    gotobinderror(rc, "finalize");

    rc = commit();
    gotobinderror(rc, "commit");

    rv = CKR_OK;

out:
    free(attrs);
    return rv;

error:
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        LOGW("Could not finalize stmt: %d", rc);
    }

    rollback();

    rv = CKR_GENERAL_ERROR;
    goto out;
}

CK_RV db_delete_object(tobject *tobj) {

    CK_RV rv = CKR_GENERAL_ERROR;

    sqlite3_stmt *stmt = NULL;

    static const char *sql =
      "DELETE FROM tobjects WHERE id=?;";

    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("%s", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = start();
    if (rc != SQLITE_OK) {
        goto error;
    }

    rc = sqlite3_bind_int(stmt, 1, tobj->id);
    gotobinderror(rc, "id");

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOGE("step error: %s", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = sqlite3_finalize(stmt);
    gotobinderror(rc, "finalize");

    rc = commit();
    gotobinderror(rc, "commit");

    rv = CKR_OK;

out:
    return rv;

error:
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        LOGW("Could not finalize stmt: %d", rc);
    }

    rollback();

    rv = CKR_GENERAL_ERROR;
    goto out;
}

CK_RV db_add_primary(twist blob, unsigned *pid) {
    assert(blob);
    assert(pid);

    CK_RV rv = CKR_GENERAL_ERROR;

    sqlite3_stmt *stmt = NULL;

    const char *sql =
          "INSERT INTO pobjects ("
            "hierarchy, "     // index: 1 type: TEXT
            "handle,"          // index: 2 type: BLOB
            "objauth"         // index: 3 type: TEXT
          ") VALUES ("
            "?,?,?"
          ");";

    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("%s", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = start();
    if (rc != SQLITE_OK) {
        goto error;
    }

    rc = sqlite3_bind_text(stmt, 1, "o", -1, SQLITE_STATIC);
    gotobinderror(rc, "hierarchy");

    rc = sqlite3_bind_blob(stmt, 2, blob, twist_len(blob), SQLITE_STATIC);
    gotobinderror(rc, "handle");

    rc = sqlite3_bind_text(stmt, 3, "", -1, SQLITE_STATIC);
    gotobinderror(rc, "objauth");

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOGE("step error: %s", sqlite3_errmsg(global.db));
        goto error;
    }

    sqlite3_int64 id = sqlite3_last_insert_rowid(global.db);
    if (id == 0) {
        LOGE("Could not get id: %s", sqlite3_errmsg(global.db));
        goto error;
    }

    if (id > UINT_MAX) {
        LOGE("id is larger than unsigned int, got: %lld", id);
        goto error;
    }

    *pid = (unsigned)id;

    rc = sqlite3_finalize(stmt);
    gotobinderror(rc, "finalize");

    rc = commit();
    gotobinderror(rc, "commit");

    rv = CKR_OK;

out:
    return rv;

error:
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        LOGW("Could not finalize stmt: %d", rc);
    }

    rollback();

    rv = CKR_GENERAL_ERROR;
    goto out;
}

CK_RV db_update_token_config(token *tok) {
    assert(tok);

    CK_RV rv = CKR_GENERAL_ERROR;

    sqlite3_stmt *stmt = NULL;

    char *config = emit_config_to_string(tok);
    if (!config) {
        LOGE("Could not get token config");
        return CKR_GENERAL_ERROR;
    }

    const char *sql =
          "UPDATE tokens SET"
            " config=?"      // index: 1 type: TEXT (JSON)
            " WHERE id=?;";  // Index 2 type: int
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("%s", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = sqlite3_bind_text(stmt, 1, config, -1, SQLITE_STATIC);
    gotobinderror(rc, "config");

    rc = sqlite3_bind_int(stmt, 2, tok->id);
    gotobinderror(rc, "id");

    rc = sqlite3_finalize(stmt);
    if (rc) {
        LOGE("finalize");
        /* finalizing again probably won't fix this */
        goto out;
    }

    rv = CKR_OK;

out:
    free(config);
    return rv;

error:
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        LOGW("Could not finalize stmt: %d", rc);
    }

    rollback();

    rv = CKR_GENERAL_ERROR;
    goto out;

}

CK_RV db_update_tobject_attrs(unsigned id, attr_list *attrs) {
    assert(attrs);

    CK_RV rv = CKR_GENERAL_ERROR;

    sqlite3_stmt *stmt = NULL;

    char *attr_str = emit_attributes_to_string(attrs);
    if (!attr_str) {
        LOGE("Could not emit tobject attributes");
        return CKR_GENERAL_ERROR;
    }

    const char *sql =
          "UPDATE tobjects SET"
            " attrs=?"      // index: 1 type: TEXT (JSON)
            " WHERE id=?;";  // Index 2 type: int
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("%s", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = sqlite3_bind_text(stmt, 1, attr_str, -1, SQLITE_STATIC);
    gotobinderror(rc, "attrs");

    rc = sqlite3_bind_int(stmt, 2, id);
    gotobinderror(rc, "id");

    rc = sqlite3_finalize(stmt);
    if (rc) {
        LOGE("finalize");
        /* finalizing again probably won't fix this */
        goto out;
    }

    rv = CKR_OK;

out:
    free(attr_str);
    return rv;

error:
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        LOGW("Could not finalize stmt: %d", rc);
    }

    rollback();

    rv = CKR_GENERAL_ERROR;
    goto out;
}

CK_RV db_add_token(token *tok) {
    assert(tok);
    assert(tok->id);

    /* This function is only called from token_initialize, hence... */
    assert(tok->config.is_initialized);

    CK_RV rv = CKR_GENERAL_ERROR;

    sqlite3_stmt *stmt = NULL;

    char *config = emit_config_to_string(tok);
    if (!config) {
        LOGE("Could not get token config");
        return CKR_GENERAL_ERROR;
    }

    /* strip trailing spaces */
    char label_buf[sizeof(tok->label) + 1] = { 0 };
    memcpy(label_buf, tok->label, sizeof(tok->label));

    size_t i;
    for (i=sizeof(tok->label); i > 0; i--) {
        char *p = &label_buf[i-1];
        if (*p != ' ') {
            break;
        }
        *p = '\0';
    }

    const char *sql =
          "INSERT INTO tokens ("
            "id,"         // index: 1 type: INT
            "pid, "       // index: 2 type: INT
            "label,"      // index: 3 type: TEXT
            "config"      // index: 4 type: TEXT (JSON)
          ") VALUES ("
            "?,?,?,?"
          ");";

    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("%s", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = start();
    if (rc != SQLITE_OK) {
        goto error;
    }

    /*
     * we specify the id since we have an in-memory id that we need to use
     * This will also cause the constraint that primary key's are unique to
     * fail if someone comes in and initializes a token with this id.
     *
     * XXX
     * We should consider relaxing this:
     *   - https://github.com/tpm2-software/tpm2-pkcs11/issues/371
     */
    rc = sqlite3_bind_int(stmt, 1, tok->id);
    gotobinderror(rc, "id");

    rc = sqlite3_bind_int(stmt, 2, tok->pid);
    gotobinderror(rc, "pid");

    rc = sqlite3_bind_text(stmt, 3, label_buf, -1, SQLITE_STATIC);
    gotobinderror(rc, "config");

    rc = sqlite3_bind_text(stmt, 4, config, -1, SQLITE_STATIC);
    gotobinderror(rc, "label");

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOGE("step error: %s", sqlite3_errmsg(global.db));
        goto error;
    }

    sqlite3_int64 id = sqlite3_last_insert_rowid(global.db);
    if (id == 0) {
        LOGE("Could not get id: %s", sqlite3_errmsg(global.db));
        goto error;
    }

    if (id > UINT_MAX) {
        LOGE("id is larger than unsigned int, got: %lld", id);
        goto error;
    }

    assert(tok->id == id);

    rc = sqlite3_finalize(stmt);
    gotobinderror(rc, "finalize");

    /* add the sealobjects WITHIN the transaction */
    sql = "INSERT INTO sealobjects"
            "(tokid, soauthsalt, sopriv, sopub)"
            "VALUES(?,?,?,?)";

    rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("%s", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = sqlite3_bind_int(stmt, 1, tok->id);
    gotobinderror(rc, "tokid");

    rc = sqlite3_bind_text(stmt, 2, tok->sealobject.soauthsalt, -1, SQLITE_STATIC);
    gotobinderror(rc, "soauthsalt");

    rc = sqlite3_bind_blob(stmt, 3, tok->sealobject.sopriv,
            twist_len(tok->sealobject.sopriv), SQLITE_STATIC);
    gotobinderror(rc, "sopriv");

    rc = sqlite3_bind_blob(stmt, 4, tok->sealobject.sopub,
            twist_len(tok->sealobject.sopub), SQLITE_STATIC);
    gotobinderror(rc, "sopub");

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOGE("step error: %s", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = sqlite3_finalize(stmt);
    gotobinderror(rc, "finalize");

    rc = commit();
    gotobinderror(rc, "commit");

    rv = CKR_OK;

out:
    free(config);
    return rv;

error:
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        LOGW("Could not finalize stmt: %d", rc);
    }

    rollback();

    rv = CKR_GENERAL_ERROR;
    goto out;
}


CK_RV db_get_first_pid(unsigned *id) {
    assert(id);

    CK_RV rv = CKR_GENERAL_ERROR;

    const char *sql =
            "SELECT id FROM pobjects ORDER BY id ASC LIMIT 1";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot prepare first pid query: %s\n", sqlite3_errmsg(global.db));
        return rv;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *id = sqlite3_column_int(stmt, 0);
    } else if (rc == SQLITE_DONE) {
        *id = 0;
    } else {
        LOGE("Cannot step query: %s\n", sqlite3_errmsg(global.db));
        goto error;
    }

    rv = CKR_OK;

error:
    sqlite3_finalize(stmt);
    return rv;
}


#define DB_NAME "tpm2_pkcs11.sqlite3"
#define PKCS11_STORE_ENV_VAR "TPM2_PKCS11_STORE"

static CK_RV handle_env_var(char *path, size_t len, bool *skip) {

    *skip = false;

    char *env_path = getenv(PKCS11_STORE_ENV_VAR);
    if (!env_path) {
        *skip = true;
        return CKR_OK;
    }

    /*
     * It's an in memory db, use it:
     *   - https://www.sqlite.org/inmemorydb.html
     */
    if (!strncmp(env_path, "file::memory", 12) || !strcmp(env_path, ":memory:")) {
        unsigned l = snprintf(path, len, "%s", env_path);
        if (l >= len) {
            LOGE("Completed DB path was over-length, got %d expected less than %lu",
                l, len);
            return CKR_GENERAL_ERROR;
        }
        return CKR_OK;
    }

    unsigned l = snprintf(path, len, "%s/%s", env_path, DB_NAME);
    if (l >= len) {
        LOGE("Completed DB path was over-length, got %d expected less than %lu",
                l, len);
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

static CK_RV handle_home(char *path, size_t len, bool *skip) {

    *skip = false;

    char *env_home = getenv("HOME");
    if (!env_home) {
        *skip = true;
        return CKR_OK;
    }

    unsigned l = snprintf(path, len, "%s/.tpm2_pkcs11/%s", env_home, DB_NAME);
    if (l >= len) {
        LOGE("Completed DB path was over-length, got %d expected less than %lu",
                l, len);
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

static CK_RV handle_cwd(char *path, size_t len, bool *skip) {

    *skip = false;

    char *cwd_path = getcwd(NULL, 0);
    if (!cwd_path) {
        return errno == ENOMEM ? CKR_HOST_MEMORY : CKR_GENERAL_ERROR;
    }

    unsigned l = snprintf(path, len, "%s/%s", cwd_path, DB_NAME);
    free(cwd_path);
    if (l >= len) {
        LOGE("Completed DB path was over-length, got %d expected less than %lu",
                l, len);
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

static CK_RV handle_path(char *path, size_t len, bool *skip) {

    *skip = false;

    unsigned l = snprintf(path, len, "%s/%s", TPM2_PKCS11_STORE_DIR, DB_NAME);
    if (l >= len) {
        LOGE("Completed DB path was over-length, got %d expected less than %lu",
                l, len);
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

typedef enum handler_idx handler_idx;
enum handler_idx {
    HANDLER_IDX_ENV,
    HANDLER_IDX_STORE_DIR,
    HANDLER_IDX_HOME,
    HANDLER_IDX_CWD,
    HANDLER_IDX_CNT,
};

typedef CK_RV (*db_handler)(char *path, size_t len, handler_idx index);

static CK_RV db_for_path(char *path, size_t len, db_handler h) {

    /*
     * Search in the following order:
     * 1. ENV variable
     * 2. TPM2_PKCS11_STORE_DIR
     * 2. $HOME/.tpm2_pkcs11
     * 3. cwd
     */

    handler_idx i;
    for (i=0; i < HANDLER_IDX_CNT; i++) {

        CK_RV rv = CKR_GENERAL_ERROR;
        bool skip = false;

        switch (i) {
        case HANDLER_IDX_ENV:
            rv = handle_env_var(path, len, &skip);
            break;
        case HANDLER_IDX_STORE_DIR:
            rv = handle_path(path, len, &skip);
            break;
        case HANDLER_IDX_HOME:
            rv = handle_home(path, len, &skip);
            break;
        case HANDLER_IDX_CWD:
            rv = handle_cwd(path, len, &skip);
            break;
        default:
            LOGE("Unknown handler_idx: %d", i);
            return CKR_GENERAL_ERROR;
        }

        /* handler had fatal error, exit with return code */
        if (rv != CKR_OK) {
            return rv;
        }

        /* handler says skip, something must not be set */
        if (skip) {
            continue;
        }

        rv = h(path, len, i);
        if (rv != CKR_TOKEN_NOT_PRESENT) {
            return rv;
        }
    }

    return CKR_TOKEN_NOT_PRESENT;
}

static CK_RV db_get_path_handler(char *path, size_t len, handler_idx index) {
    UNUSED(len);

    /* Always attempt to use ENV VAR */
    if (index == HANDLER_IDX_ENV) {
        LOGV("using "PKCS11_STORE_ENV_VAR"=\"%s\"", path);
        return CKR_OK;
    }

    struct stat sb;
    int rc = stat(path, &sb);
    if (rc) {
        LOGV("Could not stat db at path \"%s\", error: %s", path, strerror(errno));

        /* no db, keep looking */
        return CKR_TOKEN_NOT_PRESENT;
    }

    /*
     * made it all the way through and found an existing store,
     * done searching.
     */
    return CKR_OK;
}

static CK_RV db_get_existing(char *path, size_t len) {

    return db_for_path(path, len, db_get_path_handler);
}

static CK_RV db_create_handler(char *path, size_t len, handler_idx index) {
    UNUSED(len);

    CK_RV rv = CKR_TOKEN_NOT_PRESENT;

    /* nothing to do for index CWD */
    if (index == HANDLER_IDX_CWD) {
        return CKR_OK;
    }

    char *pathdup = strdup(path);
    if (!pathdup) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    char *d = dirname(pathdup);

    if (index == HANDLER_IDX_ENV || index == HANDLER_IDX_HOME) {

        struct stat sb;
        int rc = stat(d, &sb);
        if (rc && errno != ENOENT) {
            LOGV("Could not stat db dir \"%s\", error: %s", d, strerror(errno));
            /* no db dir, keep looking */
            goto out;
        }

        if (rc == 0) {
            goto done;
        }

        rc = mkdir(d, S_IRWXU|S_IRWXG);
        if (rc) {
            LOGE("Could not mkdir \"%s\", error: %s", d, strerror(errno));
            rv = HANDLER_IDX_ENV ? CKR_GENERAL_ERROR : CKR_TOKEN_NOT_PRESENT;
            goto out;
        }

        /* success */
        goto done;
    }

    if (index == HANDLER_IDX_STORE_DIR) {

        /* tests if it exists AND we can use it */
        const char *test_file_path = TPM2_PKCS11_STORE_DIR"/.test";
        FILE *f = fopen(test_file_path, "w+");
        if (!f) {
            /*
             * we don't care about errors, we just skip it, but if it's
             * an access issue, we will let the user know via LOGW.
             * */
            if (errno != ENOENT) {
                const char *msg = (errno == EPERM || errno == EACCES) ?
                        "Error checking access to \"%s\", skipping. error: %s" :
                        "\"%s\" exists, but no access, skipping. error: %s";
                LOGW(msg, TPM2_PKCS11_STORE_DIR,
                        strerror(errno));
            }
            goto out;
        }
        /* all is well, unlink and move on */
        fclose(f);
        unlink(test_file_path);
        goto done;
    }

    /* I don't know what it is fatal error */
    assert(0);
    LOGE("Unhandled search index: %d", index);
    rv = CKR_GENERAL_ERROR;
    goto out;

    /*
     * made it all the way through and found a dir I can use,
     * done searching. Now use it to create the db.
     */
done:
    rv = CKR_OK;

out:
    free(pathdup);
    return rv;
}

#define DB_EMPTY 0

static CK_RV db_get_version(sqlite3 *db, unsigned *version) {

    CK_RV rv = CKR_GENERAL_ERROR;

    const char *sql = "SELECT schema_version FROM schema";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGW("Cannot prepare version query: %s\n", sqlite3_errmsg(global.db));
        *version = DB_EMPTY;
        return CKR_OK;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *version = sqlite3_column_int(stmt, 0);
    } else if (rc == SQLITE_DONE) {
        *version = DB_EMPTY;
    } else {
        LOGE("Cannot step query: %s\n", sqlite3_errmsg(global.db));
        *version = DB_EMPTY;
        goto error;
    }

    rv = CKR_OK;

error:
    sqlite3_finalize(stmt);
    return rv;
}

static CK_RV run_sql_list(sqlite3 *db, const char **sql, size_t cnt) {

    size_t i;
    for (i=0; i < cnt; i++) {
        const char *s = sql[i];

        int rc = sqlite3_exec(db, s, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            LOGE("db creation failed: %s", sqlite3_errmsg(db));
            return CKR_GENERAL_ERROR;
        }
    }

    return CKR_OK;
}

static CK_RV dbup_handler_from_1_to_2(sqlite3 *updb) {

    /* Between version 1 and 2 of the DB the following changes need to be made:
     *   The existing rows:
     *     - userpub BLOB NOT NULL,
     *     - userpriv BLOB NOT NULL,
     *     - userauthsalt TEXT NOT NULL,
     *   All have the "NOT NULL" constarint removed, like so:
     *       userpub BLOB,
     *       userpriv BLOB,
     *       userauthsalt TEXT
     * So we need to create a new table with this constraint removed,
     * copy the data and move the table back
     */

    /* Create a new table to copy data to that has the constraints removed */
    const char *s = ""
        "CREATE TABLE sealobjects_new2("
            "id INTEGER PRIMARY KEY,"
            "tokid INTEGER NOT NULL,"
            "userpub BLOB,"
            "userpriv BLOB,"
            "userauthsalt TEXT,"
            "sopub BLOB NOT NULL,"
            "sopriv BLOB NOT NULL,"
            "soauthsalt TEXT NOT NULL,"
            "FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE"
        ");";
    int rc = sqlite3_exec(updb, s, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot create temp table: %s", sqlite3_errmsg(updb));
        return CKR_GENERAL_ERROR;
    }

    /* copy the data */
    s = "INSERT INTO sealobjects_new2\n"
        "SELECT * FROM sealobjects;";
    rc = sqlite3_exec(updb, s, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot copy data to the temp table: %s", sqlite3_errmsg(updb));
        return CKR_GENERAL_ERROR;
    }

    /* Drop the old table */
    s = "DROP TABLE sealobjects;";
    rc = sqlite3_exec(updb, s, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot drop the temp table: %s", sqlite3_errmsg(updb));
        return CKR_GENERAL_ERROR;
    }

    /* Rename the new table to the correct table name */
    s = "ALTER TABLE sealobjects_new2 RENAME TO sealobjects;";
    rc = sqlite3_exec(updb, s, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot rename the temp table back to the original table name: %s",
                sqlite3_errmsg(updb));
        return CKR_GENERAL_ERROR;
    }

    const char *sql[] = {
        "CREATE TRIGGER limit_tokens\n"
        "BEFORE INSERT ON tokens\n"
        "BEGIN\n"
        "    SELECT CASE WHEN\n"
        "        (SELECT COUNT (*) FROM tokens) >= 255\n"
        "    THEN\n"
        "        RAISE(FAIL, \"Maximum token count of 255 reached.\")\n"
        "    END;\n"
        "END;\n",
        "CREATE TRIGGER limit_tobjects\n"
        "BEFORE INSERT ON tobjects\n"
        "BEGIN\n"
        "    SELECT CASE WHEN\n"
        "        (SELECT COUNT (*) FROM tobjects) >= 16777215\n"
        "    THEN\n"
        "        RAISE(FAIL, \"Maximum object count of 16777215 reached.\")\n"
        "    END;\n"
        "END;\n"
    };

    return run_sql_list(updb, sql, ARRAY_LEN(sql));
}

static CK_RV dbup_handler_from_2_to_3(sqlite3 *updb) {

    /* Between version 2 and 3 of the DB the following changes need to be made:
     *  - Drop the incorrect limit_tobjects TRIGGER.
     */

    /* Create a new table to copy data to that has the constraints removed */
    const char *s = "DROP TRIGGER limit_tobjects;";
    int rc = sqlite3_exec(updb, s, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot create temp table: %s", sqlite3_errmsg(updb));
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

static CK_RV db_backup(sqlite3 *db, const char *dbpath, sqlite3 **updb, char **copypath) {

    CK_RV rv = CKR_GENERAL_ERROR;

    char temp[PATH_MAX];

    sqlite3 *copydb = NULL;

    const char *suffix = ".bak";

    sqlite3_backup *backup_conn = NULL;

    unsigned l = snprintf(temp, sizeof(temp), "%s%s", dbpath, suffix);
    if (l >= sizeof(temp)) {
        LOGE("Backup DB path is longer than PATH_MAX");
        goto out;
    }

    LOGV("Performing DB backup at: \"%s\"", temp);

    int rc = sqlite3_open(temp, &copydb);
    if (rc != SQLITE_OK) {
        LOGE("Cannot open database: %s\n", sqlite3_errmsg(copydb));
        goto out;
    }

    backup_conn = sqlite3_backup_init(copydb, "main", db, "main");
    if (!backup_conn) {
        LOGE("Cannot backup init db: %s\n", sqlite3_errmsg(copydb));
        goto out;
    }

    rc = sqlite3_backup_step(backup_conn, -1);
    if (rc != SQLITE_DONE) {
        LOGE("Cannot step db backup: %s\n", sqlite3_errmsg(copydb));
        goto out;
    }

    *copypath = strdup(temp);
    if (!(*copypath)) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    *updb = copydb;
    copydb = NULL;

    rv = CKR_OK;

out:
    if (backup_conn) {
        sqlite3_backup_finish(backup_conn);
    }
    if (copydb) {
        sqlite3_close(copydb);
    }
    return rv;
}

typedef CK_RV (*db_update_handlers)(sqlite3 *db);

static CK_RV db_update(sqlite3 **xdb, const char *dbpath, unsigned old_version, unsigned new_version) {

    sqlite3 *dbbak = NULL;
    char *dbbakpath = NULL;

    static const db_update_handlers updaters[] = {
            NULL,
            dbup_handler_from_1_to_2,
            dbup_handler_from_2_to_3,
    };

    /*
     * Sanity checks, this is definite belts and suspenders code
     */
    if (new_version > ARRAY_LEN(updaters)) {
        LOGE("db update code does not know how to update to version: %u",
                new_version);
        return CKR_GENERAL_ERROR;
    }

    if (old_version == 0) {
        LOGE("version 0 was never a valid db version");
        return CKR_GENERAL_ERROR;
    }

    /*
     * Create a DB backup of whats there
     */
    CK_RV rv = db_backup(*xdb, dbpath, &dbbak, &dbbakpath);
    if (rv != CKR_OK) {
        LOGE("Could not make DB copy");
        return rv;
    }

    /*
     * run the update handlers on the backup
     */
    size_t i;
    for(i=old_version; i < ARRAY_LEN(updaters) && i < new_version; i++) {
        CK_RV rv = updaters[i](dbbak);
        if (rv != CKR_OK) {
            LOGE("Running updater index %zu failed", i);
            goto out;
        }
    }

    const char *sql[] = {
        "REPLACE INTO schema (id, schema_version) VALUES (1, "xstr(DB_VERSION) ");",
    };

    rv = run_sql_list(dbbak, sql, ARRAY_LEN(sql));
    if (rv != CKR_OK) {
        LOGE("Could not set new schema_version");
        goto out;
    }

    /*
     * Swap the current db with the backup db, by:
     * 1. closing them
     * 2. renaming the current db as .old
     * 3. renaming the bakup db as the old db
     * 4. unlinking the .old db
     * 5. opening the new db
     */
    sqlite3_close(*xdb);
    *xdb = NULL;

    sqlite3_close(dbbak);
    dbbak = NULL;

    char buf[PATH_MAX];
    unsigned l = snprintf(buf, sizeof(buf), "%s.old", dbpath);
    if (l >= sizeof(buf)) {
        LOGE("Old database path is longer than PATH_MAX");
        rv = CKR_GENERAL_ERROR;
        goto out;
    }

    int rc = rename(dbpath, buf);
    if (rc != 0) {
       LOGE("Could not rename \"%s\" --> \"%s\", error: %s",
               dbpath, buf, strerror(errno));
       rv = CKR_GENERAL_ERROR;
       goto out;
    }

    rc = rename(dbbakpath, dbpath);
    if (rc != 0) {
       LOGE("Could not rename \"%s\" --> \"%s\", error: %s",
               dbbakpath, dbpath, strerror(errno));
       rv = CKR_GENERAL_ERROR;
       goto out;
    }

    rc = sqlite3_open(dbpath, xdb);
    if (rc != SQLITE_OK) {
        LOGE("Cannot open database: %s\n", sqlite3_errmsg(*xdb));
        rv = CKR_GENERAL_ERROR;
        goto out;
    }

    rc = unlink(buf);
    if (rc != 0) {
       LOGE("Could not unlink \"%s\", error: %s",
               buf, strerror(errno));
       rv = CKR_GENERAL_ERROR;
       goto out;
    }

    rv = CKR_OK;

out:
    if (dbbak) {
        sqlite3_close(dbbak);
    }
    free(dbbakpath);

    return rv;
}

static CK_RV db_create(char *path, size_t len) {

    return db_for_path(path, len, db_create_handler);
}

static FILE *take_lock(const char *path, char *lockpath) {

    unsigned l = snprintf(lockpath, PATH_MAX, "%s%s", path, ".lock");
    if (l >= PATH_MAX) {
        LOGE("Lock file path is longer than PATH_MAX");
        return NULL;
    }

    FILE *f = fopen(lockpath, "w+");
    if (!f) {
        LOGE("Could not open lock file \"%s\", error: %s",
                lockpath, strerror(errno));
        return NULL;
    }

    int rc = flock(fileno(f), LOCK_EX);
    if (rc < 0) {
        LOGE("Could not flock file \"%s\", error: %s",
                lockpath, strerror(errno));
        fclose(f);
        unlink(lockpath);
        return NULL;
    }

    return f;
}

static void release_lock(FILE *f, char *lockpath) {

    int rc = flock(fileno(f), LOCK_UN);
    if (rc < 0) {
        LOGE("Could not unlock file \"%s\", error: %s",
                lockpath, strerror(errno));
    }
    UNUSED(unlink(lockpath));
    UNUSED(fclose(f));
}

static CK_RV db_init_new(sqlite3 *db) {

    const char *sql[] = {
        "CREATE TABLE tokens("
            "id INTEGER PRIMARY KEY,"
            "pid INTEGER NOT NULL,"
            "label TEXT UNIQUE,"
            "config TEXT NOT NULL,"
            "FOREIGN KEY (pid) REFERENCES pobjects(id) ON DELETE CASCADE"
        ");",
        "CREATE TABLE sealobjects("
            "id INTEGER PRIMARY KEY,"
            "tokid INTEGER NOT NULL,"
            "userpub BLOB,"
            "userpriv BLOB,"
            "userauthsalt TEXT,"
            "sopub BLOB NOT NULL,"
            "sopriv BLOB NOT NULL,"
            "soauthsalt TEXT NOT NULL,"
            "FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE"
        ");",
        "CREATE TABLE pobjects("
            "id INTEGER PRIMARY KEY,"
            "hierarchy TEXT NOT NULL,"
            "handle BLOB NOT NULL,"
            "objauth TEXT NOT NULL"
        ");",
        "CREATE TABLE tobjects("
            "id INTEGER PRIMARY KEY,"
            "tokid INTEGER NOT NULL,"
            "attrs TEXT NOT NULL,"
            "FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE"
        ");",
        "CREATE TABLE schema("
            "id INTEGER PRIMARY KEY,"
            "schema_version INTEGER NOT NULL"
        ");",
        "CREATE TRIGGER limit_tokens\n"
        "BEFORE INSERT ON tokens\n"
        "BEGIN\n"
        "    SELECT CASE WHEN\n"
        "        (SELECT COUNT (*) FROM tokens) >= 255\n"
        "    THEN\n"
        "        RAISE(FAIL, \"Maximum token count of 255 reached.\")\n"
        "    END;\n"
        "END;\n",
        "REPLACE INTO schema (id, schema_version) VALUES (1, "xstr(DB_VERSION) ");",
    };

    return run_sql_list(db, sql, ARRAY_LEN(sql));
}

static CK_RV db_verify_update_ok(const char *dbpath) {

    char buf[PATH_MAX];
    unsigned l = snprintf(buf, sizeof(buf), "%s.old", dbpath);
    if (l >= sizeof(buf)) {
        LOGE("Backup DB path is longer than PATH_MAX");
        return CKR_GENERAL_ERROR;
    }

    struct stat sb;
    int rc = stat(buf, &sb);
    if (rc == 0) {
        LOGE("Backup DB exists at \"%s\" not overwriting. "
                "Refusing to run, see "
                "https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/DB_UPGRADE.md.",
                buf);
        return CKR_GENERAL_ERROR;
    } else if (rc < 0 && errno != ENOENT) {
        LOGE("Failed to stat path \"%s\", error: %s",
                buf, strerror(errno));
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

static CK_RV db_setup(sqlite3 **xdb, const char *dbpath) {

    /*
     * take the version check lock and figure out what
     * to do:
     *  - nothing
     *  - init a new db
     *  - upgrade an existing db
     */

    const char *pname = sqlite3_db_filename(*xdb, NULL);
    bool is_in_mem_db = !pname || pname[0] == '\0';

    char lockpath[PATH_MAX];
    FILE *f = NULL;
    if (!is_in_mem_db) {
        f = take_lock(dbpath, lockpath);
        if (!f) {
            return CKR_GENERAL_ERROR;
        }
    }

    CK_RV rv = db_verify_update_ok(dbpath);
    if (rv != CKR_OK) {
        goto out;
    }

    unsigned old_version = 0;
    rv = db_get_version(*xdb, &old_version);
    if (rv != CKR_OK) {
        LOGE("Could not get DB version");
        goto out;
    }

    if (old_version == DB_EMPTY) {
        rv = db_init_new(*xdb);
        goto out;
    }

    if (old_version == DB_VERSION) {
        LOGV("No DB upgrade needed");
        rv = CKR_OK;
        goto out;
    }

    if (old_version > DB_VERSION) {
        LOGE("DB Version exceeds library version: %u > %u",
                old_version, DB_VERSION);
        rv = CKR_OK;
        goto out;
    }

    rv = db_update(xdb, dbpath, old_version, DB_VERSION);

out:
    if (rv != CKR_OK) {
        LOGE("Error within db, leaving backup see: "
            "https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/DB_UPGRADE.md.");
    }

    if (!is_in_mem_db) {
        assert(f);
        release_lock(f, lockpath);
    }
    return rv;
}

static CK_RV db_new(sqlite3 **db) {

    char dbpath[PATH_MAX];
    CK_RV rv = db_get_existing(dbpath, sizeof(dbpath));
    if (rv == CKR_TOKEN_NOT_PRESENT) {
        rv = db_create(dbpath, sizeof(dbpath));
    }

    if (rv != CKR_OK) {
        LOGE("Could not find or create a pkcs11 store");
        LOGE("Consider exporting "PKCS11_STORE_ENV_VAR" to point to a valid store directory");
        return rv;
    }

    LOGV("Using sqlite3 DB: \"%s\"", dbpath);

    int rc = sqlite3_open(dbpath, db);
    if (rc != SQLITE_OK) {
        LOGE("Cannot open database: %s\n", sqlite3_errmsg(*db));
        return CKR_GENERAL_ERROR;
    }

    return db_setup(db, dbpath);
}

static CK_RV db_free(sqlite3 **db) {

    int rc = sqlite3_close(*db);
    if (rc != SQLITE_OK) {
        LOGE("Cannot close database: %s\n", sqlite3_errmsg(*db));
        return CKR_GENERAL_ERROR;
    }

    *db = NULL;

    return CKR_OK;
}

CK_RV db_init(void) {

    return db_new(&global.db);
}

CK_RV db_destroy(void) {
    return db_free(&global.db);
}
