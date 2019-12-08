/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <linux/limits.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sqlite3.h>

#include "config.h"
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

#define goto_oom(x, l) if (!x) { LOGE("oom"); goto l; }
#define goto_error(x, l) if (x) { goto l; }

static struct {
    sqlite3 *db;
} global;

static int token_count_cb(void *ud, int argc, char **argv,
                    char **azColName) {

    UNUSED(argc);
    UNUSED(azColName);

    size_t *count = (size_t *)ud;

    return str_to_ul(argv[0], count);
}

static int get_token_count(size_t *cnt) {

    const char *sql = "SELECT COUNT(*) from tokens;";
    return sqlite3_exec(global.db, sql, token_count_cb, cnt, NULL);
}

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

static int get_blob(sqlite3_stmt *stmt, int i, twist *blob) {

    return _get_blob(stmt, i, false, blob);
}

typedef struct token_get_cb_ud token_get_cb_ud;
struct token_get_cb_ud {
    size_t offset;
    size_t len;
    token *tokens;
};

tobject *db_tobject_new(sqlite3_stmt *stmt) {

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

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_TPM2_OBJAUTH_ENC);
    if (a && a->pValue && a->ulValueLen) {
        tobj->objauth = twistbin_new(a->pValue, a->ulValueLen);
        if (!tobj->objauth) {
            LOGE("oom");
            goto error;
        }
    }

    a = attr_get_attribute_by_type(tobj->attrs, CKA_TPM2_PUB_BLOB);
    if (a && a->pValue && a->ulValueLen) {
        if (!tobj->objauth) {
            LOGE("objects with CKA_TPM2_OBJAUTH_ENC should have CKA_TPM2_PUB_BLOB");
            goto error;
        }

        tobj->pub = twistbin_new(a->pValue, a->ulValueLen);
        if (!tobj->pub) {
            LOGE("oom");
            goto error;
        }
    }

    a = attr_get_attribute_by_type(tobj->attrs, CKA_TPM2_PRIV_BLOB);
    if (a && a->pValue && a->ulValueLen) {

        if (!tobj->pub) {
            LOGE("objects with CKA_TPM2_PUB_BLOB should have CKA_TPM2_PRIV_BLOB");
            goto error;
        }

        tobj->priv = twistbin_new(a->pValue, a->ulValueLen);
        if (!tobj->priv) {
            LOGE("oom");
            goto error;
        }
    }

    return tobj;

error:
    tobject_free(tobj);
    return NULL;
}

int init_tobjects(unsigned tokid, tobject **head) {

    const char *sql =
            "SELECT * FROM tobjects WHERE tokid=?1";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot prepare tobject query: %s\n", sqlite3_errmsg(global.db));
        return rc;
    }

    rc = sqlite3_bind_int(stmt, 1, tokid);
    if (rc != SQLITE_OK) {
        LOGE("Cannot bind tobject tokid: %s\n", sqlite3_errmsg(global.db));
        goto error;
    }

    list *cur = NULL;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {

        tobject *insert = db_tobject_new(stmt);
        if (!insert) {
            LOGE("Failed to initialize tobject from db");
            goto error;
        }

        if (!*head) {
            *head = insert;
            cur = &insert->l;
            continue;
        }

        assert(cur);
        assert(insert);
        cur->next = &insert->l;
        cur = cur->next;
    }

    rc = SQLITE_OK;

error:
    sqlite3_finalize(stmt);
    return rc;
}

int init_pobject(unsigned pid, pobject *pobj, tpm_ctx *tpm) {

    const char *sql =
            "SELECT handle,objauth FROM pobjects WHERE id=?1";

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


int init_sealobjects(unsigned tokid, sealobject *sealobj) {

    const char *sql =
            "SELECT * FROM sealobjects WHERE tokid=?1";

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
            sealobj->id = sqlite3_column_int(stmt, i);
        } else if (!strcmp(name, "userauthsalt")) {
            sealobj->userauthsalt = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sealobj->userauthsalt, error);
        } else if (!strcmp(name, "userpriv")) {
            goto_error(get_blob(stmt, i, &sealobj->userpriv), error);
        } else if (!strcmp(name, "userpub")) {
            goto_error(get_blob(stmt, i, &sealobj->userpub), error);
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

    int rc = get_token_count(&cnt);
    if (rc != SQLITE_OK) {
        LOGE("getting token count: %s", sqlite3_errstr(rc));
        return CKR_GENERAL_ERROR;
    }

    if (!cnt) {
        *len = cnt;
        return CKR_OK;
    }

    if (cnt > MAX_TOKEN_CNT) {
        LOGE("Too many tokens, got: %lu, expected less than %u", cnt,
                MAX_TOKEN_CNT);
        return CKR_GENERAL_ERROR;
    }

    token *tmp = calloc(cnt, sizeof(token));
    if (!tmp) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    const char *sql =
            "SELECT * FROM tokens";

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(tmp);
        LOGE("Cannot prepare tobject query: %s\n", sqlite3_errmsg(global.db));
        return rc;
    }

    size_t row = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {

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

        /*
         * Initialize the per-token session table
         */
        CK_RV rv = session_table_new(&t->s_table);
        if (rv != CKR_OK) {
            LOGE("Could not initialize session table");
            goto error;
        }

        /*
         * Initialize the per-token tpm context
         */
        rv = tpm_ctx_new(t->config.tcti, &t->tctx);
        if (rv != CKR_OK) {
            LOGE("Could not initialize tpm ctx: 0x%lx", rv);
            goto error;
        }

        int rc = init_pobject(t->pid, &t->pobject, t->tctx);
        if (rc != SQLITE_OK) {
            goto error;
        }

        rv = mutex_create(&t->mutex);
        if (rv != CKR_OK) {
            LOGE("Could not initialize mutex: 0x%lx", rv);
            goto error;
        }

        if (!t->config.is_initialized) {
            LOGV("skipping further initialization of token tid: %u", t->id);
            continue;
        }

        rc = init_sealobjects(t->id, &t->sealobject);
        if (rc != SQLITE_OK) {
            goto error;
        }

        rc = init_tobjects(t->id, &t->tobjects);
        if (rc != SQLITE_OK) {
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
    return sqlite3_exec(global.db, "BEGIN TRANSACTION", NULL, NULL, NULL);
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

CK_RV generic_mech_type_handler(CK_MECHANISM_PTR mech, CK_ULONG index, void *userdat) {
    UNUSED(index);
    assert(userdat);

    twist *t = (twist *)(userdat);

    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%lu=\n", mech->mechanism);

    twist x = twist_append(*t, tmp);
    if (!x) {
        return CKR_HOST_MEMORY;
    }

    *t = x;

    return CKR_OK;
}

CK_RV oaep_mech_type_handler(CK_MECHANISM_PTR mech, CK_ULONG index, void *userdat) {
    UNUSED(index);
    assert(userdat);
    assert(mech->pParameter);
    assert(mech->ulParameterLen);

    twist *t = (twist *)(userdat);

    CK_RSA_PKCS_OAEP_PARAMS_PTR p = mech->pParameter;

    /* 9=hashalg=592,mgf=2 */
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%lu=hashalg=%lu,mgf=%lu\n",
            mech->mechanism, p->hashAlg, p->mgf);

    twist x = twist_append(*t, tmp);
    if (!x) {
        return CKR_HOST_MEMORY;
    }

    *t = x;

    return CKR_OK;
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

CK_RV db_init(void) {

    return db_new(&global.db);
}

CK_RV db_destroy(void) {
    return db_free(&global.db);
}

#define DB_NAME "tpm2_pkcs11.sqlite3"
#define PKCS11_STORE_ENV_VAR "TPM2_PKCS11_STORE"

static CK_RV handle_env_var(char *path, size_t len, bool *skip, bool *stat_is_no_token) {

    *skip = false;
    *stat_is_no_token = true;

    char *env_path = getenv(PKCS11_STORE_ENV_VAR);
    if (!env_path) {
        *skip = true;
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

CK_RV db_get_path(char *path, size_t len) {

    int rc;

    /*
     * Search in the following order:
     * 1. ENV variable
     * 2. $HOME/.tpm2_pkcs11
     * 3. cwd
     * 4. TPM2_PKCS11_STORE_DIR
     */

    unsigned i;
    for (i=0; i < 4; i++) {

        CK_RV rv = CKR_GENERAL_ERROR;
        bool skip = false;
        bool stat_is_no_token = false;

        switch (i) {
        case 0:
            rv = handle_env_var(path, len, &skip, &stat_is_no_token);
            break;
        case 1:
            rv = handle_home(path, len, &skip);
            break;
        case 2:
            rv = handle_cwd(path, len, &skip);
            break;
        case 3:
            rv = handle_path(path, len, &skip);
            break;
            /* no default */
        }

        /* handler had fatal error, exit with return code */
        if (rv != CKR_OK) {
            return rv;
        }

        /* handler says skip, something must not be set */
        if (skip) {
            continue;
        }

        struct stat sb;
        rc = stat(path, &sb);
        if (rc) {
            LOGV("Could not stat db at path \"%s\", error: %s", path, strerror(errno));
            if (stat_is_no_token) {
                return CKR_TOKEN_NOT_PRESENT;
            }

            /* no db, keep looking */
            continue;
        }

        /*
         * made it all the way through, break out
         */
        break;
    }

    if (i >= 4) {
        LOGV("Could not find pkcs11 store");
        LOGV("Consider exporting "PKCS11_STORE_ENV_VAR" to point to a valid store directory");
        return CKR_TOKEN_NOT_PRESENT;
    }

    return CKR_OK;
}

CK_RV db_new(sqlite3 **db) {

    char path[PATH_MAX];
    CK_RV rv = db_get_path(path, sizeof(path));
    if (rv != CKR_OK) {
        return rv;
    }

    LOGV("Using sqlite3 DB: \"%s\"", path);

    int rc = sqlite3_open(path, db);
    if (rc != SQLITE_OK) {
        LOGE("Cannot open database: %s\n", sqlite3_errmsg(*db));
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV db_free(sqlite3 **db) {

    int rc = sqlite3_close(*db);
    if (rc != SQLITE_OK) {
        LOGE("Cannot close database: %s\n", sqlite3_errmsg(*db));
        return CKR_GENERAL_ERROR;
    }

    *db = NULL;

    return CKR_OK;
}
