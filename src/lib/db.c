/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <sqlite3.h>

#include "db.h"
#include "log.h"
#include "object.h"
#include "token.h"
#include "twist.h"
#include "utils.h"

#include <openssl/evp.h>

#define goto_oom(x, l) if (!x) { LOGE("oom"); goto l; }

static struct {
    sqlite3 *db;
} global;

static int str_to_bool(const char *val, bool *res) {

    if (!strcasecmp(val, "yes")
     || !strcasecmp(val, "true")
     || !strcasecmp(val, "1")
     || !strcasecmp(val, "y")) {
        *res = true;
        return 0;
    }

    if (!strcasecmp(val, "no")
     || !strcasecmp(val, "false")
     || !strcasecmp(val, "0")
     || !strcasecmp(val, "n")) {
        *res = false;
        return 0;
    }

    LOGE("Could not convert \"%s\" to bool.", val);
    return 1;
}

static int str_to_ul(const char *val, size_t *res) {

    errno=0;
    *res = strtoul(val, NULL, 0);
    if (errno) {
        LOGE("Could not convert \"%s\" to integer", val);
        return 1;
    }

    return 0;
}

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

typedef struct token_get_cb_ud token_get_cb_ud;
struct token_get_cb_ud {
    size_t offset;
    size_t len;
    token *tokens;
};

typedef bool (*pfn_onkvp)(const char *key, const char *value, size_t index, void *data);
typedef bool (*pfn_onkvp_allocator)(unsigned long count, void *data);

bool generic_parse_kvp(char *line, size_t index, void *data, pfn_onkvp cb) {

    char *kvp;
    char *tmp = line;
    char *saveptr = NULL;
    while ((kvp = strtok_r(tmp, "\t ", &saveptr))) {
        tmp = NULL;

        char *split = strchr(kvp, '=');
        if (!split) {
            return false;
        }

        *split = '\0';

        char *value = split + 1;
        char *key = kvp;

        bool result = cb(key, value, index, data);
        if (!result) {
            return result;
        }
    }

    return true;
}

static bool alloc_attrs(unsigned long count, void *userdata) {

    tobject *tobj = (tobject *)userdata;

    tobj->atributes.count = count;

    tobj->atributes.attrs = calloc(count, sizeof(*tobj->atributes.attrs));
    if (!tobj->atributes.attrs) {
        LOGE("oom");
        return false;
    }

    return true;
}

static bool bn2bin(BIGNUM *bn, CK_ATTRIBUTE_PTR a) {

    bool rc = false;

    int len = BN_num_bytes(bn);
    a->pValue = calloc(1, len);
    if (!a->pValue) {
        LOGE("oom");
        goto out;
    }

    BN_bn2bin(bn, a->pValue);
    a->ulValueLen = len;

    rc = true;

out:
    BN_free(bn);

    return rc;
}

static bool parse_attrs(const char *key, const char *value, size_t index, void *userdata) {

    tobject *tobj = (tobject *)userdata;
    CK_ATTRIBUTE_PTR a = &tobj->atributes.attrs[index];

    size_t type;
    int rc = str_to_ul(key, &type);
    if (rc) {
        LOGE("Could not convert key \"%s\" to unsigned long",
                key);
        return false;
    }

    a->type = type;

    switch(a->type) {
    /* native endianess unsigned longs */
    case CKA_KEY_TYPE:
        /* falls through */
    case CKA_CLASS: {

        size_t val;
        rc = str_to_ul(value, &val);
        if (rc) {
            LOGE("Could not convert key \"%s\" value \"%s\" to big integer",
                    key, value);
            return false;
        }

        a->pValue = calloc(1, sizeof(unsigned long));
        if (!a->pValue) {
            LOGE("oom");
            return false;
        }

        memcpy(a->pValue, &val, sizeof(unsigned long));
        a->ulValueLen = sizeof(unsigned long);
    } break;
    /* base10 encoded big integers */
    case CKA_PUBLIC_EXPONENT: {

        BIGNUM *bn = NULL;
        rc = BN_dec2bn(&bn, value);
        if (!rc) {
            LOGE("Could not convert key \"%s\" value \"%s\" to big integer",
                    key, value);
            return false;
        }

        return bn2bin(bn, a);
    } break;
    /* base16 encoded big integers */
    case CKA_MODULUS: {

        BIGNUM *bn = NULL;
        rc = BN_hex2bn(&bn, value);
        if (!rc) {
            LOGE("Could not convert key \"%s\" value \"%s\" to big integer",
                    key, value);
            return false;
        }

        return bn2bin(bn, a);
    } break;

    /* strings */
    case CKA_ID: {

        a->ulValueLen = strlen(value);
        a->pValue = strdup(value);
        if (!a->pValue) {
            LOGE("oom");
            return false;
        }
    } break;
    default:
        LOGE("Unknown key, got: \"%s\"", key);
        return false;
    }

    return true;
}

static bool alloc_mech(unsigned long count, void *userdata) {

    tobject *tobj = (tobject *)userdata;

    tobj->mechanisms.count = count;
    tobj->mechanisms.mech = calloc(count, sizeof(*tobj->mechanisms.mech));

    if (!tobj->mechanisms.mech) {
        LOGE("oom");
        return false;
    }

    return true;
}

static bool parse_mech(const char *key, const char *value, size_t index, void *userdata) {

    tobject *tobj = (tobject *)userdata;
    CK_MECHANISM_PTR m = &tobj->mechanisms.mech[index];

    size_t mechanism;
    int rc = str_to_ul(key, &mechanism);
    if (rc) {
        LOGE("Could not convert key \"%s\" to unsigned long",
                key);
        return false;
    }

    m->mechanism = mechanism;

    switch(m->mechanism) {
    /* unsigned longs */
    case CKM_RSA_PKCS_OAEP:
        /* falls through */
    case CKM_AES_CBC: {
        size_t val;
        int rc = str_to_ul(key, &val);
        if (rc) {
            LOGE("Could not convert key \"%s\" value \"%s\" to unsigned long",
                    key, value);
            return false;
        }

        m->pParameter = calloc(1, sizeof(val));
        if (!m->pParameter) {
            LOGE("oom");
            return false;
        }

        memcpy(m->pParameter, &val, sizeof(val));
        m->ulParameterLen = sizeof(val);
    } break;
    default:
        LOGE("Unknown key, got: \"%s\"", key);
        return false;
    }

    return true;
}

static bool parse_token_config(const char *key, const char *value, size_t index, void *userdata) {

    UNUSED(index);

    token *t = (token *)userdata;

    if(!strcmp(key, "sym-support")) {
        return !str_to_bool(value, &t->config.sym_support);
    } else {
        LOGE("Unknown token config key: \"%s\"", key);
    }

    return false;
}

CK_RV parse_generic_kvp_line(const char *kvplines,
        void *data, pfn_onkvp_allocator allocator, pfn_onkvp handler) {

    CK_RV rv = CKR_GENERAL_ERROR;

    /* PARSE
     * type=0 value=4
     * type=256 value=31
     */

    char *kvpstr = strdup(kvplines);
    if (!kvpstr) {
        return CKR_HOST_MEMORY;
    }

    /*
     * Get the count of how many
     */
    char *line;
    char *tmp = kvpstr;
    char *saveptr = NULL;

    unsigned long count = 0;
    while ((line = strtok_r(tmp, "\r\n", &saveptr))) {
        tmp = NULL;
        count++;
    }

    free(kvpstr);

    /*
     * Call the allocator
     */
    if (allocator) {
        bool result = allocator(count, data);
        if (!result) {
            return CKR_HOST_MEMORY;
        }
    }

    if (!count) {
        return CKR_OK;
    }

    /*
     * Make a new copy for strtok to destroy
     */
    kvpstr = strdup(kvplines);
    if (!kvpstr) {
        return CKR_HOST_MEMORY;
    }

    saveptr = NULL;
    tmp = kvpstr;
    size_t i = 0;
    while ((line = strtok_r(tmp, "\r\n", &saveptr))) {
        tmp = NULL;

        /*
         * Call the parser handler, giving them the data and current
         * offset.
         */
        bool result = generic_parse_kvp(line, i, data, handler);
        if (!result) {
            goto out;
        }

        i++;
    }

    rv = CKR_OK;

out:

    free(kvpstr);

    return rv;
}

tobject *tobject_new(sqlite3_stmt *stmt) {

    tobject *tobj = calloc(1, sizeof(tobject));
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

        } else if (!strcmp(name, "sid")) {
            // Ignore sid we don't need it as sobject has that data.
        } else if (!strcmp(name, "priv")) {
            tobj->priv = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(tobj->priv, error);

        } else if (!strcmp(name, "pub")) {
            tobj->pub = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(tobj->pub, error);

        } else if (!strcmp(name, "objauth")) {
            tobj->objauth = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(tobj->objauth, error);
        } else if (!strcmp(name, "attrs")) {
            const char *attrs = (const char *)sqlite3_column_text(stmt, i);
            CK_RV rv = parse_generic_kvp_line(attrs, tobj, alloc_attrs, parse_attrs);
            if (rv != CKR_OK) {
                if (rv == CKR_HOST_MEMORY) {
                    goto_oom(NULL, error);
                }
                LOGE("Could not parse DB attrs, got: \"%s\"", attrs);
                goto error;
            }
        } else if (!strcmp(name, "mech")) {
            const char *mech = (const char *)sqlite3_column_text(stmt, i);
            CK_RV rv = parse_generic_kvp_line(mech, tobj, alloc_mech, parse_mech);
            if (rv != CKR_OK) {
                if (rv == CKR_HOST_MEMORY) {
                    goto_oom(NULL, error);
                }
                LOGE("Could not parse DB mech, got: \"%s\"", mech);
                goto error;
            }
        } else {
            LOGE("Unknown row, got: %s", name);
            goto error;
        }
    }

    return tobj;

error:
    tobject_free(tobj);
    return NULL;
}

int init_tobjects(unsigned sid, tobject **head) {

    UNUSED(sid);

    const char *sql =
            "SELECT * FROM tobjects WHERE sid=?1";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot prepare tobject query: %s\n", sqlite3_errmsg(global.db));
        return rc;
    }

    rc = sqlite3_bind_int(stmt, 1, sid);
    if (rc != SQLITE_OK) {
        LOGE("Cannot bind tobject sid: %s\n", sqlite3_errmsg(global.db));
        goto error;
    }

    list *cur = NULL;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {

        tobject *t = tobject_new(stmt);

        if (!t) {
            goto error;
        }

        if (!*head) {
            *head = t;
            cur = &t->l;
            continue;
        }

        /*
         * This check as been added to silence a false positive from scan-build:
         * ../src/lib/db.c:454:23: warning: Access to field 'next' results in a dereference of a null pointer (loaded from variable 'cur')
         *   cur->next = &t->l;
         *   ~~~       ^
         */
        if (!cur) {
            LOGE("Linked list not initialized properly");
            goto error;
        }

        cur->next = &t->l;
        cur = cur->next;
    }

    rc = SQLITE_OK;

error:
    sqlite3_finalize(stmt);
    return rc;
}

int init_sobject(unsigned tokid, sobject *sobj) {

    const char *sql =
            "SELECT * FROM sobjects WHERE id=?1";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot prepare sobject query: %s\n", sqlite3_errmsg(global.db));
        return rc;
    }

    rc = sqlite3_bind_int(stmt, 1, tokid);
    if (rc != SQLITE_OK) {
        LOGE("Cannot bind sobject tokid: %s\n", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        LOGE("stepping in sobjects, got: %s\n", sqlite3_errstr(rc));
        goto error;
    }

    int i;
    int col_count = sqlite3_data_count(stmt);
    for (i=0; i < col_count; i++) {
        const char *name = sqlite3_column_name(stmt, i);

        if (!strcmp(name, "id")) {
            sobj->id = sqlite3_column_int(stmt, i);

        } else if (!strcmp(name, "priv")) {
            sobj->priv = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sobj->priv, error);

        } else if (!strcmp(name, "pub")) {
            sobj->pub = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sobj->pub, error);

        } else if (!strcmp(name, "objauth")) {
            sobj->objauth = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sobj->objauth, error);

        } else if (!strcmp(name, "tokid")) {
            // pass

        } else {
            LOGE("Unknown row, got: %s", name);
            goto error;
        }
    }

    rc = SQLITE_OK;

error:
    sqlite3_finalize(stmt);

    return rc;
}

int init_pobject(unsigned pid, pobject *pobj) {

    const char *sql =
            "SELECT handle FROM pobjects WHERE id=?1";

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

    pobj->handle = sqlite3_column_int(stmt, 0);

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


int init_wrappingobject(unsigned tokid, wrappingobject *wobj) {

    const char *sql =
            "SELECT * FROM wrappingobjects WHERE tokid=?1";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(global.db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOGE("Cannot prepare wrappingobject query: %s\n", sqlite3_errmsg(global.db));
        return rc;
    }

    rc = sqlite3_bind_int(stmt, 1, tokid);
    if (rc != SQLITE_OK) {
        LOGE("Cannot bind tokid: %s\n", sqlite3_errmsg(global.db));
        goto error;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        LOGE("stepping in wrappingobjects, got: %s\n", sqlite3_errstr(rc));
        goto error;
    }

    int i;
    int col_count = sqlite3_data_count(stmt);
    for (i=0; i < col_count; i++) {
        const char *name = sqlite3_column_name(stmt, i);

        if (!strcmp(name, "id")) {
            wobj->id = sqlite3_column_int(stmt, i);
        } else if (!strcmp(name, "objauth")) {
            wobj->objauth = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(wobj->objauth, error);
        } else if (!strcmp(name, "pub")) {
            wobj->pub = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(wobj->pub, error);
        } else if (!strcmp(name, "priv")) {
            wobj->priv = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(wobj->priv, error);
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
        } else if (!strcmp(name, "userauthiters")) {
            sealobj->userauthiters = sqlite3_column_int(stmt, i);
        } else if (!strcmp(name, "userauthsalt")) {
            sealobj->userauthsalt = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sealobj->userauthsalt, error);
        } else if (!strcmp(name, "userpriv")) {
            sealobj->userpriv = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sealobj->userpriv, error);
        } else if (!strcmp(name, "userpub")) {
            sealobj->userpub = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sealobj->userpub, error);
        } else if (!strcmp(name, "soauthiters")) {
            sealobj->soauthiters = sqlite3_column_int(stmt, i);
        } else if (!strcmp(name, "soauthsalt")) {
            sealobj->soauthsalt = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sealobj->soauthsalt, error);
        } else if (!strcmp(name, "sopriv")) {
            sealobj->sopriv = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sealobj->sopriv, error);
        } else if (!strcmp(name, "sopub")) {
            sealobj->sopub = twist_new((char *)sqlite3_column_text(stmt, i));
            goto_oom(sealobj->sopub, error);
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

CK_RV db_get_tokens(token **t, size_t *len) {

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

            } else if (!strcmp(name, "userpobjauthkeysalt")) {
                t->userpobjauthkeysalt = twist_new((char *)sqlite3_column_text(stmt, i));
                goto_oom(t->userpobjauthkeysalt, error);

            } else if (!strcmp(name, "userpobjauthkeyiters")) {
                t->userpobjauthkeyiters = sqlite3_column_int(stmt, i);

            } else if (!strcmp(name, "userpobjauth")) {
                t->userpobjauth = twist_new((char *)sqlite3_column_text(stmt, i));
                goto_oom(t->userpobjauth, error);

            } else if (!strcmp(name, "sopobjauthkeysalt")) {
                t->sopobjauthkeysalt = twist_new((char *)sqlite3_column_text(stmt, i));
                goto_oom(t->sopobjauthkeysalt, error);

            } else if (!strcmp(name, "sopobjauthkeyiters")) {
                t->sopobjauthkeyiters = sqlite3_column_int(stmt, i);

            } else if (!strcmp(name, "sopobjauth")) {
                t->sopobjauth = twist_new((char *)sqlite3_column_text(stmt, i));
                goto_oom(t->sopobjauth, error);

            } else if (!strcmp(name, "config")) {
                const char *config = (const char *)sqlite3_column_text(stmt, i);
                CK_RV rv = parse_generic_kvp_line(config, t, NULL,
                        parse_token_config);
                if (rv != CKR_OK) {
                    if (rv == CKR_HOST_MEMORY) {
                        goto_oom(NULL, error);
                    }
                    LOGE("Could not parse token config, got: \"%s\"", config);
                    goto error;
                }

            } else {
                LOGE("Unknown key: %s", name);
                goto error;
            }
        }

        int rc = init_pobject(t->pid, &t->pobject);
        if (rc != SQLITE_OK) {
            goto error;
        }

        /*
         * If we're using the TPM to wrap objects, get the wrapping objet
         * details.
         *
         * Note: the other case of SW, where the wrapping object auth value
         * is the key, the assignment occurs later when the key is unsealed
         * via login.
         */
        if (t->config.sym_support) {
            rc = init_wrappingobject(t->id, &t->wrappingobject);
            if (rc != SQLITE_OK) {
                goto error;
            }
        }

        rc = init_sealobjects(t->id, &t->sealobject);
        if (rc != SQLITE_OK) {
            goto error;
        }

        rc = init_sobject(t->id, &t->sobject);
        if (rc != SQLITE_OK) {
            goto error;
        }

        rc = init_tobjects(t->sobject.id, &t->tobjects);
        if (rc != SQLITE_OK) {
            goto error;
        }
    }

    *t = tmp;
    *len = cnt;
    sqlite3_finalize(stmt);

    return CKR_OK;

error:
    token_free_list(tmp, cnt);
    sqlite3_finalize(stmt);
    return CKR_GENERAL_ERROR;

}

CK_RV db_init(void) {

    return db_new(&global.db);
}

CK_RV db_destroy(void) {
    return db_free(&global.db);
}

#define DB_NAME "tpm2_pkcs11.sqlite3"
#define PKCS11_STORE_ENV_VAR "TPM2_PKCS11_STORE"
static char *db_get_path(void) {

    int rc;
    char *path;

    const char *fmt = "%s/"DB_NAME;
    char *base_path = getenv(PKCS11_STORE_ENV_VAR);
    if (!base_path) {
        fmt = ".tpm2_pkcs11/"DB_NAME;
        base_path = getenv("HOME");
    }

    rc = asprintf(&path, fmt, base_path);
    UNUSED(rc);

    if (!path) {
        return NULL;
    }

    struct stat sb;
    rc = stat(path, &sb);
    if (rc) {
        LOGE("Could not stat db \""DB_NAME"\" under store \"%s\", error: %s", base_path,
                strerror(errno));
        LOGE("Consider exporting "PKCS11_STORE_ENV_VAR" to point to a valid store sirectory");
        free(path);
        return NULL;
    }

    return path;
}

CK_RV db_new(sqlite3 **db) {

    char *path = db_get_path();

    int rc = sqlite3_open(path, db);
    free(path);
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
