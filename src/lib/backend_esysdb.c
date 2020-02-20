/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include "backend_esysdb.h"
#include "db.h"
#include "tpm.h"

CK_RV backend_esysdb_init(void) {
    tpm_init();

    return db_init();
}

CK_RV backend_esysdb_destroy(void) {
    db_destroy();

    tpm_destroy();

    return CKR_OK;
}

static CK_RV get_or_create_primary(token *t) {

    twist blob = NULL;

    /* if there is no primary object ... */
    if (t->pid) {
        return CKR_OK;
    }

    /* is there one in the db to use ? */
    CK_RV rv = db_get_first_pid(&t->pid);
    if (rv != CKR_OK) {
        return rv;
    }

    /* if so use it */
    if (t->pid) {
        /* tokens in the DB store already have an associated primary object */
        return db_init_pobject(t->pid, &t->pobject, t->tctx);
    }

    /* is their a PC client spec key ? */
    rv = tpm_get_existing_primary(t->tctx, &t->pobject.handle, &blob);
    if (rv != CKR_OK) {
        return rv;
    }

    /* nothing, create one */
    if (!t->pobject.handle) {
        rv = tpm_create_primary(t->tctx, &t->pobject.handle, &blob);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    assert(t->pobject.handle);

    rv = db_add_primary(blob, &t->pid);
    assert(t->pid);
    twist_free(blob);
    return rv;
}

/** Create a new token in esysdb backend.
 *
 * See backend_create_token_seal()
 */
CK_RV backend_esysdb_create_token_seal(token *t, const twist hexwrappingkey,
                       const twist newauth, const twist newsalthex) {

    CK_RV rv = CKR_GENERAL_ERROR;

    /*
     * find or create a primary object and get the serialized blob
     * for it.
     */
    rv = get_or_create_primary(t);
    if (rv != CKR_OK) {
        LOGE("Could not find nor create a primary object");
        goto error;
    }

    /* we have a primary object, create the seal object underneath it */
    rv = tpm2_create_seal_obj(t->tctx, t->pobject.objauth, t->pobject.handle,
            newauth, NULL, hexwrappingkey, &t->sealobject.sopub,
            &t->sealobject.sopriv, &t->sealobject.handle);
    if (rv != CKR_OK) {
        LOGE("Could not create SO seal object");
        goto error;
    }

    t->sealobject.soauthsalt = newsalthex;

    /* TODO get TCTI config from ENV var and use throughout this process */
    t->config.is_initialized = true;

    rv = db_add_token(t);
    if (rv != CKR_OK) {
        LOGE("Could not add token to db");
        goto error;
    }

    assert(t->id);

error:
    return rv;
}

/** Retrieve the all tokens available.
 *
 * See backend_get_tokens()
 */
CK_RV backend_esysdb_get_tokens(token **tok, size_t *len) {
    return db_get_tokens(tok, len);
}
