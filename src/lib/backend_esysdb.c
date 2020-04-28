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

CK_RV backend_esysdb_ctx_new(token *t) {
    return tpm_ctx_new(t->config.tcti, &t->tctx);
}

void backend_esysdb_ctx_free(token *t) {
    tpm_ctx_free(t->tctx);
}

static CK_RV get_or_create_primary(token *t) {

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
    twist blob = NULL;
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
            &t->sealobject.sopriv);
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

/** Retrieve all esys tokens available.
 *
 * See backend_get_tokens()
 */
CK_RV backend_esysdb_get_tokens(token **tok, size_t *len) {
    return db_get_tokens(tok, len);
}

static void change_token_mem_data(token *tok, bool is_so,
        twist newsalthex, twist newprivblob, twist newpubblob) {

    twist *authsalt;
    twist *priv;
    twist *pub;

    if (is_so) {
        authsalt = &tok->sealobject.soauthsalt;
        priv = &tok->sealobject.sopriv;
        pub = &tok->sealobject.sopub;
    } else {
        authsalt = &tok->sealobject.userauthsalt;
        priv = &tok->sealobject.userpriv;
        pub = &tok->sealobject.userpub;
    }

    twist_free(*authsalt);
    twist_free(*priv);

    *authsalt = newsalthex;
    *priv = newprivblob;

    if (newpubblob) {
        twist_free(*pub);
        *pub = newpubblob;
    }
}

/** Initialize the user PIN data for a given token.
 *
 * See backend_init_user()
 */
CK_RV backend_esysdb_init_user(token *tok, const twist sealdata,
                        const twist newauthhex, const twist newsalthex) {
    CK_RV rv = CKR_GENERAL_ERROR;

    twist newpubblob = NULL;
    twist newprivblob = NULL;

    /* create a new seal object and seal the data */
    rv = tpm2_create_seal_obj(tok->tctx,
            tok->pobject.objauth,
            tok->pobject.handle,
            newauthhex,
            tok->sealobject.userpub,
            sealdata,
            &newpubblob,
            &newprivblob);
    if (rv != CKR_OK) {
        goto out;
    }

    /* update the db data */
    rv = db_update_for_pinchange(
            tok,
            false,
            /* new seal object auth metadata */
            newsalthex,

            /* private and public blobs */
            newprivblob,
            newpubblob);
    if (rv != CKR_OK) {
        goto out;
    }

     /* update in-memory metadata for seal object and primary object */
    change_token_mem_data(tok, false, newsalthex, newprivblob, newpubblob);

out:
    /* If the function failed, then these pointers ARE NOT CLAIMED and must be free'd */
    if (rv != CKR_OK) {
        twist_free(newprivblob);
        twist_free(newpubblob);
    }

    return rv;
}

/** Store a new object for a given token in the backend.
 *
 * See backend_add_object()
 */
CK_RV backend_esysdb_add_object(token *t, tobject *tobj) {
    LOGV("Adding object to esysdb backend");
    return db_add_new_object(t, tobj);
}

/** Given a token with a config, persist it.
 *
 * See backend_update_token_config()
 */
CK_RV backend_esysdb_update_token_config (token *tok) {

    return db_update_token_config(tok);
}

CK_RV backend_esysdb_update_tobject_attrs(tobject *tobj, attr_list *attrs) {

    return db_update_tobject_attrs(tobj->id, attrs);
}

CK_RV backend_esysdb_rm_tobject(tobject *tobj) {

    return db_delete_object(tobj);
}

/** Unseal a token's wrapping key.
 *
 * see backend_token_unseal_wrapping_key()
 */
CK_RV backend_esysdb_token_unseal_wrapping_key(token *tok, bool user, twist tpin) {

    CK_RV rv = CKR_GENERAL_ERROR;
    bool on_error_flush_session = false;

    sealobject *sealobj = &tok->sealobject;
    twist sealpub = user ? sealobj->userpub : sealobj->sopub;
    twist sealpriv = user ? sealobj->userpriv : sealobj->sopriv;

    if (user && !sealpub && !sealpriv) {
        return CKR_USER_PIN_NOT_INITIALIZED;
    }

    assert(sealpub);
    assert(sealpriv);

    if (!tpm_session_active(tok->tctx)) {
        LOGV("token parent object handle is 0x%08x", tok->pobject.handle);
        CK_RV tmp = tpm_session_start(tok->tctx, tok->pobject.objauth, tok->pobject.handle);
        if (tmp != CKR_OK) {
            LOGE("Could not start Auth Session with the TPM.");
            return tmp;
        }

        on_error_flush_session = true;
    }

    uint32_t pobj_handle = tok->pobject.handle;
    twist pobjauth = tok->pobject.objauth;
    uint32_t sealhandle;

    bool res = tpm_loadobj(tok->tctx, pobj_handle, pobjauth, sealpub, sealpriv, &sealhandle);
    if (!res) {
        goto error;
    }

    twist sealsalt = user ? sealobj->userauthsalt : sealobj->soauthsalt;
    twist sealobjauth = utils_hash_pass(tpin, sealsalt);
    if (!sealobjauth) {
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    twist wrappingkeyhex = tpm_unseal(tok->tctx, sealhandle, sealobjauth);
    twist_free(sealobjauth);
    tpm_flushcontext(tok->tctx, sealhandle);
    if (!wrappingkeyhex) {
        rv = CKR_PIN_INCORRECT;
        goto error;
    }

    if (tok->wrappingkey) {
        twist_free(wrappingkeyhex);
    } else {
        tok->wrappingkey = twistbin_unhexlify(wrappingkeyhex);
        twist_free(wrappingkeyhex);
        if (!tok->wrappingkey) {
            LOGE("Expected internal wrapping key in base 16 format");
            goto error;
        }
    }

    return CKR_OK;

error:
    if (on_error_flush_session) {
        tpm_session_stop(tok->tctx);
    }

    return rv;
}
