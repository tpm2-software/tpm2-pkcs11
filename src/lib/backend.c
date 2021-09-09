/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include "backend.h"
#include "backend_esysdb.h"
#include "backend_fapi.h"

enum backend {
    backend_error,
    backend_esysdb,
    backend_fapi
};

static enum backend get_backend(void) {

    const char *env = getenv("TPM2_PKCS11_BACKEND");

    if (!env || !strcasecmp(env, "esysdb")) {
        return backend_esysdb;
    }

    if (!strcasecmp(env, "fapi")) {
        return backend_fapi;
    }

    return backend_error;
}

/* This file includes the logic for selecting, aggregating and
 * distributing calls to different backends.
 * For now this will only be the esysdb backend that uses tss2-esys
 * and sqlite3 for operations.
 * In the future, logic will be added to also include the tss2-fapi
 * library for storage and TPM interaction.
 */

static bool fapi_init = false;
static bool esysdb_init = false;

CK_RV backend_init(void) {
    LOGV("Initializing backends");

    enum backend backend = get_backend();

    if (backend == backend_error) {
        return CKR_GENERAL_ERROR;
    }

    CK_RV rv = backend_fapi_init();
    if (rv) {
        static const char *msg = "FAPI backend was not initialized.";
        if (backend == backend_fapi) {
            LOGE(msg);
            return rv;
        }
        LOGW(msg);
    } else {
        fapi_init = true;
    }

    rv = backend_esysdb_init();
    if (rv) {
        LOGW("ESYSDB backend was not initialized.");
    } else {
        esysdb_init = true;
    }

    if (!fapi_init && !esysdb_init) {
        LOGE("Neither FAPI nor ESYSDB backends could be initialized.");
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

CK_RV backend_destroy(void) {
    LOGV("Destroying backends");
    CK_RV rv = CKR_OK;

    enum backend backend = get_backend();

    if (fapi_init) {
        rv = backend_fapi_destroy();
        if (backend != backend_fapi) {
            rv = CKR_OK;
        }
    }
    if (esysdb_init) {
        CK_RV rv2 = backend_esysdb_destroy();
        if (rv2 != CKR_OK) {
            rv = rv2;
        }
    }
    fapi_init = false;
    esysdb_init = false;
    return rv;
}

CK_RV backend_ctx_new(token *t) {
    enum backend backend = get_backend();

    if (backend == backend_fapi) {
        return backend_fapi_ctx_new(t);
    } else {
        return backend_esysdb_ctx_new(t);
    }
}

void backend_ctx_free(token *t) {
    if (t->type == token_type_esysdb) {
        backend_esysdb_ctx_free(t);
    } else {
        backend_fapi_ctx_free(t);
    }
    tpm_ctx_free(t->tctx);
}

void backend_ctx_reset(token *t) {
    backend_esysdb_ctx_reset(t);
    /* fapi doesn't appear to need anything */
}

/** Create a new token
 *
 * Create a new sealed object and store it in the data store.
 *
 * @param[in,out] t The token information on input and generated token
 *                  on output.
 * @param[in] hexwrappingkey TODO
 * @param[in] newauth The authorization value for the security operator
 *                    of the newly created token.
 * @param[in] newsalthex TODO
 * @returns TODO
 */
CK_RV backend_create_token_seal(token *t, const twist hexwrappingkey,
                       const twist newauth, const twist newsalthex) {
    enum backend backend = get_backend();

    if (backend == backend_fapi) {
        if (!fapi_init) {
            LOGE("FAPI backend not initialized.");
            return CKR_GENERAL_ERROR;
        }
        LOGV("Creating token under FAPI");
        return backend_fapi_create_token_seal(t, hexwrappingkey, newauth, newsalthex);
    } else {
        if (!esysdb_init) {
            LOGE("FAPI backend not initialized.");
            return CKR_GENERAL_ERROR;
        }
        LOGV("Creating token under ESYSDB");
        return backend_esysdb_create_token_seal(t, hexwrappingkey, newauth, newsalthex);
    }
}

/** Retrieve all tokens available.
 *
 * The returned list is a set of all stored tokens with all
 * objects inside the token structure.
 * @param[out] tok The list of tokens.
 * @param[out] len The number of entries in tok.
 * @returns TODO
 */
CK_RV backend_get_tokens(token **tok, size_t *len) {
    CK_RV rv = CKR_GENERAL_ERROR;

    enum backend backend = get_backend();

    /* make sure tmp has a path to be populated */
    if (!esysdb_init && !fapi_init) {
        LOGE("No backend initialized");
        return CKR_GENERAL_ERROR;
    }

    token *tmp = calloc(MAX_TOKEN_CNT, sizeof(token));
    if (!tmp) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    if (esysdb_init) {
        rv = backend_esysdb_get_tokens(tmp, len);
        if (rv) {
            LOGE("Getting tokens from esysdb backend failed.");
            return rv;
        }
        LOGV("Esysdb returned %zi token", *len);
    }

    if (fapi_init) {
        rv = backend_fapi_add_tokens(tmp, len);
        if (rv) {
            static const char *msg = "Getting tokens from fapi backend failed.";
            if (backend == backend_fapi) {
                LOGE(msg);
                token_free_list(&tmp, len);
                return rv;
            } else {
                LOGW(msg);
            }
        }
        LOGV("FAPI + Esysdb returned %zi token", *len);
    }

    /* -1 for starting at id 1 and -1 for the empty token */
    if (*len >= MAX_TOKEN_CNT - 2) {
        LOGW("Too many tokens, must have less than %d to show empty tokens", MAX_TOKEN_CNT - 1);
        token_free_list(&tmp, len);
        return CKR_GENERAL_ERROR;
    }

    token *t = &tmp[*len];

    for (t->id = 1; t->id < MAX_TOKEN_CNT && *len; t->id += 1) {
        size_t i = 0;
        for (; i < *len; i++) {
            if ((tmp[i]).id == t->id) {
                break;
            }
        }
        if (i == *len) {
            break;
        }
    }

    *len += 1;
    rv = token_min_init(t);
    if (rv != CKR_OK) {
        token_free_list(&tmp, len);
        return rv;
    }

    *tok = tmp;

    LOGV("Esysdb + FAPI returned %zi token", *len);

    return rv;
}

/** Initialize the user PIN data for a given token.
 *
 * @param[in,out] t The token to initialize user pin for.
 * @param[in] sealdata The data to be stored inside the created seal.
 * @param[in] newauthhex The auth value to be set of the created seal.
 * @param[in] newsalthex The salt value to be stored for this auth.
 * returns TODO
 */
CK_RV backend_init_user(token *t, const twist sealdata,
                        const twist newauthhex, const twist newsalthex) {
    switch (t->type) {
    case token_type_esysdb:
        return backend_esysdb_init_user(t, sealdata, newauthhex, newsalthex);
    case token_type_fapi:
        return backend_fapi_init_user(t, sealdata, newauthhex, newsalthex);
    default:
        assert(1);
        return CKR_GENERAL_ERROR;
    }
}

/** Store a new object for a given token in the backend.
 *
 * Note: Adding the object to the ring buffer in the token
 *       struct is done independently.
 *
 * @param[in,out] t The token to add the object to.
 * @param[in] tobj The object to store.
 * @returns TODO
 */
CK_RV backend_add_object(token *t, tobject *tobj) {
    switch (t->type) {
    case token_type_esysdb:
        LOGV("Adding object to token using esysdb backend.");
        return backend_esysdb_add_object(t, tobj);
    case token_type_fapi:
        LOGV("Adding object to token using fapi backend.");
        return backend_fapi_add_object(t, tobj);
    default:
        assert(1);
        return CKR_GENERAL_ERROR;
    }
}

/** Given a token with a config, persist it.
 *
 * @param t
 *  The token whose config to propagate to persistent storage.
 *
 * @return
 *  CKR_OK on success, anything else is an error.
 */
CK_RV backend_update_token_config(token *t) {
    switch (t->type) {
    case token_type_esysdb:
        LOGV("Adding object to token using esysdb backend.");
        return backend_esysdb_update_token_config(t);
    case token_type_fapi:
        LOGE("Not supported on FAPI");
        return CKR_FUNCTION_NOT_SUPPORTED;
    default:
        assert(1);
        return CKR_GENERAL_ERROR;
    }
}
/** Given a token and tobject, will persist the new attributes.
 *
 * @param tok
 *  The token to persist to.
 * @param tobj
 *  The tobject to persist.
 * @param attrs
 *  The new attributes to persist.
 * @return
 *  CKR_OK on success, anything else is an error.
 */
CK_RV backend_update_tobject_attrs(token *tok, tobject *tobj, attr_list *attrs) {

    switch (tok->type) {
    case token_type_esysdb:
        return backend_esysdb_update_tobject_attrs(tobj, attrs);
    case token_type_fapi:
        return backend_fapi_update_tobject_attrs(tok, tobj, attrs);
    default:
        assert(1);
        return CKR_GENERAL_ERROR;
    }
}

/**
 * Removes a tobject from the backend.
 * @param tok
 *  The token to remove from.
 * @param tobj
 *  The tobject to remove.
 * @return
 *  CKR_OK on success, anything else is an error.
 */
CK_RV backend_rm_tobject(token *tok, tobject *tobj) {

    switch (tok->type) {
    case token_type_esysdb:
        return backend_esysdb_rm_tobject(tobj);
    case token_type_fapi:
        return backend_fapi_rm_tobject(tok, tobj);
    default:
        assert(1);
        return CKR_GENERAL_ERROR;
    }
}

/** Unseal a token's wrapping key.
 *
 * Unseal a token's wrapping key as part of the Login process.
 * The wrapping key is then used to decrypt the individual tobjects'
 * auth values.
 *
 * @param[in,out] tok The token to remove from.
 * @param[in] user Whether to unseal from the user or so seal.
 * @param[in] tpin The pin value to use for unsealing.
 * @return CKR_OK on success, anything else is an error.
 */
CK_RV backend_token_unseal_wrapping_key(token *tok, bool user, twist tpin) {

    switch (tok->type) {
    case token_type_esysdb:
        return backend_esysdb_token_unseal_wrapping_key(tok, user, tpin);
    case token_type_fapi:
        return backend_fapi_token_unseal_wrapping_key(tok, user, tpin);
    default:
        assert(1);
        return CKR_GENERAL_ERROR;
    }
}

/** Change the authValue of a token's seal blob.
 *
 * @param[in,out] tok The token to remove from.
 * @param[in] user Whether to unseal from the user or so seal.
 * @param[in] tpin The pin value to use for unsealing.
 * @return CKR_OK on success, anything else is an error.
 */
CK_RV backend_token_changeauth(token *tok, bool user, twist toldpin, twist tnewpin) {

    switch (tok->type) {
    case token_type_esysdb:
        return backend_esysdb_token_changeauth(tok, user, toldpin, tnewpin);
    case token_type_fapi:
        return backend_fapi_token_changeauth(tok, user, toldpin, tnewpin);
    default:
        assert(1);
        return CKR_GENERAL_ERROR;
    }
}
