/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include "backend.h"
#include "backend_esysdb.h"
#include "backend_fapi.h"

/* This file includes the logic for selecting, aggregating and
 * distributing calls to different backends.
 * For now this will only be the esysdb backend that uses tss2-esys
 * and sqlite3 for operations.
 * In the future, logic will be added to also inlcude the tss2-fapi
 * library for storage and TPM interaction.
 */

static bool fapi_init = false;
static bool esysdb_init = false;

CK_RV backend_init(void) {
    LOGV("Initializing backends");

    CK_RV rv = backend_fapi_init();
    if (rv) {
        LOGW("FAPI backend was not initialized.");
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
    if (fapi_init) {
        rv = backend_fapi_destroy();
    }
    if (esysdb_init) {
        CK_RV rv2 = backend_esysdb_destroy();
        if (!rv) {
            rv = rv2;
        }
    }
    fapi_init = false;
    esysdb_init = false;
    return rv;
}

CK_RV backend_ctx_new(token *t) {
    CK_RV rv = backend_fapi_ctx_new(t);
    if (rv) {
        return rv;
    }
    return backend_esysdb_ctx_new(t);
}

void backend_ctx_free(token *t) {
    backend_fapi_ctx_free(t);
    backend_esysdb_ctx_free(t);
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
    const char *env = getenv("FAPI_PREVIEW");
    if (env && (!strcmp(env, "yes") || !strcmp(env, "true"))) {
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
    token tmp;

    if (esysdb_init) {
        rv = backend_esysdb_get_tokens(tok, len);
        if (rv) {
            LOGE("Getting tokens from esysdb backend failed.");
            return rv;
        }
        LOGV("Esysdb returned %zi token", *len);

        /* This is used to move the empty token to the end. */
        /* TODO: Would be better to have a nicer way of doing so. */
        tmp = (*tok)[*len - 1];
        *len -= 1;
    }

    if (fapi_init) {
        rv = backend_fapi_add_tokens(*tok, len);
        if (rv) {
            LOGE("Getting tokens from fapi backend failed.");
            token_free_list(*tok, *len);
            return rv;
        }
    }

    if (esysdb_init) {
        (*tok)[*len] = tmp;
        *len += 1;
    }

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
 * Note: Adding the the object to the ring buffer in the token
 *       struct is done independantly.
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
        LOGW("Updating token config using esysdb backend.");
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
        LOGV("Adding object to token using esysdb backend.");
        LOGW("Updating token config using esysdb backend.");
        return backend_esysdb_update_tobject_attrs(tobj, attrs);
    case token_type_fapi:
        LOGE("Not supported on FAPI");
        return CKR_FUNCTION_NOT_SUPPORTED;
    default:
        assert(1);
        return CKR_GENERAL_ERROR;
    }
}
