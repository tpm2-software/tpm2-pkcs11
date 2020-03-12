/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include "backend_fapi.h"
#include <tss2/tss2_fapi.h>

FAPI_CONTEXT *fctx = NULL;

CK_RV backend_fapi_init(void) {
    if (fctx != NULL) {
        LOGW("Backend FAPI already initialized.");
        return CKR_OK;
    }
    LOGV("Calling Fapi_Initialize");
    TSS2_RC rc = Fapi_Initialize(&fctx, NULL);
    if (rc) {
        LOGW("Could not initialize FAPI");
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

CK_RV backend_fapi_destroy(void) {
    LOGV("Calling Fapi_Finalize");
    Fapi_Finalize(&fctx);
    return CKR_OK;
}

CK_RV backend_fapi_ctx_new(token *t) {
    t->fapi.ctx = fctx;
    return CKR_OK;
}

void backend_fapi_ctx_free(token *t) {
    (void)(t);
}


#define PREFIX "/HS/SRK/tpm2-pkcs11-token-"

static char * tss_path_from_id(unsigned id, const char *type) {
    char *path = malloc(strlen(PREFIX) + strlen(type) + 1 + 8 + 1);
    if (!path)
        return NULL;

    sprintf(&path[0], PREFIX "%s-%08x", type, id);

    return path;
}

/** Create a new token in fapi backend.
 *
 * See backend_create_token_seal()
 */
CK_RV backend_fapi_create_token_seal(token *t, const twist hexwrappingkey,
                       const twist newauth, const twist newsalthex) {
    TSS2_RC rc;
    uint8_t *tpm2bPublic, *tpm2bPrivate, *appdata;
    size_t tpm2bPublicSize, tpm2bPrivateSize, appdata_len;
    twist pub, priv;

    char *path = tss_path_from_id(t->id, "so");

    rc = Fapi_CreateSeal(t->fapi.ctx, path,
                         NULL /*type*/, twist_len(hexwrappingkey),
                         NULL /*policy*/, newauth, (uint8_t*)hexwrappingkey);
    if (rc) {
        LOGE("Creation of a FAPI seal failed.");
        free(path);
        return CKR_GENERAL_ERROR;
    }

    rc = Fapi_SetDescription(t->fapi.ctx, path, (char*)&t->label[0]);
    if (rc) {
        LOGE("Setting FAPI seal description failed.");
        Fapi_Delete(t->fapi.ctx, path);
        free(path);
        return CKR_GENERAL_ERROR;
    }

    appdata_len = twist_len(newsalthex) + 1;
    appdata = malloc(appdata_len);
    if (!appdata) {
        LOGE("oom");
        Fapi_Delete(t->fapi.ctx, path);
        free(path);
        return CKR_GENERAL_ERROR;
    }        
    memcpy(appdata, newsalthex, appdata_len - 1);
    appdata[appdata_len - 1] = '\0';

    rc = Fapi_SetAppData(t->fapi.ctx, path, appdata, appdata_len);
    free(appdata);
    if (rc) {
        LOGE("Setting FAPI seal appdata failed.");
        Fapi_Delete(t->fapi.ctx, path);
        free(path);
        return CKR_GENERAL_ERROR;
    }

    rc = Fapi_GetTpmBlobs(t->fapi.ctx, path, &tpm2bPublic, &tpm2bPublicSize,
                          &tpm2bPrivate, &tpm2bPrivateSize, NULL /* policy */);
    free(path);
    if (rc) {
        LOGE("Getting the TPM data blobs failed.");
        return CKR_GENERAL_ERROR;
    }

    pub = twistbin_new(tpm2bPublic, tpm2bPublicSize);
    Fapi_Free(tpm2bPublic);
    priv = twistbin_new(tpm2bPrivate, tpm2bPrivateSize);
    Fapi_Free(tpm2bPrivate);
    if (!pub || !priv) {
        LOGE("Out of memory");
        return CKR_GENERAL_ERROR;
    }

    t->sealobject.sopub = pub;
    t->sealobject.sopriv = priv;
    t->sealobject.soauthsalt = newsalthex;

    t->type = token_type_fapi;

    /* TODO get TCTI config from ENV var and use throughout this process */
    t->config.is_initialized = true;

    assert(t->id);

    /* FIXME Manually setting SRK handle here */
    t->pid = 0x81000001;

    return CKR_OK;
}

/** Retrieve all fapi tokens available.
 *
 * See backend_get_tokens()
 */
CK_RV backend_fapi_add_tokens(token *tok, size_t *len) {
    CK_RV rv = CKR_GENERAL_ERROR;
    TSS2_RC rc;
    char *pathlist, *path, *subpath, *strtokr_save = NULL;
    unsigned id;
    char *label;
    uint8_t *tpm2bPublic, *tpm2bPrivate, *appdata;
    size_t tpm2bPublicSize, tpm2bPrivateSize, appdata_len;
    twist pub, priv, blob;
    token *t;

    rc = Fapi_List(fctx, "/HS/SRK", &pathlist);
    if (rc == 0x0006000a) {
        /* If no token seals were found, we're done here. */
        LOGV("No FAPI token seals found.");
        return CKR_OK;
    }
    if (rc) {
        LOGE("Listing FAPI token objects failed.");
        return CKR_GENERAL_ERROR;
    }

    for (path = strtok_r(pathlist, ":", &strtokr_save); path != NULL;
            path = strtok_r(NULL, ":", &strtokr_save)) {
        /* Skip over potential profile nodes that don't interest us. */
        if (!strncmp(path, "/P_", strlen("/P_"))) {
            subpath = index(path + 1, '/');
            if (!subpath) {
                LOGE("Malformed path received");
                goto error;
            }
        } else {
            subpath = path;
        }
        if (sscanf(subpath, PREFIX "so-%08x", &id) != 1) {
            LOGV("%s aka %s is not a token, ignoring", path, subpath);
            continue;
        }
        LOGV("Found a token at %s", path);

        t = &tok[*len];
        *len += 1;

        t->type = token_type_fapi;
        t->id = id;

        rv = token_min_init(t);
        if (rv) {
            LOGE("token min init failed");
            goto error;
        }

        //FIXME
        t->fapi.ctx = fctx;

        rc = Fapi_GetDescription(t->fapi.ctx, path, &label);
        if (rc) {
            LOGE("Getting FAPI seal description failed.");
            goto error;
        }
        memcpy(&t->label[0], label, strlen(label));
        Fapi_Free(label);

        /* FIXME Manually setting SRK handle here */
        t->pid = 0x81000001;

        rc = Fapi_GetTpmBlobs(t->fapi.ctx, path, &tpm2bPublic, &tpm2bPublicSize,
                              &tpm2bPrivate, &tpm2bPrivateSize, NULL /* policy */);
        if (rc) {
            LOGE("Getting the TPM data blobs failed.");
            goto error;
        }

        pub = twistbin_new(tpm2bPublic, tpm2bPublicSize);
        Fapi_Free(tpm2bPublic);
        priv = twistbin_new(tpm2bPrivate, tpm2bPrivateSize);
        Fapi_Free(tpm2bPrivate);
        if (!pub || !priv) {
            LOGE("Out of memory");
            goto error;
        }

        t->sealobject.sopub = pub;
        t->sealobject.sopriv = priv;

        rc = Fapi_GetAppData(t->fapi.ctx, path, &appdata, &appdata_len);
        if (rc) {
            LOGE("Getting FAPI seal appdata failed.");
            goto error;
        }

        t->sealobject.soauthsalt = twistbin_new(appdata, strlen((char *)appdata));
        if (t->sealobject.soauthsalt == NULL) {
            LOGE("OOM");
            goto error;
        }

        rv = tpm_get_existing_primary(t->tctx, &t->pobject.handle, &blob);
        if (rv != CKR_OK) {
            return rv;
        }
        twist_free(blob);

        t->config.is_initialized = true;

        /* Initialize the User PIN area. */
        /*********************************/
        path = tss_path_from_id(t->id, "usr");
        if (!path) {
            LOGE("OOM");
            goto error;
        }
        rc = Fapi_GetTpmBlobs(t->fapi.ctx, path, &tpm2bPublic, &tpm2bPublicSize,
                              &tpm2bPrivate, &tpm2bPrivateSize, NULL /* policy */);
        if (rc == 0x00060020) {
            LOGV("No user pin found for token %08x.", t->id);
            free(path);
            continue;
        }
        if (rc) {
            LOGE("Getting the TPM data blobs failed.");
            free(path);
            return CKR_GENERAL_ERROR;
        }
        LOGV("Adding user pin at %s", path);

        pub = twistbin_new(tpm2bPublic, tpm2bPublicSize);
        Fapi_Free(tpm2bPublic);
        priv = twistbin_new(tpm2bPrivate, tpm2bPrivateSize);
        Fapi_Free(tpm2bPrivate);
        if (!pub || !priv) {
            LOGE("Out of memory");
            goto error;
        }

        t->sealobject.userpub = pub;
        t->sealobject.userpriv = priv;

        rc = Fapi_GetAppData(t->fapi.ctx, path, &appdata, NULL);
        if (rc) {
            LOGE("Getting FAPI seal appdata failed.");
            goto error;
        }

        t->sealobject.userauthsalt = twistbin_new(appdata, strlen((char *)appdata));
        Fapi_Free(appdata);
        if (t->sealobject.userauthsalt == NULL) {
            LOGE("OOM");
            goto error;
        }
    }

    rv = CKR_OK;

out:
    Fapi_Free(pathlist);
    return rv;

error:
    if (rv == CKR_OK)
        rv = CKR_GENERAL_ERROR;
    goto out;
}

/** Initialize the user PIN data for a given token.
 *
 * See backend_init_user()
 */
CK_RV backend_fapi_init_user(token *t, const twist sealdata,
                        const twist newauthhex, const twist newsalthex) {
    TSS2_RC rc;
    uint8_t *tpm2bPublic, *tpm2bPrivate, *appdata;
    size_t tpm2bPublicSize, tpm2bPrivateSize, appdata_len;
    twist pub, priv;

    char *path = tss_path_from_id(t->id, "usr");

    rc = Fapi_CreateSeal(t->fapi.ctx, path,
                         NULL /*type*/, twist_len(sealdata),
                         NULL /*policy*/, newauthhex, (uint8_t*)sealdata);
    if (rc) {
        LOGE("Creation of a FAPI seal failed.");
        free(path);
        return CKR_GENERAL_ERROR;
    }

    rc = Fapi_SetDescription(t->fapi.ctx, path, (char*)&t->label[0]);
    if (rc) {
        LOGE("Setting FAPI seal description failed.");
        Fapi_Delete(t->fapi.ctx, path);
        free(path);
        return CKR_GENERAL_ERROR;
    }

    appdata_len = twist_len(newsalthex) + 1;
    appdata = malloc(appdata_len);
    if (!appdata) {
        LOGE("oom");
        Fapi_Delete(t->fapi.ctx, path);
        free(path);
        return CKR_GENERAL_ERROR;
    }        
    memcpy(appdata, newsalthex, appdata_len - 1);
    appdata[appdata_len - 1] = '\0';

    rc = Fapi_SetAppData(t->fapi.ctx, path, appdata, appdata_len);
    free(appdata);
    if (rc) {
        LOGE("Setting FAPI seal appdata failed.");
        Fapi_Delete(t->fapi.ctx, path);
        free(path);
        return CKR_GENERAL_ERROR;
    }

    rc = Fapi_GetTpmBlobs(t->fapi.ctx, path, &tpm2bPublic, &tpm2bPublicSize,
                          &tpm2bPrivate, &tpm2bPrivateSize, NULL /* policy */);
    free(path);
    if (rc) {
        LOGE("Getting the TPM data blobs failed.");
        return CKR_GENERAL_ERROR;
    }

    pub = twistbin_new(tpm2bPublic, tpm2bPublicSize);
    Fapi_Free(tpm2bPublic);
    priv = twistbin_new(tpm2bPrivate, tpm2bPrivateSize);
    Fapi_Free(tpm2bPrivate);
    if (!pub || !priv) {
        LOGE("Out of memory");
        return CKR_GENERAL_ERROR;
    }

    twist_free(t->sealobject.userpub);
    twist_free(t->sealobject.userpriv);
    twist_free(t->sealobject.userauthsalt);

    t->sealobject.userpub = pub;
    t->sealobject.userpriv = priv;
    t->sealobject.userauthsalt = newsalthex;

    return CKR_OK;
}
