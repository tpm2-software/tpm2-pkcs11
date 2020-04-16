/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include "backend_fapi.h"
#include "emitter.h"
#include "parser.h"
#include "utils.h"
#include <tss2/tss2_fapi.h>

FAPI_CONTEXT *fctx = NULL;
unsigned maxobjectid = 0;

CK_RV backend_fapi_init(void) {
    if (fctx) {
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
    UNUSED(t);
}


#define PREFIX "/HS/SRK/tpm2-pkcs11-token-"

static char * tss_path_from_id(unsigned id, const char *type) {
    /* Allocate for PREFIX + type + "-" + id + '\0' */
    size_t size = 0;
    safe_add(size, strlen(PREFIX), strlen(type));
    safe_adde(size, strlen(PREFIX));
    safe_adde(size, 1 + 8 + 1);

    char *path = malloc(size);
    if (!path) {
        return NULL;
    }

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

    /* Prefixing fapi_ids in order to avoid collisions with esysdb */
    t->id += 0x80;

    char *path = tss_path_from_id(t->id, "so");
    if (!path) {
        LOGE("No path constructed.");
        return CKR_GENERAL_ERROR;
    }

    rc = Fapi_CreateSeal(t->fapi.ctx, path,
                         NULL /*type*/, twist_len(hexwrappingkey),
                         NULL /*policy*/, newauth, (uint8_t*)hexwrappingkey);
    if (rc) {
        LOGE("Creation of a FAPI seal failed.");
        free(path);
        return CKR_GENERAL_ERROR;
    }

    /* Turn trailing whitespaces into trailing \0; cause some software is weird */
    for (size_t i = sizeof(t->label); i > 0; i--) {
        if (t->label[i-1] != ' ') {
            break;
        }
        t->label[i-1] = '\0';
    }

    char label[sizeof(t->label) + 1]; /* token-label length plus \0, cannot overflow */
    label[sizeof(t->label)] = '\0';
    memcpy(&label[0], &t->label[0], sizeof(t->label));

    rc = Fapi_SetDescription(t->fapi.ctx, path, &label[0]);
    if (rc) {
        LOGE("Setting FAPI seal description failed.");
        Fapi_Delete(t->fapi.ctx, path);
        free(path);
        return CKR_GENERAL_ERROR;
    }

    size_t appdata_len = 0;
    safe_add(appdata_len, twist_len(newsalthex), 1);

    uint8_t *appdata = malloc(appdata_len);
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

    uint8_t *tpm2bPublic;
    size_t tpm2bPublicSize;
    uint8_t *tpm2bPrivate;
    size_t tpm2bPrivateSize;
    rc = Fapi_GetTpmBlobs(t->fapi.ctx, path, &tpm2bPublic, &tpm2bPublicSize,
                          &tpm2bPrivate, &tpm2bPrivateSize, NULL /* policy */);
    free(path);
    if (rc) {
        LOGE("Getting the TPM data blobs failed.");
        return CKR_GENERAL_ERROR;
    }

    twist pub = twistbin_new(tpm2bPublic, tpm2bPublicSize);
    Fapi_Free(tpm2bPublic);
    twist priv = twistbin_new(tpm2bPrivate, tpm2bPrivateSize);
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
    twist blob;
    CK_RV rv = tpm_get_existing_primary(t->tctx, &t->pobject.handle, &blob);
    if (rv != CKR_OK) {
        return rv;
    }
    twist_free(blob);

    return CKR_OK;
}

/** Retrieve all fapi tokens available.
 *
 * See backend_get_tokens()
 */
CK_RV backend_fapi_add_tokens(token *tok, size_t *len) {
    CK_RV rv = CKR_GENERAL_ERROR;
    TSS2_RC rc;
    char *pathlist;

    rc = Fapi_List(fctx, "/HS/SRK", &pathlist);
    if (rc == TSS2_FAPI_RC_IO_ERROR) {
        /* If no token seals were found, we're done here. */
        LOGV("No FAPI token seals found.");
        return CKR_OK;
    }
    if (rc) {
        LOGE("Listing FAPI token objects failed.");
        return CKR_GENERAL_ERROR;
    }

    char *strtokr_save = NULL;
    for (char *path = strtok_r(pathlist, ":", &strtokr_save);
            path != NULL; path = strtok_r(NULL, ":", &strtokr_save)) {

        /* Skip over potential profile nodes that don't interest us. */
        char *subpath = path;
        if (!strncmp(path, "/P_", strlen("/P_"))) {
            subpath = index(path + 1, '/');
            if (!subpath) {
                LOGE("Malformed path received");
                goto error;
            }
        }

        unsigned id;
        if (sscanf(subpath, PREFIX "so-%08x", &id) != 1) {
            LOGV("%s aka %s is not a token, ignoring", path, subpath);
            continue;
        }
        LOGV("Found a token at %s", path);

        token *t = &tok[*len];
        memset(t, 0, sizeof(*t));
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

        char *label;
        rc = Fapi_GetDescription(t->fapi.ctx, path, &label);
        if (rc) {
            LOGE("Getting FAPI seal description failed.");
            goto error;
        }
        memcpy(&t->label[0], label, strlen(label));
        Fapi_Free(label);

        /* FIXME Manually setting SRK handle here */
        t->pid = 0x81000001;

        uint8_t *tpm2bPublic;
        size_t tpm2bPublicSize;
        uint8_t *tpm2bPrivate;
        size_t tpm2bPrivateSize;
        rc = Fapi_GetTpmBlobs(t->fapi.ctx, path, &tpm2bPublic, &tpm2bPublicSize,
                              &tpm2bPrivate, &tpm2bPrivateSize, NULL /* policy */);
        if (rc) {
            LOGE("Getting the TPM data blobs failed.");
            goto error;
        }

        twist pub = twistbin_new(tpm2bPublic, tpm2bPublicSize);
        Fapi_Free(tpm2bPublic);
        twist priv = twistbin_new(tpm2bPrivate, tpm2bPrivateSize);
        Fapi_Free(tpm2bPrivate);
        if (!pub || !priv) {
            LOGE("Out of memory");
            goto error;
        }

        t->sealobject.sopub = pub;
        t->sealobject.sopriv = priv;

        uint8_t *appdata;
        size_t appdata_len;

        rc = Fapi_GetAppData(t->fapi.ctx, path, &appdata, &appdata_len);
        if (rc) {
            LOGE("Getting FAPI seal appdata failed.");
            goto error;
        }

        t->sealobject.soauthsalt = twistbin_new(appdata, strlen((char *)appdata));
        if (!t->sealobject.soauthsalt) {
            LOGE("OOM");
            goto error;
        }

        size_t offset = 0;
        safe_add(offset, strlen((char *)appdata), 1);
        uint8_t *yaml = &appdata[offset];

        while ((size_t)(yaml - appdata) < appdata_len) {
            LOGV("Current tobj at offset %zi / %zi is: %s",
                 yaml - appdata, appdata_len, yaml);

            if (((size_t)(yaml - appdata) > appdata_len - 9) ||
                    (strlen((char*)yaml) < 10)) {
                LOGE("Incomplete tobj in appdata");
                Fapi_Free(appdata);
                goto error;
            }

            tobject *tobj = tobject_new();
            if (!tobj) {
                LOGE("oom");
                Fapi_Free(appdata);
                goto error;
            }

            if (sscanf((char*)yaml, "%08x:", &tobj->id) != 1) {
                LOGE("Could not scan tobj id");
                free(tobj);
                Fapi_Free(appdata);
                goto error;
            }

            maxobjectid = (maxobjectid > tobj->id)? maxobjectid : tobj->id;

            if (!parse_attributes_from_string(&yaml[9], strlen((char*)&yaml[9]),
                                              &tobj->attrs)) {
                LOGE("Could not parse FAPI attrs, got: \"%s\"", yaml);
                free(tobj);
                Fapi_Free(appdata);
                goto error;
            }

            rv = object_init_from_attrs(tobj);
            if (rv != CKR_OK) {
                LOGE("Object initialization failed");
                free(tobj);
                Fapi_Free(appdata);
                goto error;
            }

            rv = token_add_tobject_last(tok, tobj);
            if (rv != CKR_OK) {
                LOGE("Failed to initialize tobject from FAPI");
                free(tobj);
                Fapi_Free(appdata);
                goto error;
            }

            size_t offset = 0;
            safe_add(offset, strlen((char *)yaml), 1);
            yaml += offset;
            LOGV("\nCurrent next is: %zi / %zi", yaml - appdata, appdata_len);
        }
        Fapi_Free(appdata);

        twist blob;
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
            LOGE("No path constructed.");
            goto error;
        }
        rc = Fapi_GetTpmBlobs(t->fapi.ctx, path, &tpm2bPublic, &tpm2bPublicSize,
                              &tpm2bPrivate, &tpm2bPrivateSize, NULL /* policy */);
        if (rc == TSS2_FAPI_RC_KEY_NOT_FOUND) {
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
        if (!t->sealobject.userauthsalt) {
            LOGE("OOM");
            goto error;
        }
    }

    rv = CKR_OK;

out:
    Fapi_Free(pathlist);
    return rv;

error:
    if (rv == CKR_OK) {
        rv = CKR_GENERAL_ERROR;
    }
    goto out;
}

/** Initialize the user PIN data for a given token.
 *
 * See backend_init_user()
 */
CK_RV backend_fapi_init_user(token *t, const twist sealdata,
                        const twist newauthhex, const twist newsalthex) {
    TSS2_RC rc;

    char *path = tss_path_from_id(t->id, "usr");
    if (!path) {
        LOGE("No path constructed.");
        return CKR_GENERAL_ERROR;
    }

    rc = Fapi_CreateSeal(t->fapi.ctx, path,
                         NULL /*type*/, twist_len(sealdata),
                         NULL /*policy*/, newauthhex, (uint8_t*)sealdata);
    if (rc) {
        LOGE("Creation of a FAPI seal failed.");
        free(path);
        return CKR_GENERAL_ERROR;
    }

    char label[sizeof(t->label) + 1]; /* token-label length plus \0, no overflow possible */
    label[sizeof(t->label)] = '\0';
    memcpy(&label[0], &t->label[0], sizeof(t->label));

    rc = Fapi_SetDescription(t->fapi.ctx, path, &label[0]);
    if (rc) {
        LOGE("Setting FAPI seal description failed.");
        Fapi_Delete(t->fapi.ctx, path);
        free(path);
        return CKR_GENERAL_ERROR;
    }

    size_t appdata_len = 0;
    safe_add(appdata_len, twist_len(newsalthex), 1);

    uint8_t *appdata = malloc(appdata_len);
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

    uint8_t *tpm2bPublic;
    size_t tpm2bPublicSize;
    uint8_t *tpm2bPrivate;
    size_t tpm2bPrivateSize;

    rc = Fapi_GetTpmBlobs(t->fapi.ctx, path, &tpm2bPublic, &tpm2bPublicSize,
                          &tpm2bPrivate, &tpm2bPrivateSize, NULL /* policy */);
    free(path);
    if (rc) {
        LOGE("Getting the TPM data blobs failed.");
        return CKR_GENERAL_ERROR;
    }

    twist pub = twistbin_new(tpm2bPublic, tpm2bPublicSize);
    Fapi_Free(tpm2bPublic);
    twist priv = twistbin_new(tpm2bPrivate, tpm2bPrivateSize);
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

/** Store a new object for a given token in the backend.
 *
 * See backend_add_object()
 *
 * The object is added to the AppData of the token object
 * in the FAPI keystore. The different objects are separated
 * by a \0 delimiter. The first element of the AppData is the
 * salthex, so the first object starts after the first \0.
 */
CK_RV backend_fapi_add_object(token *t, tobject *tobj) {
    TSS2_RC rc;

    LOGE("Adding object to fapi token %i", t->id);

    char *path = tss_path_from_id(t->id, "so");
    if (!path) {
        LOGE("No path constructed.");
        return CKR_GENERAL_ERROR;
    }

    safe_adde(maxobjectid, 1);
    tobj->id = maxobjectid;

    char *attrs = emit_attributes_to_string(tobj->attrs);
    if (!attrs) {
        LOGE("OOM");
        free(path);
        return CKR_GENERAL_ERROR;
    }

    uint8_t *appdata;
    size_t appdata_len;
    rc = Fapi_GetAppData(t->fapi.ctx, path, &appdata, &appdata_len);
    if (rc) {
        LOGE("Getting FAPI seal appdata failed.");
        goto error;
    }

    size_t newappdata_len = appdata_len;
    safe_adde(newappdata_len, 9); /* id as 8byte hex and ':' */
    safe_adde(newappdata_len, strlen(attrs));
    safe_adde(newappdata_len, 1); /* terminating '\0' */
    uint8_t *newappdata = malloc(newappdata_len);
    if (!newappdata) {
        LOGE("OOM");
        Fapi_Free(appdata);
        goto error;
    }

    memcpy(&newappdata[0], &appdata[0], appdata_len);
    sprintf((char*)&newappdata[appdata_len], "%08x:", tobj->id);
    memcpy(&newappdata[appdata_len + 9], attrs, strlen(attrs));
    newappdata[newappdata_len - 1] = '\0';
    Fapi_Free(appdata);

    rc = Fapi_SetAppData(t->fapi.ctx, path, newappdata, newappdata_len);
    free(newappdata);
    if (rc) {
        LOGE("Getting FAPI seal appdata failed.");
        goto error;
    }

    free(path);
    free(attrs);
    return CKR_OK;

error:
    free(path);
    free(attrs);
    return CKR_GENERAL_ERROR;
}

/** Given a token and tobject, will persist the new attributes in fapi backend.
 *
 * see backend_update_tobject_attrs().
 */
CK_RV backend_fapi_update_tobject_attrs(token *t, tobject *tobj, attr_list *attrlist) {
    TSS2_RC rc;

    char *path = tss_path_from_id(t->id, "so");
    if (!path) {
        LOGE("No path constructed.");
        return CKR_GENERAL_ERROR;
    }

    uint8_t *appdata;
    size_t appdata_len;
    rc = Fapi_GetAppData(t->fapi.ctx, path, &appdata, &appdata_len);
    if (rc) {
        LOGE("Getting FAPI seal appdata failed.");
        goto error;
    }

    /* Skip over soauthvalue (the first element of appData) */
    size_t tobj_start = strlen((char*)appdata) + 1;

    /* Find the offset of the tobj to delete */
    while (1) {
        if (tobj_start + 9 >= appdata_len) {
            LOGE("tobj not found in appdata.");
            goto error;
        }

        unsigned id;
        if (sscanf((char*)&appdata[tobj_start], "%08x:", &id) != 1) {
            LOGE("bad tobject.");
            goto error;
        }

        if (id == tobj->id) {
            LOGV("Object found at offset %zi.", tobj_start);
            break;
        }

        safe_adde(tobj_start, strlen((char*)&appdata[tobj_start]));
        safe_adde(tobj_start, 1);
    }

    size_t tobj_len = strlen((char*)&appdata[tobj_start]);

    char *attrs = emit_attributes_to_string(attrlist);
    if (!attrs) {
        LOGE("OOM");
        free(path);
        return CKR_GENERAL_ERROR;
    }

    size_t newappdata_len = appdata_len - tobj_len;
    safe_adde(newappdata_len, 9); /* id as 8byte hex and ':' */
    safe_adde(newappdata_len, strlen(attrs));
    safe_adde(newappdata_len, 1); /* terminating '\0' */
    uint8_t *newappdata = malloc(newappdata_len);
    if (!newappdata) {
        LOGE("OOM");
        Fapi_Free(appdata);
        goto error;
    }

    memcpy(&newappdata[0], &appdata[0], tobj_start);
    sprintf((char*)&newappdata[appdata_len], "%08x:", tobj->id);
    memcpy(&newappdata[appdata_len + 9], attrs, strlen(attrs));
    newappdata[tobj_start + 9 + strlen(attrs)] = '\0';
    memcpy(&newappdata[tobj_start + 9 + strlen(attrs) + 1],
           &appdata[tobj_start + tobj_len],
           appdata_len - tobj_start - tobj_len);
    newappdata[newappdata_len - 1] = '\0';
    Fapi_Free(appdata);

    rc = Fapi_SetAppData(t->fapi.ctx, path, newappdata, newappdata_len);
    Fapi_Free(newappdata);
    if (rc) {
        LOGE("Getting FAPI seal appdata failed.");
        goto error;
    }

    free(path);
    return CKR_OK;

error:
    free(path);
    return CKR_GENERAL_ERROR;
}

/** Removes a tobject from the fapi backend.
 *
 * See backend_rm_tobject().
 */
CK_RV backend_fapi_rm_tobject(token *t, tobject *tobj) {
    TSS2_RC rc;

    char *path = tss_path_from_id(t->id, "so");
    if (!path) {
        LOGE("No path constructed.");
        return CKR_GENERAL_ERROR;
    }

    uint8_t *appdata;
    size_t appdata_len;
    rc = Fapi_GetAppData(t->fapi.ctx, path, &appdata, &appdata_len);
    if (rc) {
        LOGE("Getting FAPI seal appdata failed.");
        goto error;
    }

    /* Skip over soauthvalue (the first element of appData) */
    size_t tobj_start = strlen((char*)appdata) + 1;

    /* Find the offset of the tobj to delete */
    while (1) {
        if (tobj_start + 9 >= appdata_len) {
            LOGE("tobj not found in appdata.");
            goto error;
        }

        unsigned id;
        if (sscanf((char*)&appdata[tobj_start], "%08x:", &id) != 1) {
            LOGE("bad tobject.");
            goto error;
        }

        if (id == tobj->id) {
            LOGV("Object found at offset %zi.", tobj_start);
            break;
        }

        safe_adde(tobj_start, strlen((char*)&appdata[tobj_start]));
        safe_adde(tobj_start, 1);
    }

    size_t tobj_len = strlen((char*)&appdata[tobj_start]);
    memmove(&appdata[tobj_start - 1], &appdata[tobj_start + tobj_len],
            appdata_len - tobj_start - tobj_len);
    appdata_len -= tobj_len + 1;

    rc = Fapi_SetAppData(t->fapi.ctx, path, appdata, appdata_len);
    Fapi_Free(appdata);
    if (rc) {
        LOGE("Getting FAPI seal appdata failed.");
        goto error;
    }

    free(path);
    return CKR_OK;

error:
    free(path);
    return CKR_GENERAL_ERROR;
}
