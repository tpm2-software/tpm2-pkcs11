/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"

#ifdef HAVE_FAPI
#include <tss2/tss2_fapi.h>
#endif

#include "backend_fapi.h"
#include "emitter.h"
#include "parser.h"
#include "utils.h"

#ifdef HAVE_FAPI
FAPI_CONTEXT *fctx = NULL;
unsigned maxobjectid = 0;

static CK_RV get_key(FAPI_CONTEXT *fapictx, tpm_ctx *tctx, const char *path, uint32_t *esysHandle, uint32_t *tpmHandle) {

    bool ret;
    TSS2_RC rc;
    uint8_t type;
    uint8_t *data;
    size_t length;

    rc = Fapi_GetEsysBlob(fapictx, path, &type, &data, &length);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Cannot get Esys blob for key %s", path);
        return CKR_GENERAL_ERROR;
    }

    twist twistdata = twistbin_new(data, length);
    Fapi_Free(data);
    if (!twistdata) {
        return CKR_HOST_MEMORY;
    }

    switch(type) {
    case FAPI_ESYSBLOB_CONTEXTLOAD:
        ret = tpm_contextload_handle(tctx, twistdata, esysHandle);
        if (!ret) {
            LOGE("Error on contextload");
            return CKR_GENERAL_ERROR;
        }
        if (tpmHandle) {
            *tpmHandle = 0;
        }
        return CKR_OK;
    case FAPI_ESYSBLOB_DESERIALIZE:
        ret = tpm_deserialize_handle(tctx, twistdata, esysHandle);
        if (!ret) {
            LOGE("Error on deserialize");
            return CKR_GENERAL_ERROR;
        }
        /* Esys_TR_GetTpmHandle() was added to tss2-esys in v2.4. The rest
         * of the code works fine with older versions. Hence, we open-code
         * the function call here to restrict the dependency on >= 2.4 to
         * FAPI-enabled builds.
         */
        ret = tpm_get_tpmhandle(tctx, *esysHandle, tpmHandle);
        if (!ret) {
            LOGE("Error on get_tpmhandle");
            return CKR_GENERAL_ERROR;
        }
        return CKR_OK;
    default:
        LOGE("Unknown FAPI type for ESYS blob.");
        twist_free(twistdata);
        return CKR_GENERAL_ERROR;
    }
}

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
    TSS2_TCTI_CONTEXT *tcti;

    TSS2_RC rc = Fapi_GetTcti(fctx, &tcti);
    if (rc) {
        LOGE("Getting FAPI's tcti context");
        return CKR_GENERAL_ERROR;
    }

    t->type = token_type_fapi;
    t->fapi.ctx = fctx;
    return tpm_ctx_new_fromtcti(tcti, &t->tctx);
}

void backend_fapi_ctx_free(token *t) {
    UNUSED(t);
}


#define PREFIX "/HS/SRK/tpm2-pkcs11-token-"

static char *tss_path_from_id(unsigned id, const char *type) {
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

static char *path_get_parent(const char *path) {
    char *end = rindex(path, '/');
    if (!end) {
        return NULL;
    }
    return strndup(path, end - path);
}

/** Create a new token in fapi backend.
 *
 * See backend_create_token_seal()
 */
CK_RV backend_fapi_create_token_seal(token *t, const twist hexwrappingkey,
                       const twist newauth, const twist newsalthex) {
    TSS2_RC rc;

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

    t->fapi.soauthsalt = newsalthex;

    t->type = token_type_fapi;

    t->config.is_initialized = true;

    assert(t->id);

    char *parentpath = path_get_parent(path);
    free(path);
    if (!parentpath) {
        return CKR_HOST_MEMORY;
    }

    CK_RV rv = get_key(t->fapi.ctx, t->tctx, parentpath, &t->pobject.handle, &t->pid);
    free(parentpath);
    if (rv != CKR_OK) {
        LOGE("Error getting parent key");
        return rv;
    }

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

        char *parentpath = path_get_parent(path);
        if (!parentpath) {
            rv = CKR_HOST_MEMORY;
            goto error;
        }

        rv = get_key(t->fapi.ctx, t->tctx, parentpath, &t->pobject.handle, &t->pid);
        free(parentpath);
        if (rv != CKR_OK) {
            return rv;
        }

        char *label;
        rc = Fapi_GetDescription(t->fapi.ctx, path, &label);
        if (rc) {
            LOGE("Getting FAPI seal description failed.");
            goto error;
        }
        memcpy(&t->label[0], label, strlen(label));
        Fapi_Free(label);

        LOGV("Parsing objects for token %i:%s", t->id, &t->label[0]);

        uint8_t *appdata;
        size_t appdata_len;

        rc = Fapi_GetAppData(t->fapi.ctx, path, &appdata, &appdata_len);
        if (rc) {
            LOGE("Getting FAPI seal appdata failed.");
            goto error;
        }

        t->fapi.soauthsalt = twistbin_new(appdata, strlen((char *)appdata));
        if (!t->fapi.soauthsalt) {
            LOGE("OOM");
            Fapi_Free(appdata);
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

            rv = token_add_tobject_last(t, tobj);
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

        t->config.is_initialized = true;

        /* Initialize the User PIN area. */
        /*********************************/
        path = tss_path_from_id(t->id, "usr");
        if (!path) {
            LOGE("No path constructed.");
            goto error;
        }

        rc = Fapi_GetAppData(t->fapi.ctx, path, &appdata, NULL);
        free(path);
        if (rc == TSS2_FAPI_RC_KEY_NOT_FOUND) {
            LOGV("No user pin found for token %08x.", t->id);
            continue;
        }
        if (rc) {
            LOGE("Getting FAPI seal appdata failed.");
            goto error;
        }

        t->fapi.userauthsalt = twistbin_new(appdata, strlen((char *)appdata));
        Fapi_Free(appdata);
        if (!t->fapi.userauthsalt) {
            LOGE("OOM");
            goto error;
        }
    }

    rv = CKR_OK;

out:
    Fapi_Free(pathlist);
    return rv;

error:
    Fapi_Free(pathlist);
    if (rv == CKR_OK) {
        rv = CKR_GENERAL_ERROR;
    }
    token_free_list(tok, *len);
    *len = 0;
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

    free(path);
    twist_free(t->fapi.userauthsalt);

    t->fapi.userauthsalt = newsalthex;

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

    LOGV("Adding object to fapi token %i", t->id);

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
    uint8_t *newappdata = malloc(newappdata_len);
    if (!newappdata) {
        LOGE("OOM");
        Fapi_Free(appdata);
        goto error;
    }

    memcpy(&newappdata[0], &appdata[0], tobj_start);
    sprintf((char*)&newappdata[tobj_start], "%08x:%s", tobj->id, attrs);
    memcpy(&newappdata[tobj_start + 9 + strlen(attrs) + 1],
           &appdata[tobj_start + tobj_len],
           appdata_len - tobj_start - tobj_len - 1);
    newappdata[newappdata_len - 1] = '\0';

    Fapi_Free(appdata);

    rc = Fapi_SetAppData(t->fapi.ctx, path, newappdata, newappdata_len);
    free(newappdata);
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

struct authtable {
    const char *path;
    const char *auth;
};

static TSS2_RC auth_cb(const char *path, char const *description, const char **auth, void *userData) {

    LOGV("Searching auth value for %s", description);

    struct authtable *at = (struct authtable *) userData;

    for (; at->path != NULL; at = &at[1]) {
        /* Using strstr because description may be prefixed with a crypto profile */
        if (strstr(path, at->path)) {
            *auth = at->auth;
            if (!*auth) {
                return TSS2_FAPI_RC_MEMORY;
            }
            return TSS2_RC_SUCCESS;
        }
    }

    return TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN;
}

/** Unseal a token's wrapping key.
 *
 * see backend_token_unseal_wrapping_key()
 */
CK_RV backend_fapi_token_unseal_wrapping_key(token *tok, bool user, twist tpin) {

    CK_RV rv = CKR_GENERAL_ERROR;
    TSS2_RC rc;

    char *path = tss_path_from_id(tok->id, user ? "usr":"so");
    if (!path) {
        LOGE("No path constructed.");
        return CKR_HOST_MEMORY;
    }

    twist sealsalt = user ? tok->fapi.userauthsalt : tok->fapi.soauthsalt;
    twist sealobjauth = utils_hash_pass(tpin, sealsalt);
    if (!sealobjauth) {
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    char label[sizeof(tok->label) + 1]; /* token-label length plus \0, cannot overflow */
    label[sizeof(tok->label)] = '\0';
    memcpy(&label[0], &tok->label[0], sizeof(tok->label));

    /* FAPI may return the description (which is the label) or the path.
       Thus we register our auth value for either. */
    struct authtable authtable[] = {
        { path, (char *)sealobjauth },
        { &label[0], (char *)sealobjauth },
        { NULL, NULL } };

    rc = Fapi_SetAuthCB(tok->fapi.ctx, auth_cb, &authtable[0]);
    if (rc) {
        twist_free(sealobjauth);
        LOGE("Fapi_SetAuthCB failed.");
        goto error;
    }

    uint8_t *data;
    size_t size;
    rc = Fapi_Unseal(tok->fapi.ctx, path, &data, &size);
    Fapi_SetAuthCB(tok->fapi.ctx, NULL, NULL);
    twist_free(sealobjauth);
    if (user && rc == TSS2_FAPI_RC_PATH_NOT_FOUND) {
        rv = CKR_USER_PIN_NOT_INITIALIZED;
        goto error;
    }
    if (rc) {
        LOGE("Fapi_Unseal failed.");
        goto error;
    }

    twist wrappingkeyhex = twistbin_new(data, size);
    Fapi_Free(data);
    if (!wrappingkeyhex) {
        rv = CKR_HOST_MEMORY;
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

    free(path);

    /* Since tobject are esysdb backed, they need an active session. */
    if (!tpm_session_active(tok->tctx)) {
        LOGV("token parent object handle is 0x%08x", tok->pobject.handle);
        CK_RV tmp = tpm_session_start(tok->tctx, tok->pobject.objauth, tok->pobject.handle);
        if (tmp != CKR_OK) {
            LOGE("Could not start Auth Session with the TPM.");
            return tmp;
        }
    }

    return CKR_OK;

error:
    free(path);
    return rv;
}

CK_RV backend_fapi_token_changeauth(token *tok, bool user, twist toldpin, twist tnewpin) {

    CK_RV rv = CKR_GENERAL_ERROR;
    TSS2_RC rc;

    char *path = tss_path_from_id(tok->id, user ? "usr":"so");
    if (!path) {
        LOGE("No path constructed.");
        return CKR_HOST_MEMORY;
    }

    twist newsalthex = NULL;
    twist newauthhex = NULL;
    twist oldauth = NULL;

    rv = utils_setup_new_object_auth(tnewpin, &newauthhex, &newsalthex);
    if (rv != CKR_OK) {
        goto out;
    }
    rv = CKR_GENERAL_ERROR;

    oldauth = utils_hash_pass(toldpin, user ? tok->fapi.userauthsalt : tok->fapi.soauthsalt);
    if (!oldauth) {
        goto out;
    }

    char label[sizeof(tok->label) + 1]; /* token-label length plus \0, cannot overflow */
    label[sizeof(tok->label)] = '\0';
    memcpy(&label[0], &tok->label[0], sizeof(tok->label));

    /* FAPI may return the description (which is the label) or the path.
       Thus we register our auth value for either. */
    struct authtable authtable[] = {
        { path, (char *)oldauth },
        { &label[0], (char *)oldauth },
        { NULL, NULL } };

    rc = Fapi_SetAuthCB(tok->fapi.ctx, auth_cb, &authtable[0]);
    if (rc) {
        LOGE("Fapi_SetAuthCB failed.");
        goto out;
    }

    LOGV("Attempting to change auth value for %s", path);

    rc = Fapi_ChangeAuth(tok->fapi.ctx, path, newauthhex);
    Fapi_SetAuthCB(tok->fapi.ctx, NULL, NULL);
    if (rc) {
        LOGE("Fapi_ChangeAuth failed.");
        goto out;
    }

    uint8_t *appdata;
    size_t appdata_len;

    rc = Fapi_GetAppData(tok->fapi.ctx, path, &appdata, &appdata_len);
    if (rc) {
        LOGE("Getting FAPI seal appdata failed.");
        goto out;
    }

    size_t newappdata_len = appdata_len - strlen((char*)appdata);
    safe_adde(newappdata_len, twist_len(newsalthex));
    uint8_t *newappdata = malloc(newappdata_len);
    if (!newappdata) {
        Fapi_Free(appdata);
        rv = CKR_HOST_MEMORY;
        goto out;
    }
    memcpy(newappdata, newsalthex, twist_len(newsalthex));
    memcpy(&newappdata[twist_len(newsalthex)], &appdata[strlen((char*)appdata)],
           appdata_len - strlen((char*)appdata));

    Fapi_Free(appdata);

    rc = Fapi_SetAppData(tok->fapi.ctx, path, newappdata, newappdata_len);
    free(newappdata);
    if (rc) {
        LOGE("Setting FAPI seal appdata failed.");
        goto out;
    }

    if (user) {
        twist_free(tok->fapi.userauthsalt);
        tok->fapi.userauthsalt = newsalthex;
    } else {
        twist_free(tok->fapi.soauthsalt);
        tok->fapi.soauthsalt = newsalthex;
    }

    rv = CKR_OK;

out:
    free(path);

    if (rv != CKR_OK) {
        twist_free(newsalthex);
    }

    twist_free(oldauth);
    twist_free(newauthhex);

    return rv;
}
#else

CK_RV backend_fapi_init(void) {

	return CKR_OK;
}

CK_RV backend_fapi_destroy(void) {

	return CKR_OK;
}

CK_RV backend_fapi_ctx_new(token *t) {

	UNUSED(t);
	LOGE("FAPI NOT ENABLED");
	return CKR_GENERAL_ERROR;
}

void backend_fapi_ctx_free(token *t) {

	UNUSED(t);
	LOGV("FAPI NOT ENABLED");
}

CK_RV backend_fapi_create_token_seal(token *t, const twist hexwrappingkey,
                       const twist newauth, const twist newsalthex) {
	UNUSED(t);
	UNUSED(hexwrappingkey);
	UNUSED(newauth);
	UNUSED(newsalthex);
	LOGE("FAPI NOT ENABLED");
	return CKR_GENERAL_ERROR;
}

CK_RV backend_fapi_add_tokens(token *tok, size_t *len) {

	UNUSED(tok);
	UNUSED(len);
	LOGV("FAPI NOT ENABLED");
	return CKR_GENERAL_ERROR;
}

CK_RV backend_fapi_init_user(token *t, const twist sealdata,
                        const twist newauthhex, const twist newsalthex) {
	UNUSED(t);
	UNUSED(sealdata);
	UNUSED(newauthhex);
	UNUSED(newsalthex);
	LOGE("FAPI NOT ENABLED");
	return CKR_GENERAL_ERROR;
}

CK_RV backend_fapi_add_object(token *t, tobject *tobj) {

	UNUSED(t);
	UNUSED(tobj);
	LOGE("FAPI NOT ENABLED");
	return CKR_GENERAL_ERROR;
}

CK_RV backend_fapi_update_tobject_attrs(token *tok, tobject *tobj, attr_list *attrlist) {

	UNUSED(tok);
	UNUSED(tobj);
	UNUSED(attrlist);
	LOGE("FAPI NOT ENABLED");
	return CKR_GENERAL_ERROR;
}

CK_RV backend_fapi_rm_tobject(token *tok, tobject *tobj) {

	UNUSED(tok);
	UNUSED(tobj);
	LOGE("FAPI NOT ENABLED");
	return CKR_GENERAL_ERROR;
}

CK_RV backend_fapi_token_unseal_wrapping_key(token *tok, bool user, twist tpin) {

	UNUSED(tok);
	UNUSED(user);
	UNUSED(tpin);
	LOGE("FAPI NOT ENABLED");
	return CKR_GENERAL_ERROR;
}

CK_RV backend_fapi_token_changeauth(token *tok, bool user, twist toldpin, twist tnewpin) {

	UNUSED(tok);
	UNUSED(user);
	UNUSED(toldpin);
	UNUSED(tnewpin);
	LOGE("FAPI NOT ENABLED");
	return CKR_GENERAL_ERROR;
}

#endif
