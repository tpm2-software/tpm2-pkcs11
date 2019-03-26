/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <limits.h>
#include <stdlib.h>

#include "db.h"
#include "checks.h"
#include "log.h"
#include "object.h"
#include "pkcs11.h"
#include "session_ctx.h"
#include "token.h"
#include "utils.h"

typedef struct tobject_match_list tobject_match_list;
struct tobject_match_list {
    CK_OBJECT_HANDLE tobj_handle;
    tobject_match_list *next;
};

typedef struct object_find_data object_find_data;
struct object_find_data {
    tobject_match_list *head;
    tobject_match_list *cur;
};

void tobject_free(tobject *tobj) {

    if (!tobj) {
        return;
    }

    twist_free(tobj->priv);
    twist_free(tobj->pub);
    twist_free(tobj->objauth);
    twist_free(tobj->unsealed_auth);

    objattrs *a = tobject_get_attrs(tobj);
    CK_RV rv = utils_attr_free(a->attrs, a->count);
    assert(rv == CKR_OK);
    free(a->attrs);

    CK_ULONG i = 0;
    for (i=0; i < tobj->mechanisms.count; i++) {
        CK_MECHANISM_PTR m = &tobj->mechanisms.mech[i];
        if (m->pParameter) {
            free(m->pParameter);
        }
    }

    free(tobj->mechanisms.mech);

    free(tobj);
}

void sobject_free(sobject *sobj) {
    twist_free(sobj->priv);
    twist_free(sobj->pub);
    twist_free(sobj->objauth);
    twist_free(sobj->authraw);
}

void wrappingobject_free(wrappingobject *wobj) {
    twist_free(wobj->priv);
    twist_free(wobj->pub);
    twist_free(wobj->objauth);
}

void sealobject_free(sealobject *sealobj) {
    twist_free(sealobj->soauthsalt);
    twist_free(sealobj->sopriv);
    twist_free(sealobj->sopub);
    twist_free(sealobj->userauthsalt);
    twist_free(sealobj->userpub);
    twist_free(sealobj->userpriv);
}

static bool object_CKM_RSA_PKCS_OAEP_params_supported(
        CK_RSA_PKCS_OAEP_PARAMS_PTR requested,
        CK_RSA_PKCS_OAEP_PARAMS_PTR got) {

    return requested->hashAlg == got->hashAlg &&
            requested->mgf == got->mgf;
}

static bool object_CKM_AES_CBC_params_supported(
        CK_MECHANISM_PTR requested
        ) {

    // IV is blocksize for AES
    return requested->ulParameterLen == 16;
}

CK_RV object_mech_is_supported(tobject *tobj, CK_MECHANISM_PTR mech) {

    bool is_equal;
    CK_ULONG i;
    bool got_to_params = false;
    for (i=0; i < tobj->mechanisms.count; i++) {
        CK_MECHANISM_PTR m = &tobj->mechanisms.mech[i];

        if (mech->mechanism != m->mechanism) {
            continue;
        }

        got_to_params = true;

        /*
         * Ensure the parameters are supported, this would need to be done for each mechanism
         * as things like label, etc are flexible. However, keep a default handler of strict
         * memcmp for things that are empty or can be fully specified in the DB.
         */
        switch (mech->mechanism) {
        case CKM_RSA_X_509:
            /* no params */
            is_equal = true;
            break;
        case CKM_RSA_PKCS_OAEP:
            is_equal = object_CKM_RSA_PKCS_OAEP_params_supported(
                    mech->pParameter,
                    m->pParameter
                    );
            break;
        case CKM_AES_CBC:
            is_equal = object_CKM_AES_CBC_params_supported(
                    mech);
            break;
        default:
            is_equal =
                mech->ulParameterLen == m->ulParameterLen
            && !memcmp(mech->pParameter, m->pParameter, m->ulParameterLen);
        }

        if(!is_equal) {
            continue;
        }

        /* match */
        return CKR_OK;
    }

    return got_to_params ? CKR_MECHANISM_PARAM_INVALID : CKR_MECHANISM_INVALID;
}

static bool attr_filter(objattrs *attrs, CK_ATTRIBUTE_PTR templ, CK_ULONG count) {


    CK_ULONG i;
    // If ulCount is set to 0 all items match automatically.
    if (count == 0) {
	    return true;
    }

    for (i=0; i < count; i++) {
        CK_ATTRIBUTE_PTR search = &templ[i];

        CK_ATTRIBUTE_PTR compare = NULL;
        bool is_attr_match = false;
        CK_ULONG j;
        for(j=0; j < attrs->count; j++) {
            compare = &attrs->attrs[j];

            if (search->type != compare->type) {
                continue;
            }

            if (search->ulValueLen != compare->ulValueLen) {
                continue;
            }

            bool match = !memcmp(compare->pValue, search->pValue, search->ulValueLen);
            if (match) {
                is_attr_match = true;
                break;
            }
        }

        /*
         * If we didn't get an attribute match, then the searched for attribute wasn't
         * found and it's not a match. Ie search attribute set must be subset of compare
         * attribute set
         */

        if (!is_attr_match) {
            return false;
        }

    }

    /*
     * Done with matching loops, we always found a match, thus we have a match
     * assign it.
     */

    /* all the specified template attributes matched */
    return true;
}

tobject *object_attr_filter(tobject *tobj, CK_ATTRIBUTE_PTR templ, CK_ULONG count) {

    objattrs *attrs = tobject_get_attrs(tobj);
    bool res = attr_filter(attrs, templ, count);
    return res ? tobj : NULL;
}


void object_find_data_free(object_find_data **fd) {

    if (!*fd) {
        return;
    }

    tobject_match_list *cur = (*fd)->head;
    while (cur) {
        tobject_match_list *tmp = cur;
        cur = cur->next;
        free(tmp);
    }

    free(*fd);
    *fd = NULL;

    return;
}

static object_find_data *object_find_data_new(void) {
    return calloc(1, sizeof(object_find_data));
}

CK_RV object_find_init(session_ctx *ctx, CK_ATTRIBUTE_PTR templ, CK_ULONG count) {

    // if count is 0 template is not used and all objects are requested so templ can be NULL.
    if (count > 0) {
        check_pointer(templ);
    }

    CK_RV rv = CKR_GENERAL_ERROR;

    object_find_data *fd = NULL;

    bool is_active = session_ctx_opdata_is_active(ctx);
    if (is_active) {
        rv = CKR_OPERATION_ACTIVE;
        goto out;
    }

    fd = object_find_data_new();
    if (!fd) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    if (!tok->tobjects) {
        goto empty;
    }

    tobject_match_list *match_cur = NULL;
    list *cur = &tok->tobjects->l;
    while(cur) {

        // Get the current object, and grab it's id for the object handle
        tobject *tobj = list_entry(cur, tobject, l);
        cur = cur->next;

        tobject *match = object_attr_filter(tobj, templ, count);
        if (!match) {
            continue;
        }

        /* we have a match, build the list */
        if (!fd->head) {
            /* set the head to point into the list */
            fd->head = calloc(1, sizeof(*match_cur));
            if (!fd->head) {
                rv = CKR_HOST_MEMORY;
                goto out;
            }

            match_cur = fd->head;
            match_cur->tobj_handle = tobj->id;
        } else {
            assert(match_cur);
            match_cur->next = calloc(1, sizeof(*match_cur));
            if (!match_cur->next) {
                rv = CKR_HOST_MEMORY;
                goto out;
            }

            match_cur->next->tobj_handle = tobj->id;
            match_cur = match_cur->next;
        }
    }

    fd->cur = fd->head;

empty:

    session_ctx_opdata_set(ctx, operation_find, fd, (opdata_free_fn)object_find_data_free);

    rv = CKR_OK;

out:
    if (rv != CKR_OK) {
        object_find_data_free(&fd);
    }

    return rv;
}

CK_RV object_find(session_ctx *ctx, CK_OBJECT_HANDLE *object, CK_ULONG max_object_count, CK_ULONG_PTR object_count) {

    check_pointer(object);
    check_pointer(object_count);

    UNUSED(max_object_count);

    CK_RV rv = CKR_OK;

    object_find_data *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, operation_find, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG count = 0;
    while(opdata->cur && count < max_object_count) {

        // Get the current object, and grab it's id for the object handle
        CK_OBJECT_HANDLE handle = opdata->cur->tobj_handle;
        object[count] = handle;

        // Update our iterator
        opdata->cur = opdata->cur->next;

        count++;
    }

    *object_count = count;

    return CKR_OK;
}

CK_RV object_find_final(session_ctx *ctx) {

    CK_RV rv = CKR_GENERAL_ERROR;

    object_find_data *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, operation_find, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    session_ctx_opdata_clear(ctx);

    return CKR_OK;
}

static CK_RV find_object_by_id(token *tok, CK_OBJECT_HANDLE handle, bool inc, tobject **tobj) {

    list *cur = &tok->tobjects->l;
    while(cur) {

        tobject *cur_tobj = list_entry(cur, tobject, l);

        if (handle == cur_tobj->id) {
            CK_RV rv = inc ? tobject_user_increment(cur_tobj) : CKR_OK;
            if (rv == CKR_OK) {
                *tobj = cur_tobj;
            }
            return rv;
        }
        cur = cur->next;
    }

    return CK_INVALID_HANDLE;
}

CK_ATTRIBUTE_PTR object_get_attribute_by_type(tobject *tobj, CK_ATTRIBUTE_TYPE atype) {

    CK_ULONG i;

    objattrs *attrs = tobject_get_attrs(tobj);

    for (i=0; i < attrs->count; i++) {

        CK_ATTRIBUTE_PTR a = &attrs->attrs[i];

        if (a->type == atype) {
            return a;
        }
    }

    return NULL;
}

CK_ATTRIBUTE_PTR object_get_attribute_full(tobject *tobj, CK_ATTRIBUTE_PTR attr) {

    objattrs *attrs = tobject_get_attrs(tobj);

    CK_ULONG i;
    for (i=0; i < attrs->count; i++) {

        CK_ATTRIBUTE_PTR a = &attrs->attrs[i];

        if (a->type == attr->type
         && a->ulValueLen == attr->ulValueLen) {
            if (a->ulValueLen > 0
             && memcmp(a->pValue, attr->pValue, attr->ulValueLen)) {
                /* length is greater then 0 and don't match, keep looking */
                continue;
            }
            /* length is both 0 OR length > 0 and matched on memcmp */
            return a;
        }
    }

    return NULL;
}

CK_RV object_get_attributes(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE *templ, CK_ULONG count) {

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tobject *tobj = NULL;
    CK_RV rv = find_object_by_id(tok, object, true, &tobj);
    /* no match or error */
    if (rv != CKR_OK) {
        return rv;
    }

    /*
     * For each item requested in the template, find if the request has a match
     * and copy the size and possibly data (if allocated).
     */

    CK_ULONG i;
    for (i=0; i < count; i++) {

        CK_ATTRIBUTE_PTR t = &templ[i];

        CK_ATTRIBUTE_PTR found = object_get_attribute_by_type(tobj, t->type);
        if (found) {
            if (!t->pValue) {
                /* only populate size if the buffer is null */
                t->ulValueLen = found->ulValueLen;
                continue;
            }

            /* The found attribute should fit inside the one to copy to */
            if (found->ulValueLen > t->ulValueLen) {
                rv = CKR_BUFFER_TOO_SMALL;
                goto out;
            }

            t->ulValueLen = found->ulValueLen;
            memcpy(t->pValue, found->pValue, found->ulValueLen);
       } else {
           /* If it's not found it defaults to empty. */
           t->pValue = NULL;
           t->ulValueLen = CK_UNAVAILABLE_INFORMATION;
           rv = CKR_ATTRIBUTE_TYPE_INVALID;
       }
    }


out:
    tobject_user_decrement(tobj);
    return rv;
}

tobject *tobject_new(void) {

    tobject *tobj = calloc(1, sizeof(tobject));
    if (!tobj) {
        LOGE("oom");
        return NULL;
    }

    return tobj;
}

CK_RV tobject_set_blob_data(tobject *tobj, twist pub, twist priv) {
    assert(pub);

    tobj->priv = twist_dup(priv);
    if (priv && !tobj->priv) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    tobj->pub = twist_dup(pub);
    if (!tobj->pub) {
        twist_free(tobj->priv);
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    return CKR_OK;
}

CK_RV tobject_set_auth(tobject *tobj, twist authbin, twist wrappedauthhex) {
    assert(tobj);
    assert(authbin);
    assert(wrappedauthhex);

    tobj->unsealed_auth = twist_dup(authbin);
    if (!tobj->unsealed_auth) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    tobj->objauth = twist_dup(wrappedauthhex);
    if (!tobj->objauth) {
        LOGE("oom");
        twist_free(tobj->unsealed_auth);
        return CKR_HOST_MEMORY;
    }

    return CKR_OK;
}

void tobject_set_handle(tobject *tobj, uint32_t handle) {
    assert(tobj);

    tobj->handle = handle;
}

CK_RV tobject_append_attrs(tobject *tobj, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    assert(tobj);
    assert(attrs);

    if (!attrs->ulValueLen) {
        return CKR_OK;
    }

    objattrs *objattrs = tobject_get_attrs(tobj);

    size_t offset = objattrs->count;
    size_t newlen = objattrs->count + count;
    size_t newbytes = sizeof(*objattrs->attrs) * newlen;
    void *newattrs = realloc(objattrs->attrs, newbytes);
    if (!newattrs) {
        return CKR_HOST_MEMORY;
    }

    objattrs->count = newlen;
    objattrs->attrs = newattrs;

    /* clear out the newly allocated memory */
    memset(&objattrs->attrs[offset], 0, count * sizeof(*objattrs->attrs));

    return utils_attr_deep_copy(attrs, count, &objattrs->attrs[offset]);
}

void tobject_set_id(tobject *tobj, unsigned id) {
    assert(tobj);
    tobj->id = id;
}

CK_RV tobject_append_mechs(tobject *tobj, CK_MECHANISM_PTR mech, CK_ULONG count) {
    assert(tobj);

    size_t offset = tobj->mechanisms.count;
    size_t newcnt = tobj->mechanisms.count + count;
    size_t newbytes = sizeof(*tobj->mechanisms.mech) * newcnt;

    void *newmechs = realloc(tobj->mechanisms.mech, newbytes);
    if (!newmechs) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    tobj->mechanisms.count = newcnt;
    tobj->mechanisms.mech = newmechs;

    /* clear out the newly allocated memory */
    memset(&tobj->mechanisms.mech[offset], 0, count * sizeof(*tobj->mechanisms.mech));

    return utils_mech_deep_copy(mech, count, &tobj->mechanisms.mech[offset]);
}

objattrs *tobject_get_attrs(tobject *tobj) {
    return &tobj->attrs;
}

CK_RV tobject_user_increment(tobject *tobj) {

    if (tobj->active == UINT_MAX) {
       LOGE("tobject active at max count, cannot issue. id: %lu", tobj->id);
       return CKR_GENERAL_ERROR;
    }

    tobj->active++;

    return CKR_OK;
}

CK_RV tobject_user_decrement(tobject *tobj) {

    if (!tobj->active) {
        LOGE("Returning a non-active tobject id: %lu", tobj->id);
        return CKR_GENERAL_ERROR;
    }

    tobj->active--;

    return CKR_OK;
}

static bool tobject_is_busy(tobject *tobj) {
    assert(tobj);

    return tobj->active > 0;
}

CK_RV object_destroy(session_ctx *ctx, CK_OBJECT_HANDLE object) {

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tobject *tobj = NULL;
    CK_RV rv = find_object_by_id(tok, object, false, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    bool is_busy = tobject_is_busy(tobj);
    if (is_busy) {
        return CKR_FUNCTION_FAILED;
    }

    rv = db_delete_object(tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    /*
     * Remove from list by tying previous to next. We know that tobjects
     * list is not NULL because we looked up a tobject in that list.
     *
     * TODO: Consider bi-directional circular linked list, it would
     * make this a lot easier.
     *
     * Since we already found tobject, it's impossible for tobject
     * to not exist in the list, thus we will always find a match.
     */

    /* if its head, just make head next */
    if (tok->tobjects->id == tobj->id) {
        list *next = tok->tobjects->l.next;
        tobject *n = next ? list_entry(next, tobject, l) : NULL;
        tok->tobjects = n;
    /* go fish - not head so skip head, keep track of previous */
    } else {
        tobject *prev = tok->tobjects;
        list *cur;
        list_for_each(tok->tobjects->l.next, cur) {
            tobject *c = list_entry(cur, tobject, l);
            if (c->id == tobj->id) {
                /* set previous to point to current "c's" next object */
                prev->l.next = c->l.next;
                break;
            }
        }
    }

    tobject_free(tobj);
    rv = CKR_OK;

    return rv;
}
