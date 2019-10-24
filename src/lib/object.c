/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <limits.h>
#include <stdlib.h>
#include <assert.h>

#include "session.h"
#include "checks.h"
#include "log.h"
#include "object.h"
#include "pkcs11.h"
#include "token.h"
#include "utils.h"


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

    if (!tobj) return NULL;
    objattrs *attrs = tobject_get_attrs(tobj);
    bool res = attr_filter(attrs, templ, count);
    return res ? tobj : NULL;
}


CK_RV object_find_init(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR templ, CK_ULONG count) {

    // if count is 0 template is not used and all objects are requested so templ can be NULL.
    if (count > 0) {
        check_pointer(templ);
    }

    CK_RV rv;

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (session_tab[session].search) {
        return CKR_OPERATION_ACTIVE;
    }

    rv = tss_get_object_ids(session_tab[session].slot_id, &session_tab[session].search,
                            &session_tab[session].search_count);
    if (rv)
        return rv;

    for (size_t i = 0; i < session_tab[session].search_count; i++) {
        //TODO Filter
        object_attr_filter(NULL, templ, count);
    }

    return CKR_OK;
}

CK_RV object_find(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *object,
                  CK_ULONG max_object_count, CK_ULONG_PTR object_count) {

    check_pointer(object);
    check_pointer(object_count);

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_tab[session].search) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    if (session_tab[session].search_count == 0) {
        *object_count = 0;
        return CKR_OK;
    }

    if (session_tab[session].search_count > max_object_count) {
        memcpy(object, session_tab[session].search, max_object_count * sizeof(*object));
        *object_count = max_object_count;
        session_tab[session].search_count -= max_object_count;
        memmove(&session_tab[session].search[0], &session_tab[session].search[max_object_count],
                session_tab[session].search_count * sizeof(*object));
    } else {
        memcpy(object, session_tab[session].search,
               session_tab[session].search_count * sizeof(*object));
        *object_count = session_tab[session].search_count;
        session_tab[session].search_count = 0;
    }

    return CKR_OK;
}

CK_RV object_find_final(CK_SESSION_HANDLE session) {

    if (session_tab[session].slot_id == 0) {
        LOGE("Session handle invalid");
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_tab[session].search) {
        LOGE("Session has no pending search");
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    free(session_tab[session].search);

    return CKR_OK;
}

CK_ATTRIBUTE_PTR tobject_get_attribute_by_type(tobject *tobj, CK_ATTRIBUTE_TYPE needle) {

    objattrs *attrs = tobject_get_attrs(tobj);
    return util_get_attribute_by_type(needle, attrs->attrs, attrs->count);
}

CK_ATTRIBUTE_PTR tobject_get_attribute_full(tobject *tobj, CK_ATTRIBUTE_PTR needle) {

    objattrs *attrs = tobject_get_attrs(tobj);
    return util_get_attribute_full(needle, attrs->attrs, attrs->count);
}

#define setresult(K, V) result.K = V; result_size = sizeof(result.K)

CK_RV object_get_attributes(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                            CK_ATTRIBUTE_PTR templ, CK_ULONG count) {

    CK_RV rv = CKR_OK;
    TPM2B_PUBLIC public;
    char *description, *str;

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    rv = tss_data_from_id(session_tab[session].slot_id, object, &public, NULL,
                          &description, NULL, NULL);
    if (rv) {
        LOGE("Error in tss data retrieval");
        return rv;
    }
    LOGV("Got key with description %s", description);

    CK_ULONG result_size = 0;
    union {
        CK_OBJECT_CLASS class;
        CK_KEY_TYPE key_type;
        char label[256];
        CK_BYTE id[32];
        CK_BBOOL encrypt;
        CK_BBOOL decrypt;
        CK_BBOOL wrap;
        CK_BBOOL unwrap;
        CK_BBOOL sign;
        CK_BBOOL verify;
        CK_BBOOL derive;
        CK_BYTE modulus[TPM2_MAX_RSA_KEY_BYTES];
        CK_ULONG modulus_bits;
        uint32_t public_exponent;  /* CK_BYTE[4] */
        CK_BBOOL allways_authenticate;
        uint8_t buffer[0];
    } result;

    /*
     * For each item requested in the template, find if the request has a match
     * and copy the size and possibly data (if allocated).
     */
    CK_ULONG i;
    for (i=0; i < count; i++) {
        CK_ATTRIBUTE_PTR t = &templ[i];
        LOGV("Attribute %x requested for object %08x-%08x", t->type,
             session_tab[session].slot_id, object);

        switch (t->type) {
        case CKA_CLASS:
            if (object & 0x10000000) {
                setresult(class, CKO_PUBLIC_KEY);
            } else {
                setresult(class, CKO_PRIVATE_KEY);
            }
            result_size = sizeof(result.class);
            break;
        case CKA_LABEL:
            memset(&result.label[0], 0, sizeof(result.label));
            str = description;
            if (object & 0x10000000) {
                strsep(&str, ":");
                strsep(&str, ":");
                strsep(&str, ":");
                str = strsep(&str, ":");
            } else {
                strsep(&str, ":");
                str = strsep(&str, ":");
            }
            LOGV("Attribute label %s", str);
            strcpy(&result.label[0], str);
            result_size = strlen(str);
            Fapi_Free(description);
            break;
        case CKA_KEY_TYPE:
            if (public.publicArea.type == TPM2_ALG_RSA) {
                setresult(key_type, CKK_RSA);
            } else if (public.publicArea.type == TPM2_ALG_ECC) {
                setresult(key_type, CKK_EC);
            } else {
                result_size = 0;
            }
            break;
        case CKA_ID:
            memset(&result.id[0], 0, sizeof(result.id));
            str = description;
            if (object & 0x10000000) {
                strsep(&str, ":");
                strsep(&str, ":");
                str = strsep(&str, ":");
            } else {
                str = strsep(&str, ":");
            }
            LOGV("Attribute id %s", str);
            for (size_t i = 0; i < strlen(str) / 2; i++)
                sscanf(&str[i*2], "%02"SCNx8, &result.id[i]);
            result_size = strlen(str) / 2;
            Fapi_Free(description);
            break;
        case CKA_ENCRYPT:
            setresult(encrypt, CK_TRUE);
            break;
        case CKA_DECRYPT:
            setresult(decrypt, CK_TRUE);
            break;
        case CKA_WRAP:
            setresult(wrap, CK_FALSE);
            break;
        case CKA_UNWRAP:
            setresult(unwrap, CK_FALSE);
            break;
        case CKA_SIGN:
            setresult(sign, CK_TRUE);
            break;
        case CKA_VERIFY:
            setresult(verify, CK_TRUE);
            break;
        case CKA_DERIVE:
            setresult(derive, CK_FALSE);
            break;
        case CKA_MODULUS:
            result_size = public.publicArea.unique.rsa.size;
            memcpy(&result.modulus, &public.publicArea.unique.rsa.buffer[0], result_size);
            break;
        case CKA_MODULUS_BITS:
            setresult(modulus_bits, public.publicArea.parameters.rsaDetail.keyBits);
            break;
        case CKA_PUBLIC_EXPONENT:
            if (public.publicArea.parameters.rsaDetail.exponent) {
                setresult(public_exponent, htobe32(public.publicArea.parameters.rsaDetail.exponent));
            } else {
                setresult(public_exponent, htobe32(65537));
            }
            break;
        case CKA_ALWAYS_AUTHENTICATE:
            setresult(allways_authenticate, CK_TRUE);
            break;
        case 0x80000001:
            LOGV("Unknown vendor-specific attribute 0x80000001 requested");
            t->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        default:
            t->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        }

        if (!result_size) {
            t->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        }
        if (!t->pValue) {
            t->ulValueLen = result_size;
            continue;
        }
        if (t->ulValueLen < result_size) {
            t->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            rv = CKR_BUFFER_TOO_SMALL;
        }

        memcpy(t->pValue, &result.buffer[0], result_size);
        t->ulValueLen = result_size;
    }
    return rv;
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

CK_RV object_destroy(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object) {

    TSS2_RC rc;
    FAPI_CONTEXT *fctx;
    char *path;

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (object & 0x10000000) {
        /* Public key object belonging to a private key */
        LOGE("Cannot delete public object belonging to a private object. Got: 0x%lx", object);
        return CKR_ACTION_PROHIBITED;
    } else if ((object & 0xF0000000) == 0) {
        /* Private key object */
        path = tss_keypath_from_id(session_tab[session].slot_id, object);
        if (!path) return CKR_OBJECT_HANDLE_INVALID;

        rc = Fapi_Initialize(&fctx, NULL);
        check_tssrc(rc, return CKR_GENERAL_ERROR);

        rc = Fapi_Delete(fctx, path);
        free(path);
        Fapi_Finalize(&fctx);
        check_tssrc(rc, return CKR_FUNCTION_FAILED);

        return CKR_OK;
    }
    /* Unknown object type */
    return CKR_OBJECT_HANDLE_INVALID;
}
