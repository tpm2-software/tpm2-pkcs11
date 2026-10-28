/* SPDX-License-Identifier: BSD-2-Clause */

#include <limits.h>
#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include "attrs.h"
#include "backend.h"
#include "checks.h"
#include "db.h"
#include "emitter.h"
#include "key.h"
#include "log.h"
#include "object.h"
#include "pkcs11.h"
#include "session_ctx.h"
#include "ssl_util.h"
#include "token.h"
#include "tpm.h"
#include "utils.h"

typedef struct tobject_match_list tobject_match_list;
struct tobject_match_list {
    CK_OBJECT_HANDLE tobj_handle;
    CK_BBOOL cka_private;
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

    /* cleanse the ENCRYPTED objauth so it goes away */
    if (tobj->objauth) {
        OPENSSL_cleanse((void *)tobj->objauth, twist_len(tobj->objauth));
        twist_free(tobj->objauth);
        tobj->objauth = NULL;
    }

    twist_free(tobj->priv);
    twist_free(tobj->pub);
    twist_free(tobj->tpm_serialized_tr);

    /* cleanse the PLAINTEXT objauth so it goes away */
    if (tobj->unsealed_auth) {
        OPENSSL_cleanse((void *)tobj->unsealed_auth, twist_len(tobj->unsealed_auth));
        twist_free(tobj->unsealed_auth);
        tobj->unsealed_auth = NULL;
    }

    attr_list *a = tobject_get_attrs(tobj);
    attr_list_free(a);
    free(tobj);
}

CK_RV object_mech_is_supported(tobject *tobj, CK_MECHANISM_PTR mech) {

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_ALLOWED_MECHANISMS);
    if (!a) {
        LOGE("Expected object to have: CKA_ALLOWED_MECHANISMS");
        return CKR_GENERAL_ERROR;
    }

    CK_ULONG count = a->ulValueLen/sizeof(CK_MECHANISM_TYPE);
    CK_MECHANISM_TYPE_PTR mt = (CK_MECHANISM_TYPE_PTR)a->pValue;

    CK_ULONG i;
    for(i=0; i < count; i++) {
        CK_MECHANISM_TYPE t = mt[i];
        if (t == mech->mechanism) {
            return CKR_OK;
        }
    }

    /* TODO further sanity checking for CKR_MECHANISM_PARAM_INVALID */

    return CKR_MECHANISM_INVALID;
}

CK_RV tobject_get_min_buf_size(tobject *tobj, CK_MECHANISM_PTR mech, size_t *maxsize) {

    assert(tobj);
    assert(mech);

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_KEY_TYPE);
    if (!a) {
        LOGE("Expected attribute CKA_KEY_TYPE");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    CK_KEY_TYPE key_type;
    CK_RV rv = attr_CK_KEY_TYPE(a, &key_type);
    if (rv != CKR_OK) {
        return rv;
    }

    if (key_type == CKK_RSA) {

        a = attr_get_attribute_by_type(tobj->attrs, CKA_MODULUS);
        if (!a) {
            LOGE("RSA Keys should have a modulus");
            return CKR_GENERAL_ERROR;
        }

        *maxsize = a->ulValueLen;
        return CKR_OK;

    }

    if (key_type == CKK_EC) {
        a = attr_get_attribute_by_type(tobj->attrs, CKA_EC_PARAMS);
        if (!a) {
            LOGE("EC Keys should have params");
            return CKR_GENERAL_ERROR;
        }

        int nid = 0;
        CK_RV rv = ssl_util_params_to_nid(a, &nid);
        if (rv != CKR_OK) {
            return rv;
        }

        /*
         * The signature output from a PKCS#11 ECDSA operation is the raw R,S output
         * which is twice the size of the keysize
         */
        unsigned keysize;

        switch (nid) {
        case NID_X9_62_prime192v1:
            keysize = 24;
        break;
        case NID_secp224r1:
            keysize = 28;
        break;
        case NID_X9_62_prime256v1:
            keysize = 32;
        break;
        case NID_secp384r1:
            keysize = 48;
        break;
        case NID_secp521r1:
            keysize = 66; /* round up */
        break;
        default:
            LOGE("Unsupported nid to tpm signature size maaping: %d", nid);
            return CKR_CURVE_NOT_SUPPORTED;
        }

        *maxsize = keysize * 2;

        return CKR_OK;
    }

    if (key_type == CKK_SHA_1_HMAC) {
        *maxsize = 20;
        return CKR_OK;
    }

    if (key_type == CKK_SHA256_HMAC) {
        *maxsize = 32;
        return CKR_OK;
    }

    if (key_type == CKK_SHA384_HMAC) {
        *maxsize = 48;
        return CKR_OK;
    }

    /* Best guess on buffer size for CKK_GENERIC_SECRET */
    if (key_type == CKK_SHA512_HMAC) {
        *maxsize = 64;
        return CKR_OK;
    }

    if (key_type == CKK_GENERIC_SECRET) {

        switch (mech->mechanism) {
            case CKM_SHA_1_HMAC:
                *maxsize = 20;
                return CKR_OK;
            case CKM_SHA256_HMAC:
                *maxsize = 32;
                return CKR_OK;
            case CKM_SHA384_HMAC:
                *maxsize = 48;
                return CKR_OK;
            case CKM_SHA512_HMAC:
                *maxsize = 64;
                return CKR_OK;
            default:
                LOGE("Cannot handle CKK_GENERIC_SECRET Mechanism: 0x%lx",
                        mech->mechanism);
                return CKR_MECHANISM_INVALID;
        }
    }

    LOGE("Unknown signing key type, got: 0x%lx", key_type);

    return CKR_GENERAL_ERROR;
}

static bool attr_filter(attr_list *attrs, CK_ATTRIBUTE_PTR templ, CK_ULONG count) {


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
        for(j=0; j < attr_list_get_count(attrs); j++) {
            const CK_ATTRIBUTE_PTR ptr = attr_list_get_ptr(attrs);
            compare = &ptr[j];

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

    attr_list *attrs = tobject_get_attrs(tobj);
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

static CK_RV do_match_set(tobject_match_list *match_cur, tobject *tobj) {

    match_cur->tobj_handle = tobj->obj_handle;

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_CLASS);
    if (!a) {
        LOGE("Objects must have CK_OBJECT_CLASS");
        assert(0);
        return CKR_GENERAL_ERROR;
    }

    match_cur->cka_private = attr_list_get_CKA_PRIVATE(tobj->attrs, CK_FALSE);

    return CKR_OK;
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

    if (!tok->tobjects.head) {
        LOGV("Token %i contains no objects.", tok->id);
        goto empty;
    }

    tobject_match_list *match_cur = NULL;
    list *cur = &tok->tobjects.head->l;
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

        } else {
            assert(match_cur);
            match_cur->next = calloc(1, sizeof(*match_cur));
            if (!match_cur->next) {
                rv = CKR_HOST_MEMORY;
                goto out;
            }

            match_cur = match_cur->next;
        }

        rv = do_match_set(match_cur, tobj);
        if (rv != CKR_OK) {
            goto out;
        }
    }

    fd->cur = fd->head;

empty:

    session_ctx_opdata_set(ctx, operation_find, NULL, fd, (opdata_free_fn)object_find_data_free);

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

    CK_RV rv = CKR_OK;

    object_find_data *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, operation_find, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    CK_ULONG count = 0;
    while(opdata->cur && count < max_object_count) {

        // Get the current object, and grab it's id for the object handle
        CK_OBJECT_HANDLE handle = opdata->cur->tobj_handle;

        // filter out CKA_PRIVATE set to CK_TRUE if not logged in and PIN is needed
        if (opdata->cur->cka_private && !token_is_user_logged_in(tok) && !tok->config.empty_user_pin) {
            opdata->cur = opdata->cur->next;
            continue;
        }

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

    session_ctx_opdata_clear(ctx, operation_find);

    return CKR_OK;
}

/*
 * Whether an object's CKA_VALUE is kept wrapped with the token wrapping key in CKA_TPM2_ENC_BLOB, and
 * never in the store as plain text: a private data object's, or a private secret key's held as a plain
 * object (an ECDH-derived key, a readable generic secret). A key in the TPM has no CKA_VALUE to keep.
 */
static bool value_is_protected(CK_OBJECT_CLASS clazz, CK_BBOOL cka_private) {
    return cka_private && (clazz == CKO_DATA || clazz == CKO_SECRET_KEY);
}

/**
 * given an attribute list with CKA_TPM2_ENC_BLOB, will unwrap it with the token wrapping
 * key and store it in CKA_VALUE.
 * @param tok
 *  The token
 * @param attrs
 *  The attribute list to modify.
 * @return
 *  CKR_OK on success.
 */
static CK_RV unwrap_protected_cka_value(token *tok, attr_list *attrs) {
    /* Caller wants CKA_VALUE in their template and it's not found, we need to fetch it, do we have
     * the wrapped value in the DB? */
    assert(tok->wrappingkey);

    CK_ATTRIBUTE_PTR ciphertext_attr = attr_get_attribute_by_type(attrs, CKA_TPM2_ENC_BLOB);
    if (ciphertext_attr) {

        twist plaintext = NULL;
        size_t len = 0;
        if (ciphertext_attr->ulValueLen) {
            twist ciphertext = twistbin_new(ciphertext_attr->pValue, ciphertext_attr->ulValueLen);
            if (!ciphertext) {
                LOGE("oom");
                return CKR_HOST_MEMORY;
            }

            CK_RV rv = utils_ctx_unwrap_objauth(tok->wrappingkey, ciphertext, &plaintext);
            twist_free(ciphertext);
            if (rv != CKR_OK) {
                LOGE("Could not unwrap CKA_VALUE");
                return rv;
            }

            len = twist_len(plaintext);
        }

        CK_ATTRIBUTE temp = {
            .type = CKA_VALUE,
            .pValue = (void *)plaintext,
            .ulValueLen = len
        };

        /*
         * Add the unwrapped value back to CKA_VALUE
         *  - Append if not in the list
         *  - Update if it's in the list
         */
        CK_ATTRIBUTE_PTR found = attr_get_attribute_by_type(attrs, CKA_VALUE);
        CK_RV rv = found ?
                attr_list_update_entry(attrs, &temp) : attr_list_append_entry(&attrs, &temp);
        if (plaintext) {
            OPENSSL_cleanse((void *)plaintext, len);
        }
        twist_free(plaintext);
        if (rv != CKR_OK) {
            return rv;
        }

    } else {
        // TODO: Fetch from TPM to support more object types?
        // TODO: set CKA_VALUE to 0?
        LOGW("Needed CKA_VALUE but didn't find encrypted blob");
    }

    return CKR_OK;
}

/**
 * given an attribute list with CKA_VALUE, will wrap it with the token wrapping
 * key and store it in CKA_TPM2_ENC_BLOB. A zero length CKA_VALUE attribute will
 * clear the CKA_TPM2_ENC_BLOB attribute.
 * @param tok
 *  The token
 * @param attrs
 *  The attribute list to modify
 * @return
 *  CKR_OK on success.
 */
static CK_RV wrap_protected_cka_value(token *tok, attr_list *attrs) {
    assert(tok->wrappingkey);

    /* this may or maynot exist */
    CK_ATTRIBUTE_PTR enc_blob_attr = attr_get_attribute_by_type(attrs, CKA_TPM2_ENC_BLOB);

    CK_ATTRIBUTE_PTR plaintext_attr = attr_get_attribute_by_type(attrs, CKA_VALUE);
    if (!plaintext_attr) {
        LOGE("Expected vendor attribute CKA_VALUE");
        return CKR_GENERAL_ERROR;
    }

    twist ciphertext = NULL;
    size_t len = 0;
    if (plaintext_attr->ulValueLen) {
        twist plaintext = twistbin_new(plaintext_attr->pValue, plaintext_attr->ulValueLen);
        if (!plaintext) {
            LOGE("oom");
            return CKR_HOST_MEMORY;
        }

        CK_RV rv = utils_ctx_wrap_objauth(tok->wrappingkey, plaintext, &ciphertext);
        OPENSSL_cleanse((void *)plaintext, twist_len(plaintext));
        twist_free(plaintext);
        if (rv != CKR_OK) {
            LOGE("Could not wrap CKA_VALUE");
            return rv;
        }
        len = twist_len(ciphertext);
    }

    CK_ATTRIBUTE temp = {
        .type = CKA_TPM2_ENC_BLOB,
        .pValue = (void *)ciphertext,
        .ulValueLen = len
    };

    /* add the wrapped value back to CKA_TPM2_ENC_BLOB */
    CK_RV rv = enc_blob_attr ? attr_list_update_entry(attrs, &temp) :
            attr_list_append_entry(&attrs, &temp);
    twist_free(ciphertext);
    if (rv != CKR_OK) {
        return rv;
    }

    return CKR_OK;
}

CK_RV object_get_host_value(token *tok, tobject *tobj, twist *value) {
    assert(tok);
    assert(tobj);
    check_pointer(value);

    /* a key in the TPM: its value never leaves it */
    if (tobj->pub || tobj->priv) {
        return CKR_KEY_HANDLE_INVALID;
    }

    CK_OBJECT_CLASS clazz = attr_list_get_CKA_CLASS(tobj->attrs, CK_OBJECT_CLASS_BAD);
    CK_BBOOL cka_private = attr_list_get_CKA_PRIVATE(tobj->attrs, CK_FALSE);
    bool is_protected = value_is_protected(clazz, cka_private);

    /* even one already unwrapped in memory: the value is the user's, only while logged in */
    if (is_protected && !tok->wrappingkey) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    twist v = NULL;
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_VALUE);
    if (a && a->ulValueLen) {
        v = twistbin_new(a->pValue, a->ulValueLen);
        if (!v) {
            LOGE("oom");
            return CKR_HOST_MEMORY;
        }
    } else if (is_protected) {
        a = attr_get_attribute_by_type(tobj->attrs, CKA_TPM2_ENC_BLOB);
        if (a && a->ulValueLen) {
            twist ciphertext = twistbin_new(a->pValue, a->ulValueLen);
            if (!ciphertext) {
                LOGE("oom");
                return CKR_HOST_MEMORY;
            }

            CK_RV rv = utils_ctx_unwrap_objauth(tok->wrappingkey, ciphertext, &v);
            twist_free(ciphertext);
            if (rv != CKR_OK) {
                LOGE("Could not unwrap CKA_VALUE");
                return rv;
            }
        }
    }

    /* none kept on the host: a key stored before its value was wrapped, or an empty one */
    if (!v || !twist_len(v)) {
        twist_free(v);
        return CKR_KEY_HANDLE_INVALID;
    }

    *value = v;

    return CKR_OK;
}

/*
 * Whether a key's attribute can't be revealed, because the key is sensitive or unextractable (PKCS#11
 * C_GetAttributeValue, case 1). Only keys have CKA_SENSITIVE and CKA_EXTRACTABLE: a data object, a
 * certificate or a public key gives its CKA_VALUE.
 */
static bool attr_is_hidden(attr_list *attrs, CK_OBJECT_CLASS clazz, CK_ATTRIBUTE_TYPE type) {

    if (type != CKA_VALUE || (clazz != CKO_SECRET_KEY && clazz != CKO_PRIVATE_KEY)) {
        return false;
    }

    CK_BBOOL b = CK_FALSE;
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, CKA_SENSITIVE);
    if (a && attr_CK_BBOOL(a, &b) == CKR_OK && b == CK_TRUE) {
        return true;
    }

    a = attr_get_attribute_by_type(attrs, CKA_EXTRACTABLE);
    return a && attr_CK_BBOOL(a, &b) == CKR_OK && b == CK_FALSE;
}

/*
 * Whether a host-held value would be kept in plain text in the store (a public object's) while its key
 * hides it (sensitive or unextractable): C_CreateObject, C_DeriveKey, C_CopyObject and
 * C_SetAttributeValue don't make such a key, as C_UnwrapKey and the key encapsulation functions don't
 * (key_check_new_template()). The caller knows the value is held on the host, not in the TPM.
 */
static bool public_value_hidden(attr_list *attrs, CK_OBJECT_CLASS clazz) {
    return !value_is_protected(clazz, attr_list_get_CKA_PRIVATE(attrs, CK_FALSE))
            && attr_is_hidden(attrs, clazz, CKA_VALUE);
}

/*
 * CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID and CKR_BUFFER_TOO_SMALL say an entry couldn't be
 * filled, and the template is still processed; any of them may be returned. Any other error wins over them.
 */
static bool is_entry_rv(CK_RV rv) {
    return rv == CKR_ATTRIBUTE_SENSITIVE || rv == CKR_ATTRIBUTE_TYPE_INVALID || rv == CKR_BUFFER_TOO_SMALL;
}

static void merge_rv(CK_RV *rv, CK_RV entry_rv) {
    if (*rv == CKR_OK || (is_entry_rv(*rv) && !is_entry_rv(entry_rv))) {
        *rv = entry_rv;
    }
}

CK_RV object_get_attributes(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE *templ, CK_ULONG count) {

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tobject *tobj = NULL;
    CK_RV rv = token_find_tobject(tok, object, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = tobject_user_increment(tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    /*
     * A sensitive or unextractable key never reveals CKA_VALUE. Otherwise a protected value is kept
     * wrapped in CKA_TPM2_ENC_BLOB, and is only unwrapped while the user is logged in, as only then is
     * tok->wrappingkey there.
     */
    CK_OBJECT_CLASS clazz = attr_list_get_CKA_CLASS(tobj->attrs, CK_OBJECT_CLASS_BAD);
    CK_BBOOL cka_private = attr_list_get_CKA_PRIVATE(tobj->attrs, CK_FALSE);
    bool is_user_logged_in = token_is_user_logged_in (tok);

    /*
     * For each item requested in the template, find if the request has a match
     * and copy the size and possibly data (if allocated).
     */

    CK_ULONG i;
    for (i=0; i < count; i++) {

        CK_ATTRIBUTE_PTR t = &templ[i];

        if (attr_is_hidden(tobj->attrs, clazz, t->type)) {
            t->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            merge_rv(&rv, CKR_ATTRIBUTE_SENSITIVE);
            continue;
        }

        CK_ATTRIBUTE_PTR found = attr_get_attribute_by_type(tobj->attrs, t->type);
        if (value_is_protected(clazz, cka_private) && t->type == CKA_VALUE && is_user_logged_in &&
                (!found || !found->ulValueLen)) {
            CK_RV unwrap_rv = unwrap_protected_cka_value(tok, tobj->attrs);
            if (unwrap_rv != CKR_OK) {
                t->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                merge_rv(&rv, unwrap_rv);
                continue;
            }
            /* with the value it may have added */
            found = attr_get_attribute_by_type(tobj->attrs, t->type);
        }

        if (found) {
            if (!t->pValue) {
                /* only populate size if the buffer is null */
                t->ulValueLen = found->ulValueLen;
                continue;
            }

            /* The found attribute should fit inside the one to copy to */
            if (found->ulValueLen > t->ulValueLen) {
                t->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                merge_rv(&rv, CKR_BUFFER_TOO_SMALL);
                continue;
            }

            t->ulValueLen = found->ulValueLen;
            if (found->ulValueLen && found->pValue) {
                memcpy(t->pValue, found->pValue, found->ulValueLen);
            }
       } else {
           /* If it's not found it defaults to empty. */
           t->pValue = NULL;
           t->ulValueLen = CK_UNAVAILABLE_INFORMATION;
           LOGV("Invalid Attribute for tid %u: type(%lu) ulValueLen(%lu), pData(%s)",
                   tobj->id, t->type, t->ulValueLen, t->pValue ? "non-null" : "null");
           merge_rv(&rv, CKR_ATTRIBUTE_TYPE_INVALID);
       }
    }

    tobject_user_decrement(tobj);
    // if no error occurred rv is CKR_OK from previous call
    return rv;
}

/* Whether the backend stores the object: a token object does, a session object (even orphaned) doesn't. */
static bool is_stored(tobject *tobj) {
    return !tobj->owner && !tobj->orphaned;
}

/*
 * What C_SetAttributeValue and C_CopyObject may change, per object class (PKCS#11 3.2 4.1.2, 4.1.3,
 * 5.7.6). An attribute may be modified when its table in chapter 4 marks it with footnote 8, or the text
 * says so; footnotes 11 and 12 make a bool one-way.
 * - CHANGE_ANY: footnote 8, or the text: "Only the CKA_LABEL attribute can be modified" (Table 19),
 *   "Only the CKA_ID, CKA_ISSUER, and CKA_SERIAL_NUMBER attributes may be modified" (Table 22, X.509),
 *   "Only the CKA_ISSUER attribute" (Table 23, WTLS), "Only the CKA_AC_ISSUER, CKA_SERIAL_NUMBER and
 *   CKA_ATTR_TYPES attributes" (Table 24, attribute certificates), CKA_ID and the dates of a key
 *   (Table 26), CKA_SUBJECT of a public or private key (Tables 27, 29). A data object's attributes are
 *   the application's (Table 20).
 * - CHANGE_OFF: may become false, never true again. The usages (Tables 26, 27, 29, 30, footnote 8): the
 *   TPM fixes a key's attributes when it makes it, and they can be wider than the PKCS#11 ones (an RSA
 *   signing key can decrypt, see apply_usage()), so the PKCS#11 usages are what hold the key to its use.
 *   CKA_EXTRACTABLE (8,12), CKA_COPYABLE ("Can't be set to TRUE once it is set to FALSE", Table 19), and
 *   CKA_DESTROYABLE, by the same token.
 * - CHANGE_ON: CKA_SENSITIVE may become true, never false again (8,11).
 * - CHANGE_COPY: only a copy changes it: CKA_TOKEN, CKA_PRIVATE, CKA_MODIFIABLE (Table 19, 4.1.3).
 * - CHANGE_NONE: read-only. CKA_CLASS (1), CKA_UNIQUE_ID ("MUST fail", 4.4.1), CKA_KEY_TYPE (1,5), what
 *   the token sets (2,4,6: CKA_LOCAL, CKA_KEY_GEN_MECHANISM, CKA_ALWAYS_SENSITIVE,
 *   CKA_NEVER_EXTRACTABLE), the key material, and the attributes without footnote 8:
 *   CKA_ALLOWED_MECHANISMS, the templates, CKA_TRUSTED (10), CKA_WRAP_WITH_TRUSTED (11 alone),
 *   CKA_ALWAYS_AUTHENTICATE (false would widen the key). A private key's CKA_PUBLIC_KEY_INFO has
 *   footnote 8, but the token MUST then check it against the key, which this one can't: read-only.
 * Every vendor attribute (the CKA_TPM2_* blobs, auth and handle) is read-only. An attribute that isn't
 * in the table is read-only if the object has it, and else not one of its class: CKR_ATTRIBUTE_TYPE_INVALID.
 */
enum attr_change {
    CHANGE_ANY,
    CHANGE_OFF,
    CHANGE_ON,
    CHANGE_COPY,
    CHANGE_NONE,
};

#define OC_DATA      (1u << 0)
#define OC_X509      (1u << 1)
#define OC_WTLS      (1u << 2)
#define OC_ATTR_CERT (1u << 3)
#define OC_PUB       (1u << 4)
#define OC_PRIV      (1u << 5)
#define OC_SECRET    (1u << 6)
#define OC_CERT      (OC_X509 | OC_WTLS | OC_ATTR_CERT)
#define OC_KEY       (OC_PUB | OC_PRIV | OC_SECRET)
#define OC_STORAGE   (OC_DATA | OC_CERT | OC_KEY)
#define OC_ANY       (~0u)

typedef struct attr_change_rule attr_change_rule;
struct attr_change_rule {
    CK_ATTRIBUTE_TYPE type;
    unsigned classes;
    enum attr_change change;
    /* a copy may set it to either value (4.1.3: CKA_DESTROYABLE) */
    bool copy_any;
};

static const attr_change_rule attr_change_rules[] = {
    /* Table 14 and 19: any object */
    { CKA_CLASS,            OC_ANY,     CHANGE_NONE, false },
    { CKA_UNIQUE_ID,        OC_STORAGE, CHANGE_NONE, false },
    { CKA_LABEL,            OC_STORAGE, CHANGE_ANY,  false },
    { CKA_TOKEN,            OC_STORAGE, CHANGE_COPY, false },
    { CKA_PRIVATE,          OC_STORAGE, CHANGE_COPY, false },
    { CKA_MODIFIABLE,       OC_STORAGE, CHANGE_COPY, false },
    { CKA_COPYABLE,         OC_STORAGE, CHANGE_OFF,  false },
    { CKA_DESTROYABLE,      OC_STORAGE, CHANGE_OFF,  true  },
    /* Table 20 */
    { CKA_APPLICATION,      OC_DATA,    CHANGE_ANY,  false },
    { CKA_OBJECT_ID,        OC_DATA,    CHANGE_ANY,  false },
    { CKA_VALUE,            OC_DATA,    CHANGE_ANY,  false },
    /* Tables 21 to 24 */
    { CKA_ID,               OC_X509,    CHANGE_ANY,  false },
    { CKA_ISSUER,           OC_X509 | OC_WTLS, CHANGE_ANY, false },
    { CKA_SERIAL_NUMBER,    OC_X509 | OC_ATTR_CERT, CHANGE_ANY, false },
    { CKA_AC_ISSUER,        OC_ATTR_CERT, CHANGE_ANY, false },
    { CKA_ATTR_TYPES,       OC_ATTR_CERT, CHANGE_ANY, false },
    { CKA_CERTIFICATE_TYPE, OC_CERT,    CHANGE_NONE, false },
    { CKA_TRUSTED,          OC_CERT | OC_PUB | OC_SECRET, CHANGE_NONE, false },
    { CKA_CERTIFICATE_CATEGORY, OC_CERT, CHANGE_NONE, false },
    { CKA_CHECK_VALUE,      OC_CERT | OC_SECRET, CHANGE_NONE, false },
    { CKA_START_DATE,       OC_CERT,    CHANGE_NONE, false },
    { CKA_END_DATE,         OC_CERT,    CHANGE_NONE, false },
    { CKA_PUBLIC_KEY_INFO,  OC_CERT | OC_PUB | OC_PRIV, CHANGE_NONE, false },
    { CKA_SUBJECT,          OC_X509 | OC_WTLS, CHANGE_NONE, false },
    { CKA_VALUE,            OC_CERT,    CHANGE_NONE, false },
    { CKA_URL,              OC_X509 | OC_WTLS, CHANGE_NONE, false },
    { CKA_HASH_OF_SUBJECT_PUBLIC_KEY, OC_X509 | OC_WTLS, CHANGE_NONE, false },
    { CKA_HASH_OF_ISSUER_PUBLIC_KEY,  OC_X509 | OC_WTLS, CHANGE_NONE, false },
    { CKA_NAME_HASH_ALGORITHM,        OC_X509 | OC_WTLS, CHANGE_NONE, false },
    { CKA_JAVA_MIDP_SECURITY_DOMAIN,  OC_X509, CHANGE_NONE, false },
    { CKA_OWNER,            OC_ATTR_CERT, CHANGE_NONE, false },
    /* Table 26 */
    { CKA_KEY_TYPE,         OC_KEY,     CHANGE_NONE, false },
    { CKA_ID,               OC_KEY,     CHANGE_ANY,  false },
    { CKA_START_DATE,       OC_KEY,     CHANGE_ANY,  false },
    { CKA_END_DATE,         OC_KEY,     CHANGE_ANY,  false },
    { CKA_DERIVE,           OC_KEY,     CHANGE_OFF,  false },
    { CKA_LOCAL,            OC_KEY,     CHANGE_NONE, false },
    { CKA_KEY_GEN_MECHANISM, OC_KEY,    CHANGE_NONE, false },
    { CKA_ALLOWED_MECHANISMS, OC_KEY,   CHANGE_NONE, false },
    { CKA_OBJECT_VALIDATION_FLAGS, OC_KEY, CHANGE_NONE, false },
    /* Tables 27, 29 and 30 */
    { CKA_SUBJECT,          OC_PUB | OC_PRIV, CHANGE_ANY, false },
    { CKA_ENCRYPT,          OC_PUB | OC_SECRET, CHANGE_OFF, false },
    { CKA_VERIFY,           OC_PUB | OC_SECRET, CHANGE_OFF, false },
    { CKA_VERIFY_RECOVER,   OC_PUB,     CHANGE_OFF,  false },
    { CKA_WRAP,             OC_PUB | OC_SECRET, CHANGE_OFF, false },
    { CKA_ENCAPSULATE,      OC_PUB,     CHANGE_OFF,  false },
    { CKA_DECRYPT,          OC_PRIV | OC_SECRET, CHANGE_OFF, false },
    { CKA_SIGN,             OC_PRIV | OC_SECRET, CHANGE_OFF, false },
    { CKA_SIGN_RECOVER,     OC_PRIV,    CHANGE_OFF,  false },
    { CKA_UNWRAP,           OC_PRIV | OC_SECRET, CHANGE_OFF, false },
    { CKA_DECAPSULATE,      OC_PRIV,    CHANGE_OFF,  false },
    { CKA_SENSITIVE,        OC_PRIV | OC_SECRET, CHANGE_ON, false },
    { CKA_EXTRACTABLE,      OC_PRIV | OC_SECRET, CHANGE_OFF, false },
    { CKA_ALWAYS_SENSITIVE, OC_PRIV | OC_SECRET, CHANGE_NONE, false },
    { CKA_NEVER_EXTRACTABLE, OC_PRIV | OC_SECRET, CHANGE_NONE, false },
    { CKA_WRAP_WITH_TRUSTED, OC_PRIV | OC_SECRET, CHANGE_NONE, false },
    { CKA_ALWAYS_AUTHENTICATE, OC_PRIV, CHANGE_NONE, false },
    { CKA_WRAP_TEMPLATE,    OC_PUB | OC_SECRET, CHANGE_NONE, false },
    { CKA_UNWRAP_TEMPLATE,  OC_PRIV | OC_SECRET, CHANGE_NONE, false },
    { CKA_DERIVE_TEMPLATE,  OC_PRIV | OC_SECRET, CHANGE_NONE, false },
    { CKA_PUBLIC_CRC64_VALUE, OC_PUB | OC_PRIV, CHANGE_NONE, false },
    /* the key material: a key's value is the key, only C_DeriveKey sets it (object_set_derived_value) */
    { CKA_VALUE,            OC_KEY,     CHANGE_NONE, false },
    { CKA_VALUE_LEN,        OC_SECRET,  CHANGE_NONE, false },
    { CKA_MODULUS,          OC_PUB | OC_PRIV, CHANGE_NONE, false },
    { CKA_MODULUS_BITS,     OC_PUB | OC_PRIV, CHANGE_NONE, false },
    { CKA_PUBLIC_EXPONENT,  OC_PUB | OC_PRIV, CHANGE_NONE, false },
    { CKA_PRIVATE_EXPONENT, OC_PRIV,    CHANGE_NONE, false },
    { CKA_PRIME_1,          OC_PRIV,    CHANGE_NONE, false },
    { CKA_PRIME_2,          OC_PRIV,    CHANGE_NONE, false },
    { CKA_EXPONENT_1,       OC_PRIV,    CHANGE_NONE, false },
    { CKA_EXPONENT_2,       OC_PRIV,    CHANGE_NONE, false },
    { CKA_COEFFICIENT,      OC_PRIV,    CHANGE_NONE, false },
    { CKA_EC_PARAMS,        OC_PUB | OC_PRIV, CHANGE_NONE, false },
    { CKA_EC_POINT,         OC_PUB | OC_PRIV, CHANGE_NONE, false },
};

/* The object's class in the table: a certificate's depends on its type. 0 for a class it doesn't list. */
static unsigned attr_change_class(attr_list *attrs, CK_OBJECT_CLASS clazz) {

    switch (clazz) {
    case CKO_DATA:
        return OC_DATA;
    case CKO_PUBLIC_KEY:
        return OC_PUB;
    case CKO_PRIVATE_KEY:
        return OC_PRIV;
    case CKO_SECRET_KEY:
        return OC_SECRET;
    case CKO_CERTIFICATE: {
        CK_ULONG cert_type = CK_UNAVAILABLE_INFORMATION;
        CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(attrs, CKA_CERTIFICATE_TYPE);
        if (a && attr_CK_ULONG(a, &cert_type) != CKR_OK) {
            cert_type = CK_UNAVAILABLE_INFORMATION;
        }
        return cert_type == CKC_WTLS ? OC_WTLS :
               cert_type == CKC_X_509_ATTR_CERT ? OC_ATTR_CERT : OC_X509;
    }
    default:
        return 0;
    }
}

static const attr_change_rule *attr_change_rule_get(unsigned oclass, CK_ATTRIBUTE_TYPE type) {

    size_t i;
    for (i = 0; i < ARRAY_LEN(attr_change_rules); i++) {
        const attr_change_rule *r = &attr_change_rules[i];
        if (r->type == type && (r->classes & oclass)) {
            return r;
        }
    }

    return NULL;
}

/*
 * Whether the template entry t may change the object tobj, of class clazz: by C_SetAttributeValue, or for
 * the copy C_CopyObject makes (copy). A copy may also give any attribute it can't change the value it
 * already has, but a value and the vendor attributes are never compared.
 */
static CK_RV check_attr_change(tobject *tobj, CK_OBJECT_CLASS clazz, CK_ATTRIBUTE_PTR t, bool copy) {

    if (!t->pValue && t->ulValueLen) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    const char *what = copy ? "a copy" : "C_SetAttributeValue";

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, t->type);
    bool vendor = (t->type & CKA_VENDOR_DEFINED) == CKA_VENDOR_DEFINED;

    const attr_change_rule *r = vendor ? NULL : attr_change_rule_get(attr_change_class(tobj->attrs, clazz),
            t->type);
    if (!r && !vendor && !a) {
        LOGE("%s isn't an attribute of a class %lu object", attr_get_name(t->type), clazz);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    enum attr_change change = r ? r->change : CHANGE_NONE;

    /* a copy keeps the value it copies: a protected one is re-kept as a whole (copy_rekeep_value()) */
    if (copy && t->type == CKA_VALUE) {
        change = CHANGE_NONE;
    }

    if (change == CHANGE_NONE || (change == CHANGE_COPY && !copy)) {
        /* 4.4.1: a template can't give CKA_UNIQUE_ID, not even the value it has */
        bool same = copy && a && t->type != CKA_VALUE && t->type != CKA_UNIQUE_ID && !vendor
                && a->ulValueLen == t->ulValueLen
                && (!t->ulValueLen || !memcmp(a->pValue, t->pValue, t->ulValueLen));
        if (!same) {
            LOGE("%s can't be changed by %s", attr_get_name(t->type), what);
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        return CKR_OK;
    }

    if (change == CHANGE_ANY) {
        if (t->type == CKA_START_DATE || t->type == CKA_END_DATE) {
            return !t->ulValueLen || t->ulValueLen == sizeof(CK_DATE) ?
                    CKR_OK : CKR_ATTRIBUTE_VALUE_INVALID;
        }
        return CKR_OK;
    }

    CK_BBOOL value = CK_FALSE;
    if (attr_CK_BBOOL(t, &value) != CKR_OK) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (change == CHANGE_COPY || (copy && r->copy_any)) {
        return CKR_OK;
    }

    /* CKA_COPYABLE and CKA_DESTROYABLE default to true, the others to false */
    CK_BBOOL current = t->type == CKA_COPYABLE || t->type == CKA_DESTROYABLE ? CK_TRUE : CK_FALSE;
    if (a && attr_CK_BBOOL(a, &current) != CKR_OK) {
        return CKR_GENERAL_ERROR;
    }

    CK_BBOOL wider = change == CHANGE_ON ? CK_FALSE : CK_TRUE;
    if (value != current && value == wider) {
        LOGE("%s can't be changed to %s", attr_get_name(t->type), value ? "true" : "false");
        return CKR_ATTRIBUTE_READ_ONLY;
    }

    return CKR_OK;
}

static CK_RV object_set_attributes_common(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE *templ,
        CK_ULONG count, bool value_settable) {

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tobject *tobj = NULL;
    CK_RV rv = token_find_tobject(tok, object, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = tobject_user_increment(tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_OBJECT_CLASS clazz = attr_list_get_CKA_CLASS(tobj->attrs, CK_OBJECT_CLASS_BAD);
    if (clazz == CK_OBJECT_CLASS_BAD) {
        LOGE("Expect ALL objects to contain attribute CKA_CLASS");
        rv = CKR_GENERAL_ERROR;
        goto out;
    }

    /*
     * PKCS#11 5.7.6 has CKA_MODIFIABLE=false refuse every change with CKR_ACTION_PROHIBITED. That isn't
     * enforced here: tpm2_ptool gives every object it makes CKA_MODIFIABLE=false (objects.py), and those
     * objects have always been relabelled through C_SetAttributeValue.
     */

    CK_BBOOL cka_private = attr_list_get_CKA_PRIVATE(tobj->attrs, CK_FALSE);

    /* create a temp copy to work on so we have transactional atomicity */
    attr_list *tmp = NULL;
    rv = attr_list_dup(tobj->attrs, &tmp);
    if (rv != CKR_OK) {
        goto out;
    }

    /*
     * For each item, if check_attr_change() lets it change the object:
     * 1. If it exists, update the contents
     * 2. If it is new, add it.
     * value_settable is C_DeriveKey setting the value of the key it has just made, which nothing else may.
     */
    CK_ULONG i;
    for (i=0; i < count; i++) {

        CK_ATTRIBUTE_PTR t = &templ[i];

        rv = value_settable ? CKR_OK : check_attr_change(tobj, clazz, t, false);
        if (rv != CKR_OK) {
            goto error;
        }

        CK_ATTRIBUTE_PTR found = attr_get_attribute_by_type(tmp, t->type);
        rv = found ? attr_list_update_entry(tmp, t) :
            attr_list_append_entry(&tmp, t);
        if (rv != CKR_OK) {
            goto error;
        }

        /* a protected CKA_VALUE is kept encrypted: wrap the new value, now it's in the list */
        if (t->type == CKA_VALUE && value_is_protected(clazz, cka_private)) {
            rv = wrap_protected_cka_value(tok, tmp);
            if (rv != CKR_OK) {
                goto error;
            }
        }
    }

    /*
     * A public object's value is kept in plain text in the store: a key held on the host doesn't hide
     * it (see public_value_hidden()). Turning CKA_SENSITIVE on or CKA_EXTRACTABLE off is refused, as
     * for an attribute that can't change; the key may still be copied to a private one that hides it.
     */
    if (!value_settable && !tobj->pub && public_value_hidden(tmp, clazz)
            && !public_value_hidden(tobj->attrs, clazz)) {
        LOGE("A public key held on the host can't be made sensitive or unextractable");
        rv = CKR_ATTRIBUTE_READ_ONLY;
        goto error;
    }

    /* We don't want to emit CKA_VALUE for CKA_PRIVATE objects to the backend store */
    bool is_backed_up = false;
    CK_ATTRIBUTE backup = { 0 };
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tmp, CKA_VALUE);
    if (cka_private && a && a->ulValueLen) {
        backup.pValue = a->pValue;
        backup.ulValueLen = a->ulValueLen;
        a->pValue = NULL;
        a->ulValueLen = 0;
        is_backed_up = true;
    }

    /* in memory is updated, so update the persistent store; a session object has none */
    if (is_stored(tobj)) {
        rv = backend_update_tobject_attrs(tok, tobj, tmp);
    }

    /* put the value back before anything else, so a failure's attr_list_free() cleanses it */
    if (is_backed_up) {
        a->pValue = backup.pValue;
        a->ulValueLen = backup.ulValueLen;
    }

    if (rv != CKR_OK) {
        goto error;
    }

    /*
     * everything completed successfully, swap the
     * attribute pointers.
     */
    attr_list_free(tobj->attrs);
    tobj->attrs = tmp;

    rv = CKR_OK;

out:
    tobject_user_decrement(tobj);

    return rv;

error:
    attr_list_free(tmp);
    goto out;
}

CK_RV object_set_attributes(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE *templ, CK_ULONG count) {
    return object_set_attributes_common(ctx, object, templ, count, false);
}

CK_RV object_set_derived_value(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR value) {
    check_pointer(value);

    if (value->type != CKA_VALUE) {
        LOGE("Expected CKA_VALUE, got %s", attr_get_name(value->type));
        return CKR_GENERAL_ERROR;
    }

    return object_set_attributes_common(ctx, object, value, 1, true);
}

DEBUG_VISIBILITY tobject *__real_tobject_new(void) {

	tobject *tobj = calloc(1, sizeof(tobject));
    if (!tobj) {
        LOGE("oom");
        return NULL;
    }

    return tobj;
}

WEAK tobject *tobject_new(void) {
	return __real_tobject_new();
}

CK_RV tobject_set_blob_data(tobject *tobj, twist pub, twist priv) {
    assert(pub);
    assert(tobj);

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

    if (priv) {
        bool r = attr_list_add_buf(tobj->attrs, CKA_TPM2_PRIV_BLOB,
                (CK_BYTE_PTR)priv, twist_len(priv));
        if (!r) {
            return CKR_GENERAL_ERROR;
        }
    }

    bool r = attr_list_add_buf(tobj->attrs, CKA_TPM2_PUB_BLOB,
            (CK_BYTE_PTR)pub, pub ? twist_len(pub) : 0);

    return r ? CKR_OK : CKR_GENERAL_ERROR;
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

    bool r = attr_list_add_buf(tobj->attrs, CKA_TPM2_OBJAUTH_ENC,
            (CK_BYTE_PTR)wrappedauthhex, twist_len(wrappedauthhex));
    return r ? CKR_OK : CKR_GENERAL_ERROR;
}

void tobject_set_esys_tr(tobject *tobj, uint32_t esys_tr) {
    assert(tobj);

    tobj->tpm_esys_tr = esys_tr;
}

void tobject_set_id(tobject *tobj, unsigned id) {
    assert(tobj);
    tobj->id = id;
}

attr_list *tobject_get_attrs(tobject *tobj) {
    return tobj->attrs;
}

CK_RV _tobject_user_increment(tobject *tobj, const char *filename, int lineno) {

    if (tobj->active == UINT_MAX) {
       LOGE("tobject active at max count, cannot issue. id: %u", tobj->id);
       return CKR_GENERAL_ERROR;
    }

    tobj->active++;
    _LOGV(filename, lineno, "Incremented tobject id: %u, value: %u", tobj->id, tobj->active);

    return CKR_OK;
}

CK_RV _tobject_user_decrement(tobject *tobj, const char *filename, int lineno) {

    if (!tobj->active) {
        LOGE("Returning a non-active tobject id: %u", tobj->id);
        return CKR_GENERAL_ERROR;
    }

    tobj->active--;
    _LOGV(filename, lineno, "Decremented tobject id: %u, value: %u", tobj->id, tobj->active);

    return CKR_OK;
}

static bool tobject_is_busy(tobject *tobj) {
    assert(tobj);

    return tobj->active > 0;
}

static CK_RV flush_tobject_handle(token *tok, tobject *tobj) {

    assert(tok);
    assert(tobj);

    if (!tobj->tpm_esys_tr || tobj->tpm_serialized_tr) {
        return CKR_OK;
    }

    bool result = tpm_flushcontext(tok->tctx, tobj->tpm_esys_tr);
    if (!result) {
        LOGE("Could not flush object handle for tobject id: %u", tobj->id);
        return CKR_GENERAL_ERROR;
    }

    tobj->tpm_esys_tr = 0;

    return CKR_OK;
}

CK_RV object_destroy(session_ctx *ctx, CK_OBJECT_HANDLE object) {

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tobject *tobj = NULL;
    CK_RV rv = token_find_tobject(tok, object, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    /* 5.7.3: an object whose CKA_DESTROYABLE is false stays; one without the attribute can go */
    CK_BBOOL destroyable = CK_TRUE;
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_DESTROYABLE);
    if (a && attr_CK_BBOOL(a, &destroyable) == CKR_OK && destroyable == CK_FALSE) {
        LOGE("Object %lu isn't destroyable", object);
        return CKR_ACTION_PROHIBITED;
    }

    bool is_busy = tobject_is_busy(tobj);
    if (is_busy) {
        return CKR_FUNCTION_FAILED;
    }

    rv = flush_tobject_handle(tok, tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = object_unstore(tok, tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    token_rm_tobject(tok, tobj);

    tobject_free(tobj);
    rv = CKR_OK;

    return rv;
}

/* CKA_UNIQUE_ID is 16 random bytes, hex-encoded: an identifier, not key material, so OpenSSL's RNG does */
#define UNIQUE_ID_BYTES 16

/* whether an object of the token other than self has the CKA_UNIQUE_ID id */
static bool unique_id_in_use(token *tok, tobject *self, twist id) {

    list *cur = tok->tobjects.head ? &tok->tobjects.head->l : NULL;
    while (cur) {
        tobject *t = list_entry(cur, tobject, l);
        cur = cur->next;

        if (t == self) {
            continue;
        }

        CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(t->attrs, CKA_UNIQUE_ID);
        if (a && a->ulValueLen == twist_len(id) && !memcmp(a->pValue, id, a->ulValueLen)) {
            return true;
        }
    }

    return false;
}

CK_RV object_new_unique_id(token *tok, tobject *tobj) {

    assert(tok);
    assert(tobj);
    assert(tobj->attrs);

    twist id = NULL;
    do {
        twist_free(id);

        unsigned char rnd[UNIQUE_ID_BYTES];
        if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
            LOGE("Could not get random bytes for a CKA_UNIQUE_ID");
            return CKR_GENERAL_ERROR;
        }

        id = twist_hex_new((char *)rnd, sizeof(rnd));
        if (!id) {
            LOGE("oom");
            return CKR_HOST_MEMORY;
        }
    /* 128 bits won't collide in practice, but the spec makes them unique within the token */
    } while (unique_id_in_use(tok, tobj, id));

    CK_ATTRIBUTE a = { CKA_UNIQUE_ID, (void *)id, twist_len(id) };
    CK_RV rv = attr_get_attribute_by_type(tobj->attrs, CKA_UNIQUE_ID) ?
            attr_list_update_entry(tobj->attrs, &a) : attr_list_append_entry(&tobj->attrs, &a);
    twist_free(id);

    return rv;
}

CK_RV object_add_missing_unique_ids(token *tok) {

    assert(tok);

    list *cur = tok->tobjects.head ? &tok->tobjects.head->l : NULL;
    while (cur) {
        tobject *tobj = list_entry(cur, tobject, l);
        cur = cur->next;

        if (attr_get_attribute_by_type(tobj->attrs, CKA_UNIQUE_ID)) {
            continue;
        }

        CK_RV rv = object_new_unique_id(tok, tobj);
        if (rv != CKR_OK) {
            return rv;
        }

        /*
         * Loaded objects hold what the store has (a private CKA_VALUE is only in CKA_TPM2_ENC_BLOB), so
         * this writes back the same attributes, and the new ID.
         */
        rv = backend_update_tobject_attrs(tok, tobj, tobj->attrs);
        if (rv != CKR_OK) {
            LOGW("Could not store the CKA_UNIQUE_ID given to object id %u; it changes on the next load",
                    tobj->id);
        }
    }

    return CKR_OK;
}

CK_RV object_store(token *tok, session_ctx *ctx, tobject *tobj) {

    /* a new object, a copy among them, gets its own (4.4.1), stored with it */
    CK_RV rv = object_new_unique_id(tok, tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    if (attr_list_get_CKA_TOKEN(tobj->attrs, CK_TRUE)) {
        return backend_add_object(tok, tobj);
    }

    tobj->owner = ctx;
    return CKR_OK;
}

CK_RV object_unstore(token *tok, tobject *tobj) {

    return is_stored(tobj) ? backend_rm_tobject(tok, tobj) : CKR_OK;
}

void object_destroy_session_objects(token *tok, session_ctx *ctx) {

    list *cur = tok->tobjects.head ? &tok->tobjects.head->l : NULL;
    while (cur) {
        tobject *tobj = list_entry(cur, tobject, l);
        cur = cur->next;

        if (tobj->owner != ctx) {
            continue;
        }

        if (tobject_is_busy(tobj)) {
            LOGW("Session object %lu is in use by another session; it stays until C_Finalize",
                    tobj->obj_handle);
            tobj->owner = NULL;
            tobj->orphaned = true;
            continue;
        }

        if (flush_tobject_handle(tok, tobj) != CKR_OK) {
            LOGW("Could not flush session object %lu", tobj->obj_handle);
        }

        token_rm_tobject(tok, tobj);
        tobject_free(tobj);
    }
}

static CK_RV handle_rsa_public(CK_ATTRIBUTE_PTR templ, CK_ULONG count, attr_list **new_attrs) {

    CK_RV rv = CKR_GENERAL_ERROR;

    /* RSA Public keys should have a modulus and exponent, verify */
    CK_ATTRIBUTE_PTR a_modulus = attr_get_attribute_by_type_raw(templ, count, CKA_MODULUS);
    if (!a_modulus) {
        return CKR_TEMPLATE_INCOMPLETE;
    }

    CK_ATTRIBUTE_PTR a_exponent = attr_get_attribute_by_type_raw(templ, count, CKA_PUBLIC_EXPONENT);
    if (!a_exponent) {
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /*
     * Create a new typed attr list
     */
    attr_list *tmp_attrs = NULL;
    bool res = attr_typify(templ, count, &tmp_attrs);
    if (!res) {
        return CKR_GENERAL_ERROR;
    }
    assert(tmp_attrs);

    /* Add attribute CKA_LOCAL if missing */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tmp_attrs, CKA_LOCAL);
    if (!a) {
        bool result = attr_list_add_bool(tmp_attrs, CKA_LOCAL, CK_FALSE);
        if (!result) {
            rv = CKR_HOST_MEMORY;
            goto out;
        }
    }

    /* add CKA_ENCRYPT if missing */
    a = attr_get_attribute_by_type(tmp_attrs, CKA_ENCRYPT);
    if (!a) {
        bool result = attr_list_add_bool(tmp_attrs, CKA_ENCRYPT, CK_TRUE);
        if (!result) {
            rv = CKR_HOST_MEMORY;
            goto out;
        }
    }

    /* add CKA_VERIFY if missing */
    a = attr_get_attribute_by_type(tmp_attrs, CKA_VERIFY);
    if (!a) {
        bool result = attr_list_add_bool(tmp_attrs, CKA_VERIFY, CK_TRUE);
        if (!result) {
            rv = CKR_HOST_MEMORY;
            goto out;
        }
    }

    /* add CKA_KEY_GEN_MECHANISM as CK_UNAVAILABLE_INFORMATION */
    a = attr_get_attribute_by_type(tmp_attrs, CKA_KEY_GEN_MECHANISM);
    if (!a) {
        bool result = attr_list_add_int(tmp_attrs, CKA_KEY_GEN_MECHANISM, CK_UNAVAILABLE_INFORMATION);
        if (!result) {
            rv = CKR_HOST_MEMORY;
            goto out;
        }
    } else {
        CK_ULONG genmech = 0;
        rv = attr_CK_ULONG(a, &genmech);
        if (rv != CKR_OK) {
            LOGE("Error converting attribute CKA_KEY_GEN_MECHANISM");
            goto out;
        }

        if (genmech != CK_UNAVAILABLE_INFORMATION) {
           LOGE("CKA_KEY_GEN_MECHANISM cannot be anything but "
                   "CKA_KEY_GEN_MECHANISM, got: %lu",
                   genmech);
           rv = CKR_ATTRIBUTE_VALUE_INVALID;
           goto out;
        }
    }

    /* populate missing RSA public key attributes */
    rv = attr_common_add_RSA_publickey(&tmp_attrs);
    if (rv != CKR_OK) {
        LOGE("Could not add RSA public missing attributes");
        goto out;
    }

    /* transfer ownership to caller */
    *new_attrs = tmp_attrs;
    tmp_attrs = NULL;

out:
    attr_list_free(tmp_attrs);

    return rv;
}

static CK_RV handle_data_object(token *tok, CK_ATTRIBUTE_PTR templ, CK_ULONG count, attr_list **new_attrs) {

    CK_RV rv = CKR_GENERAL_ERROR;
    /*
     * Create a new typed attr list
     */
    attr_list *tmp_attrs = NULL;
    bool res = attr_typify(templ, count, &tmp_attrs);
    if (!res) {
        return CKR_GENERAL_ERROR;
    }
    assert(tmp_attrs);

    CK_BBOOL cka_private = attr_list_get_CKA_PRIVATE(tmp_attrs, CK_TRUE);
    if (!cka_private) {
        LOGE("CKA_PRIVATE cannot be CK_FALSE");
        rv = CKR_ATTRIBUTE_VALUE_INVALID;
        goto out;
    }

    rv = wrap_protected_cka_value(tok, tmp_attrs);
    if (rv != CKR_OK) {
        goto out;
    }

    /* Set any defaults and do error checking */
    rv = attr_common_add_data(&tmp_attrs);
    if (rv != CKR_OK) {
        goto out;
    }

    /* transfer ownership to caller */
    *new_attrs = tmp_attrs;
    tmp_attrs = NULL;

out:
    attr_list_free(tmp_attrs);

    return rv;
}

static CK_RV handle_cert_object(CK_ATTRIBUTE_PTR templ, CK_ULONG count, attr_list **new_attrs) {

    CK_RV rv = CKR_GENERAL_ERROR;
    /*
     * Create a new typed attr list
     */
    attr_list *tmp_attrs = NULL;
    bool res = attr_typify(templ, count, &tmp_attrs);
    if (!res) {
        return CKR_GENERAL_ERROR;
    }
    assert(tmp_attrs);

    CK_BBOOL cka_private = attr_list_get_CKA_PRIVATE(tmp_attrs, CK_FALSE);
    if (cka_private) {
        LOGE("CKA_PRIVATE cannot be CK_TRUE");
        rv = CKR_ATTRIBUTE_VALUE_INVALID;
        goto out;
    }

    /* Set any defaults and do error checking */
    rv = attr_common_add_storage(&tmp_attrs);
    if (rv != CKR_OK) {
        goto out;
    }

    /* transfer ownership to caller */
    *new_attrs = tmp_attrs;
    tmp_attrs = NULL;

out:
    attr_list_free(tmp_attrs);

    return rv;
}

static CK_RV handle_secret_object(token *tok, CK_ATTRIBUTE_PTR templ, CK_ULONG count, attr_list **new_attrs)
{
    CK_RV rv = CKR_OK;
    /*
     * Create a new typed attr list
     */
    attr_list *tmp_attrs = NULL;
    bool res = attr_typify(templ, count, &tmp_attrs);
    if (!res) {
        return CKR_GENERAL_ERROR;
    }
    assert(tmp_attrs);

    /* Set any defaults and do error checking */
    rv = attr_common_add_storage(&tmp_attrs);
    if (rv != CKR_OK) {
        goto out;
    }

    /*
     * A private key's value is kept wrapped, as a data object's is, or the store would have none: once
     * the defaults say whether it's private. One without a value yet (C_DeriveKey's) is wrapped when
     * it's set.
     */
    CK_BBOOL cka_private = attr_list_get_CKA_PRIVATE(tmp_attrs, CK_FALSE);

    /* a public one's is kept in plain text: it isn't sensitive or unextractable (see public_value_hidden()) */
    if (public_value_hidden(tmp_attrs, CKO_SECRET_KEY)) {
        LOGE("A sensitive or unextractable key held on the host can't be public");
        rv = CKR_TEMPLATE_INCONSISTENT;
        goto out;
    }
    if (value_is_protected(CKO_SECRET_KEY, cka_private)
            && attr_get_attribute_by_type(tmp_attrs, CKA_VALUE)) {
        rv = wrap_protected_cka_value(tok, tmp_attrs);
        if (rv != CKR_OK) {
            goto out;
        }
    }

    /* transfer ownership to caller */
    *new_attrs = tmp_attrs;
    tmp_attrs = NULL;

out:
    attr_list_free(tmp_attrs);

    return rv;
}

/*
 * Whether a template asks for a value that can be read back, CKA_EXTRACTABLE=true or CKA_SENSITIVE=false,
 * which a key in the TPM can't honour. A generic secret like that (a password, a blob) stays a plain
 * object holding its value, as it did before such keys went to the TPM.
 */
static bool wants_readable_value(CK_ATTRIBUTE_PTR templ, CK_ULONG count) {

    CK_BBOOL b = CK_FALSE;
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type_raw(templ, count, CKA_EXTRACTABLE);
    if (a && attr_CK_BBOOL(a, &b) == CKR_OK && b == CK_TRUE) {
        return true;
    }

    a = attr_get_attribute_by_type_raw(templ, count, CKA_SENSITIVE);
    return a && attr_CK_BBOOL(a, &b) == CKR_OK && b == CK_FALSE;
}

bool object_secret_in_tpm(CK_KEY_TYPE key_type, CK_ATTRIBUTE_PTR templ, CK_ULONG count) {
    return key_is_tpm_secret(key_type)
            && !(key_type == CKK_GENERIC_SECRET && wants_readable_value(templ, count));
}

/*
 * Stores a new object, unless it's a session object, and adds it to the token, which gives it its
 * handle. A private object's CKA_VALUE isn't written to the store: it's kept in memory, wrapped in
 * CKA_TPM2_ENC_BLOB when it's protected. On failure the caller still owns, and frees, tobj.
 */
static CK_RV object_add_new(token *tok, session_ctx *ctx, tobject *tobj) {

    bool is_backed_up = false;
    CK_ATTRIBUTE backup = { 0 };

    /* if it's a private object we can't expose the CKA_VALUE attribute */
    CK_BBOOL cka_private = attr_list_get_CKA_PRIVATE(tobj->attrs, CK_FALSE);
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_VALUE);
    if (cka_private && a && a->ulValueLen) {
        backup.ulValueLen = a->ulValueLen;
        backup.pValue = a->pValue;
        a->ulValueLen = 0;
        a->pValue = NULL;
        is_backed_up = true;
    }

    /* add the object to the db, unless it's a session object */
    CK_RV rv = object_store(tok, ctx, tobj);

    /* put the value back before anything else, so a failure's tobject_free() cleanses it */
    if (is_backed_up) {
        /* object_store() added CKA_UNIQUE_ID, which may have moved the list */
        a = attr_get_attribute_by_type(tobj->attrs, CKA_VALUE);
        assert(a);
        a->ulValueLen = backup.ulValueLen;
        a->pValue = backup.pValue;
    }

    if (rv != CKR_OK) {
        return rv;
    }

    /* add the object to the token */
    rv = token_add_tobject(tok, tobj);
    if (rv != CKR_OK) {
        /* not left in the store with no object to remove it through */
        if (object_unstore(tok, tobj) != CKR_OK) {
            LOGW("Could not remove object id %u from the store", tobj->id);
        }
        return rv;
    }

    return CKR_OK;
}

/*
 * value_later: the object is a secret key whose CKA_VALUE the caller sets once it's made, as C_DeriveKey
 * does; through C_CreateObject a secret key needs its value.
 */
static CK_RV object_create_common(session_ctx *ctx, CK_ATTRIBUTE *templ, CK_ULONG count,
        CK_OBJECT_HANDLE *object, bool value_later) {
    assert(ctx);
    check_pointer(templ);
    check_pointer(object);

    CK_RV rv = CKR_GENERAL_ERROR;

    CK_STATE state = session_ctx_state_get(ctx);
    LOGV("state: %lu", state);

    /*
     * Currently we only support RW user session state objects.
     */
    switch(state) {
    case CKS_RW_USER_FUNCTIONS:
        break;
    case CKS_RW_PUBLIC_SESSION:
    case CKS_RW_SO_FUNCTIONS:
        return CKR_USER_NOT_LOGGED_IN;
    default:
        return CKR_SESSION_READ_ONLY;
    }

    /* the token gives every object its CKA_UNIQUE_ID (4.4.1) */
    rv = attr_refuse_unique_id(templ, count);
    if (rv != CKR_OK) {
        return rv;
    }

    /* and only the SO may make an object trusted */
    rv = attr_refuse_trusted(templ, count);
    if (rv != CKR_OK) {
        return rv;
    }

    /*
     * If CKA_LOCAL is specified, it can never be CK_TRUE
     * TODO: At somepoint these attr_get_attribute_by_type_raw() calls
     * could be done by general extractors and default error values ala
     * attr_list_get_CKA_PRIVATE() type calls for raw attr lists.
     */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type_raw(templ, count, CKA_LOCAL);
    if (a) {
        CK_BBOOL bbool = CK_FALSE;
        rv = attr_CK_BBOOL(a, &bbool);
        if (rv != CKR_OK) {
            LOGE("Error converting attribute CKA_LOCAL");
            return rv;
        }
        if (bbool == CK_TRUE) {
           LOGE("CKA_LOCAL cannot be true");
           return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    /*
     * We only support:
     * - CKK_RSA - CKO_PUBLIC_KEY
     * - CKO_DATA
     *  so verify it.
     */
    a = attr_get_attribute_by_type_raw(templ, count, CKA_CLASS);
    if (!a) {
        LOGE("Expected attribute CKA_CLASS");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    CK_OBJECT_CLASS clazz;
    rv = attr_CK_OBJECT_CLASS(a, &clazz);
    if (rv != CKR_OK) {
        LOGE("Error converting attribute CKA_CLASS");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* Not all objects have a key type, only KEY Objects do */
    CK_KEY_TYPE key_type = CKA_KEY_TYPE_BAD;
    a = attr_get_attribute_by_type_raw(templ, count, CKA_KEY_TYPE);
    if (a) {
        rv = attr_CK_KEY_TYPE(a, &key_type);
        if (rv != CKR_OK) {
            LOGE("Error converting attribute CKA_KEY_TYPE");
            return rv;
        }
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);
    attr_list *new_attrs = NULL;

    /*
     * A secret key with its value is made in the TPM, so it can be used. One without, as C_DeriveKey
     * creates before setting its value, stays a plain object holding the value.
     */
    bool has_value = attr_get_attribute_by_type_raw(templ, count, CKA_VALUE) != NULL;
    if (clazz == CKO_SECRET_KEY && !has_value && !value_later) {
        LOGE("A secret key needs its CKA_VALUE");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* C_DeriveKey sets the value: a template's own would be what the key really holds */
    if (has_value && value_later) {
        LOGE("A derived key's template can't have CKA_VALUE");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    if (clazz == CKO_SECRET_KEY && has_value && object_secret_in_tpm(key_type, templ, count)) {
        return key_import_secret(ctx, key_type, templ, count, object);
    }

    if (key_type == CKK_RSA && clazz == CKO_PUBLIC_KEY) {
        rv = handle_rsa_public(templ, count, &new_attrs);
    } else if (clazz == CKO_DATA) {
        rv = handle_data_object(tok, templ, count, &new_attrs);
    } else if (clazz == CKO_CERTIFICATE) {
        rv = handle_cert_object(templ, count, &new_attrs);
    } else if (clazz == CKO_SECRET_KEY) {
        rv = handle_secret_object(tok, templ, count, &new_attrs);
    } else {
        LOGE("Can only create RSA Public key objects or"
                " data objects, CKA_CLASS(%lu), CKA_KEY_TYPE(%lu)",
                clazz, key_type);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (rv != CKR_OK) {
        LOGE("Error creating object, "
                "CKA_CLASS(%lu), CKA_KEY_TYPE(%lu) rv: %lu",
                clazz, key_type, rv);
        return rv;
    }

    /* ok create the new tobject */
    tobject *new_tobj = tobject_new();
    if (!new_tobj) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    new_tobj->attrs = new_attrs;
    new_attrs = NULL;

    rv = object_add_new(tok, ctx, new_tobj);
    if (rv != CKR_OK) {
        goto out;
    }

    /* assign temp tobject to callee provided pointer */
    *object = new_tobj->obj_handle;
    new_tobj = NULL;

    rv = CKR_OK;

out:
    attr_list_free(new_attrs);
    tobject_free(new_tobj);

    return rv;
}

CK_RV object_create(session_ctx *ctx, CK_ATTRIBUTE *templ, CK_ULONG count, CK_OBJECT_HANDLE *object) {
    return object_create_common(ctx, templ, count, object, false);
}

CK_RV object_create_valueless_secret(session_ctx *ctx, CK_ATTRIBUTE *templ, CK_ULONG count,
        CK_OBJECT_HANDLE *object) {
    return object_create_common(ctx, templ, count, object, true);
}

/*
 * A host-held value (a data object's, or a secret key's not in the TPM) is wrapped while the object is
 * private, and plain text while it's public: a copy changing CKA_PRIVATE re-keeps it. A sensitive or
 * unextractable key's value isn't made public, as it would then be written to the store as plain text.
 */
static CK_RV copy_rekeep_value(token *tok, tobject *tobj, CK_OBJECT_CLASS clazz, attr_list **attrs) {

    if (tobj->pub) {
        return CKR_OK;
    }

    /* whether or not the copy changes CKA_PRIVATE */
    if (public_value_hidden(*attrs, clazz)) {
        LOGE("A sensitive or unextractable key's copy can't be public");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    CK_BBOOL was_private = attr_list_get_CKA_PRIVATE(tobj->attrs, CK_FALSE);
    CK_BBOOL is_private = attr_list_get_CKA_PRIVATE(*attrs, CK_FALSE);
    bool to_protect = value_is_protected(clazz, is_private);
    if (value_is_protected(clazz, was_private) == to_protect) {
        return CKR_OK;
    }

    twist value = NULL;
    CK_RV rv = object_get_host_value(tok, tobj, &value);
    if (rv == CKR_KEY_HANDLE_INVALID) {
        /* no value to keep */
        return CKR_OK;
    }
    if (rv != CKR_OK) {
        return rv;
    }

    CK_ATTRIBUTE v = {
        .type = CKA_VALUE,
        .pValue = (void *)value,
        .ulValueLen = twist_len(value)
    };
    rv = attr_get_attribute_by_type(*attrs, CKA_VALUE) ?
            attr_list_update_entry(*attrs, &v) : attr_list_append_entry(attrs, &v);
    if (rv != CKR_OK) {
        goto out;
    }

    if (to_protect) {
        rv = wrap_protected_cka_value(tok, *attrs);
    } else if (attr_get_attribute_by_type(*attrs, CKA_TPM2_ENC_BLOB)) {
        /* a public value is kept as plain text */
        CK_ATTRIBUTE none = { .type = CKA_TPM2_ENC_BLOB, .pValue = NULL, .ulValueLen = 0 };
        rv = attr_list_update_entry(*attrs, &none);
    }

out:
    OPENSSL_cleanse((void *)value, twist_len(value));
    twist_free(value);

    return rv;
}

CK_RV object_copy(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR templ, CK_ULONG count,
        CK_OBJECT_HANDLE_PTR new_object) {
    assert(ctx);
    check_pointer(new_object);

    if (!templ && count) {
        return CKR_ARGUMENTS_BAD;
    }

    /* only the SO may make an object trusted, even one that already is */
    CK_RV rv = attr_refuse_trusted(templ, count);
    if (rv != CKR_OK) {
        return rv;
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    /* the object functions say an unknown handle is no object, not no key */
    tobject *tobj = NULL;
    rv = token_find_tobject(tok, object, &tobj);
    if (rv != CKR_OK) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    rv = tobject_user_increment(tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    attr_list *tmp = NULL;
    tobject *new_tobj = NULL;

    CK_OBJECT_CLASS clazz = attr_list_get_CKA_CLASS(tobj->attrs, CK_OBJECT_CLASS_BAD);
    if (clazz == CK_OBJECT_CLASS_BAD) {
        LOGE("Expect ALL objects to contain attribute CKA_CLASS");
        rv = CKR_GENERAL_ERROR;
        goto out;
    }

    CK_BBOOL b = CK_TRUE;
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_COPYABLE);
    if (a && attr_CK_BBOOL(a, &b) == CKR_OK && b == CK_FALSE) {
        LOGE("Object %lu isn't copyable", object);
        rv = CKR_ACTION_PROHIBITED;
        goto out;
    }

    /* the copy starts as the object's attributes, its TPM blobs and wrapped auth among them */
    rv = attr_list_dup(tobj->attrs, &tmp);
    if (rv != CKR_OK) {
        goto out;
    }

    CK_ULONG i;
    for (i = 0; i < count; i++) {

        CK_ATTRIBUTE_PTR t = &templ[i];

        rv = check_attr_change(tobj, clazz, t, true);
        if (rv != CKR_OK) {
            goto out;
        }

        rv = attr_get_attribute_by_type(tmp, t->type) ?
                attr_list_update_entry(tmp, t) : attr_list_append_entry(&tmp, t);
        if (rv != CKR_OK) {
            goto out;
        }
    }

    rv = copy_rekeep_value(tok, tobj, clazz, &tmp);
    if (rv != CKR_OK) {
        goto out;
    }

    new_tobj = tobject_new();
    if (!new_tobj) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    new_tobj->attrs = tmp;
    tmp = NULL;

    /* its own pub, priv and auth copies; it's loaded in the TPM, and authenticated, on its own */
    rv = object_init_from_attrs(new_tobj);
    if (rv != CKR_OK) {
        goto out;
    }

    /* a new store record, or a session object owned by ctx */
    rv = object_add_new(tok, ctx, new_tobj);
    if (rv != CKR_OK) {
        goto out;
    }

    *new_object = new_tobj->obj_handle;
    new_tobj = NULL;

out:
    attr_list_free(tmp);
    tobject_free(new_tobj);
    tobject_user_decrement(tobj);

    return rv;
}

CK_RV object_get_size(session_ctx *ctx, CK_OBJECT_HANDLE object, CK_ULONG_PTR size) {
    assert(ctx);
    check_pointer(size);

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tobject *tobj = NULL;
    CK_RV rv = token_find_tobject(tok, object, &tobj);
    if (rv != CKR_OK) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    CK_OBJECT_CLASS clazz = attr_list_get_CKA_CLASS(tobj->attrs, CK_OBJECT_CLASS_BAD);
    CK_BBOOL cka_private = attr_list_get_CKA_PRIVATE(tobj->attrs, CK_FALSE);
    bool is_protected = value_is_protected(clazz, cka_private);

    /*
     * PKCS#11 leaves the meaning to the token: the attributes plus the TPM blobs. A protected value
     * is counted as its CKA_TPM2_ENC_BLOB, so the size doesn't change as the plain text is unwrapped
     * at a read and dropped at logout.
     */
    CK_ULONG total = 0;
    CK_ULONG n = attr_list_get_count(tobj->attrs);
    CK_ATTRIBUTE_PTR attrs = attr_list_get_ptr(tobj->attrs);
    CK_ULONG i;
    for (i = 0; i < n; i++) {
        if (is_protected && attrs[i].type == CKA_VALUE) {
            continue;
        }
        total += attrs[i].ulValueLen;
    }

    total += tobj->pub ? twist_len(tobj->pub) : 0;
    total += tobj->priv ? twist_len(tobj->priv) : 0;

    *size = total;

    return CKR_OK;
}

CK_RV object_init_from_attrs(tobject *tobj) {
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_TPM2_OBJAUTH_ENC);
    if (a && a->pValue && a->ulValueLen) {
        tobj->objauth = twistbin_new(a->pValue, a->ulValueLen);
        if (!tobj->objauth) {
            LOGE("oom");
            goto error;
        }
    }

    a = attr_get_attribute_by_type(tobj->attrs, CKA_TPM2_PUB_BLOB);
    if (a && a->pValue && a->ulValueLen) {

        tobj->pub = twistbin_new(a->pValue, a->ulValueLen);
        if (!tobj->pub) {
            LOGE("oom");
            goto error;
        }
    }

    a = attr_get_attribute_by_type(tobj->attrs, CKA_TPM2_PRIV_BLOB);
    if (a && a->pValue && a->ulValueLen) {

        if (!tobj->pub) {
            LOGE("objects with CKA_TPM2_PUB_BLOB should have CKA_TPM2_PRIV_BLOB");
            goto error;
        }

        tobj->priv = twistbin_new(a->pValue, a->ulValueLen);
        if (!tobj->priv) {
            LOGE("oom");
            goto error;
        }
    }

    a = attr_get_attribute_by_type(tobj->attrs, CKA_TPM2_SERIALIZED_TR);
    if (a && a->pValue && a->ulValueLen) {
        tobj->tpm_serialized_tr = twistbin_new(a->pValue, a->ulValueLen);
        if (!tobj->tpm_serialized_tr) {
            LOGE("oom");
            goto error;
        }
    }

    return CKR_OK;

error:
    return CKR_GENERAL_ERROR;
}
