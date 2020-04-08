/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"
#include <assert.h>
#include <stdlib.h>

#include "attrs.h"
#include "log.h"
#include "pkcs11.h"
#include "typed_memory.h"
#include "utils.h"

struct attr_list {
    CK_ULONG max;
    CK_ULONG count;
    CK_ATTRIBUTE_PTR attrs;
};

#define ADD_ATTR_HANDLER(t, m) { .type = t, .memtype = m }

typedef struct attr_handler2 attr_handler2;
struct attr_handler2 {
    CK_ATTRIBUTE_TYPE type;
    CK_BYTE memtype;
};

#define ALLOC_LEN 16

static bool _attr_list_add(attr_list *l,
        CK_ATTRIBUTE_TYPE type, CK_ULONG len, CK_BYTE_PTR buf,
        int memtype) {

    /* do we need space in the attribute list? if so realloc */
    if (l->count == l->max) {
        bool res = __builtin_add_overflow(l->max, ALLOC_LEN, &l->max);
        if (res) {
            LOGE("add overflow\n");
            return false;
        }

        size_t bytes = 0;
        safe_mul(bytes, l->max, sizeof(*l->attrs));

        void *tmp = realloc(l->attrs, bytes);
        if (!tmp) {
            LOGE("oom");
            return false;
        }

        l->attrs = (CK_ATTRIBUTE_PTR)tmp;

        /*
         * clear the newly allocated region
         * If the mul operation didn't overflow above, then
         * mul cannot overflow here, so use regular mul
         */
        safe_mul(bytes, ALLOC_LEN, sizeof(*l->attrs));
        memset(&l->attrs[l->count], 0, bytes);
    }

    /* only hex strings and sequences can be empty */
    if (!len && (memtype != TYPE_BYTE_HEX_STR) && (memtype != TYPE_BYTE_INT_SEQ)) {
        LOGE("type cannot be empty, got: %d", memtype);
        return false;
    }

    if (!len) {
        l->attrs[l->count].type = type;
        assert(!l->attrs[l->count].pValue);
        assert(!l->attrs[l->count].ulValueLen);
        l->count++;
        return true;
    }

    void *newnode = type_calloc(1, len, memtype);
    if (!newnode) {
        LOGE("oom");
        return false;
    }
    memcpy(newnode, buf, len);

    l->attrs[l->count].type = type;
    l->attrs[l->count].ulValueLen = len;
    l->attrs[l->count++].pValue = newnode;

    return true;
}

static bool add_type_copy(CK_ATTRIBUTE_PTR a, CK_BYTE memtype, attr_list *l) {

    if (!a->pValue || !a->ulValueLen) {
        return attr_list_add_buf(l, a->type, NULL, 0);
    }

    if (!memtype) {
        LOGW("Guessing type for attribute, consider adding type info: 0x%lx", a->type);

        /* guess based on length */
        switch(a->ulValueLen) {
        case sizeof(CK_BBOOL):
            memtype = TYPE_BYTE_BOOL;
            break;
        case sizeof(CK_ULONG):
            memtype = TYPE_BYTE_INT;
            break;
        default:
            memtype = TYPE_BYTE_HEX_STR;
        }
    }

    return _attr_list_add(l, a->type, a->ulValueLen, a->pValue, memtype);
}

static attr_handler2 attr_handlers[] = {
    ADD_ATTR_HANDLER(CKA_CLASS, TYPE_BYTE_INT),
    ADD_ATTR_HANDLER(CKA_TOKEN, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_PRIVATE, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_LABEL, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_VALUE, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_CERTIFICATE_TYPE, TYPE_BYTE_INT),
    ADD_ATTR_HANDLER(CKA_ISSUER, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_SERIAL_NUMBER, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_TRUSTED, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_CERTIFICATE_CATEGORY, TYPE_BYTE_INT),
    ADD_ATTR_HANDLER(CKA_JAVA_MIDP_SECURITY_DOMAIN, TYPE_BYTE_INT),
    ADD_ATTR_HANDLER(CKA_URL, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_CHECK_VALUE, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_HASH_OF_ISSUER_PUBLIC_KEY, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_NAME_HASH_ALGORITHM, TYPE_BYTE_INT),
    ADD_ATTR_HANDLER(CKA_KEY_TYPE, TYPE_BYTE_INT),
    ADD_ATTR_HANDLER(CKA_SUBJECT, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_ID, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_SENSITIVE, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_ENCRYPT, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_DECRYPT, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_WRAP, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_UNWRAP, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_SIGN, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_SIGN_RECOVER, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_VERIFY, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_VERIFY_RECOVER, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_DERIVE, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_START_DATE, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_END_DATE, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_MODULUS, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_MODULUS_BITS, TYPE_BYTE_INT),
    ADD_ATTR_HANDLER(CKA_PUBLIC_EXPONENT, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_PUBLIC_KEY_INFO, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_VALUE_LEN, TYPE_BYTE_INT),
    ADD_ATTR_HANDLER(CKA_EXTRACTABLE, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_LOCAL, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_NEVER_EXTRACTABLE, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_ALWAYS_SENSITIVE, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_KEY_GEN_MECHANISM, TYPE_BYTE_INT),
    ADD_ATTR_HANDLER(CKA_MODIFIABLE, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_COPYABLE, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_DESTROYABLE, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_EC_PARAMS, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_EC_POINT, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_ALWAYS_AUTHENTICATE, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_WRAP_WITH_TRUSTED, TYPE_BYTE_BOOL),
    ADD_ATTR_HANDLER(CKA_WRAP_TEMPLATE, TYPE_BYTE_TEMP_SEQ),
    ADD_ATTR_HANDLER(CKA_UNWRAP_TEMPLATE, TYPE_BYTE_TEMP_SEQ),
    ADD_ATTR_HANDLER(CKA_ALLOWED_MECHANISMS, TYPE_BYTE_INT_SEQ),
    ADD_ATTR_HANDLER(CKA_TPM2_OBJAUTH_ENC, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_TPM2_PUB_BLOB, TYPE_BYTE_HEX_STR),
    ADD_ATTR_HANDLER(CKA_TPM2_PRIV_BLOB, TYPE_BYTE_HEX_STR),
};

static attr_handler2 default_handler = { .memtype = 0 };

static attr_handler2 *attr_lookup(CK_ATTRIBUTE_TYPE t) {

    size_t i;
    for (i=0; i < ARRAY_LEN(attr_handlers); i++) {
        attr_handler2 *h = &attr_handlers[i];
        if (h->type == t) {
            return h;
        }
    }

    LOGW("Using default attribute handler for %lu,"
            " consider registering a handler", t);

    /* attempt using the default */
    return &default_handler;
}

attr_list *attr_list_new(void) {
    return calloc(1, sizeof(attr_list));
}

bool attr_list_add_int(attr_list *l, CK_ATTRIBUTE_TYPE type, CK_ULONG value) {

    return _attr_list_add(l, type, sizeof(value), (CK_BYTE_PTR)&value, TYPE_BYTE_INT);
}

bool attr_list_add_bool(attr_list *l, CK_ATTRIBUTE_TYPE type, CK_BBOOL value) {

    return _attr_list_add(l, type, sizeof(value), &value, TYPE_BYTE_BOOL);
}

bool attr_list_add_buf(attr_list *l, CK_ATTRIBUTE_TYPE type, CK_BYTE_PTR value, CK_ULONG len) {

    return _attr_list_add(l, type, len, value, TYPE_BYTE_HEX_STR);
}

CK_ULONG attr_list_get_count(attr_list *l) {
    assert(l);
    return l->count;
}

CK_ATTRIBUTE_PTR attr_list_get_ptr(attr_list *l) {
    assert(l);
    return l->attrs;
}

void attr_list_free(attr_list *attrs) {

    if (!attrs) {
        return;
    }

    CK_ULONG i;
    for (i=0; i < attrs->count; i++) {
        const CK_ATTRIBUTE_PTR a = &attrs->attrs[i];
        free(a->pValue);
    }

    free(attrs->attrs);
    free(attrs);
}

CK_RV attr_list_raw_invoke_handlers(const CK_ATTRIBUTE_PTR attrs, CK_ULONG count,
        const attr_handler *handlers, size_t len, void *udata) {

    size_t i;

    if (!attrs || !count) {
        return CKR_OK;
    }

    for(i=0; i < count; i++) {
        const CK_ATTRIBUTE_PTR a = &attrs[i];
        size_t j;
        for(j=0; j < len; j++) {
            const attr_handler *h = &handlers[j];
            if (h->type == a->type) {
                CK_RV rv = h->handler(a, udata);
                if (rv != CKR_OK) {
                    return rv;
                }
            }
        }
        LOGV("ignoring attribute: 0x%lx", a->type);
    }

    return CKR_OK;
}

CK_RV attr_list_invoke_handlers(attr_list *l, const attr_handler *handlers, size_t len, void *udata) {

    if (!l) {
        return CKR_OK;
    }

    return attr_list_raw_invoke_handlers(attr_list_get_ptr(l), attr_list_get_count(l),
            handlers, len, udata);
}

bool attr_typify(CK_ATTRIBUTE_PTR attrs, CK_ULONG cnt, attr_list **copy) {

    attr_list *c = attr_list_new();
    if (!c) {
        return CKR_HOST_MEMORY;
    }

    CK_ULONG i;
    for (i=0; i < cnt; i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        attr_handler2 *h = attr_lookup(a->type);
        bool res = add_type_copy(a, h->memtype, c);
        if (!res) {
            attr_list_free(c);
            return res;
        }
    }

    *copy = c;

    return true;
}

CK_RV attr_list_dup(attr_list *old, attr_list **new) {
    assert(old);
    assert(new);

    CK_RV rv = CKR_GENERAL_ERROR;

    /* create the container */
    attr_list *tmp = calloc(1, sizeof(attr_list));
    if (!tmp) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    /* create the attribute list */
    tmp->attrs = calloc(old->max, sizeof(CK_ATTRIBUTE));
    if (!tmp->attrs) {
        LOGE("oom");
        free(tmp);
        return CKR_HOST_MEMORY;
    }
    tmp->max = old->max;

    /* deep copy the attrs */
    size_t i;
    for (i=0; i < old->count; i++) {
        CK_ATTRIBUTE_PTR o = &old->attrs[i];
        CK_ATTRIBUTE_PTR n = &tmp->attrs[i];

        n->type = o->type;
        if (o->pValue && o->ulValueLen) {
            rv = type_mem_dup(o->pValue, o->ulValueLen, &n->pValue);
            if (rv != CKR_OK) {
                goto error;
            }
            n->ulValueLen = o->ulValueLen;
        }

        tmp->count++;
    }

    *new = tmp;

    return CKR_OK;

error:
    attr_list_free(tmp);
    return rv;
}

CK_ATTRIBUTE_PTR attr_get_attribute_by_type_raw(CK_ATTRIBUTE_PTR haystack, CK_ULONG haystack_count,
        CK_ATTRIBUTE_TYPE needle) {

    assert(haystack);

    CK_ULONG i;
    for (i=0; i < haystack_count; i++) {

        CK_ATTRIBUTE_PTR a = &haystack[i];
        if (a->type == needle) {
            return a;
        }
    }

    return NULL;
}

CK_ATTRIBUTE_PTR attr_get_attribute_by_type(attr_list *haystack, CK_ATTRIBUTE_TYPE needle) {

    assert(haystack);

    return attr_get_attribute_by_type_raw(haystack->attrs, haystack->count, needle);
}

attr_list *attr_list_append_attrs(
        attr_list *old_attrs,
        attr_list **new_attrs) {

    if (!(*new_attrs)) {
        return old_attrs;
    }

    if (!old_attrs) {
        return *new_attrs;
    }

    /* todo safe addition */
    CK_ULONG old_len = attr_list_get_count(old_attrs);
    CK_ULONG new_len = attr_list_get_count(*new_attrs);

    CK_ULONG total_len = 0;
    safe_add(total_len, new_len, old_len);

    if (!new_len) {
        attr_list_free(*new_attrs);
        *new_attrs = NULL;
        return old_attrs;
    }

    // need to fit 500 have space for 16
    if (total_len > old_attrs->max) {

        size_t blocks = total_len / ALLOC_LEN;
        safe_adde(blocks, total_len % ALLOC_LEN ? 1 : 0);

        CK_ULONG alloc_items = 0;
        safe_mul(alloc_items, blocks, ALLOC_LEN);

        size_t bytes = 0;
        safe_mul(bytes, alloc_items, sizeof(CK_ATTRIBUTE));
        void *tmp = realloc(old_attrs->attrs, bytes);
        if (!tmp) {
            return NULL;
        }
        old_attrs->attrs = tmp;
        CK_ATTRIBUTE_PTR clear_point = &old_attrs->attrs[old_attrs->max];

        /* clear the delta */
        size_t delta = alloc_items - old_attrs->max;
        safe_mul(bytes, delta, sizeof(CK_ATTRIBUTE));
        memset(clear_point, 0, bytes);
        old_attrs->max = alloc_items;
    }

    CK_ATTRIBUTE_PTR cpy_point = &old_attrs->attrs[old_len];

    size_t bytes = 0;
    safe_mul(bytes, new_len,  sizeof(CK_ATTRIBUTE));

    memcpy(cpy_point, (*new_attrs)->attrs, bytes);

    old_attrs->count = total_len;

    free((*new_attrs)->attrs);
    free(*new_attrs);
    *new_attrs = NULL;

    return old_attrs;
}

static CK_RV attr_common_add_storage(attr_list **storage_attrs) {

    CK_RV rv = CKR_GENERAL_ERROR;

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(*storage_attrs, CKA_CLASS);
    if (!a) {
        LOGE("Expected object to have CKA_CLASS");
        return CKR_GENERAL_ERROR;
    }

    CK_ULONG v;
    rv = attr_CK_ULONG(a, &v);
    if (rv != CKR_OK) {
        return rv;
    }

    attr_list *new_attrs = attr_list_new();
    if (!new_attrs) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    /* currently immutable */
    bool r = attr_list_add_bool(new_attrs, CKA_TOKEN, CK_TRUE);
    goto_error_false(r);
    r = attr_list_add_bool(new_attrs, CKA_MODIFIABLE, CK_TRUE);
    goto_error_false(r);
    r = attr_list_add_bool(new_attrs, CKA_COPYABLE, CK_TRUE);
    goto_error_false(r);
    r = attr_list_add_bool(new_attrs, CKA_DESTROYABLE, CK_TRUE);
    goto_error_false(r);

    /* defaults */
    CK_BBOOL defpriv = ((v == CKO_PRIVATE_KEY) || (v == CKO_SECRET_KEY)) ?
            CK_TRUE : CK_FALSE;

    a = attr_get_attribute_by_type(*storage_attrs, CKA_PRIVATE);
    if (!a) {
        r = attr_list_add_bool(new_attrs, CKA_PRIVATE, defpriv);
        goto_error_false(r);
    }

    a = attr_get_attribute_by_type(*storage_attrs, CKA_LABEL);
    if (!a) {
        r = attr_list_add_buf(new_attrs, CKA_LABEL, NULL, 0);
        goto_error_false(r);
    }

    *storage_attrs = attr_list_append_attrs(*storage_attrs,
            &new_attrs);
    goto_error_false(*storage_attrs);
    return CKR_OK;

error:
    attr_list_free(new_attrs);

    return rv;
}

static CK_RV attr_common_add_key(attr_list **key_attrs) {

    CK_RV rv = CKR_HOST_MEMORY;

    /* expected */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(*key_attrs, CKA_KEY_TYPE);
    if (!a) {
        LOGE("Expected object to have CKA_KEY_TYPE");
        return CKR_GENERAL_ERROR;
    }

    a = attr_get_attribute_by_type(*key_attrs, CKA_LOCAL);
    if (!a) {
        LOGE("Expected object to have CKA_LOCAL");
        return CKR_GENERAL_ERROR;
    }

    a = attr_get_attribute_by_type(*key_attrs, CKA_KEY_GEN_MECHANISM);
    if (!a) {
        LOGE("Expected object to have CKA_KEY_GEN_MECHANISM");
        return CKR_GENERAL_ERROR;
    }

    a = attr_get_attribute_by_type(*key_attrs, CKA_ALLOWED_MECHANISMS);
    if (!a) {
        LOGE("Expected object to have CKA_ALLOWED_MECHANISMS");
        return CKR_GENERAL_ERROR;
    }

    attr_list *new_attrs = attr_list_new();
    if (!new_attrs) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    /* defaults */
    a = attr_get_attribute_by_type(*key_attrs, CKA_ID);
    if (!a) {
        bool r = attr_list_add_buf(new_attrs, CKA_ID, NULL, 0);
        goto_error_false(r);
    }

    a = attr_get_attribute_by_type(*key_attrs, CKA_START_DATE);
    if (!a) {
        bool r = attr_list_add_buf(new_attrs, CKA_START_DATE, NULL, 0);
        goto_error_false(r);
    }

    a = attr_get_attribute_by_type(*key_attrs, CKA_END_DATE);
    if (!a) {
        bool r = attr_list_add_buf(new_attrs, CKA_END_DATE, NULL, 0);
        goto_error_false(r);
    }

    bool r = attr_list_add_bool(new_attrs, CKA_DERIVE, CK_FALSE);
    goto_error_false(r);


    *key_attrs = attr_list_append_attrs(*key_attrs, &new_attrs);
    goto_error_false(*key_attrs);

    return attr_common_add_storage(key_attrs);

error:
    attr_list_free(new_attrs);

    return rv;
}

static CK_RV attr_common_add_publickey(attr_list **public_attrs) {

    CK_RV rv = CKR_HOST_MEMORY;

    /* expected */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(*public_attrs, CKA_ENCRYPT);
    if (!a) {
        LOGE("Expected object to have CKA_ENCRYPT");
        return CKR_GENERAL_ERROR;
    }

    a = attr_get_attribute_by_type(*public_attrs, CKA_VERIFY);
    if (!a) {
        LOGE("Expected object to have CKA_VERIFY");
        return CKR_GENERAL_ERROR;
    }

    attr_list *new_attrs = attr_list_new();
    if (!new_attrs) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    /* defaults */
    a = attr_get_attribute_by_type(*public_attrs, CKA_SUBJECT);
    if (!a) {
        bool r = attr_list_add_buf(new_attrs, CKA_SUBJECT, NULL, 0);
        goto_error_false(r);
    }

    bool r = attr_list_add_bool(new_attrs, CKA_SUBJECT, CK_FALSE);
    goto_error_false(r);

    r = attr_list_add_bool(new_attrs, CKA_TRUSTED, CK_FALSE);
    goto_error_false(r);

    r = attr_list_add_buf(new_attrs, CKA_WRAP_TEMPLATE, NULL, 0);
    goto_error_false(r);

    r = attr_list_add_buf(new_attrs, CKA_PUBLIC_KEY_INFO, NULL, 0);
    goto_error_false(r);

    r = attr_list_add_int(new_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    goto_error_false(r);

    r = attr_list_add_bool(new_attrs, CKA_WRAP, CK_FALSE);
    goto_error_false(r);

    r = attr_list_add_bool(new_attrs, CKA_VERIFY_RECOVER, CK_FALSE);
    goto_error_false(r);

    *public_attrs = attr_list_append_attrs(*public_attrs, &new_attrs);
    goto_error_false(*public_attrs);

    return attr_common_add_key(public_attrs);

error:
    attr_list_free(new_attrs);

    return rv;
}

CK_RV attr_common_add_RSA_publickey(attr_list **public_attrs) {

    CK_RV rv = CKR_GENERAL_ERROR;

    attr_list *new_attrs = attr_list_new();
    if (!new_attrs) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    /* default if not set */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(*public_attrs, CKA_MODULUS_BITS);
    if (!a) {
        a = attr_get_attribute_by_type(*public_attrs, CKA_MODULUS);
        if (!a) {
            LOGE("Expected object to have CKA_MODULUS");
            goto error;
        }

        CK_ULONG modulus_bits = 0;
        safe_mul(modulus_bits, a->ulValueLen, 8);
        bool r = attr_list_add_int(new_attrs, CKA_MODULUS_BITS, modulus_bits);
        goto_error_false(r);
    }

    *public_attrs = attr_list_append_attrs(*public_attrs, &new_attrs);
    goto_error_false(*public_attrs);

    return attr_common_add_publickey(public_attrs);
error:
    attr_list_free(new_attrs);

    return rv;
}

static CK_RV attr_common_add_EC_publickey(attr_list **public_attrs) {

    /* expected */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(*public_attrs, CKA_EC_POINT);
    if (!a) {
        LOGE("Expected object to have CKA_EC_POINT");
        return CKR_GENERAL_ERROR;
    }

    a = attr_get_attribute_by_type(*public_attrs, CKA_EC_PARAMS);
    if (!a) {
        LOGE("Expected object to have CKA_EC_PARAMS");
        return CKR_GENERAL_ERROR;
    }

    return attr_common_add_publickey(public_attrs);
}

static CK_RV attr_common_add_privatekey(attr_list **private_attrs) {

    CK_RV rv = CKR_HOST_MEMORY;

    /* expected */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(*private_attrs, CKA_DECRYPT);
    if (!a) {
        LOGE("Expected object to have CKA_DECRYPT");
        return CKR_GENERAL_ERROR;
    }

    a = attr_get_attribute_by_type(*private_attrs, CKA_SIGN);
    if (!a) {
        LOGE("Expected object to have CKA_SIGN");
        return CKR_GENERAL_ERROR;
    }

    a = attr_get_attribute_by_type(*private_attrs, CKA_EXTRACTABLE);
    if (!a) {
        LOGE("Expected object to have CKA_EXTRACTABLE");
        return CKR_GENERAL_ERROR;
    }

    a = attr_get_attribute_by_type(*private_attrs, CKA_ALWAYS_SENSITIVE);
    if (!a) {
        LOGE("Expected object to have CKA_ALWAYS_SENSITIVE");
        return CKR_GENERAL_ERROR;
    }

    a = attr_get_attribute_by_type(*private_attrs, CKA_NEVER_EXTRACTABLE);
    if (!a) {
        LOGE("Expected object to have CKA_NEVER_EXTRACTABLE");
        return CKR_GENERAL_ERROR;
    }

    attr_list *new_attrs = attr_list_new();
    if (!new_attrs) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    /* defaults */
    a = attr_get_attribute_by_type(*private_attrs, CKA_SUBJECT);
    if (!a) {
        bool r = attr_list_add_buf(new_attrs, CKA_SUBJECT, NULL, 0);
        goto_error_false(r);
    }

    a = attr_get_attribute_by_type(*private_attrs, CKA_ALWAYS_AUTHENTICATE);
    if (!a) {
        bool r = attr_list_add_bool(new_attrs, CKA_ALWAYS_AUTHENTICATE, CK_FALSE);
        goto_error_false(r);
    }

    bool r = attr_list_add_bool(new_attrs, CKA_SIGN_RECOVER, CK_FALSE);
    goto_error_false(r);

    r = attr_list_add_bool(new_attrs, CKA_SENSITIVE, CK_FALSE);
    goto_error_false(r);


    r = attr_list_add_bool(new_attrs, CKA_UNWRAP, CK_FALSE);
    goto_error_false(r);

    r = attr_list_add_bool(new_attrs, CKA_WRAP_WITH_TRUSTED, CK_FALSE);
    goto_error_false(r);

    r = attr_list_add_buf(new_attrs, CKA_UNWRAP_TEMPLATE, NULL, 0);
    goto_error_false(r);

    r = attr_list_add_buf(new_attrs, CKA_PUBLIC_KEY_INFO, NULL, 0);
    goto_error_false(r);

    r = attr_list_add_int(new_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    goto_error_false(r);

    *private_attrs = attr_list_append_attrs(*private_attrs, &new_attrs);
    goto_error_false(*private_attrs);

    return attr_common_add_key(private_attrs);

error:
    attr_list_free(new_attrs);

    return rv;
}

static CK_RV attr_common_add_RSA_privatekey(attr_list **private_attrs) {

    CK_RV rv = CKR_HOST_MEMORY;

    /* expected */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(*private_attrs, CKA_MODULUS);
    if (!a) {
        LOGE("Expected object to have CKA_MODULUS");
        return CKR_GENERAL_ERROR;
    }

    a = attr_get_attribute_by_type(*private_attrs, CKA_PUBLIC_EXPONENT);
    if (!a) {
        LOGE("Expected object to have CKA_PUBLIC_EXPONENT");
        return CKR_GENERAL_ERROR;
    }

    attr_list *new_attrs = NULL;

    a = attr_get_attribute_by_type(*private_attrs, CKA_MODULUS_BITS);
    if (!a) {

        new_attrs = attr_list_new();
        if (!new_attrs) {
            LOGE("oom");
            return CKR_HOST_MEMORY;
        }

        a = attr_get_attribute_by_type(*private_attrs, CKA_MODULUS);
        /* we checked above this cant fail */
        assert(a);
        CK_ULONG modulus_bits = 0;
        safe_mul(modulus_bits, a->ulValueLen, 8);
        bool r = attr_list_add_int(new_attrs, CKA_MODULUS_BITS, modulus_bits);
        goto_error_false(r);
    }

    *private_attrs = attr_list_append_attrs(*private_attrs, &new_attrs);
    goto_error_false(*private_attrs);

    return attr_common_add_privatekey(private_attrs);

error:
    attr_list_free(new_attrs);

    return rv;
}

static CK_RV attr_common_add_EC_privatekey(attr_list **private_attrs) {

    /* expected */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(*private_attrs, CKA_EC_POINT);
    if (!a) {
        LOGE("Expected object to have CKA_EC_POINT");
        return CKR_GENERAL_ERROR;
    }

    return attr_common_add_privatekey(private_attrs);
}

CK_RV rsa_gen_mechs(attr_list *new_pub_attrs, attr_list *new_priv_attrs) {

    /* XXX These are hardcoded for now */
    CK_MECHANISM_TYPE t[] = {
        CKM_RSA_X_509,
        CKM_RSA_PKCS_OAEP,
        CKM_RSA_PKCS,
        CKM_SHA1_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_RSA_PKCS_PSS,
        CKM_SHA1_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
    };

    if (new_pub_attrs) {
        bool r = attr_list_add_buf(new_pub_attrs, CKA_ALLOWED_MECHANISMS,
                (CK_BYTE_PTR)&t, sizeof(t));
        goto_error_false(r);
    }

    if (new_priv_attrs) {
        bool r = attr_list_add_buf(new_priv_attrs, CKA_ALLOWED_MECHANISMS,
            (CK_BYTE_PTR)&t, sizeof(t));
        goto_error_false(r);
    }

    return CKR_OK;

error:
    return CKR_GENERAL_ERROR;
}

/*
 * Add required attributes to the RSA objects based on:
 *   - http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850406
 *     - 2.1.2 and 2.1.3
 */
static CK_RV rsa_add_missing_attrs(attr_list **public_attrs, attr_list **private_attrs) {

    CK_RV rv = CKR_HOST_MEMORY;

    attr_list *new_pub_attrs = attr_list_new();
    if (!new_pub_attrs) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    attr_list *new_priv_attrs = attr_list_new();
    if (!new_priv_attrs) {
        attr_list_free(new_pub_attrs);
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    rv = rsa_gen_mechs(new_pub_attrs, new_priv_attrs);
    if (rv != CKR_OK) {
        goto error;
    }

    bool r = attr_list_add_int(new_pub_attrs, CKA_KEY_TYPE, CKK_RSA);
    goto_error_false(r);

    r = attr_list_add_int(new_priv_attrs, CKA_KEY_TYPE, CKK_RSA);
    goto_error_false(r);

    *public_attrs = attr_list_append_attrs(*public_attrs, &new_pub_attrs);
    goto_error_false(*public_attrs);


    *private_attrs = attr_list_append_attrs(*private_attrs, &new_priv_attrs);
    goto_error_false(*private_attrs);

    rv = attr_common_add_RSA_privatekey(private_attrs);
    if (rv != CKR_OK) {
        goto error;
    }

    rv = attr_common_add_RSA_publickey(public_attrs);
    if (rv != CKR_OK) {
        goto error;
    }
    return CKR_OK;

error:
    attr_list_free(new_priv_attrs);
    attr_list_free(new_pub_attrs);

    return rv;
}

static CK_RV ecc_gen_mechs(attr_list *new_pub_attrs, attr_list *new_priv_attrs) {

    /* XXX These are hardcoded for now */
    CK_MECHANISM_TYPE t[] = {
        CKM_ECDSA,
        CKM_ECDSA_SHA1,
    };

    bool r = attr_list_add_buf(new_pub_attrs, CKA_ALLOWED_MECHANISMS,
            (CK_BYTE_PTR)&t, sizeof(t));
    goto_error_false(r);

    r = attr_list_add_buf(new_priv_attrs, CKA_ALLOWED_MECHANISMS,
            (CK_BYTE_PTR)&t, sizeof(t));
    goto_error_false(r);

    return CKR_OK;

error:
    return CKR_GENERAL_ERROR;
}

static CK_RV ecc_add_missing_attrs(attr_list **public_attrs, attr_list **private_attrs) {

    CK_RV rv = CKR_HOST_MEMORY;

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(*public_attrs, CKA_EC_PARAMS);
    if (!a) {
        LOGE("CKA_EC_PARAMS missing");
        return CKR_GENERAL_ERROR;
    }

    attr_list *new_pub_attrs = attr_list_new();
    if (!new_pub_attrs) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    attr_list *new_priv_attrs = attr_list_new();
    if (!new_priv_attrs) {
        attr_list_free(new_pub_attrs);
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    bool r = attr_list_add_buf(new_pub_attrs, CKA_EC_PARAMS,
            a->pValue, a->ulValueLen);
    goto_error_false(r);

    rv = ecc_gen_mechs(new_pub_attrs, new_priv_attrs);
    if (rv != CKR_OK) {
        goto error;
    }

    /* clients behave better when EC_PRIVATE objects have CKA_EC_PARAMS */
    a = attr_get_attribute_by_type(*public_attrs, CKA_EC_PARAMS);
    if (!a) {
        LOGE("Expected object to have CKA_EC_PARAMS");
        goto error;
    }

    r = attr_list_add_buf(new_priv_attrs, CKA_EC_PARAMS, a->pValue, a->ulValueLen);
    goto_error_false(r);


    r = attr_list_add_int(new_pub_attrs, CKA_KEY_TYPE, CKK_EC);
    goto_error_false(r);

    r = attr_list_add_int(new_priv_attrs, CKA_KEY_TYPE, CKK_EC);
    goto_error_false(r);

    *private_attrs = attr_list_append_attrs(*private_attrs, &new_priv_attrs);
    goto_error_false(*private_attrs);

    *public_attrs = attr_list_append_attrs(*public_attrs, &new_pub_attrs);
    goto_error_false(*public_attrs);

    rv = attr_common_add_EC_privatekey(private_attrs);
    if (rv != CKR_OK) {
        goto error;
    }

    return attr_common_add_EC_publickey(public_attrs);

error:
    attr_list_free(new_priv_attrs);
    attr_list_free(new_pub_attrs);

    return rv;
}

static CK_RV attr_conditional_add(
        attr_list *search_attrs,            /* look in this list */
        CK_ULONG conds[], size_t conds_len, /* if not set add them */
        attr_list *ext_attrs,               /* from this list of attributes */
        attr_list **filtered_attrs) {       /* and return them to me */

    assert(filtered_attrs);

    attr_handler2 *h;

    attr_list *d = attr_list_new();
    if (!d) {
        return CKR_HOST_MEMORY;
    }

    bool r;
    CK_ULONG c;
    /* for each of the new attrs ADD TO PRIVATE */
    for (c = 0; c < ext_attrs->count; c++) {
        /* current extra attribute we're examining */
        CK_ATTRIBUTE_PTR cur = &ext_attrs->attrs[c];
        /* actual filtered list to save it to, shallow copy ok */
        CK_ULONG i;
        /* is it a conditional attr */
        for (i = 0; i < conds_len; i++) {
            /* yes it's conditional */
            if (cur->type == conds[i]) {
                /*
                 * is it in the externally supplied attribute present in the user specified
                 * template
                 */
                CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(search_attrs,
                        cur->type);
                if (!a) {
                    /*
                     * we just treat it like a regular attribute to add so break out of the inner loop
                     */
                    goto add_item;
                } else if (a->ulValueLen != cur->ulValueLen
                        || memcmp(a->pValue, cur->pValue, cur->ulValueLen)) {
                    /* yes - better match */
                    LOGE("User specified and TPM specified attr mismatch: 0x%lx",
                            cur->type);
                    attr_list_free(d);
                    return CKR_GENERAL_ERROR;
                }
                break;
            }
        }
        /* not conditional and specified, skip */
        if (i != conds_len) {
            continue;
        }
add_item:
        /* no - add it, shallow copy ok */
        h = attr_lookup(cur->type);
        assert(h);
        r = add_type_copy(cur, h->memtype, d);
        if (!r) {
            attr_list_free(d);
            return CKR_GENERAL_ERROR;
        }
    }

    if (!d->count) {
        attr_list_free(d);
        *filtered_attrs = NULL;
    } else {
        *filtered_attrs = d;
    }

    return CKR_OK;
}

CK_RV attr_add_missing_attrs(attr_list **public_attrs, attr_list **private_attrs,
        attr_list *ext_attrs, CK_MECHANISM_TYPE mech) {

    switch (mech) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        break;
    case CKM_EC_KEY_PAIR_GEN:
        break;
    default:
        LOGE("Unsupported keygen mechanism: 0x%lx", mech);
        return CKR_MECHANISM_INVALID;
    }

    CK_RV rv = CKR_GENERAL_ERROR;

    attr_list *filtered_pub_attrs = NULL;
    attr_list *filtered_priv_attrs = NULL;

    bool r = attr_list_add_int(*public_attrs, CKA_KEY_GEN_MECHANISM, mech);
    goto_error_false(r);

    r = attr_list_add_int(*private_attrs, CKA_KEY_GEN_MECHANISM, mech);
    goto_error_false(r);

    /*
     * We can't just blindly add the extra attributes, as we don't want the tpm specifying
     * attributes already in the template.
     *
     * Conditionally add them for public and private
     */
    /* add only if not set, sanity check that values match */
    CK_ULONG conds[] = {
        CKA_DECRYPT,
        CKA_VERIFY,
        CKA_SIGN,
        CKA_ENCRYPT,
    };

    rv = attr_conditional_add(
            *private_attrs,
            conds, ARRAY_LEN(conds),
            ext_attrs,
            &filtered_priv_attrs);
    if (rv != CKR_OK) {
        goto error;
    }

    rv = attr_conditional_add(
            *public_attrs,
            conds, ARRAY_LEN(conds),
            ext_attrs,
            &filtered_pub_attrs);
    if (rv != CKR_OK) {
        goto error;
    }

    *private_attrs = attr_list_append_attrs(*private_attrs,
            &filtered_priv_attrs);
    goto_error_false(*private_attrs);

    *public_attrs = attr_list_append_attrs(*public_attrs,
            &filtered_pub_attrs);
    goto_error_false(*public_attrs);

    /* key type specific stuff */
    switch (mech) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        return rsa_add_missing_attrs(public_attrs, private_attrs);
        break;
    case CKM_EC_KEY_PAIR_GEN:
        return ecc_add_missing_attrs(public_attrs, private_attrs);
    }

    assert(0);
    LOGE("barn fire");
    return CKR_GENERAL_ERROR;

error:
    attr_list_free(filtered_priv_attrs);
    attr_list_free(filtered_pub_attrs);

    return rv;
}

CK_RV attr_list_update_entry(attr_list *attrs, CK_ATTRIBUTE_PTR untrusted_attr) {
    assert(attrs);
    assert(untrusted_attr);

    CK_ATTRIBUTE_TYPE t = untrusted_attr->type;

    attr_handler2 *handler = attr_lookup(t);

    CK_ATTRIBUTE_PTR found = attr_get_attribute_by_type(attrs, t);

    /* the existing type memory should match the expected type memory */
    CK_BYTE expected_memory_type = type_from_ptr(found->pValue,
            found->ulValueLen);

    /* internal state check */
    if (expected_memory_type != handler->memtype) {
        LOGE("expected memory(%u-%s) != handler memory(%u-%s)",
            expected_memory_type, type_to_str(expected_memory_type),
            handler->memtype, type_to_str(handler->memtype));
        return CKR_GENERAL_ERROR;
    }

    /* validate sizes */
    void *pValue = untrusted_attr->pValue;
    CK_ULONG ulValueLen = untrusted_attr->ulValueLen;

    switch (handler->memtype) {
    case TYPE_BYTE_INT:
        if (ulValueLen != sizeof(CK_ULONG)) {
            LOGE("ulValueLen(%lu) != sizeof(CK_ULONG)", ulValueLen);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
    case TYPE_BYTE_BOOL:
        if (ulValueLen != sizeof(CK_BBOOL)) {
            LOGE("ulValueLen(%lu) != sizeof(CK_BBOOL)", ulValueLen);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
    case TYPE_BYTE_INT_SEQ:
        if (ulValueLen % sizeof(CK_ULONG)) {
            LOGE("ulValueLen(%lu) %% sizeof(CK_ULONG)",
                    ulValueLen % sizeof(CK_ULONG));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
    case TYPE_BYTE_HEX_STR:
        /* nothing to do */
        break;
    default:
        LOGE("Unknown data type representation, got: %u",
                handler->memtype);
        return CKR_GENERAL_ERROR;
    }

    if (ulValueLen != found->ulValueLen) {
        void *new_pValue = type_zrealloc(found->pValue, ulValueLen, handler->memtype);
        if (!new_pValue) {
            LOGE("oom");
            return CKR_HOST_MEMORY;
        }
        /* update the found node with the new resized memory */
        found->ulValueLen = ulValueLen;
        found->pValue = new_pValue;
    }

    /* update the contents of memory with what was provided */
    memcpy(found->pValue, pValue, ulValueLen);

    return CKR_OK;
}

CK_RV attr_list_append_entry(attr_list **attrs, CK_ATTRIBUTE_PTR untrusted_attr) {
    assert(attrs);
    assert(*attrs);
    assert(untrusted_attr);

    attr_list *new_item = NULL;
    bool res = attr_typify(untrusted_attr, 1, &new_item);
    if (!res) {
        LOGE("Could not typify attr: %lu", untrusted_attr->type);
        return CKR_GENERAL_ERROR;
    }

    attr_list *x = attr_list_append_attrs(
            *attrs,
            &new_item);
    if (!x) {
        return CKR_GENERAL_ERROR;
    }

    *attrs = x;

    return CKR_OK;
}

#define UTILS_GENERIC_ATTR_TYPE_CONVERT(T) \
    CK_RV attr_##T(CK_ATTRIBUTE_PTR attr, T *x) { \
      assert(attr); \
      assert(x); \
    \
        if (attr->ulValueLen != sizeof(*x)) { \
            return CKR_ATTRIBUTE_VALUE_INVALID; \
        } \
    \
        *x = *(T *)attr->pValue; \
    \
        return CKR_OK; \
    }

UTILS_GENERIC_ATTR_TYPE_CONVERT(CK_ULONG);
UTILS_GENERIC_ATTR_TYPE_CONVERT(CK_BBOOL);
UTILS_GENERIC_ATTR_TYPE_CONVERT(CK_OBJECT_CLASS);
UTILS_GENERIC_ATTR_TYPE_CONVERT(CK_KEY_TYPE);
