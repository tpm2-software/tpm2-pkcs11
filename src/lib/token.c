/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "attrs.h"
#include "backend.h"
#include "checks.h"
#include "list.h"
#include "mech.h"
#include "object.h"
#include "pkcs11.h"
#include "session.h"
#include "session_table.h"
#include "slot.h"
#include "token.h"
#include "utils.h"

static const CK_UTF8CHAR TPM2_TOKEN_SERIAL_NUMBER[] = "0000000000000000";

void pobject_config_free(pobject_config *c) {

    if (c->is_transient) {
        free(c->template_name);
    } else {
        twist_free(c->blob);
    }

    memset(c, 0, sizeof(*c));
}

DEBUG_VISIBILITY void pobject_free(pobject *pobj) {

    twist_free(pobj->objauth);

    pobject_config_free(&pobj->config);

    memset(pobj, 0, sizeof(*pobj));
}

WEAK CK_RV token_min_init(token *t) {

    /*
     * Initialize the per-token session table
     */
    CK_RV rv = session_table_new(&t->s_table);
    if (rv != CKR_OK) {
        LOGE("Could not initialize session table");
        return rv;
    }

    /*
     * Initialize the per-token tpm context
     */
    rv = backend_ctx_new(t);
    if (rv != CKR_OK) {
        LOGE("Could not initialize tpm ctx: 0x%lx", rv);
        return rv;
    }

    /*
     * Initialize the per-token mechanism details table
     */
    rv = mdetail_new(t->tctx, &t->mdtl, t->config.pss_sigs_good);
    if (rv != CKR_OK) {
        LOGE("Could not initialize tpm mdetails: 0x%lx", rv);
        return rv;
    }

    rv = mutex_create(&t->mutex);
    if (rv != CKR_OK) {
        LOGE("Could not initialize mutex: 0x%lx", rv);
    }

    return rv;
}

void token_reset(token *t) {

    /* forget the primary object so it can be reinitialized as needed */
    pobject_free(&t->pobject);

    backend_ctx_reset(t);
    /*
     * the rest of the state can live so we don't need to free/realloc it
     * Beware of who holds the mutex!
     */
}

void token_free_list(token **tok_ptr, size_t *ptr_len) {

    size_t len = *ptr_len;
    token *t = *tok_ptr;
    *tok_ptr = NULL;
    *ptr_len = 0;
    if (!t) {
        return;
    }

    size_t i;
    for (i=0; i < len; i++) {
        token_free(&t[i]);
    }
    memset(t, 0, sizeof(*t) * len);
    free(t);
}

WEAK CK_RV token_add_tobject_last(token *tok, tobject *t) {

    if (!tok->tobjects.tail) {
        t->l.prev = t->l.next = NULL;
        tok->tobjects.tail = tok->tobjects.head = t;
        t->obj_handle = 1;
        return CKR_OK;
    }

    CK_OBJECT_HANDLE handle = tok->tobjects.tail->obj_handle;
    if (handle == ~((CK_OBJECT_HANDLE)0)) {
        LOGE("Too many objects for token, id: %u, label: %*s", tok->id,
                (int)sizeof(tok->label), tok->label);
        return CKR_OK;
    }

    handle++;
    t->obj_handle = handle;
    tok->tobjects.tail->l.next = &t->l;
    t->l.prev = &tok->tobjects.tail->l;
    tok->tobjects.tail = t;
    return CKR_OK;
}

CK_RV token_add_tobject(token *tok, tobject *t) {

    if (!tok->tobjects.head) {
        t->l.prev = t->l.next = NULL;
        tok->tobjects.tail = tok->tobjects.head = t;
        t->obj_handle = 1;
        return CKR_OK;
    }

    /* minimum potential handle to add */
    CK_OBJECT_HANDLE index = 2;

    list *cur = &tok->tobjects.head->l;
    while(cur) {

        if (index == 0) {
            LOGE("Rollover, too many objects for token, id: %u, label: %*s", tok->id,
                    (int)sizeof(tok->label), tok->label);
            return CKR_OK;
        }

        tobject *c = list_entry(cur, tobject, l);

        /* end of list, just add it updating the tail pointer */
        if (!c->l.next) {
            t->obj_handle = index;
            t->l.prev = cur;
            cur->next = &t->l;
            tok->tobjects.tail = t;
            return CKR_OK;
        }

        tobject *n = list_entry(c->l.next, tobject, l);

        /* gap */
        if (n->obj_handle - c->obj_handle > 1) {
            assert(index < n->obj_handle && index > c->obj_handle);
            t->obj_handle = index;

            /* new object should point to next and previous */
            t->l.next = &n->l;
            t->l.prev = cur;

            /* existing object ahead should point back at new object */
            n->l.prev = &t->l;

            /* existing object behind should point forward at new object */
            c->l.next = &t->l;

            return CKR_OK;
        }

        index++;
        cur = cur->next;
    }

    LOGE("Could not insert tobject into token");

    return CKR_GENERAL_ERROR;
}

CK_RV token_find_tobject(token *tok, CK_OBJECT_HANDLE handle, tobject **tobj) {
    assert(tok);
    assert(tobj);

    if (!tok->tobjects.head) {
        return CKR_KEY_HANDLE_INVALID;
    }

    list *cur = &tok->tobjects.head->l;
    while(cur) {
        tobject *c = list_entry(cur, tobject, l);
        if (c->obj_handle == handle) {
            *tobj = c;
            return CKR_OK;
        }
        cur = cur->next;
    }

    return CKR_KEY_HANDLE_INVALID;
}

void token_rm_tobject(token *tok, tobject *t) {

    assert(tok->tobjects.head);
    assert(tok->tobjects.tail);

    /* only item in the list */
    if (t == tok->tobjects.tail &&
            t == tok->tobjects.head) {
        /* just empty the list */
        tok->tobjects.head = tok->tobjects.tail = NULL;
    } else if (t == tok->tobjects.head) {
        tok->tobjects.head = tok->tobjects.head->l.next ?
                list_entry(tok->tobjects.head->l.next, tobject, l) : NULL;
    } else if (t == tok->tobjects.tail) {
        /*
         * remove the tail by setting the tail equal to the previous list object
         * and setting the new tails next pointer to null as it's pointing to the
         * old tail location.
         */
        tok->tobjects.tail = list_entry(tok->tobjects.tail->l.prev, tobject, l);
        tok->tobjects.tail->l.next = NULL;
    } else {
        /*
         * the previous objects next pointer should point past
         * the removed object by pointing to it's next
         */
        t->l.prev->next = t->l.next;
        t->l.next->prev = t->l.prev;
    }

    t->l.next = t->l.prev = NULL;
}

void token_config_free(token_config *c) {

    if (!c) {
        return;
    }

    free(c->tcti);
    memset(c, 0, sizeof(*c));
}

void token_free(token *t) {

    /*
     * for each session remove them
     */
    session_table_free_ctx_all(t);
    session_table_free(t->s_table);
    t->s_table = NULL;

    if (t->pobject.config.is_transient) {
        tpm_flushcontext(t->tctx, t->pobject.handle);
    }

    pobject_free(&t->pobject);

    if (t->tobjects.head) {
        list *cur = &t->tobjects.head->l;
        while(cur) {
            tobject *tobj = list_entry(cur, tobject, l);
            cur = cur->next;
            tobject_free(tobj);
        }
    }
    t->tobjects.head = t->tobjects.tail = NULL;

    backend_ctx_free(t);
    t->tctx = NULL;

    mutex_destroy(t->mutex);
    t->mutex = NULL;

    token_config_free(&t->config);

    mdetail_free(&t->mdtl);
}

CK_RV token_get_info (token *t, CK_TOKEN_INFO *info) {
    check_pointer(t);
    check_pointer(info);

    int rval;
    time_t rawtime;
    struct tm tminfo;

    memset(info, 0, sizeof(*info));

    rval = tpm_get_token_info(t->tctx, info);
    if (rval != CKR_OK) {
        return CKR_GENERAL_ERROR;
    }

    // Support Flags
    info->flags = CKF_RNG;

    if (!t->config.empty_user_pin) {
        info->flags |= CKF_LOGIN_REQUIRED;
    }

    if (t->config.is_initialized) {
        info->flags |= CKF_TOKEN_INITIALIZED;
        info->flags |= CKF_USER_PIN_INITIALIZED;
    }

    // Identification
    str_padded_copy(info->label, t->label);
    str_padded_copy(info->serialNumber, TPM2_TOKEN_SERIAL_NUMBER);


    // Memory: TODO not sure what memory values should go here, the platform?
    info->ulFreePrivateMemory = ~0;
    info->ulFreePublicMemory = ~0;
    info->ulTotalPrivateMemory = ~0;
    info->ulTotalPublicMemory = ~0;

    // Maximums and Minimums
    info->ulMaxPinLen = 128;
    info->ulMinPinLen = 0;
    info->ulMaxSessionCount = MAX_NUM_OF_SESSIONS;
    info->ulMaxRwSessionCount = MAX_NUM_OF_SESSIONS;

    // Session
    session_table_get_cnt(t->s_table, &info->ulSessionCount, &info->ulRwSessionCount, NULL);

    // Time
    time (&rawtime);
    gmtime_r(&rawtime, &tminfo);
    strftime ((char *)info->utcTime, sizeof(info->utcTime), "%Y%m%d%H%M%S", &tminfo);
    // The last two bytes must be '0', not NULL/'\0' terminated.
    info->utcTime[14] = '0';
    info->utcTime[15] = '0';

    return CKR_OK;
}

CK_RV token_init(token *t, CK_BYTE_PTR pin, CK_ULONG pin_len, CK_BYTE_PTR label) {
    check_pointer(pin);
    check_pointer(label);

    CK_RV rv = CKR_GENERAL_ERROR;

    twist newauth = NULL;
    twist newsalthex = NULL;

    /*
     * validate that label doesn't have embedded NULL bytes
     */
    void *found = memchr(label, '\0', sizeof(t->label));
    if (found) {
        LOGE("Label has embedded 0 bytes");
        return CKR_ARGUMENTS_BAD;
    }

    if (t->config.is_initialized) {
        LOGE("Token already initialized");
        return CKR_ARGUMENTS_BAD;
    }

    twist sopin = twistbin_new(pin, pin_len);
    if (!sopin) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    twist hexwrappingkey = utils_get_rand_hex_str(32);
    if (!sopin) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    rv = utils_setup_new_object_auth(sopin, &newauth, &newsalthex);
    if (rv != CKR_OK) {
        goto error;
    }

    memcpy(t->label, label, sizeof(t->label));

    rv = backend_create_token_seal(t, hexwrappingkey, newauth, newsalthex);
    if (rv != CKR_OK) {
        LOGE("Could not create new token");
        goto error;
    }
    /* Ownership of newsalthex is transferred in the previous call */
    newsalthex = NULL;

    rv = slot_add_uninit_token();
    if (rv != CKR_OK) {
        LOGW("Could not add uninitialized token");
    }

    rv =  CKR_OK;
out:
    twist_free(sopin);
    twist_free(newauth);
    twist_free(newsalthex);
    twist_free(hexwrappingkey);

    return rv;

error:
    token_reset(t);
    goto out;
}

bool token_is_any_user_logged_in(token *tok) {

    return tok->login_state != token_no_one_logged_in;
}

bool token_is_user_logged_in(token *tok) {

    return tok->login_state & token_user_logged_in;
}

bool token_is_so_logged_in(token *tok) {

    return tok->login_state & token_so_logged_in;
}


void token_lock(token *t) {
    mutex_lock_fatal(t->mutex);
}

void token_unlock(token *t) {
    mutex_unlock_fatal(t->mutex);
}

CK_RV token_setpin(token *tok, CK_UTF8CHAR_PTR oldpin, CK_ULONG oldlen, CK_UTF8CHAR_PTR newpin, CK_ULONG newlen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    /* pin data */
    twist toldpin = NULL;
    twist tnewpin = NULL;

    bool is_so = token_is_so_logged_in(tok);

    toldpin = twistbin_new(oldpin, oldlen);
    if (!toldpin) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    tnewpin = twistbin_new(newpin, newlen);
    if (!tnewpin) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    /* Clear empty-user-pin if a new user PIN is being set */
    if (!is_so && newlen && tok->config.empty_user_pin) {
        tok->config.empty_user_pin = false;
        rv = backend_update_token_config(tok);
        if (rv != CKR_OK) {
            LOGE("Clearing empty user PIN state");
            goto out;
        }
    }

    rv = backend_token_changeauth(tok, !is_so, toldpin, tnewpin);
    if (rv != CKR_OK) {
        LOGE("Changing token auth");
        goto out;
    }

    if (!is_so && !newlen && !tok->config.empty_user_pin) {
        tok->config.empty_user_pin = true;
        rv = backend_update_token_config(tok);
        if (rv != CKR_OK) {
            /* Failing to set empty-user-pin is not fatal, as the PIN changed */
            LOGW("Setting empty user PIN state failed");
        }
    }

out:

    twist_free(toldpin);
    twist_free(tnewpin);

    return rv;
}

CK_RV token_initpin(token *tok, CK_UTF8CHAR_PTR newpin, CK_ULONG newlen) {

    CK_RV rv = CKR_GENERAL_ERROR;

    twist tnewpin = NULL;

    twist newkeysalthex = NULL;

    twist newsalthex = NULL;
    twist newauthhex = NULL;

    twist sealdata = NULL;

    tnewpin = twistbin_new(newpin, newlen);
    if (!tnewpin) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    /* generate a new auth */
    rv = utils_setup_new_object_auth(tnewpin, &newauthhex, &newsalthex);
    if (rv != CKR_OK) {
        goto out;
    }

    /* we store the seal data in hex form, but it's in binary form in memory, so convert it */
    sealdata = twist_hexlify(tok->wrappingkey);
    if (!sealdata) {
        LOGE("oom");
        goto out;
    }

    /* Clear empty-user-pin if a new user PIN is being set */
    if (newlen && tok->config.empty_user_pin) {
        tok->config.empty_user_pin = false;
        rv = backend_update_token_config(tok);
        if (rv != CKR_OK) {
            LOGE("Clearing empty user PIN state");
            goto out;
        }
    }

    rv = backend_init_user(tok, sealdata, newauthhex, newsalthex);
    if (rv != CKR_OK) {
        goto out;
    }

    if (!newlen && !tok->config.empty_user_pin) {
        tok->config.empty_user_pin = true;
        rv = backend_update_token_config(tok);
        if (rv != CKR_OK) {
            /* Failing to set empty-user-pin is not fatal, as the user was initialized */
            LOGW("Setting empty user PIN state failed");
        }
    }

    rv = CKR_OK;

out:

    /* If the function failed, then these pointers ARE NOT CLAIMED and must be free'd */
    if (rv != CKR_OK) {
        twist_free(newkeysalthex);
        twist_free(newsalthex);
    }

    twist_free(sealdata);
    twist_free(newauthhex);

    twist_free(tnewpin);

    return rv;
}

CK_RV token_load_object(token *tok, CK_OBJECT_HANDLE key, tobject **loaded_tobj) {
    CK_RV rv;
    tpm_ctx *tpm = tok->tctx;

    /* Unseal the wrapping key, if the user PIN is empty */
    if (!tok->wrappingkey && tok->config.empty_user_pin) {
        twist tpin = twistbin_new("", 0);
        if (!tpin) {
            return CKR_HOST_MEMORY;
        }
        rv = backend_token_unseal_wrapping_key(tok, true, tpin);
        twist_free(tpin);
        if (rv != CKR_OK) {
            LOGE("Error unsealing wrapping key");
            return rv;
        }
    }

    rv = token_find_tobject(tok, key, loaded_tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    tobject *tobj = *loaded_tobj;

    rv = tobject_user_increment(tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    /* this might not be the best place for this check */
    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_CLASS);
    if (!a) {
        LOGE("All objects expected to have CKA_CLASS, missing"
                " for tobj id: %u", tobj->id);
        return CKR_GENERAL_ERROR;
    }

    CK_OBJECT_CLASS v;
    rv = attr_CK_OBJECT_CLASS(a, &v);
    if (rv != CKR_OK) {
        return rv;
    }

    if (v != CKO_PRIVATE_KEY
            && v != CKO_PUBLIC_KEY
            && v != CKO_SECRET_KEY) {
        LOGE("Cannot use tobj id %u in a crypto operation", tobj->id);
        return CKR_KEY_HANDLE_INVALID;
    }

    /*
     * The object may already be loaded by the TPM or may just be
     * a public key object not-resident in the TPM.
     */
    if (tobj->tpm_handle || !tobj->pub) {
        *loaded_tobj = tobj;
        return CKR_OK;
    }

    rv = tpm_loadobj(
            tpm,
            tok->pobject.handle, tok->pobject.objauth,
            tobj->pub, tobj->priv,
            &tobj->tpm_handle);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = utils_ctx_unwrap_objauth(tok->wrappingkey, tobj->objauth,
            &tobj->unsealed_auth);
    if (rv != CKR_OK) {
        LOGE("Error unwrapping tertiary object auth");
        return rv;
    }

    *loaded_tobj = tobj;
    return CKR_OK;
}
