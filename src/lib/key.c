/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <openssl/rand.h>

#include "checks.h"
#include "db.h"
#include "key.h"
#include "pkcs11.h"
#include "session.h"
#include "session_ctx.h"
#include "utils.h"

CK_RV key_gen (CK_SESSION_HANDLE session, struct _CK_MECHANISM *mechanism,
        struct _CK_ATTRIBUTE *public_key_template, unsigned long public_key_attribute_count, struct _CK_ATTRIBUTE *private_key_template,
        unsigned long private_key_attribute_count, CK_OBJECT_HANDLE *public_key, CK_OBJECT_HANDLE *private_key) {

    check_is_init();

    CK_RV rv = CKR_GENERAL_ERROR;

    session_ctx *ctx = session_lookup(session);
    if (!ctx) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    // TODO use me
    (void) mechanism;
    (void) public_key_template;
    (void) public_key_attribute_count;
    (void) private_key_template;
    (void) private_key_attribute_count;

    //tpm_ctx *sys = session_ctx_get_tpm_ctx(ctx);

//    util_buf *so_pin = session_ctx_get_so_pin_unlocked(ctx);
//    assert(so_pin);
//
//    db_get_primary_key_auth();
//
//    bool res = tpm_genkeypair(sys, salt, NULL,
//            public_key_template, public_key_attribute_count,
//            private_key_template, private_key_attribute_count);
//    if (!res) {
//        goto unlock;
//    }

//    rv = db_insert_keypair(public_key_template, public_key_attribute_count,
//            private_key_template, private_key_attribute_count,
//            public_key, private_key);
//    if (!res) {
//        goto unlock;
//    }

    // TODO Real keygen here and set up objects.
    *public_key = 42;
    *private_key= 43;

    rv = CKR_OK;

//unlock:
    session_ctx_unlock(ctx);

    return rv;
}
