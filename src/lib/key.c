/* SPDX-License-Identifier: BSD-2 */
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

CK_RV key_gen (token *tok, CK_MECHANISM *mechanism,
        CK_ATTRIBUTE *public_key_template, CK_ULONG public_key_attribute_count, CK_ATTRIBUTE *private_key_template,
        CK_ULONG private_key_attribute_count, CK_OBJECT_HANDLE *public_key, CK_OBJECT_HANDLE *private_key) {

    // TODO use me
    UNUSED(tok);

    UNUSED(mechanism);

    UNUSED(public_key);
    UNUSED(public_key_template);
    UNUSED(public_key_attribute_count);

    UNUSED(private_key);
    UNUSED(private_key_template);
    UNUSED(private_key_attribute_count);

    return CKR_FUNCTION_NOT_SUPPORTED;
}
