/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_KEY_H_
#define SRC_PKCS11_KEY_H_

#include "pkcs11.h"

typedef struct token token;
typedef struct session_ctx session_ctx;

CK_RV key_gen (
        session_ctx *ctx,

        CK_MECHANISM_PTR mechanism,

        CK_ATTRIBUTE_PTR public_key_template,
        CK_ULONG public_key_attribute_count,

        CK_ATTRIBUTE_PTR private_key_template,
        CK_ULONG private_key_attribute_count,

        CK_OBJECT_HANDLE_PTR public_key,
        CK_OBJECT_HANDLE_PTR private_key);

#endif /* SRC_PKCS11_KEY_H_ */
