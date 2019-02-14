/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef _SRC_LIB_SIGN_H_
#define _SRC_LIB_SIGN_H_

#include "pkcs11.h"

typedef struct token token;

CK_RV sign_init(token *tok, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV sign_update(token *tok, unsigned char *part, unsigned long part_len);

CK_RV sign_final_ex(token *tok, unsigned char *signature, unsigned long *signature_len, bool is_oneshot);

static inline CK_RV sign_final(token *tok, unsigned char *signature, unsigned long *signature_len) {
    return sign_final_ex(tok, signature, signature_len, false);
}

CK_RV sign(token *tok, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len);

CK_RV verify_init(token *tok, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV verify_update(token *tok, unsigned char *part, unsigned long part_len);

CK_RV verify_final(token *tok, unsigned char *signature, unsigned long signature_len);

CK_RV verify(token *tok, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long signature_len);

#endif
