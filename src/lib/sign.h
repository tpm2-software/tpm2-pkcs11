/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef _SRC_LIB_SIGN_H_
#define _SRC_LIB_SIGN_H_

#include "pkcs11.h"

CK_RV sign_init (CK_SESSION_HANDLE session, struct _CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV sign_update (CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len);

CK_RV sign_final (CK_SESSION_HANDLE session, unsigned char *signature, unsigned long *signature_len);

CK_RV sign (CK_SESSION_HANDLE session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len);

CK_RV verify_init (CK_SESSION_HANDLE session, struct _CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV verify_update (CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len);

CK_RV verify_final (CK_SESSION_HANDLE session, unsigned char *signature, unsigned long signature_len);

CK_RV verify (CK_SESSION_HANDLE session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long signature_len);

#endif
