/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_LIB_ENCRYPT_H_
#define SRC_LIB_ENCRYPT_H_

#include "pkcs11.h"

CK_RV encrypt_init (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV encrypt_update (CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len);

CK_RV encrypt_final (CK_SESSION_HANDLE session, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len);

CK_RV decrypt_init (CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV decrypt_update (CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len);

CK_RV decrypt_final (CK_SESSION_HANDLE session, unsigned char *last_part, unsigned long *last_part_len);

#endif /* SRC_LIB_ENCRYPT_H_ */
