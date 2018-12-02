/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_LIB_ENCRYPT_H_
#define SRC_LIB_ENCRYPT_H_

#include "pkcs11.h"

typedef struct token token;

CK_RV encrypt_init (token *tok, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV encrypt_update (token *tok, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len);

CK_RV encrypt_final (token *tok, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len);

CK_RV decrypt_init (token *tok, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV decrypt_update (token *tok, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len);

CK_RV decrypt_final (token *tok, unsigned char *last_part, unsigned long *last_part_len);

CK_RV decrypt_oneshot (token *tok, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len);

CK_RV encrypt_oneshot (token *tok, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len);

#endif /* SRC_LIB_ENCRYPT_H_ */
