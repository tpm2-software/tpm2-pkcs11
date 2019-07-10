/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_LIB_ENCRYPT_H_
#define SRC_LIB_ENCRYPT_H_

#include <stdlib.h>

#include "pkcs11.h"
#include "tpm.h"

typedef struct encryptdecryptdata {
    CK_OBJECT_HANDLE key;
    CK_MECHANISM_TYPE mtype;
    union {
        oaepparams oaep;
    };
    uint8_t plain[1024];
    size_t plain_size;
    uint8_t cipher[1024];
    size_t cipher_size;
} encryptdecryptdata;

typedef struct token token;

typedef struct encrypt_op_data encrypt_op_data;
struct encrypt_op_data {
    tobject *tobj;
    tpm_encrypt_data *tpm_enc_data;
};

encrypt_op_data *encrypt_op_data_new(void);
void encrypt_op_data_free(encrypt_op_data **opdata);

CK_RV encrypt_init(CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV encrypt_update(CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len);

CK_RV encrypt_final(CK_SESSION_HANDLE session, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len);

CK_RV decrypt_init(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key);

CK_RV decrypt_update (CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_part, CK_ULONG encrypted_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len);

CK_RV decrypt_final(CK_SESSION_HANDLE session, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len);


CK_RV decrypt_oneshot(CK_SESSION_HANDLE session, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len);

CK_RV encrypt_oneshot(CK_SESSION_HANDLE session, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len);

#endif /* SRC_LIB_ENCRYPT_H_ */
