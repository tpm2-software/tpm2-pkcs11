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

typedef struct token token;

typedef struct encrypt_op_data encrypt_op_data;
struct encrypt_op_data {
    tpm_encrypt_data *tpm_enc_data;
};

encrypt_op_data *encrypt_op_data_new(void);
void encrypt_op_data_free(encrypt_op_data **opdata);

CK_RV encrypt_init_op (token *tok, encrypt_op_data *supplied_opdata, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);
static inline CK_RV encrypt_init(token *tok, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    return encrypt_init_op(tok, NULL, mechanism, key);
}

CK_RV encrypt_update_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len);
static inline CK_RV encrypt_update (token *tok, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {
    return encrypt_update_op (tok, NULL, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV encrypt_final_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len);
static inline CK_RV encrypt_final (token *tok, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len) {
    return encrypt_final_op (tok, NULL, last_encrypted_part, last_encrypted_part_len);
}

CK_RV decrypt_init_op (token *tok, encrypt_op_data *supplied_opdata, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);
static inline CK_RV decrypt_init (token *tok, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    return decrypt_init_op (tok, NULL, mechanism, key);
}

CK_RV decrypt_update_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len);
static inline CK_RV decrypt_update (token *tok, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {
        return decrypt_update_op (tok, NULL, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV decrypt_final_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *last_part, unsigned long *last_part_len);
static inline CK_RV decrypt_final (token *tok,  unsigned char *last_part, unsigned long *last_part_len) {
    return decrypt_final_op (tok, NULL, last_part, last_part_len);
}

CK_RV decrypt_oneshot_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len);
static inline CK_RV decrypt_oneshot (token *tok, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len) {
    return decrypt_oneshot_op (tok, NULL, encrypted_data, encrypted_data_len, data, data_len);
}

CK_RV encrypt_oneshot_op (token *tok, encrypt_op_data *supplied_opdata, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len);
static inline CK_RV encrypt_oneshot (token *tok, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len) {
    return encrypt_oneshot_op (tok, NULL, data, data_len, encrypted_data, encrypted_data_len);
}

#endif /* SRC_LIB_ENCRYPT_H_ */
