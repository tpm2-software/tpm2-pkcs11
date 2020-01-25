/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_LIB_ENCRYPT_H_
#define SRC_LIB_ENCRYPT_H_

#include <stdlib.h>

#include "pkcs11.h"
#include "tpm.h"

typedef struct token token;

typedef struct sw_encrypt_data sw_encrypt_data;
typedef struct encrypt_op_data encrypt_op_data;

typedef union crypto_op_data crypto_op_data;
union crypto_op_data{
    tpm_encrypt_data *tpm_enc_data;
    sw_encrypt_data *sw_enc_data;
};

struct encrypt_op_data {
    bool use_sw;
    CK_OBJECT_CLASS clazz;
    crypto_op_data cryptopdata;
};

encrypt_op_data *encrypt_op_data_new(tobject *tobj);
void encrypt_op_data_free(encrypt_op_data **opdata);

CK_RV encrypt_init_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);
static inline CK_RV encrypt_init(session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    return encrypt_init_op(ctx, NULL, mechanism, key);
}

CK_RV encrypt_update_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len);
static inline CK_RV encrypt_update (session_ctx *ctx, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {
    return encrypt_update_op (ctx, NULL, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV encrypt_final_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len);
static inline CK_RV encrypt_final (session_ctx *ctx, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len) {
    return encrypt_final_op (ctx, NULL, last_encrypted_part, last_encrypted_part_len);
}

CK_RV decrypt_init_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);
static inline CK_RV decrypt_init (session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    return decrypt_init_op (ctx, NULL, mechanism, key);
}

CK_RV decrypt_update_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len);
static inline CK_RV decrypt_update (session_ctx *ctx, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {
        return decrypt_update_op (ctx, NULL, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV decrypt_final_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, unsigned char *last_part, unsigned long *last_part_len);
static inline CK_RV decrypt_final (session_ctx *ctx,  unsigned char *last_part, unsigned long *last_part_len) {
    return decrypt_final_op (ctx, NULL, last_part, last_part_len);
}

CK_RV decrypt_oneshot_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len);
static inline CK_RV decrypt_oneshot (session_ctx *ctx, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len) {
    return decrypt_oneshot_op (ctx, NULL, encrypted_data, encrypted_data_len, data, data_len);
}

CK_RV encrypt_oneshot_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len);
static inline CK_RV encrypt_oneshot (session_ctx *ctx, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len) {
    return encrypt_oneshot_op (ctx, NULL, data, data_len, encrypted_data, encrypted_data_len);
}

#endif /* SRC_LIB_ENCRYPT_H_ */
