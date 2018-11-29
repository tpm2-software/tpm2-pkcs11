/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_TPM_H_
#define SRC_PKCS11_TPM_H_

#include <stdbool.h>
#include <stdint.h>

#include "object.h"
#include "twist.h"
#include "utils.h"

typedef struct tpm_ctx tpm_ctx;

/**
 * Destroys the system API context, and when the refcnt
 * hits 0 for the tcti context, destroys it as well.
 * @param ctx
 *  The tpm context
 * @note: NOT THREAD SAFE: Assumes session table lock held
 */
void tpm_ctx_free(tpm_ctx *ctx);

/**
 * Creates a new tpm_ctx with it's own ESAPI
 * and TCTI contexts internally.
 * @param tctx
 *  The tpm_ctx to create.
 * @return
 *  CJR_OK on success, anything else is a failure.
 */
CK_RV tpm_ctx_new(tpm_ctx **tctx);

/**
 * Generates random bytes from the TPM
 * @param ctx
 *  The tpm api context.
 * @param data
 *  The date to write the random bytes into.
 * @param size
 *  The number of random bytes to generate.
 * @return
 *  true on success, false otherwise.
 */
bool tpm_getrandom(tpm_ctx *ctx, uint8_t *data, size_t size);

CK_RV tpm_stirrandom(tpm_ctx *ctx, unsigned char *seed, unsigned long seed_len);

bool tpm_loadobj(tpm_ctx *ctx, uint32_t phandle, twist auth,
        twist pub_path, twist priv_path, uint32_t *handle);

bool tpm_flushcontext(tpm_ctx *ctx, uint32_t handle);

twist tpm_unseal(tpm_ctx *ctx, uint32_t handle, twist objauth);

bool tpm_sign(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen);

bool tpm_verify(tpm_ctx *ctx, tobject *tobj, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG siglen);

CK_RV tpm_hash_init(tpm_ctx *ctx, CK_MECHANISM_TYPE mode, uint32_t *sequence_handle);
CK_RV tpm_hash_update(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG data_len);
CK_RV tpm_hash_final(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG_PTR data_len);

#define CKM_AES_NULL (CKM_VENDOR_DEFINED | 0x1)

CK_RV tpm_encrypt(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mode, twist iv, twist plaintext, twist *ciphertext, twist *iv_out);

CK_RV tpm_decrypt_handle(tpm_ctx *ctx, uint32_t handle, twist objauth, CK_MECHANISM_TYPE mode, twist iv, twist ciphertext, twist *plaintext, twist *iv_out);

CK_RV tpm_decrypt(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mode, twist iv, twist ciphertext, twist *plaintext, twist *iv_out);

CK_RV tpm_rsa_decrypt(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech,
        CK_BYTE_PTR ctext, CK_ULONG ctextlen,
        CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen);

bool tpm_register_handle(tpm_ctx *ctx, uint32_t *handle);

#endif /* SRC_PKCS11_TPM_H_ */
