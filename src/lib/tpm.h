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

/**
 * Perform a signing operation using the TPM.
 * @param ctx
 *  The tpm context.
 * @param tobj
 *  The tertiary object (aka key) to sign with.
 * @param mech
 *  The PKCS11 mechanism.
 * @param data
 *  The data to sign, should be digested.
 * @param datalen
 *  The length of the data.
 * @param sig
 *  The signature buffer to output the data in.
 * @param siglen
 *  The length of the signature buffer.
 * @return
 *  Any CK_RV that C_Sign() can return.
 */
CK_RV tpm_sign(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen);

/**
 * Perform a verification in the TPM.
 * @param ctx
 *  The tpm context.
 * @param tobj
 *  The tertiary object (aka key) to sign with.
 * @param mech
 *  The PKCS11 mechanism.
 * @param data
 *  The data to verify, should be digested.
 * @param datalen
 *  The length of the data.
 * @param sig
 *  The signature to verify.
 * @param siglen
 *  The length of the signature.
 * @return
 *  Any CK_RV that C_Verify() can return.
 */
CK_RV tpm_verify(tpm_ctx *ctx, tobject *tobj, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG siglen);

CK_RV tpm_hash_init(tpm_ctx *ctx, CK_MECHANISM_TYPE mode, uint32_t *sequence_handle);
CK_RV tpm_hash_update(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG data_len);
CK_RV tpm_hash_final(tpm_ctx *ctx, uint32_t sequence_handle, CK_BYTE_PTR data, CK_ULONG_PTR data_len);

typedef struct tpm_encrypt_data tpm_encrypt_data;
CK_RV tpm_encrypt_data_init(tpm_ctx *ctx, uint32_t handle, twist auth, CK_MECHANISM_PTR, tpm_encrypt_data **encdata);
void tpm_encrypt_data_free(tpm_encrypt_data *encdata);

CK_RV tpm_encrypt(tpm_encrypt_data *tpm_enc_data, CK_BYTE_PTR ptext, CK_ULONG ptextlen, CK_BYTE_PTR ctext, CK_ULONG_PTR ctextlen);

CK_RV tpm_decrypt(tpm_encrypt_data *tpm_enc_data, CK_BYTE_PTR ctext, CK_ULONG ctextlen, CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen);

bool tpm_register_handle(tpm_ctx *ctx, uint32_t *handle);

CK_RV tpm_changeauth(tpm_ctx *ctx, uint32_t parent_handle, uint32_t object_handle,
        twist oldauth, twist newauth,
        twist *newblob);

CK_RV tpm2_create_seal_obj(tpm_ctx *ctx, twist parentauth, uint32_t parent_handle, twist objauth, twist oldpubblob, twist sealdata, twist *newpubblob, twist *newprivblob, uint32_t *handle);

CK_RV tpm_sesion_start(tpm_ctx *ctx, twist auth, uint32_t handle);

CK_RV tpm_session_stop(tpm_ctx *ctx);

typedef struct tpm_object_data tpm_object_data;
struct tpm_object_data {

    uint32_t privhandle;
    uint32_t pubhandle;

    CK_MECHANISM_TYPE mechanism;
    union {
        struct {
            twist modulus;
            uint32_t exponent;
        } rsa;
        struct {
            twist ecpoint;
        } ecc;
    };

    twist pubblob;
    twist privblob;
};

void tpm_objdata_free(tpm_object_data *objdata);

CK_RV tpm2_generate_key(
        tpm_ctx *tpm,

        uint32_t parent,
        twist parentauth,

        twist newauthbin,

        CK_MECHANISM_PTR mechanism,

        CK_ULONG pubcnt,
        CK_ATTRIBUTE_PTR pubattrs,

        CK_ULONG privcnt,
        CK_ATTRIBUTE_PTR privattrs,

        tpm_object_data *objdata);

#endif /* SRC_PKCS11_TPM_H_ */
