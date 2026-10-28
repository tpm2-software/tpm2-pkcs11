/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_KEY_H_
#define SRC_PKCS11_KEY_H_

#include <stdbool.h>

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

/**
 * C_GenerateKey: an AES key (CKM_AES_KEY_GEN) made by the TPM, under the token's primary key. It is a
 * token object unless the template has CKA_TOKEN=false, as key pairs are.
 */
CK_RV key_gen_secret(
        session_ctx *ctx,

        CK_MECHANISM_PTR mechanism,

        CK_ATTRIBUTE_PTR template,
        CK_ULONG attribute_count,

        CK_OBJECT_HANDLE_PTR key);

/**
 * True for the secret key types kept in the TPM: AES, generic secrets and HMAC keys.
 */
bool key_is_tpm_secret(CK_KEY_TYPE type);

/**
 * The checks key_import_secret() makes of a secret key's template that don't depend on its value: the
 * usage attributes the key type can have, CKA_SENSITIVE and CKA_EXTRACTABLE. The template has no
 * CKA_VALUE yet.
 * @return
 *  CKR_OK, or what key_import_secret() would give for the template.
 */
CK_RV key_check_secret_template(CK_KEY_TYPE key_type, CK_ATTRIBUTE_PTR templ, CK_ULONG count);

/**
 * C_CreateObject of a secret key with its CKA_VALUE: an AES key (16, 24 or 32 bytes), or an HMAC key
 * (CKK_GENERIC_SECRET or a CKK_SHA*_HMAC type, up to 128 bytes, the most the TPM holds), made in the
 * TPM with that value. The value is never stored outside the TPM.
 */
CK_RV key_import_secret(session_ctx *ctx, CK_KEY_TYPE key_type,
        CK_ATTRIBUTE_PTR template, CK_ULONG attribute_count, CK_OBJECT_HANDLE_PTR key);

#endif /* SRC_PKCS11_KEY_H_ */
