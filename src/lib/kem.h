/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_LIB_KEM_H_
#define SRC_LIB_KEM_H_

#include "pkcs11.h"

typedef struct session_ctx session_ctx;

/**
 * Encapsulates a key (C_EncapsulateKey) with a public key: makes a secret key and the ciphertext that
 * C_DecapsulateKey makes it again from with the private key.
 *  - CKM_RSA_PKCS_OAEP: the secret is CKA_VALUE_LEN bytes from the TPM's RNG, encrypted with the RSA
 *    public key (in software). CKM_RSA_PKCS isn't offered (see kem.c).
 *  - CKM_ECDH1_DERIVE, with no public data and CKD_NULL: an ephemeral key pair is made on the EC public
 *    key's curve (TPM2_ECDH_KeyGen), its public point is the ciphertext, and the secret is Z, truncated
 *    from its leading end to CKA_VALUE_LEN when the template has it.
 * The new key is made by key_create_from_value(). No session operation is started. Uses the PKCS#11 5.2
 * convention for the output, the length being known without the TPM; a length query makes nothing.
 * @param ctx
 *  The session.
 * @param mech
 *  The mechanism.
 * @param public_key
 *  The public key, with CKA_ENCAPSULATE=true.
 * @param templ
 *  The new key's template.
 * @param count
 *  The number of attributes in templ.
 * @param ciphertext
 *  The ciphertext, or NULL to ask for its length.
 * @param ciphertext_len
 *  The size of ciphertext; set to the length of the ciphertext.
 * @param key
 *  The new key's handle, on success with a ciphertext.
 * @return
 *  CKR_OK on success.
 *  CKR_MECHANISM_INVALID for another mechanism, CKR_MECHANISM_PARAM_INVALID for a bad parameter.
 *  CKR_KEY_HANDLE_INVALID for a handle that isn't an object.
 *  CKR_KEY_TYPE_INCONSISTENT when the key isn't the mechanism's kind of public key.
 *  CKR_KEY_FUNCTION_NOT_PERMITTED when its CKA_ENCAPSULATE isn't true.
 *  CKR_TEMPLATE_INCONSISTENT when it has a CKA_ENCAPSULATE_TEMPLATE, which isn't supported.
 *  What key_check_new_template() gives for the template.
 *  CKR_TEMPLATE_INCOMPLETE without a CKA_VALUE_LEN the mechanism needs: always for RSA, and for an AES
 *  key Z isn't the length of.
 *  CKR_ATTRIBUTE_VALUE_INVALID for a CKA_VALUE_LEN of 0, or an AES one not 16, 24 or 32.
 *  CKR_KEY_SIZE_RANGE for a CKA_VALUE_LEN longer than the mechanism makes with the key.
 *  CKR_BUFFER_TOO_SMALL with the length in ciphertext_len.
 *  What key_create_from_value() gives.
 */
CK_RV kem_encapsulate(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE public_key,
        CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_BYTE_PTR ciphertext, CK_ULONG_PTR ciphertext_len,
        CK_OBJECT_HANDLE_PTR key);

/**
 * Decapsulates a key (C_DecapsulateKey) with a private key, from what kem_encapsulate() gave.
 *  - CKM_RSA_PKCS_OAEP: key_unwrap_as() with CKA_DECAPSULATE (PKCS#11 6.1.8: "exactly equivalent to
 *    C_UnwrapKey").
 *  - CKM_ECDH1_DERIVE: the ciphertext, the ephemeral point raw or DER-encoded, is the other party's
 *    point for TPM2_ECDH_ZGen, and the secret Z as kem_encapsulate() has it.
 * No session operation is started, and nothing is made when it fails.
 * @return
 *  CKR_OK on success.
 *  CKR_MECHANISM_INVALID for another mechanism, CKR_MECHANISM_PARAM_INVALID for a bad parameter.
 *  CKR_UNWRAPPING_KEY_HANDLE_INVALID, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT for the private key.
 *  CKR_KEY_FUNCTION_NOT_PERMITTED when its CKA_DECAPSULATE isn't true.
 *  CKR_USER_NOT_LOGGED_IN when it's a CKA_ALWAYS_AUTHENTICATE key: there is no Init to log in after.
 *  CKR_TEMPLATE_INCONSISTENT when it has a CKA_DECAPSULATE_TEMPLATE, which isn't supported, or for ECDH
 *  a CKA_VALUE_LEN longer than Z.
 *  What key_check_new_template() gives for the template.
 *  CKR_WRAPPED_KEY_LEN_RANGE for a ciphertext of the wrong length.
 *  CKR_WRAPPED_KEY_INVALID for one that doesn't decrypt, or decrypts to a value the template can't
 *  take, or isn't a point on the key's curve.
 *  What key_unwrap_as() and key_create_from_value() give.
 */
CK_RV kem_decapsulate(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE private_key,
        CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_BYTE_PTR ciphertext, CK_ULONG ciphertext_len,
        CK_OBJECT_HANDLE_PTR key);

#endif /* SRC_LIB_KEM_H_ */
