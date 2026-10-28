/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_LIB_WRAP_H_
#define SRC_LIB_WRAP_H_

#include <stdbool.h>

#include "attrs.h"
#include "pkcs11.h"

typedef struct session_ctx session_ctx;

/* The boolean attribute type of a key, CK_FALSE when it has none */
CK_BBOOL key_attr_bool(attr_list *attrs, CK_ATTRIBUTE_TYPE type);

/*
 * Whether a key has a template attribute (CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE,
 * CKA_ENCAPSULATE_TEMPLATE, CKA_DECAPSULATE_TEMPLATE) other than the empty one every key gets. Matching
 * or merging one (PKCS#11 4.10) isn't supported: the store can't keep the nested attributes, which are
 * only the application's pointers, so a key having one is refused rather than its template ignored. Only
 * the attribute's length is read.
 */
bool key_has_template(attr_list *attrs, CK_ATTRIBUTE_TYPE type);

/**
 * Wraps a key (C_WrapKey): encrypts the value of a secret key held on the host with the wrapping key,
 * using CKM_RSA_PKCS_OAEP (an RSA public key, in software) or CKM_AES_CBC_PAD (an AES key, in the TPM).
 * The wrapping key needs CKA_WRAP=true, and the key CKA_EXTRACTABLE=true; a sensitive key may be wrapped.
 * No session operation is started. Uses the PKCS#11 5.2 convention for the output, the length being
 * known without the TPM.
 * @param ctx
 *  The session.
 * @param mech
 *  The wrapping mechanism.
 * @param wrapping_key
 *  The key to wrap with.
 * @param key
 *  The key to wrap.
 * @param wrapped
 *  The wrapped key, or NULL to ask for its length.
 * @param wrapped_len
 *  The size of wrapped; set to the length of the wrapped key.
 * @return
 *  CKR_OK on success.
 *  CKR_MECHANISM_INVALID for any other mechanism, CKR_MECHANISM_PARAM_INVALID for a bad parameter.
 *  CKR_WRAPPING_KEY_HANDLE_INVALID or CKR_KEY_HANDLE_INVALID for a handle that isn't an object.
 *  CKR_WRAPPING_KEY_TYPE_INCONSISTENT when the wrapping key isn't the mechanism's.
 *  CKR_KEY_FUNCTION_NOT_PERMITTED when the wrapping key's CKA_WRAP isn't true.
 *  CKR_KEY_HANDLE_INVALID when the wrapping key has a CKA_WRAP_TEMPLATE, which isn't supported, or the
 *  key isn't a key.
 *  CKR_KEY_NOT_WRAPPABLE for a private or public key, or any key with CKA_WRAP_WITH_TRUSTED=true: no
 *  wrapping key is believed trusted, as only the SO may set CKA_TRUSTED and no SO session makes objects.
 *  CKR_KEY_UNEXTRACTABLE when the key's CKA_EXTRACTABLE isn't true, or its value is in the TPM.
 *  CKR_KEY_SIZE_RANGE when the key is too long for an OAEP message.
 *  CKR_BUFFER_TOO_SMALL with the length in wrapped_len.
 */
CK_RV key_wrap(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped, CK_ULONG_PTR wrapped_len);

/**
 * Unwraps a key (C_UnwrapKey): key_unwrap_as() for CKM_RSA_PKCS_OAEP and CKM_AES_CBC_PAD, with the
 * unwrapping key's CKA_UNWRAP.
 */
CK_RV key_unwrap(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE unwrapping_key,
        CK_BYTE_PTR wrapped, CK_ULONG wrapped_len, CK_ATTRIBUTE_PTR templ, CK_ULONG count,
        CK_OBJECT_HANDLE_PTR key);

/**
 * Decrypts a wrapped secret in the TPM with the unwrapping key, an RSA private key (CKM_RSA_PKCS_OAEP,
 * and for a caller that allows them CKM_RSA_PKCS and CKM_RSA_X_509) or an AES key (CKM_AES_CBC_PAD), and
 * makes a secret key of it with key_create_from_value(). No session operation is started, and nothing is
 * made when it fails. The caller checks the mechanism is one for its function.
 * @param usage
 *  The attribute the unwrapping key needs true: CKA_UNWRAP (C_UnwrapKey), CKA_DECAPSULATE
 *  (C_DecapsulateKey). Its template attribute (CKA_UNWRAP_TEMPLATE, CKA_DECAPSULATE_TEMPLATE) isn't
 *  supported: a key that has one is refused.
 * @return
 *  CKR_OK on success.
 *  CKR_UNWRAPPING_KEY_HANDLE_INVALID, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT for the unwrapping key.
 *  CKR_KEY_FUNCTION_NOT_PERMITTED when its usage attribute isn't true.
 *  CKR_TEMPLATE_INCONSISTENT when it has a template attribute.
 *  What key_create_from_value() gives for the template, checked before the TPM decrypts.
 *  CKR_WRAPPED_KEY_LEN_RANGE when the wrapped key isn't the mechanism's length (k, whole blocks).
 *  CKR_WRAPPED_KEY_INVALID for any failure once the TPM decrypts: bad OAEP or CBC padding, or a value
 *  that isn't the length the template's CKA_VALUE_LEN or key type says. One code, so the caller can't
 *  tell good padding from bad.
 *  What key_create_from_value() gives.
 */
CK_RV key_unwrap_as(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE unwrapping_key,
        CK_ATTRIBUTE_TYPE usage, CK_BYTE_PTR wrapped, CK_ULONG wrapped_len, CK_ATTRIBUTE_PTR templ,
        CK_ULONG count, CK_OBJECT_HANDLE_PTR key);

/**
 * The checks on a new key's template that don't depend on its value, which key_create_from_value()
 * makes too, so a caller makes them before the TPM is asked for anything: what the token sets, a
 * CKA_VALUE, the class and key type, and the extractable-default rule.
 * @param key_type
 *  Set to the template's key type: CKK_AES, CKK_GENERIC_SECRET or an HMAC key type.
 * @param extractable
 *  Set to CKA_EXTRACTABLE as the extractable-default rule has it.
 * @param has_extractable
 *  Set to whether the template gives CKA_EXTRACTABLE.
 * @return
 *  CKR_OK, or what key_create_from_value() gives for the template.
 */
CK_RV key_check_new_template(CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_KEY_TYPE *key_type,
        CK_BBOOL *extractable, bool *has_extractable);

/**
 * Makes a secret key holding value, from a template for C_UnwrapKey or the key encapsulation functions,
 * through object_create(): an AES or HMAC key goes into the TPM, a generic secret readable as the
 * template has it stays a plain object. The new key's CKA_LOCAL, CKA_ALWAYS_SENSITIVE and
 * CKA_NEVER_EXTRACTABLE are false. CKA_EXTRACTABLE defaults to false for an AES or HMAC key, which can't be
 * extractable in the TPM, and to true (PKCS#11's default) for a generic secret.
 * @param ctx
 *  The session.
 * @param templ
 *  The template, which can't have CKA_VALUE nor what the token sets (CKA_UNIQUE_ID, CKA_LOCAL=true, ...).
 * @param count
 *  The number of attributes in templ.
 * @param value
 *  The key's value.
 * @param value_len
 *  Its length.
 * @param key
 *  The new key's handle, on success.
 * @return
 *  CKR_OK on success.
 *  CKR_TEMPLATE_INCOMPLETE without CKA_CLASS or CKA_KEY_TYPE.
 *  CKR_TEMPLATE_INCONSISTENT for a class other than CKO_SECRET_KEY, a CKA_VALUE, or an AES or HMAC key
 *  with CKA_EXTRACTABLE=true.
 *  CKR_ATTRIBUTE_VALUE_INVALID for a key type other than AES, HMAC and generic secret.
 *  CKR_ATTRIBUTE_READ_ONLY for what the token sets, and CKA_TRUSTED=true, which only the SO may set.
 *  What object_create() gives.
 */
CK_RV key_create_from_value(session_ctx *ctx, CK_ATTRIBUTE_PTR templ, CK_ULONG count,
        const CK_BYTE *value, CK_ULONG value_len, CK_OBJECT_HANDLE_PTR key);

/**
 * C_WrapKeyAuthenticated (S32 5.18.6): the only mechanisms defined for it are AES-GCM and AES-CCM
 * (6.13.3, 6.13.5), which the token doesn't have, so every mechanism is CKR_MECHANISM_INVALID.
 * @return
 *  CKR_ARGUMENTS_BAD for a NULL mechanism or wrapped_len, CKR_MECHANISM_INVALID otherwise.
 */
CK_RV key_wrap_authenticated(session_ctx *ctx, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key, CK_BYTE_PTR associated_data, CK_ULONG associated_data_len,
        CK_BYTE_PTR wrapped, CK_ULONG_PTR wrapped_len);

/**
 * C_UnwrapKeyAuthenticated (S32 5.18.7): as key_wrap_authenticated(), and no key is made.
 * @return
 *  CKR_ARGUMENTS_BAD for a NULL mechanism or key, CKR_MECHANISM_INVALID otherwise.
 */
CK_RV key_unwrap_authenticated(session_ctx *ctx, CK_MECHANISM_PTR mech,
        CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped, CK_ULONG wrapped_len,
        CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_BYTE_PTR associated_data,
        CK_ULONG associated_data_len, CK_OBJECT_HANDLE_PTR key);

#endif /* SRC_LIB_WRAP_H_ */
