/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef _SRC_LIB_DERIVE_H_
#define _SRC_LIB_DERIVE_H_

#include "pkcs11.h"
#include "session_ctx.h"

CK_RV derive(session_ctx *ctx,
	     CK_MECHANISM *mechanism,
	     CK_OBJECT_HANDLE tpm_key,
	     CK_ATTRIBUTE_PTR secret_template,
	     CK_ULONG secret_template_count,
	     CK_OBJECT_HANDLE_PTR secret);

/*
 * The CK_ECDH1_DERIVE_PARAMS of a CKM_ECDH1_DERIVE mechanism, whose KDF is the only one supported,
 * CKD_NULL: the secret is Z. CKR_MECHANISM_PARAM_INVALID otherwise.
 */
CK_RV ecdh1_params_get(CK_MECHANISM_PTR mechanism, CK_ECDH1_DERIVE_PARAMS_PTR *params);

#endif
