/* SPDX-License-Identifier: BSD-2-Clause */

#include <openssl/evp.h>

#include "attrs.h"
#include "object.h"
#include "pkcs11.h"
#include "tpm.h"

#ifndef SRC_LIB_MECH_H_
#define SRC_LIB_MECH_H_

/**
 * Validate that a mechanism is supported by the object/tpm.
 *
 * @param ctx
 *  A context to the tpm.
 * @param mech
 *  The mechanism parameter the application is requesting.
 * @param attrs
 *  The attributes list / template of the object being used for the operation.
 * @return
 */
CK_RV mech_validate(tpm_ctx *ctx, CK_MECHANISM_PTR mech, attr_list *attrs);

CK_RV mech_synthesize(tpm_ctx *tctx,
        CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);

CK_RV mech_is_synthetic(tpm_ctx *tctx, CK_MECHANISM_PTR mech,
        bool *is_synthetic);

CK_RV mech_get_supported(tpm_ctx *tctx, CK_MECHANISM_TYPE_PTR mechlist, CK_ULONG_PTR count);

CK_RV mech_is_hashing_needed(CK_MECHANISM_PTR mech,
        bool *is_hashing_needed);

CK_RV mech_get_digest_alg(CK_MECHANISM_PTR mech,
        CK_MECHANISM_TYPE *mech_type);

CK_RV mech_get_digester(CK_MECHANISM_PTR mech,
        const EVP_MD **md);

CK_RV mech_get_tpm_opdata(tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);

CK_RV mech_get_info(tpm_ctx *tctx, CK_MECHANISM_TYPE mech_type, CK_MECHANISM_INFO_PTR info);

CK_RV mech_get_padding(CK_MECHANISM_PTR mech, int *padding);

#endif /* SRC_LIB_MECH_H_ */
