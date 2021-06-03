/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdbool.h>

#include <openssl/evp.h>

#include "attrs.h"
#include "object.h"
#include "pkcs11.h"
#include "token.h"
#include "tpm.h"

#ifndef SRC_LIB_MECH_H_
#define SRC_LIB_MECH_H_

typedef struct mdetail mdetail;

CK_RV mdetail_new(tpm_ctx *ctx, mdetail **mout, pss_config_state pss_sig_state);

void mdetail_free(mdetail **mdtl);

CK_RV mech_validate(mdetail *mdtl, CK_MECHANISM_PTR mech, attr_list *attrs);

CK_RV mech_synthesize(mdetail *mdtl,
        CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);

CK_RV mech_unsynthesize(
        mdetail *mdtl,
        CK_MECHANISM_PTR mech, attr_list *attrs,
        CK_BYTE_PTR inbuf, CK_ULONG inlen,
        CK_BYTE_PTR outbuf, CK_ULONG_PTR outlen);

CK_RV mech_is_synthetic(mdetail *mdtl,
        CK_MECHANISM_PTR mech,
        bool *is_synthetic);

CK_RV mech_get_supported(mdetail *mdtl,
        CK_MECHANISM_TYPE_PTR mechlist, CK_ULONG_PTR count);

CK_RV mech_is_hashing_needed(
        mdetail *mdtl,
        CK_MECHANISM_PTR mech,
        bool *is_hashing_needed);

CK_RV mech_is_hashing_knowledge_needed(mdetail *m,
    CK_MECHANISM_PTR mech,
    bool *is_hashing_knowledge_needed);

CK_RV mech_get_digest_alg(mdetail *mdtl,
        CK_MECHANISM_PTR mech,
        CK_MECHANISM_TYPE *mech_type);

CK_RV mech_get_digester(mdetail *mdtl,
        CK_MECHANISM_PTR mech,
        const EVP_MD **md);

CK_RV mech_get_tpm_opdata(mdetail *mdtl, tpm_ctx *tctx,
        CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);

CK_RV mech_get_info(mdetail *mdtl, tpm_ctx *tctx,
        CK_MECHANISM_TYPE mech_type, CK_MECHANISM_INFO_PTR info);

CK_RV mech_get_padding(mdetail *mdtl,
        CK_MECHANISM_PTR mech, int *padding);

CK_RV mech_get_label(CK_MECHANISM_PTR mech, twist *label);

void mdetail_set_pss_status(mdetail *m, bool pss_sigs_good);

CK_RV mech_is_ecc(mdetail *m, CK_MECHANISM_TYPE mech_type, bool *is_ecc);

#endif /* SRC_LIB_MECH_H_ */
