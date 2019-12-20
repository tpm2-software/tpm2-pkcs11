/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef _SRC_LIB_SIGN_H_
#define _SRC_LIB_SIGN_H_

#include "pkcs11.h"
#include "session_ctx.h"

CK_RV sign_init(session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV sign_update(session_ctx *ctx, unsigned char *part, unsigned long part_len);

CK_RV sign_final_ex(session_ctx *ctx, unsigned char *signature, unsigned long *signature_len, bool is_oneshot);

static inline CK_RV sign_final(session_ctx *ctx, unsigned char *signature, unsigned long *signature_len) {
    return sign_final_ex(ctx, signature, signature_len, false);
}

CK_RV sign(session_ctx *ctx, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len);

CK_RV verify_init(session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key);

CK_RV verify_update(session_ctx *ctx, unsigned char *part, unsigned long part_len);

CK_RV verify_final(session_ctx *ctx, unsigned char *signature, unsigned long signature_len);

CK_RV verify(session_ctx *ctx, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long signature_len);

#endif
