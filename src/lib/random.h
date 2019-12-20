/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_RANDOM_H_
#define SRC_PKCS11_RANDOM_H_

#include "pkcs11.h"
#include "session_ctx.h"

typedef struct token token;
typedef struct session_ctx session_ctx;

CK_RV random_get(session_ctx *ctx, unsigned char *random_data, unsigned long random_len);

CK_RV seed_random(session_ctx *ctx, unsigned char *seed, unsigned long seed_len);

#endif /* SRC_PKCS11_RANDOM_H_ */
