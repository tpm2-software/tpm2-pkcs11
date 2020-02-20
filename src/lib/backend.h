/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SRC_LIB_BACKEND_H_
#define SRC_LIB_BACKEND_H_

#include "pkcs11.h"
#include "twist.h"
#include "token.h"

#define MAX_TOKEN_CNT 255

CK_RV backend_init(void);
CK_RV backend_destroy(void);

CK_RV backend_create_token_seal(token *t, const twist hexwrappingkey,
                       const twist newauth, const twist newsalthex);

CK_RV backend_get_tokens(token **tok, size_t *len);

#endif /* SRC_LIB_BACKEND_H_ */
