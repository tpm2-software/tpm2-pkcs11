/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SRC_LIB_BACKEND_H_
#define SRC_LIB_BACKEND_H_

#include "pkcs11.h"
#include "twist.h"
#include "token.h"

#define MAX_TOKEN_CNT 255

CK_RV backend_init(void);
CK_RV backend_destroy(void);

CK_RV backend_ctx_new(token *t);
void backend_ctx_free(token *t);
void backend_ctx_reset(token *t);
CK_RV backend_create_token_seal(token *t, const twist hexwrappingkey,
                        const twist newauth, const twist newsalthex);

CK_RV backend_get_tokens(token **tok, size_t *len);

CK_RV backend_init_user(token *t, const twist sealdata,
                        const twist newauthhex, const twist newsalthex);

CK_RV backend_add_object(token *t, tobject *tobj);

CK_RV backend_update_token_config(token *t);

CK_RV backend_update_tobject_attrs(token *tok, tobject *tobj, attr_list *attrs);

CK_RV backend_rm_tobject(token *tok, tobject *tobj);

CK_RV backend_token_unseal_wrapping_key(token *tok, bool user, twist tpin);

CK_RV backend_token_changeauth(token *tok, bool user, twist toldpin, twist tnewpin);

#endif /* SRC_LIB_BACKEND_H_ */
