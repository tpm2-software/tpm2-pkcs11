/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SRC_LIB_BACKEND_ESYSDB_H_
#define SRC_LIB_BACKEND_ESYSDB_H_

#include "pkcs11.h"
#include "twist.h"
#include "token.h"

CK_RV backend_esysdb_init(void);
CK_RV backend_esysdb_destroy(void);

CK_RV backend_esysdb_ctx_new(token *t);
void backend_esysdb_ctx_free(token *t);
void backend_esysdb_ctx_reset(token *t);

CK_RV backend_esysdb_create_token_seal(token *t, const twist hexwrappingkey,
                       const twist newauth, const twist newsalthex);

CK_RV backend_esysdb_get_tokens(token **tok, size_t *len);

CK_RV backend_esysdb_init_user(token *t, const twist sealdata,
                        const twist newauthhex, const twist newsalthex);

CK_RV backend_esysdb_add_object(token *t, tobject *tobj);

CK_RV backend_esysdb_update_token_config (token *tok);

CK_RV backend_esysdb_update_tobject_attrs(tobject *tobj, attr_list *attrs);

CK_RV backend_esysdb_rm_tobject(tobject *tobj);

CK_RV backend_esysdb_token_unseal_wrapping_key(token *tok, bool user, twist tpin);

CK_RV backend_esysdb_token_changeauth(token *tok, bool user, twist toldpin, twist tnewpin);

#endif /* SRC_LIB_BACKEND_ESYSDB_H_ */
