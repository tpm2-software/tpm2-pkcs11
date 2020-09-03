/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_LIB_EMITTER_H_
#define SRC_LIB_EMITTER_H_

#include "attrs.h"
#include "debug.h"
#include "pkcs11.h"
#include "token.h"

WEAK char *emit_attributes_to_string(attr_list *attrs);

char *emit_config_to_string(token *tok);

WEAK char *emit_pobject_to_conf_string(pobject_config *pobj);

#endif /* SRC_LIB_EMITTER_H_ */
