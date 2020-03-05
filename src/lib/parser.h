/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SRC_LIB_PARSER_H_
#define SRC_LIB_PARSER_H_

#include <stdbool.h>

#include "attrs.h"
#include "pkcs11.h"
#include "store-config.h"
#include "token.h"

bool parse_attributes_from_string(const unsigned char *yaml, size_t size,
        attr_list **attrs);

bool parse_token_config_from_string_v1(const unsigned char *yaml, size_t size,
        token_config_v1 *config);

bool parse_token_config_from_string_v2(const unsigned char *yaml, size_t size,
        token_config_v2 *config);

bool parse_store_config_from_string(const unsigned char *yaml, size_t size, store_config *config);

#endif /* SRC_LIB_PARSER_H_ */
