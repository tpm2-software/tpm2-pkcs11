/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_GENERAL_H_
#define SRC_PKCS11_GENERAL_H_

#include <stdbool.h>

#include "pkcs11.h"

CK_RV general_init(void *init_args);
CK_RV general_get_func_list(CK_FUNCTION_LIST **function_list);
CK_RV general_get_info(CK_INFO *info);
bool general_is_init(void);

CK_RV general_finalize(void *reserved);

#endif /* SRC_GENERAL_H_ */
