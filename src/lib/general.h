/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_GENERAL_H_
#define SRC_PKCS11_GENERAL_H_

#include <stdbool.h>

#include "pkcs11.h"

#define TPM2_TOKEN_LABEL                "TPM2 PKCS#11 Token"
#define TPM2_TOKEN_MANUFACTURER         "Intel"
#define TPM2_TOKEN_MODEL                "TPM2 PKCS#11"
#define TPM2_TOKEN_SERIAL_NUMBER        "0000000000000000"
#define TPM2_TOKEN_HW_VERSION           { 0, 0 }
#define TPM2_TOKEN_FW_VERSION           { 0, 0 }

#define TPM2_SLOT_DESCRIPTION           "Intel TPM2.0 Cryptoki"
#define TPM2_SLOT_MANUFACTURER          TPM2_TOKEN_MANUFACTURER
#define TPM2_SLOT_HW_VERSION            TPM2_TOKEN_HW_VERSION
#define TPM2_SLOT_FW_VERSION            TPM2_TOKEN_FW_VERSION

CK_RV general_init(void *init_args);
CK_RV general_get_func_list(CK_FUNCTION_LIST **function_list);
CK_RV general_get_info(CK_INFO *info);
bool general_is_init(void);

CK_RV general_finalize(void *reserved);

#endif /* SRC_GENERAL_H_ */
