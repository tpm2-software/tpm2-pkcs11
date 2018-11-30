/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_LIB_DIGEST_H_
#define SRC_LIB_DIGEST_H_

#include "pkcs11.h"

typedef struct token token;

CK_RV digest_init(token *tok, CK_MECHANISM *mechanism);

CK_RV digest_update(token *tok, unsigned char *part, unsigned long part_len);

CK_RV digest_final(token *tok, unsigned char *digest, unsigned long *digest_len);

CK_RV digest_oneshot(token *tok, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len);

#endif /* SRC_LIB_DIGEST_H_ */
