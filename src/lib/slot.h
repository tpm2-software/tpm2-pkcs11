/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_SLOT_H_
#define SRC_SLOT_H_

#include <stdbool.h>

#include "pkcs11.h"



#define EMPTY_TOKEN_BIT 0xf0000000

extern CK_SLOT_ID emptyTokenSlot;

CK_RV slot_init(void);
void slot_destroy(void);

CK_RV slot_get_list (unsigned char token_present, CK_SLOT_ID *slot_list, unsigned long *count);
CK_RV slot_get_info (CK_SLOT_ID slot_id, CK_SLOT_INFO *info);

typedef struct token token;
token *slot_get_token(CK_SLOT_ID slot_id);

CK_RV slot_mechanism_list_get (CK_SLOT_ID slotID, CK_MECHANISM_TYPE *mechanism_list, unsigned long *count);
CK_RV slot_mechanism_info_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *info);

#endif /* SRC_SLOT_H_ */
