/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_CHECKS_H_
#define SRC_PKCS11_CHECKS_H_

#include "pkcs11.h"
#include "general.h"
#include "slot.h"

#define check_num(ptr) if (!ptr) { return CKR_ARGUMENTS_BAD; }
#define check_pointer(ptr) if (!ptr) { return CKR_ARGUMENTS_BAD; }
#define check_slot_id(slot_id)  if (!slot_get_token(slot_id)) { return CKR_SLOT_ID_INVALID; }
#define check_is_init() if (!general_is_init()) { return CKR_CRYPTOKI_NOT_INITIALIZED; }

#endif /* SRC_PKCS11_CHECKS_H_ */
