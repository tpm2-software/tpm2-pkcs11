/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_KEY_H_
#define SRC_PKCS11_KEY_H_

#include "pkcs11.h"

CK_RV key_gen (CK_SESSION_HANDLE session, struct _CK_MECHANISM *mechanism, struct _CK_ATTRIBUTE *public_key_template, unsigned long public_key_attribute_count, struct _CK_ATTRIBUTE *private_key_template, unsigned long private_key_attribute_count, CK_OBJECT_HANDLE *public_key, CK_OBJECT_HANDLE *private_key);

#endif /* SRC_PKCS11_KEY_H_ */
