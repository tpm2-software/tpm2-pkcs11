/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_RANDOM_H_
#define SRC_PKCS11_RANDOM_H_

#include "pkcs11.h"

CK_RV random_get(CK_SESSION_HANDLE session, unsigned char *random_data, unsigned long random_len);

CK_RV seed_random (CK_SESSION_HANDLE session, unsigned char *seed, unsigned long seed_len);

#endif /* SRC_PKCS11_RANDOM_H_ */
