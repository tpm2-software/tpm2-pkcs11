/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_RANDOM_H_
#define SRC_PKCS11_RANDOM_H_


CK_RV random_get(unsigned char *random_data, unsigned long random_len);

#endif /* SRC_PKCS11_RANDOM_H_ */
