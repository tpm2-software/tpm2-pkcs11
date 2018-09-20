/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_LIB_DIGEST_H_
#define SRC_LIB_DIGEST_H_

#include "pkcs11.h"

CK_RV digest_init (CK_SESSION_HANDLE session, struct _CK_MECHANISM *mechanism);
CK_RV digest_update (CK_SESSION_HANDLE session, unsigned char *part, unsigned long part_len);
CK_RV digest_final (CK_SESSION_HANDLE session, unsigned char *digest, unsigned long *digest_len);
CK_RV digest_oneshot (CK_SESSION_HANDLE session, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len);

#endif /* SRC_LIB_DIGEST_H_ */
