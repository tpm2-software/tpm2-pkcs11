/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_CHECKS_H_
#define SRC_PKCS11_CHECKS_H_

#include "pkcs11.h"
#include "general.h"
#include "slot.h"

#define check_num(ptr) if (!ptr) { return CKR_ARGUMENTS_BAD; }
#define check_pointer(ptr) if (!ptr) { return CKR_ARGUMENTS_BAD; }

#define check_slot_id(slot_id, tok, rv)  \
    do { \
        tok = slot_get_token(slot_id); \
        if (!tok) { \
            return rv; \
        }\
    } while (0)

#endif /* SRC_PKCS11_CHECKS_H_ */
