/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_SLOT_H_
#define SRC_SLOT_H_

#include <stdbool.h>

#include "pkcs11.h"

typedef struct token token;

#define SLOT_ID 0x1234

CK_RV slot_init(void);
void slot_destroy(void);

token *slot_get_token(CK_SLOT_ID slot_id);

CK_RV slot_get_list (unsigned char token_present, CK_SLOT_ID *slot_list, unsigned long *count);
CK_RV slot_get_info (CK_SLOT_ID slot_id, CK_SLOT_INFO *info);
CK_RV slot_mechanism_list_get (CK_SLOT_ID slotID, CK_MECHANISM_TYPE *mechanism_list, unsigned long *count);
CK_RV slot_mechanism_info_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *info);
CK_RV slot_add_uninit_token(void);

/**
 * C_WaitForSlotEvent (S32 5.5.4). No slot event ever occurs: with CKF_DONT_BLOCK it returns
 * CKR_NO_EVENT, and without it blocks until C_Finalize calls slot_wake_waiters().
 * @param flags
 *  CKF_DONT_BLOCK, or 0 to block.
 * @param slot
 *  Where the slot of an event would go; never set.
 * @param reserved
 *  Must be NULL.
 * @return
 *  CKR_ARGUMENTS_BAD for a NULL slot or a reserved pointer.
 *  CKR_NO_EVENT with CKF_DONT_BLOCK.
 *  CKR_CRYPTOKI_NOT_INITIALIZED once C_Finalize woke it, or had already started.
 */
CK_RV slot_wait_for_event(CK_FLAGS flags, CK_SLOT_ID_PTR slot, CK_VOID_PTR reserved);

/**
 * Wakes every C_WaitForSlotEvent blocked, and waits for them to leave the slot event state. Called by
 * C_Finalize before anything is freed; until the next C_Initialize, a new wait returns at once.
 */
void slot_wake_waiters(void);

#endif /* SRC_SLOT_H_ */
