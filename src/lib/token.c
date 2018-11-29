/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "checks.h"
#include "db.h"
#include "list.h"
#include "pkcs11.h"
#include "session.h"
#include "session_table.h"
#include "slot.h"
#include "tpm.h"
#include "token.h"
#include "utils.h"

void token_free_list(token *t, size_t len) {

    size_t i;
    for (i=0; i < len; i++) {
        token_free(&t[i]);
    }
    free(t);
}

void token_free(token *t) {

    session_table_free(t->s_table);

    twist_free(t->sopobjauth);
    twist_free(t->sopobjauthkeysalt);

    twist_free(t->userpobjauth);
    twist_free(t->userpobjauthkeysalt);

    sobject_free(&t->sobject);
    sealobject_free(&t->sealobject);
    wrappingobject_free(&t->wrappingobject);

    if (t->tobjects) {
        list *cur = &t->tobjects->l;
        while(cur) {
            tobject *tobj = list_entry(cur, tobject, l);
            cur = cur->next;
            tobject_free(tobj);
        }
    }

    tpm_ctx_free(t->tctx);
}

CK_RV token_get_info (CK_SLOT_ID slot_id, CK_TOKEN_INFO *info) {

    check_pointer(info);

    token *t;
    check_slot_id(slot_id, t,CKR_SLOT_ID_INVALID);

    const unsigned char token_sn[]   = TPM2_TOKEN_SERIAL_NUMBER;
    const unsigned char token_manuf[]  = TPM2_TOKEN_MANUFACTURER;
    const unsigned char token_model[]  = TPM2_TOKEN_MODEL;
    const unsigned char token_hwver[2] = TPM2_SLOT_HW_VERSION;
    const unsigned char token_fwver[2] = TPM2_SLOT_FW_VERSION;
    time_t rawtime;
    struct tm * tminfo;

    memset(info, 0, sizeof(*info));

    /*
     * TODO Set these to better values
     * and get valid VERSION info. Likely
     * need to make version match what is in general.c
     * for the CK_INFO structure, not sure.
     *
     * Below is ALL the fields grouped.
     */

    // Version info
    memcpy(&info->firmwareVersion, &token_fwver, sizeof(token_fwver));
    memcpy(&info->hardwareVersion, &token_hwver, sizeof(token_hwver));

    // Support Flags
    info->flags = CKF_RNG
        | CKF_LOGIN_REQUIRED;

    if (t->config.is_initialized) {
        info->flags |= CKF_TOKEN_INITIALIZED;
    }

    // Identification
    str_padded_copy(info->label, t->label, sizeof(info->label));
    str_padded_copy(info->manufacturerID, token_manuf, sizeof(info->manufacturerID));
    str_padded_copy(info->model, token_model, sizeof(info->model));
    str_padded_copy(info->serialNumber, token_sn, sizeof(info->serialNumber));

    // Memory: TODO not sure what memory values should go here, the platform?
    info->ulFreePrivateMemory = ~0;
    info->ulFreePublicMemory = ~0;
    info->ulTotalPrivateMemory = ~0;
    info->ulTotalPublicMemory = ~0;

    // Maximums and Minimums
    info->ulMaxPinLen = 128;
    info->ulMinPinLen = 5;
    info->ulMaxSessionCount = MAX_NUM_OF_SESSIONS;
    info->ulMaxRwSessionCount = MAX_NUM_OF_SESSIONS;

    // Session
    session_table_get_cnt(t->s_table, &info->ulSessionCount, &info->ulRwSessionCount, NULL);

    // Time
    time (&rawtime);
    tminfo = gmtime(&rawtime);
    strftime ((char *)info->utcTime, sizeof(info->utcTime), "%Y%m%d%H%M%S", tminfo);

    return CKR_OK;
}
