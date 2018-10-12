/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <assert.h>

#include <tss2/tss2_sys.h>

#define LOGMODULE test
#include "log.h"
#include "pkcs11.h"
#include "db.h"
#include "test.h"

/**
 * C_FindObjects continues a search for token and session objects that match a template, obtaining additional object handles.
 * hSession is the session’s handle; phObject points to the location that receives the list (array) of additional object handles;
 * ulMaxObjectCount is the maximum number of object handles to be returned; pulObjectCount points to the location that receives the actual number of object handles returned.
 * If there are no more objects matching the template, then the location that pulObjectCount points to receives the value 0.
 * The search MUST have been initialized with C_FindObjectsInit.
 **/
void test_sign_verify_CKM_RSA_PKCS(CK_SESSION_HANDLE hSession) {

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    };

    CK_RV rv = C_FindObjectsInit(hSession, tmpl, ARRAY_LEN(tmpl));
    if(rv != CKR_OK){
        LOGE("C_FindObjectsInit failed! Response Code %x", rv);
        exit(1);
    }

    /*
     * We know there are 2 private key objects in the first item, so break up the calls
     * so we test state tracking across C_FindObject(). You can think of
     * C_FindObject like read, where it keeps moving the file pointer ahead,
     * and eventually returns EOF, in our case, count == 0.
     */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(hSession, objhandles, ARRAY_LEN(objhandles), &count);
    if(rv != CKR_OK){
        LOGE("C_FindObjects failed! Response Code %x", rv);
        exit(1);
    }
    if(count != 1){
        LOGE("C_FindObjects failed! Expected count=1, Actual count=%d", count);
        exit(1);
    }

    rv = C_FindObjects(hSession, objhandles, ARRAY_LEN(objhandles), &count);
    if(rv != CKR_OK){
        LOGE("C_FindObjects failed! Response Code %x", rv);
        exit(1);
    }
    if(count != 1){
        LOGE("C_FindObjects failed! Expected count=1, Actual count=%d", count);
        exit(1);
    }

    rv = C_FindObjects(hSession, objhandles, ARRAY_LEN(objhandles), &count);
    if(rv != CKR_OK){
        LOGE("C_FindObjects failed! Response Code %x", rv);
        exit(1);
    }
    if(count != 0){
        LOGE("C_FindObjects failed! Expected count=0, Actual count=%d", count);
        exit(1);
    }

    rv = C_FindObjectsFinal(hSession);
    if(rv != CKR_OK){
        LOGE("C_FindObjectsFinal failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_find_objects_rsa_good Test Passed!");
}

static void test_find_objects_aes_good(CK_SESSION_HANDLE hSession) {

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    };

    CK_RV rv = C_FindObjectsInit(hSession, tmpl, ARRAY_LEN(tmpl));
    if(rv != CKR_OK){
        LOGE("C_FindObjectsInit failed! Response Code %x", rv);
        exit(1);
    }

    /*
     * We know there are 2 private key objects in the first item, so break up the calls
     * so we test state tracking across C_FindObject(). You can think of
     * C_FindObject like read, where it keeps moving the file pointer ahead,
     * and eventually returns EOF, in our case, count == 0.
     */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(hSession, objhandles, ARRAY_LEN(objhandles), &count);
    if(rv != CKR_OK){
        LOGE("C_FindObjects failed! Response Code %x", rv);
        exit(1);
    }
    if(count != 1){
        LOGE("C_FindObjects failed! Expected count=1, Actual count=%d", count);
        exit(1);
    }

    rv = C_FindObjects(hSession, objhandles, ARRAY_LEN(objhandles), &count);
    if(rv != CKR_OK){
        LOGE("C_FindObjects failed! Response Code %x", rv);
        exit(1);
    }
    if(count != 1){
        LOGE("C_FindObjects failed! Expected count=1, Actual count=%d", count);
        exit(1);
    }

    rv = C_FindObjects(hSession, objhandles, ARRAY_LEN(objhandles), &count);
    if(rv != CKR_OK){
        LOGE("C_FindObjects failed! Response Code %x", rv);
        exit(1);
    }
    if(count != 0){
        LOGE("C_FindObjects failed! Expected count=0, Actual count=%d", count);
        exit(1);
    }

    rv = C_FindObjectsFinal(hSession);
    if(rv != CKR_OK){
        LOGE("C_FindObjectsFinal failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_find_objects_aes_good Test Passed!");
}

static void test_find_objects_by_label(CK_SESSION_HANDLE hSession) {

    char key_label[] = "mykeylabel";
    CK_ATTRIBUTE tmpl[] = {
      {CKA_LABEL, key_label, sizeof(key_label) - 1},
    };

    CK_RV rv = C_FindObjectsInit(hSession, tmpl, ARRAY_LEN(tmpl));
    if(rv != CKR_OK){
        LOGE("C_FindObjectsInit failed! Response Code %x", rv);
        exit(1);
    }

    /*
     * There is only one key in the test db with the label "mykeylabel"
     */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(hSession, objhandles, ARRAY_LEN(objhandles), &count);
    if(rv != CKR_OK){
        LOGE("C_FindObjects failed! Response Code %x", rv);
        exit(1);
    }

    if(count != 1){
        LOGE("C_FindObjects failed! Expected count=1, Actual count=%d", count);
        exit(1);
    }

    rv = C_FindObjectsFinal(hSession);
    if(rv != CKR_OK){
        LOGE("C_FindObjectsFinal failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("\"%s\" Test Passed!", __func__);
}

static void test_find_objects_via_empty_template(CK_SESSION_HANDLE hSession) {

    CK_RV rv = C_FindObjectsInit(hSession, NULL, 0);
    if(rv != CKR_OK){
        LOGE("C_FindObjectsInit failed! Response Code %x", rv);
        exit(1);
    }

    /*
     * There are 4 keys in the test db with
     */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[6];
    rv = C_FindObjects(hSession, objhandles, ARRAY_LEN(objhandles), &count);
    if(rv != CKR_OK){
        LOGE("C_FindObjects failed! Response Code %x", rv);
        exit(1);
    }

    if(count != 4){
        LOGE("C_FindObjects failed! Expected count=1, Actual count=%d", count);
        exit(1);
    }

    rv = C_FindObjectsFinal(hSession);
    if(rv != CKR_OK){
        LOGE("C_FindObjectsFinal failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("\"%s\" Test Passed!", __func__);
}

int test_invoke() {

    CK_RV rv = C_Initialize(NULL);
    if (rv == CKR_OK)
    	LOGV("Initialize was successful");
    else
    	LOGV("Initialize was unsuccessful");

    CK_SLOT_ID slots[6];
    unsigned long count = ARRAY_LEN(slots);
    rv = C_GetSlotList(true, slots, &count);
    if (rv == CKR_OK)
    	LOGV("C_GetSlotList was successful");
    else
    	LOGV("C_GetSlotList was unsuccessful");

    CK_SESSION_HANDLE handle;

    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL , NULL, &handle);
    if (rv == CKR_OK)
    	LOGV("C_OpenSession was successful");
    else
    	LOGV("C_OpenSession was unsuccessful");

    test_find_objects_aes_good(handle);
    test_sign_verify_CKM_RSA_PKCS(handle);
    test_find_objects_by_label(handle);
    test_find_objects_via_empty_template(handle);

    rv = C_CloseSession(handle);
    if (rv == CKR_OK)
    	LOGV("C_CloseSession was successful");
    else
    	LOGV("C_CloseSession was unsuccessful");

    rv = C_Finalize(NULL);
    if (rv == CKR_OK)
    	LOGV("C_Finalize was successful");
    else
    	LOGV("C_Finalize was unsuccessful");

    return 0;
}

