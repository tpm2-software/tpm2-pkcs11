/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
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

/*
 * Test that we can do a CKM_RSA_PKCS mechanism signature.
 *
 * This signature type will require an ASN1 digestinfo structure
 * to be populated, and then passed to the C_Sign().
 *
 * More information on the Digest Info structure can be found:
 *   - https://tools.ietf.org/html/rfc3447
 *
 * In short, its;
 *   DigestInfo ::= SEQUENCE {
 *     digestAlgorithm AlgorithmIdentifier,
 *     digest OCTET STRING
 *   }
 *
 * The nice part is the note specification has the ASN1 header you can just
 * append the hash too, so we do this:
 *
 * SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
 *              04 20 || H.
 *
 * We'll use SHA256 since the simulator supports it, we can then use
 * the CKM_SHA256_RSA_PKCS mechanism (which should go to tpm_sign
 * and the results should match.
 */

/*
 * The message to sign.
 */
static const unsigned char _data[] = { 'F', 'O', 'O', ' ', 'B', 'A', 'R' };

/*
 * The hash of the message to sign computed externally.
 */
static const unsigned char _data_hash_sha256[] = { 0x8d, 0x35, 0xc9, 0x7b, 0xcd,
        0x90, 0x2b, 0x96, 0xd1, 0xb5, 0x51, 0x74, 0x1b, 0xbe, 0x8a, 0x7f, 0x50,
        0xbb, 0x5a, 0x69, 0x0b, 0x4d, 0x02, 0x25, 0x48, 0x2e, 0xaa, 0x63, 0xdb,
        0xfb, 0x9d, 0xed };

void test_sign_verify_CKM_RSA_PKCS(CK_SESSION_HANDLE session) {

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = { { CKA_CLASS, &key_class, sizeof(key_class) }, {
            CKA_KEY_TYPE, &key_type, sizeof(key_type) }, };

    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    if (rv != CKR_OK) {
        LOGE("C_FindObjectsInit failed! Response Code %x", rv);
        exit(1);
    }

    /* Find an RSA key */
    unsigned long count;
    CK_OBJECT_HANDLE objhandles[1];
    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    if (rv != CKR_OK) {
        LOGE("C_FindObjects failed! Response Code %x", rv);
        exit(1);
    }
    if (count != 1) {
        LOGE("C_FindObjects failed! Expected count=1, Actual count=%d", count);
        exit(1);
    }

    rv = C_FindObjects(session, objhandles, ARRAY_LEN(objhandles), &count);
    if (rv != CKR_OK) {
        LOGE("C_FindObjects failed! Response Code %x", rv);
        exit(1);
    }

    rv = C_FindObjectsFinal(session);
    if (rv != CKR_OK) {
        LOGE("C_FindObjectsFinal failed! Response Code %x", rv);
        exit(1);
    }

    unsigned char userpin[] = "myuserpin";

    rv = C_Login(session, CKU_USER, userpin, sizeof(userpin) - 1);
    if (rv != CKR_OK) {
        LOGE("C_Login failed! Response Code %x", rv);
        exit(1);
    }

    /*
     * Now that we have a key for sign, build up what we need to sign,
     * which is the ASN1 digest info for CKM_RSA_PKCS
     */
    CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS };
    rv = C_SignInit(session, &mech, objhandles[0]);
    if (rv != CKR_OK) {
        LOGE("C_SignInit failed! Response Code %x", rv);
        exit(1);
    }

    /* 19 byte ASN1 header + sha256 32 byte size */
    unsigned char digest_info[19 + sizeof(_data_hash_sha256)] = {
    /* 19 byte ASN1 structure from the IETF rfc3447 for SHA256*/
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,

            /* the hash bytes, 0 them out */
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, };

    memcpy(&digest_info[19], _data_hash_sha256, sizeof(_data_hash_sha256));

    unsigned char ckm_rsa_pkcs_sig[4096];
    unsigned long ckm_rsa_pkcs_siglen = sizeof(ckm_rsa_pkcs_sig);

    rv = C_Sign(session, digest_info, sizeof(digest_info), ckm_rsa_pkcs_sig,
            &ckm_rsa_pkcs_siglen);
    if (rv != CKR_OK) {
        LOGE("C_Sign failed! Response Code %x", rv);
        exit(1);
    }

    /*
     * OK now internally hash/sign the data via CKM_SHA256_RSA_PKCS
     */
    mech.mechanism = CKM_SHA256_RSA_PKCS;
    rv = C_SignInit(session, &mech, objhandles[0]);
    if (rv != CKR_OK) {
        LOGE("C_SignInit failed! Response Code %x", rv);
        exit(1);
    }

    unsigned char ckm_sha256_rsa_pkcs_sig[4096];
    unsigned long ckm_sha256_rsa_pkcs_siglen = sizeof(ckm_rsa_pkcs_sig);

    rv = C_Sign(session, (unsigned char *) _data, sizeof(_data),
            ckm_sha256_rsa_pkcs_sig, &ckm_sha256_rsa_pkcs_siglen);
    if (rv != CKR_OK) {
        LOGE("C_Sign failed! Response Code %x", rv);
        exit(1);
    }

    if (ckm_sha256_rsa_pkcs_siglen != ckm_rsa_pkcs_siglen) {
        LOGE("Constructed Signatures differ in length: %lu != %lu",
                ckm_sha256_rsa_pkcs_siglen, ckm_rsa_pkcs_siglen);
        exit(1);
    }

    int cmp = memcmp(ckm_sha256_rsa_pkcs_sig, ckm_rsa_pkcs_sig,
            ckm_sha256_rsa_pkcs_siglen);
    if (cmp) {
        LOGE("Constructed signatures do not match");
        exit(1);
    }

    rv = C_Logout(session);
    if (rv != CKR_OK) {
        LOGE("C_Sign failed! Response Code %x", rv);
        exit(1);
    }

    LOGV("test_sign_verify_CKM_RSA_PKCS Test Passed!");
}

int main() {

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

    if (count < 2) {
        LOGE("Slot count is not 2, expected 2 slots");
        exit(1);
    }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
            NULL, &handle);
    if (rv == CKR_OK)
        LOGV("C_OpenSession was successful");
    else
        LOGV("C_OpenSession was unsuccessful");

    test_sign_verify_CKM_RSA_PKCS(handle);

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

