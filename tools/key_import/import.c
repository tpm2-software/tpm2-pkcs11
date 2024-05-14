/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/objects.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tctildr.h>

#include "attrs.h"
#include "db.h"
#include "pkcs11.h"
#include "utils.h"

#ifdef DEBUG
#define PRINT_E(...)                                                                               \
    fprintf(stderr, "%s:%d:%s() ", __FILE__, __LINE__, __func__);                                  \
    fprintf(stderr, __VA_ARGS__);                                                                  \
    fprintf(stderr, "\n")
#else
#define PRINT_E(...)                                                                               \
    fprintf(stderr, __VA_ARGS__);                                                                  \
    fprintf(stderr, "\n")
#endif

#define ADD_ATTR(a, t, l, v)                                                                       \
    do {                                                                                           \
        CK_ATTRIBUTE_PTR p = a;                                                                    \
        p->type = t;                                                                               \
        p->ulValueLen = l;                                                                         \
        p->pValue = v;                                                                             \
    } while (0)

static const struct {
    CK_RV       rv;
    const char *str;
} ckr_str_map[] = {
    { CKR_OK, "CKR_OK" },
    { CKR_CANCEL, "CKR_CANCEL" },
    { CKR_HOST_MEMORY, "CKR_HOST_MEMORY" },
    { CKR_SLOT_ID_INVALID, "CKR_SLOT_ID_INVALID" },
    { CKR_GENERAL_ERROR, "CKR_GENERAL_ERROR" },
    { CKR_FUNCTION_FAILED, "CKR_FUNCTION_FAILED" },
    { CKR_ARGUMENTS_BAD, "CKR_ARGUMENTS_BAD" },
    { CKR_NO_EVENT, "CKR_NO_EVENT" },
    { CKR_NEED_TO_CREATE_THREADS, "CKR_NEED_TO_CREATE_THREADS" },
    { CKR_CANT_LOCK, "CKR_CANT_LOCK" },
    { CKR_ATTRIBUTE_READ_ONLY, "CKR_ATTRIBUTE_READ_ONLY" },
    { CKR_ATTRIBUTE_SENSITIVE, "CKR_ATTRIBUTE_SENSITIVE" },
    { CKR_ATTRIBUTE_TYPE_INVALID, "CKR_ATTRIBUTE_TYPE_INVALID" },
    { CKR_ATTRIBUTE_VALUE_INVALID, "CKR_ATTRIBUTE_VALUE_INVALID" },
    { CKR_DATA_INVALID, "CKR_DATA_INVALID" },
    { CKR_DATA_LEN_RANGE, "CKR_DATA_LEN_RANGE" },
    { CKR_DEVICE_ERROR, "CKR_DEVICE_ERROR" },
    { CKR_DEVICE_MEMORY, "CKR_DEVICE_MEMORY" },
    { CKR_DEVICE_REMOVED, "CKR_DEVICE_REMOVED" },
    { CKR_ENCRYPTED_DATA_INVALID, "CKR_ENCRYPTED_DATA_INVALID" },
    { CKR_ENCRYPTED_DATA_LEN_RANGE, "CKR_ENCRYPTED_DATA_LEN_RANGE" },
    { CKR_FUNCTION_CANCELED, "CKR_FUNCTION_CANCELED" },
    { CKR_FUNCTION_NOT_PARALLEL, "CKR_FUNCTION_NOT_PARALLEL" },
    { CKR_FUNCTION_NOT_SUPPORTED, "CKR_FUNCTION_NOT_SUPPORTED" },
    { CKR_KEY_HANDLE_INVALID, "CKR_KEY_HANDLE_INVALID" },
    { CKR_KEY_SIZE_RANGE, "CKR_KEY_SIZE_RANGE" },
    { CKR_KEY_TYPE_INCONSISTENT, "CKR_KEY_TYPE_INCONSISTENT" },
    { CKR_KEY_NOT_NEEDED, "CKR_KEY_NOT_NEEDED" },
    { CKR_KEY_CHANGED, "CKR_KEY_CHANGED" },
    { CKR_KEY_NEEDED, "CKR_KEY_NEEDED" },
    { CKR_KEY_INDIGESTIBLE, "CKR_KEY_INDIGESTIBLE" },
    { CKR_KEY_FUNCTION_NOT_PERMITTED, "CKR_KEY_FUNCTION_NOT_PERMITTED" },
    { CKR_KEY_NOT_WRAPPABLE, "CKR_KEY_NOT_WRAPPABLE" },
    { CKR_KEY_UNEXTRACTABLE, "CKR_KEY_UNEXTRACTABLE" },
    { CKR_MECHANISM_INVALID, "CKR_MECHANISM_INVALID" },
    { CKR_MECHANISM_PARAM_INVALID, "CKR_MECHANISM_PARAM_INVALID" },
    { CKR_OBJECT_HANDLE_INVALID, "CKR_OBJECT_HANDLE_INVALID" },
    { CKR_OPERATION_ACTIVE, "CKR_OPERATION_ACTIVE" },
    { CKR_OPERATION_NOT_INITIALIZED, "CKR_OPERATION_NOT_INITIALIZED" },
    { CKR_PIN_INCORRECT, "CKR_PIN_INCORRECT" },
    { CKR_PIN_INVALID, "CKR_PIN_INVALID" },
    { CKR_PIN_LEN_RANGE, "CKR_PIN_LEN_RANGE" },
    { CKR_PIN_EXPIRED, "CKR_PIN_EXPIRED" },
    { CKR_PIN_LOCKED, "CKR_PIN_LOCKED" },
    { CKR_SESSION_CLOSED, "CKR_SESSION_CLOSED" },
    { CKR_SESSION_COUNT, "CKR_SESSION_COUNT" },
    { CKR_SESSION_HANDLE_INVALID, "CKR_SESSION_HANDLE_INVALID" },
    { CKR_SESSION_PARALLEL_NOT_SUPPORTED, "CKR_SESSION_PARALLEL_NOT_SUPPORTED" },
    { CKR_SESSION_READ_ONLY, "CKR_SESSION_READ_ONLY" },
    { CKR_SESSION_EXISTS, "CKR_SESSION_EXISTS" },
    { CKR_SESSION_READ_ONLY_EXISTS, "CKR_SESSION_READ_ONLY_EXISTS" },
    { CKR_SESSION_READ_WRITE_SO_EXISTS, "CKR_SESSION_READ_WRITE_SO_EXISTS" },
    { CKR_SIGNATURE_INVALID, "CKR_SIGNATURE_INVALID" },
    { CKR_SIGNATURE_LEN_RANGE, "CKR_SIGNATURE_LEN_RANGE" },
    { CKR_TEMPLATE_INCOMPLETE, "CKR_TEMPLATE_INCOMPLETE" },
    { CKR_TEMPLATE_INCONSISTENT, "CKR_TEMPLATE_INCONSISTENT" },
    { CKR_TOKEN_NOT_PRESENT, "CKR_TOKEN_NOT_PRESENT" },
    { CKR_TOKEN_NOT_RECOGNIZED, "CKR_TOKEN_NOT_RECOGNIZED" },
    { CKR_TOKEN_WRITE_PROTECTED, "CKR_TOKEN_WRITE_PROTECTED" },
    { CKR_UNWRAPPING_KEY_HANDLE_INVALID, "CKR_UNWRAPPING_KEY_HANDLE_INVALID" },
    { CKR_UNWRAPPING_KEY_SIZE_RANGE, "CKR_UNWRAPPING_KEY_SIZE_RANGE" },
    { CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT" },
    { CKR_USER_ALREADY_LOGGED_IN, "CKR_USER_ALREADY_LOGGED_IN" },
    { CKR_USER_NOT_LOGGED_IN, "CKR_USER_NOT_LOGGED_IN" },
    { CKR_USER_PIN_NOT_INITIALIZED, "CKR_USER_PIN_NOT_INITIALIZED" },
    { CKR_USER_TYPE_INVALID, "CKR_USER_TYPE_INVALID" },
    { CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN" },
    { CKR_USER_TOO_MANY_TYPES, "CKR_USER_TOO_MANY_TYPES" },
    { CKR_WRAPPED_KEY_INVALID, "CKR_WRAPPED_KEY_INVALID" },
    { CKR_WRAPPED_KEY_LEN_RANGE, "CKR_WRAPPED_KEY_LEN_RANGE" },
    { CKR_WRAPPING_KEY_HANDLE_INVALID, "CKR_WRAPPING_KEY_HANDLE_INVALID" },
    { CKR_WRAPPING_KEY_SIZE_RANGE, "CKR_WRAPPING_KEY_SIZE_RANGE" },
    { CKR_WRAPPING_KEY_TYPE_INCONSISTENT, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT" },
    { CKR_RANDOM_SEED_NOT_SUPPORTED, "CKR_RANDOM_SEED_NOT_SUPPORTED" },
    { CKR_RANDOM_NO_RNG, "CKR_RANDOM_NO_RNG" },
    { CKR_DOMAIN_PARAMS_INVALID, "CKR_DOMAIN_PARAMS_INVALID" },
    { CKR_BUFFER_TOO_SMALL, "CKR_BUFFER_TOO_SMALL" },
    { CKR_SAVED_STATE_INVALID, "CKR_SAVED_STATE_INVALID" },
    { CKR_INFORMATION_SENSITIVE, "CKR_INFORMATION_SENSITIVE" },
    { CKR_STATE_UNSAVEABLE, "CKR_STATE_UNSAVEABLE" },
    { CKR_CRYPTOKI_NOT_INITIALIZED, "CKR_CRYPTOKI_NOT_INITIALIZED" },
    { CKR_CRYPTOKI_ALREADY_INITIALIZED, "CKR_CRYPTOKI_ALREADY_INITIALIZED" },
    { CKR_MUTEX_BAD, "CKR_MUTEX_BAD" },
    { CKR_MUTEX_NOT_LOCKED, "CKR_MUTEX_NOT_LOCKED" },
    { CKR_VENDOR_DEFINED, "CKR_VENDOR_DEFINED" },
};

static const char *
ckr_to_string(CK_RV rv) {
    for (size_t i = 0; i < ARRAY_LEN(ckr_str_map); i++) {
        if (ckr_str_map[i].rv == rv) {
            return ckr_str_map[i].str;
        }
    }

    return "unknown error";
}

int
tpm2_ec_alg_to_asn1(TPM2_ALGORITHM_ID alg, uint8_t **der) {
    int            ret = -1;
    int            nid = NID_undef;
    ASN1_OBJECT   *obj = NULL;
    unsigned char *d = NULL;
    int            d_len = 0;

    switch (alg) {
    case TPM2_ECC_NIST_P192:
        nid = NID_X9_62_prime192v1;
        break;
    case TPM2_ECC_NIST_P224:
        nid = NID_secp224r1;
        break;
    case TPM2_ECC_NIST_P256:
        nid = NID_X9_62_prime256v1;
        break;
    case TPM2_ECC_NIST_P384:
        nid = NID_secp384r1;
        break;
    case TPM2_ECC_NIST_P521:
        nid = NID_secp521r1;
        break;
    default:
        PRINT_E("Unsupported TPM EC algorithm: %d", alg);
        goto exit;
    }

    obj = OBJ_nid2obj(nid);
    if (obj == NULL) {
        PRINT_E("Failed to convert NID to ASN1_OBJECT");
        goto exit;
    }

    d_len = i2d_ASN1_OBJECT(obj, &d);
    if (!d_len || !d) {
        PRINT_E("i2d_ASN1_OBJECT has failed");
        goto exit;
    }

    *der = malloc(d_len);
    if (!der) {
        PRINT_E("calloc has failed");
        goto exit;
    }

    memcpy(*der, d, d_len);

    ret = d_len;
exit:
    ASN1_OBJECT_free(obj);
    OPENSSL_free(d);
    return ret;
}

int
c_initialize(void) {
    CK_RV                rv;
    CK_C_INITIALIZE_ARGS args = {
        .CreateMutex = NULL,
        .DestroyMutex = NULL,
        .LockMutex = NULL,
        .UnlockMutex = NULL,
        .flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS,
    };

    rv = C_Initialize(&args);
    if (rv != CKR_OK) {
        PRINT_E("C_Initialize has failed: %s", ckr_to_string(rv));
        return 1;
    }

    return 0;
}

int
c_finalize(void) {
    CK_RV rv;

    rv = C_Finalize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_NOT_INITIALIZED) {
        PRINT_E("C_Finalize has failed: %s", ckr_to_string(rv));
        return 1;
    }

    return 0;
}

int
c_get_info(void) {
    CK_RV   rv;
    CK_INFO info;

    rv = C_GetInfo(&info);
    if (rv != CKR_OK) {
        PRINT_E("C_GetInfo has failed: %s", ckr_to_string(rv));
        return 1;
    }

    return 0;
}

int
c_get_slot(CK_SLOT_ID slot_id) {
    CK_RV         rv;
    CK_TOKEN_INFO info = { 0 };

    rv = C_GetTokenInfo(slot_id, &info);
    if (rv != CKR_OK) {
        PRINT_E("C_GetTokenInfo has failed: %s", ckr_to_string(rv));
        return 1;
    }

    if (info.flags & CKF_TOKEN_INITIALIZED) {
        printf("Slot id: %ld\n", slot_id);

        info.label[sizeof(info.label) - 1] = '\0';
        printf("Token label: %s\n", info.label);

        info.manufacturerID[sizeof(info.manufacturerID) - 1] = '\0';
        printf("Token manufacturer id: %s\n", info.manufacturerID);

        info.model[sizeof(info.model) - 1] = '\0';
        printf("Token model: %s\n", info.model);

        info.serialNumber[sizeof(info.serialNumber) - 1] = '\0';
        printf("Token serial number: %s\n", info.serialNumber);
    } else {
        PRINT_E("Token is not initialized.");
        return 1;
    }

    return 0;
}

int
c_open_session(CK_SLOT_ID slot_id, CK_SESSION_HANDLE *session) {
    CK_RV             rv;
    CK_FLAGS          flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_SESSION_HANDLE s = CK_INVALID_HANDLE;

    rv = C_OpenSession(slot_id, flags, NULL, NULL, &s);
    if (rv != CKR_OK) {
        PRINT_E("C_OpenSession has failed: %s", ckr_to_string(rv));
        return 1;
    }

    *session = s;

    return 0;
}

int
c_close_session(CK_SESSION_HANDLE session) {
    CK_RV rv;

    if (session == CK_INVALID_HANDLE) {
        return 0;
    }

    rv = C_CloseSession(session);
    if (rv != CKR_OK) {
        PRINT_E("C_CloseSession has failed: %s", ckr_to_string(rv));
        return 1;
    }

    return 0;
}

int
c_login(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR user_pin) {
    CK_RV        rv;
    CK_USER_TYPE user_type = CKU_USER;
    CK_ULONG     user_pin_len = 0;

    if (session == CK_INVALID_HANDLE) {
        return 0;
    }

    if (user_pin) {
        user_pin_len = strlen((char *)user_pin);
    }

    rv = C_Login(session, user_type, user_pin, user_pin_len);
    if (rv != CKR_OK) {
        PRINT_E("C_Login has failed: %s", ckr_to_string(rv));
        return 1;
    }

    return 0;
}

int
c_generate_keypair(CK_SESSION_HANDLE session,
                   CK_MECHANISM     *mech,
                   CK_ATTRIBUTE     *pub,
                   CK_ULONG          pub_len,
                   CK_ATTRIBUTE     *priv,
                   CK_ULONG          priv_len) {
    CK_RV            rv;
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    rv = C_GenerateKeyPair(session, mech, pub, pub_len, priv, priv_len, &pubkey, &privkey);
    if (rv != CKR_OK) {
        PRINT_E("C_GenerateKeyPair has failed: %s", ckr_to_string(rv));
        return 1;
    }

    return 0;
}

int
main(int argc, char **argv) {

    int ret = 1;

    /* tpm2-tss variables */

    TSS2_RC            tss2_rc;
    TPM2_HANDLE        parent_persistent_handle = 0;
    TPM2_HANDLE        persistent_handle = 0;
    ESYS_CONTEXT      *esys_ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    TPM2B_PUBLIC      *key_public = NULL;
    TPM2B_PUBLIC       pub_tpm2b = { 0 };
    TPM2B_PRIVATE      priv_tpm2b = { 0 };
    ESYS_TR            parent_esys_tr = 0;
    ESYS_TR            esys_tr = 0;
    TPM2B_DIGEST       parent_auth = { 0 };
    unsigned long      tpm2_handle = 0;
    char              *pub_path = NULL;
    char              *priv_path = NULL;
    size_t             offset = 0;

    /* PKCS #11 variables */

    CK_UTF8CHAR_PTR key_label = NULL;
    CK_UTF8CHAR_PTR parent_auth_value = NULL;
    CK_UTF8CHAR_PTR auth_value = NULL;
    CK_ULONG        pubkey_attrs_count = 0;
    CK_ULONG        privkey_attrs_count = 0;
    CK_MECHANISM    mech
        = { .mechanism = CKR_MECHANISM_INVALID, .pParameter = NULL, .ulParameterLen = 0 };
    CK_BBOOL          ck_true = CK_TRUE;
    CK_ATTRIBUTE      pubkey_attrs[4] = { 0 };
    CK_ATTRIBUTE      privkey_attrs[5] = { 0 };
    int               pub_attrs_ind = 0;
    int               priv_attrs_ind = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SLOT_ID        slot_id = 0;
    CK_UTF8CHAR_PTR   user_pin = NULL;
    uint8_t          *cka_ec_params = NULL;
    int               cka_ec_params_len = 0;

    /* getopt variables */

    int                  opt;
    int                  opt_index = 0;
    const char          *short_opts = "A:a:C:c:hk:l:r:s:u:t:";
    static struct option long_opts[]
        = { { "key-auth", required_argument, NULL, 'a' },
            { "persistent-handle", required_argument, NULL, 'c' },
            { "help", no_argument, NULL, 'h' },
            { "user-pin", required_argument, NULL, 'k' },
            { "key-label", required_argument, NULL, 'l' },
            { "parent-persistent-handle", required_argument, NULL, 'C' },
            { "parent-auth", required_argument, NULL, 'A' },
            { "private", required_argument, NULL, 'r' },
            { "slot-id", required_argument, NULL, 's' },
            { "public", required_argument, NULL, 'u' },
            { "tcti", required_argument, NULL, 't' },
            { 0, 0, 0, 0 } };

    /* File reading variables */

    FILE    *pub_f = NULL, *priv_f = NULL;
    uint8_t *pub_blob = NULL, *priv_blob = NULL;
    size_t   pub_sz = 0, priv_sz = 0;

    /* End of local variable declarations */

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &opt_index)) != -1) {
        switch (opt) {
        case 'A':
            parent_auth_value = (unsigned char *)optarg;
            break;

        case 'a':
            auth_value = (unsigned char *)optarg;
            break;

        case 'C':
            if (strlen(optarg) != 10 || strncmp(optarg, "0x", 2)) {
                PRINT_E("Invalid input format. Expecting an 8-character long"
                        " hexadecimal with the prefix '0x', e.g., 0x81000001.");
                goto exit;
            }

            parent_persistent_handle = strtol(optarg, NULL, 16);

            if (parent_persistent_handle < TPM2_PERSISTENT_FIRST
                || parent_persistent_handle > TPM2_PERSISTENT_LAST) {
                PRINT_E("Invalid parent persistent handle. The value must be in the range of "
                        "0x%08x to 0x%08x.",
                        TPM2_PERSISTENT_FIRST, TPM2_PERSISTENT_LAST);
                goto exit;
            }

            break;

        case 'c':
            if (strlen(optarg) != 10 || strncmp(optarg, "0x", 2)) {
                PRINT_E("Invalid input format. Expecting an 8-character long"
                        " hexadecimal with the prefix '0x', e.g., 0x81000001.");
                goto exit;
            }

            persistent_handle = strtol(optarg, NULL, 16);

            if (persistent_handle < TPM2_PERSISTENT_FIRST
                || persistent_handle > TPM2_PERSISTENT_LAST) {
                PRINT_E("Invalid persistent handle. The value must be in the range of 0x%08x to "
                        "0x%08x.",
                        TPM2_PERSISTENT_FIRST, TPM2_PERSISTENT_LAST);
                goto exit;
            }

            break;

        case 'h':
            printf("A TPM key import tool for tpm2-pkcs11 tokens, "
                   "capable of importing keys as either persistent handles or key objects.\n");
            printf("Usage: key_import [<options>]\n");
            printf("Options:\n");
            printf("  -A, --parent-auth               The authorization value of the\n");
            printf("                                  parent key.\n");
            printf("  -a, --key-auth                  The TPM key's authorization value.\n");
            printf("  -C, --parent-persistent-handle  The persistent handle of the parent key\n");
            printf("                                  to which the key objects are associated.\n");
            printf("  -c, --persistent-handle         The persistent handle of the TPM key\n");
            printf("                                  to be imported.\n");
            printf("                                  If this option is selected, do not\n");
            printf("                                  specify -r, -u, -C, or -A.\n");
            printf("  -h, --help                      Show this help message.\n");
            printf("  -k, --user-pin                  The PKCS#11 token user PIN.\n");
            printf("  -l, --key-label                 The PKCS#11 key label to assign to the\n");
            printf("                                  TPM key.\n");
            printf("  -r, --private                   A file containing the sensitive portion\n");
            printf("                                  of the TPM key object. This option is\n");
            printf("                                  specified alongside -u, -C, and -A.\n");
            printf("                                  If this option is selected, do not\n");
            printf("                                  specify -c.\n");
            printf("  -s, --slot-id                   The PKCS#11 slot ID where the token\n");
            printf("                                  resides (default is 0).\n");
            printf("  -u, --public                    A file containing the public portion of\n");
            printf("                                  the TPM key object. This option is\n");
            printf("                                  specified alongside -r, -C, and -A.\n");
            printf("                                  If this option is selected, do not\n");
            printf("                                  specify -c.\n");
            printf("  -t, --tcti                      The transmission interface with the TPM.\n");

            ret = 0;
            goto exit;

        case 'k':
            user_pin = (unsigned char *)optarg;
            break;

        case 'l':
            key_label = (unsigned char *)optarg;
            break;

        case 'r':
            priv_path = optarg;
            break;

        case 's':
            slot_id = strtol(optarg, NULL, 10);
            if (slot_id > MAX_TOKEN_CNT) {
                PRINT_E("Slot ID cannot be greater than %d", MAX_TOKEN_CNT);
                goto exit;
            }
            break;

        case 'u':
            pub_path = optarg;
            break;

        case 't':
            tss2_rc = Tss2_TctiLdr_Initialize(optarg, &tcti);
            if (tss2_rc != TSS2_RC_SUCCESS) {
                PRINT_E("Tcti initialization has failed with: %s", Tss2_RC_Decode(tss2_rc));
                goto exit;
            }

            tss2_rc = Esys_Initialize(&esys_ctx, tcti, NULL);
            if (tss2_rc != TSS2_RC_SUCCESS) {
                PRINT_E("Esys initialization has failed with: %s", Tss2_RC_Decode(tss2_rc));
                goto exit;
            }

            break;

        case '?':
            /* The option is marked as required_argument, but no argument is provided. */
            goto exit;

        default:
            /* The option is unrecognized. */
            PRINT_E("Invalid option. Check the command usage by running: %s --help", argv[0]);
            goto exit;
        }
    }

    if (!user_pin || !esys_ctx || !key_label) {
        PRINT_E("Missing inputs. Check the command usage by running: %s --help", argv[0]);
        goto exit;
    }

    if (persistent_handle && pub_path && priv_path && parent_persistent_handle) {
        PRINT_E("Ambiguous options detected. Persistent handle and key objects cannot"
                " be used together. Check the command usage by running: %s --help",
                argv[0]);
        goto exit;
    }

    ADD_ATTR(&pubkey_attrs[pub_attrs_ind++], CKA_ID, strlen((char *)key_label), key_label);
    ADD_ATTR(&pubkey_attrs[pub_attrs_ind++], CKA_LABEL, strlen((char *)key_label), key_label);

    ADD_ATTR(&privkey_attrs[priv_attrs_ind++], CKA_ID, strlen((char *)key_label), key_label);
    ADD_ATTR(&privkey_attrs[priv_attrs_ind++], CKA_LABEL, strlen((char *)key_label), key_label);
    ADD_ATTR(&privkey_attrs[priv_attrs_ind++], CKA_SENSITIVE, sizeof(ck_true), &ck_true);
    if (auth_value) {
        ADD_ATTR(&privkey_attrs[priv_attrs_ind++], CKA_TPM2_OBJAUTH, strlen((char *)auth_value),
                 auth_value);
    }

    if (persistent_handle) {

        tpm2_handle = persistent_handle;
        ADD_ATTR(&pubkey_attrs[pub_attrs_ind++], CKA_TPM2_PERSISTENT_HANDLE, sizeof(tpm2_handle),
                 &tpm2_handle);
        ADD_ATTR(&privkey_attrs[priv_attrs_ind++], CKA_TPM2_PERSISTENT_HANDLE, sizeof(tpm2_handle),
                 &tpm2_handle);

        /* Create the ESYS_TR object from the persistent handle */

        tss2_rc = Esys_TR_FromTPMPublic(esys_ctx, persistent_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                                        ESYS_TR_NONE, &esys_tr);
        if (tss2_rc != TSS2_RC_SUCCESS) {
            PRINT_E("Esys_TR_FromTPMPublic has failed with: %s", Tss2_RC_Decode(tss2_rc));
            goto exit;
        }

    } else if (pub_path && priv_path && parent_persistent_handle) {

        /* Read the public and private key blobs */

        pub_f = fopen(pub_path, "rb");
        if (!pub_f) {
            PRINT_E("Could not open the file \"%s\": %s", pub_path, strerror(errno));
            goto exit;
        }

        priv_f = fopen(priv_path, "rb");
        if (!priv_f) {
            PRINT_E("Could not open the file \"%s\": %s", priv_path, strerror(errno));
            goto exit;
        }

        pub_sz = sizeof(TPM2B_PUBLIC);
        priv_sz = sizeof(TPM2B_PRIVATE);
        pub_blob = calloc(1, pub_sz);
        priv_blob = calloc(1, priv_sz);
        if (!pub_blob || !priv_blob) {
            PRINT_E("calloc has failed");
            goto exit;
        }

        pub_sz = fread(pub_blob, 1, sizeof(TPM2B_PUBLIC), pub_f);
        if (!feof(pub_f)) {
            PRINT_E("Failed to read from pub_f");
            goto exit;
        }

        priv_sz = fread(priv_blob, 1, sizeof(TPM2B_PRIVATE), priv_f);
        if (!feof(priv_f)) {
            PRINT_E("Failed to read from priv_f");
            goto exit;
        }

        tss2_rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(pub_blob, pub_sz, &offset, &pub_tpm2b);
        if (tss2_rc != TSS2_RC_SUCCESS) {
            PRINT_E("Tss2_MU_PUBLIC_Unmarshal has failed with: %s", Tss2_RC_Decode(tss2_rc));
            goto exit;
        }

        offset = 0;
        tss2_rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(priv_blob, priv_sz, &offset, &priv_tpm2b);
        if (tss2_rc != TSS2_RC_SUCCESS) {
            PRINT_E("Tss2_MU_PRIVATE_Unmarshal has failed with: %s", Tss2_RC_Decode(tss2_rc));
            goto exit;
        }

        /* Parent authorization */

        tss2_rc = Esys_TR_FromTPMPublic(esys_ctx, parent_persistent_handle, ESYS_TR_NONE,
                                        ESYS_TR_NONE, ESYS_TR_NONE, &parent_esys_tr);
        if (tss2_rc != TSS2_RC_SUCCESS) {
            PRINT_E("Esys_TR_FromTPMPublic has failed with: %s", Tss2_RC_Decode(tss2_rc));
            goto exit;
        }

        if (parent_auth_value) {
            parent_auth.size = (UINT16)snprintf(
                (char *)parent_auth.buffer, sizeof(parent_auth.buffer), "%s", parent_auth_value);

            tss2_rc = Esys_TR_SetAuth(esys_ctx, parent_esys_tr, &parent_auth);
            if (tss2_rc != TPM2_RC_SUCCESS) {
                PRINT_E("Esys_TR_SetAuth has failed with: %s", Tss2_RC_Decode(tss2_rc));
                goto exit;
            }
        }

        /* Load the child key objects and create the ESYS_TR object */

        tss2_rc = Esys_Load(esys_ctx, parent_esys_tr, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &priv_tpm2b, &pub_tpm2b, &esys_tr);
        if (tss2_rc != TSS2_RC_SUCCESS) {
            PRINT_E("Esys_Load has failed with: %s", Tss2_RC_Decode(tss2_rc));
            goto exit;
        }

        ADD_ATTR(&pubkey_attrs[pub_attrs_ind++], CKA_TPM2_PUB_BLOB, pub_sz, pub_blob);
        ADD_ATTR(&privkey_attrs[priv_attrs_ind++], CKA_TPM2_PRIV_BLOB, priv_sz, priv_blob);

    } else {
        PRINT_E("Missing inputs. Check the command usage by running: %s --help", argv[0]);
        goto exit;
    }

    /* Set the mechanism and ECC attributes */

    tss2_rc = Esys_ReadPublic(esys_ctx, esys_tr, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &key_public, NULL, NULL);
    if (tss2_rc != TSS2_RC_SUCCESS) {
        PRINT_E("Esys_ReadPublic has failed with: %s", Tss2_RC_Decode(tss2_rc));
        goto exit;
    }

    switch (key_public->publicArea.type) {
    case TPM2_ALG_RSA:
        mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        break;
    case TPM2_ALG_ECC:
        mech.mechanism = CKM_EC_KEY_PAIR_GEN;
        cka_ec_params_len = tpm2_ec_alg_to_asn1(key_public->publicArea.parameters.eccDetail.curveID,
                                                &cka_ec_params);
        if (!cka_ec_params_len || !cka_ec_params) {
            goto exit;
        }

        ADD_ATTR(&pubkey_attrs[pub_attrs_ind++], CKA_EC_PARAMS, cka_ec_params_len, cka_ec_params);
        break;
    default:
        PRINT_E("The given TPM key type is not supported.");
        goto exit;
    }

    /* Finalize the public and private key templates */

    assert(pub_attrs_ind <= ARRAY_LEN(pubkey_attrs));
    assert(priv_attrs_ind <= ARRAY_LEN(privkey_attrs));

    pubkey_attrs_count = pub_attrs_ind;
    privkey_attrs_count = priv_attrs_ind;

    /* Start the key import process */

    if (c_initialize() || c_get_info() || c_get_slot(slot_id) || c_open_session(slot_id, &session)
        || c_login(session, user_pin)
        || c_generate_keypair(session, &mech, pubkey_attrs, pubkey_attrs_count, privkey_attrs,
                              privkey_attrs_count)) {
        goto exit_c;
    }

    ret = 0;

exit_c:
    c_close_session(session);
    c_finalize();
exit:
    pub_f ? fclose(pub_f) : 0;
    priv_f ? fclose(priv_f) : 0;
    free(cka_ec_params);
    free(pub_blob);
    free(priv_blob);
    esys_ctx ? Esys_Finalize(&esys_ctx) : 0;
    tcti ? Tss2_TctiLdr_Finalize(&tcti) : 0;
    free(key_public);
    return ret;
}
