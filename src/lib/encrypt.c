/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include "checks.h"
#include "encrypt.h"
#include "session.h"
#include "log.h"
#include "token.h"
#include "tpm.h"

static CK_RV common_init(CK_SESSION_HANDLE session, operation op, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    CK_RSA_PKCS_OAEP_PARAMS_PTR params;

    check_pointer(mechanism);

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    switch (mechanism->mechanism) {
    case CKM_RSA_X_509:
    case CKM_RSA_PKCS:
        break;
    case CKM_RSA_PKCS_OAEP:
        LOGV("OAEP mode selected");
        if (!mechanism->pParameter) {
            LOGE("OAEP without parameters");
            //TODO: Is this a size request ?
            return CKR_MECHANISM_PARAM_INVALID;
        }
        if (mechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
            LOGE("Parameter size invalid, got %li wanted %zi",
                 mechanism->ulParameterLen, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
            return CKR_MECHANISM_PARAM_INVALID;
        }
        params = (CK_RSA_PKCS_OAEP_PARAMS_PTR) mechanism->pParameter;
        if (params->source == CKZ_DATA_SPECIFIED) {
            LOGV("OAEP label of length %li provided.", params->ulSourceDataLen);
            if (!params->pSourceData) {
                LOGE("OAEP label pointer not set.");
                return CKR_MECHANISM_PARAM_INVALID;
            }
            if (params->ulSourceDataLen >
                    sizeof(session_tab[session].opdata.encryptdecrypt.oaep.pSourceData)) {
                LOGE("OAEP param pSourceData too large.");
                return CKR_MECHANISM_PARAM_INVALID;
            }
            memcpy(&session_tab[session].opdata.encryptdecrypt.oaep.pSourceData[0],
                   params->pSourceData, params->ulSourceDataLen);
            session_tab[session].opdata.encryptdecrypt.oaep.ulSourceDataLen =
                    params->ulSourceDataLen;
        } else {
            LOGV("OAEP no label provided.");
            if (params->ulSourceDataLen || params->pSourceData)
                return CKR_MECHANISM_PARAM_INVALID;
            session_tab[session].opdata.encryptdecrypt.oaep.ulSourceDataLen = 0;
        }
        session_tab[session].opdata.encryptdecrypt.oaep.hashAlg = params->hashAlg;
        session_tab[session].opdata.encryptdecrypt.oaep.mgf = params->mgf;
        break;
    default:
        LOGE("Mechanism not supported. Got 0x%lx", mechanism->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    session_tab[session].op = op;
    session_tab[session].opdata.encryptdecrypt.key = key;
    session_tab[session].opdata.encryptdecrypt.mtype = mechanism->mechanism;
    session_tab[session].opdata.encryptdecrypt.cipher_size = 0;
    session_tab[session].opdata.encryptdecrypt.plain_size = 0;

    return CKR_OK;
}

CK_RV decrypt_init(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
    return common_init(session, operation_decrypt, mechanism, key);
}

CK_RV encrypt_init(CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    return common_init(session, operation_encrypt, mechanism, key);
}

CK_RV decrypt_update(CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_part, CK_ULONG encrypted_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) {
    CK_RV rv;

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (session_tab[session].op != operation_decrypt) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (sizeof(session_tab[session].opdata.encryptdecrypt.cipher) -
            session_tab[session].opdata.encryptdecrypt.cipher_size < encrypted_part_len) {
        LOGE("Total encrypted data exceeds internal buffer");
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

    memcpy(&session_tab[session].opdata.encryptdecrypt.cipher[session_tab[session].opdata.encryptdecrypt.cipher_size],
           encrypted_part, encrypted_part_len);
    session_tab[session].opdata.encryptdecrypt.cipher_size += encrypted_part_len;

    //TODO: Check for actually expected initial size
    if (session_tab[session].opdata.encryptdecrypt.cipher_size < 10) {
        LOGV("Part saved, waiting for minimum cipher buffer to start.");
        *part_len = 0;
        return CKR_OK;
    }

    rv = tss_rsa_decrypt(session_tab[session].slot_id,
                         session_tab[session].opdata.encryptdecrypt.key,
                         &session_tab[session].seal[0],
                         session_tab[session].opdata.encryptdecrypt.mtype,
                         &session_tab[session].opdata.encryptdecrypt.oaep,
                         &session_tab[session].opdata.encryptdecrypt.cipher[0],
                         session_tab[session].opdata.encryptdecrypt.cipher_size,
                         &session_tab[session].opdata.encryptdecrypt.plain[0],
                         &session_tab[session].opdata.encryptdecrypt.plain_size);
    if (rv != CKR_OK) {
        LOGE("Encountered error during decryption.");
        return rv;
    }
    //TODO: Assuming that the wholse cipher is consumed for now
    session_tab[session].opdata.encryptdecrypt.cipher_size = 0;

    if (session_tab[session].opdata.encryptdecrypt.plain_size < *part_len)
        *part_len = session_tab[session].opdata.encryptdecrypt.plain_size;

    memcpy(part, &session_tab[session].opdata.encryptdecrypt.plain, *part_len);
    memmove(&session_tab[session].opdata.encryptdecrypt.plain,
            &session_tab[session].opdata.encryptdecrypt.plain[*part_len],
            session_tab[session].opdata.encryptdecrypt.plain_size - *part_len);
    session_tab[session].opdata.encryptdecrypt.plain_size -= *part_len;

    LOGV("Returning %li bytes for this part.", *part_len);

    // TODO check for part==NULL and also return results for encrypted_part_len==0

    return CKR_OK;
}

CK_RV decrypt_final(CK_SESSION_HANDLE session, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {
    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (session_tab[session].op != operation_decrypt) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (session_tab[session].opdata.encryptdecrypt.cipher_size != 0) {
        LOGE("Cipher not fully consumed. %zi bytes left",
             session_tab[session].opdata.encryptdecrypt.cipher_size);
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

    if (!session_tab[session].opdata.encryptdecrypt.plain_size)
        return CKR_OK;

    if (!last_part_len || session_tab[session].opdata.encryptdecrypt.plain_size > *last_part_len) {
        LOGE("Last part buffer too small.");
        return CKR_BUFFER_TOO_SMALL;
    }

    *last_part_len = session_tab[session].opdata.encryptdecrypt.plain_size;
    memcpy(last_part, &session_tab[session].opdata.encryptdecrypt.plain, *last_part_len);

    return CKR_OK;
}

CK_RV decrypt_oneshot(CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_data, CK_ULONG encrypted_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {

    CK_RV rv = decrypt_update(session, encrypted_data, encrypted_data_len,
            data, data_len);
    if (rv != CKR_OK || !data) {
        return rv;
    }

    return decrypt_final(session, NULL, NULL);
}

CK_RV encrypt_update (CK_SESSION_HANDLE session,
        CK_BYTE_PTR part, CK_ULONG part_len,
        CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {

    CK_RV rv;

    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (session_tab[session].op != operation_encrypt) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (sizeof(session_tab[session].opdata.encryptdecrypt.plain) -
            session_tab[session].opdata.encryptdecrypt.plain_size < part_len) {
        LOGE("Total encrypted data exceeds internal buffer");
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

    memcpy(&session_tab[session].opdata.encryptdecrypt.plain[
               session_tab[session].opdata.encryptdecrypt.plain_size],
           part, part_len);
    session_tab[session].opdata.encryptdecrypt.plain_size += part_len;

    //TODO: Check for actually expected initial size
    if (session_tab[session].opdata.encryptdecrypt.plain_size < 10) {
        LOGV("Part saved, waiting for minimum plaintext buffer to start.");
        *encrypted_part_len = 0;
        return CKR_OK;
    }

    rv = CKR_OK;
    //TODO
/*    rv = tss_rsa_encrypt(session_tab[session].slot_id,
                         session_tab[session].opdata.encryptdecrypt.key,
                         session_tab[session].opdata.encryptdecrypt.mtype,
                         &session_tab[session].opdata.encryptdecrypt.oaep,
                         &session_tab[session].opdata.encryptdecrypt.plain[0],
                         session_tab[session].opdata.encryptdecrypt.plain_size);
                         &session_tab[session].opdata.encryptdecrypt.cipher[0],
                         &session_tab[session].opdata.encryptdecrypt.cipher_size,
*/    if (rv != CKR_OK) {
        LOGE("Encountered error during decryption.");
        return rv;
    }
    //TODO: Assuming that the whole plaintext is consumed for now
    session_tab[session].opdata.encryptdecrypt.plain_size = 0;

    if (session_tab[session].opdata.encryptdecrypt.cipher_size < *encrypted_part_len)
        *encrypted_part_len = session_tab[session].opdata.encryptdecrypt.cipher_size;

    memcpy(encrypted_part, &session_tab[session].opdata.encryptdecrypt.cipher,
           *encrypted_part_len);
    memmove(&session_tab[session].opdata.encryptdecrypt.cipher,
            &session_tab[session].opdata.encryptdecrypt.cipher[*encrypted_part_len],
            session_tab[session].opdata.encryptdecrypt.cipher_size - *encrypted_part_len);
    session_tab[session].opdata.encryptdecrypt.cipher_size -= *encrypted_part_len;

    LOGV("Returning %li bytes for this part.", *encrypted_part_len);

    // TODO check for encrypted_part==NULL and also return results for part_len==0

    return CKR_OK;
}

CK_RV encrypt_final(CK_SESSION_HANDLE session, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {
    if (session_tab[session].slot_id == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (session_tab[session].op != operation_encrypt) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (session_tab[session].opdata.encryptdecrypt.plain_size != 0) {
        LOGE("Plaintext not fully consumed. %zi bytes left",
             session_tab[session].opdata.encryptdecrypt.plain_size);
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

    if (!session_tab[session].opdata.encryptdecrypt.cipher_size)
        return CKR_OK;

    if (!last_part_len || session_tab[session].opdata.encryptdecrypt.cipher_size > *last_part_len) {
        LOGE("Last part buffer too small.");
        return CKR_BUFFER_TOO_SMALL;
    }

    *last_part_len = session_tab[session].opdata.encryptdecrypt.cipher_size;
    memcpy(last_part, &session_tab[session].opdata.encryptdecrypt.cipher, *last_part_len);

    return CKR_OK;
}

CK_RV encrypt_oneshot(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len) {

    CK_RV rv = encrypt_update (session, data, data_len, encrypted_data, encrypted_data_len);
    if (rv != CKR_OK || !encrypted_data) {
        return rv;
    }

    return encrypt_final(session, NULL, NULL);
}
