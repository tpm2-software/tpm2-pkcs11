/* SPDX-License-Identifier: BSD-2-Clause */

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "checks.h"
#include "encrypt.h"
#include "openssl_compat.h"
#include "session.h"
#include "session_ctx.h"
#include "token.h"
#include "tpm.h"

struct sw_encrypt_data {
    int padding;
    RSA *key;
};

typedef CK_RV (*crypto_op)(crypto_op_data *enc_data, CK_BYTE_PTR in, CK_ULONG inlen, CK_BYTE_PTR out, CK_ULONG_PTR outlen);

static sw_encrypt_data *sw_encrypt_data_new(void) {

    return (sw_encrypt_data *)calloc(1, sizeof(sw_encrypt_data));
}

static void sw_encrypt_data_free(sw_encrypt_data *enc_data) {
    if (!enc_data) {
        return;
    }

    if (enc_data->key) {
        RSA_free(enc_data->key);
    }

    free(enc_data);
}

encrypt_op_data *encrypt_op_data_new(void) {

    return (encrypt_op_data *)calloc(1, sizeof(encrypt_op_data));
}

void encrypt_op_data_free(encrypt_op_data **opdata) {

    if (opdata) {
        (*opdata)->use_sw ?
                sw_encrypt_data_free((*opdata)->cryptopdata.sw_enc_data) :
                tpm_encrypt_data_free((*opdata)->cryptopdata.tpm_enc_data);
        free(*opdata);
        *opdata = NULL;
    }
}

static CK_RV sw_encrypt_data_init(CK_MECHANISM *mechanism, tobject *tobj, sw_encrypt_data **enc_data) {

    BIGNUM *e = NULL;
    BIGNUM *n = NULL;
    RSA *r = NULL;

    CK_RV rv = CKR_GENERAL_ERROR;

    /* we only support one mechanism via this path right now */
    if (mechanism->mechanism != CKM_RSA_PKCS) {
        LOGE("Cannot synthesize mechanism for key");
        return CKR_MECHANISM_INVALID;
    }

    /*
     * We know this in RSA key since we checked the mechanism,
     * create the OSSL key
     */
    r = RSA_new();
    if (!r) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_MODULUS);
    if (!a) {
        LOGE("Expected RSA key to have modulus");
        goto error;
    }

    n = BN_bin2bn(a->pValue, a->ulValueLen, NULL);
    if (!n) {
        LOGE("Could not create BN from modulus");
        goto error;
    }

    a = attr_get_attribute_by_type(tobj->attrs, CKA_PUBLIC_EXPONENT);
    if (!a) {
        LOGE("Expected RSA key to have exponent");
        goto error;
    }

    e = BN_bin2bn(a->pValue, a->ulValueLen, NULL);
    if (!e) {
        LOGE("Could not create BN from exponent");
        goto error;
    }

    int rc = RSA_set0_key(r, n, e, NULL);
    if (!rc) {
        LOGE("Could not set RSA public key from parts");
        goto error;
    }

    /* ownership of memory transferred */
    n = NULL;
    e = NULL;

    sw_encrypt_data *d = sw_encrypt_data_new();
    if (!d) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    d->key = r;
    d->padding = RSA_PKCS1_PADDING;

    *enc_data = d;

    return CKR_OK;
error:
    if (n) {
        BN_free(n);
    }
    if (e) {
        BN_free(e);
    }
    return rv;
}

CK_RV sw_encrypt(crypto_op_data *opdata,
        CK_BYTE_PTR ptext, CK_ULONG ptextlen,
        CK_BYTE_PTR ctext, CK_ULONG_PTR ctextlen) {
    assert(opdata);

    sw_encrypt_data *sw_enc_data = opdata->sw_enc_data;

    assert(sw_enc_data);
    assert(sw_enc_data->key);

    RSA *r = sw_enc_data->key;
    int padding = sw_enc_data->padding;

    /* make sure destination is big enough */
    int to_len = RSA_size(r);
    if (to_len < 0) {
        LOGE("RSA_Size cannot be 0");
        return CKR_GENERAL_ERROR;
    }

    if ((CK_ULONG)to_len > *ctextlen) {
        *ctextlen = to_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    int rc = RSA_public_encrypt(ptextlen, ptext,
        ctext, r, padding);
    if (!rc) {
        LOGE("Could not perform RSA public encrypt");
        return CKR_GENERAL_ERROR;
    }

    assert(rc > 0);

    *ctextlen = rc;

    return CKR_OK;
}

CK_RV sw_decrypt(crypto_op_data *opdata,
        CK_BYTE_PTR ctext, CK_ULONG ctextlen,
        CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen) {
    assert(opdata);

    CK_RV rv = CKR_GENERAL_ERROR;

    sw_encrypt_data *sw_enc_data = opdata->sw_enc_data;

    assert(sw_enc_data);
    assert(sw_enc_data->key);

    RSA *r = sw_enc_data->key;
    int padding = sw_enc_data->padding;
    int to_len = RSA_size(r);
    if (to_len <= 0) {
        LOGE("Expected buffer size to be > 0, got: %d", to_len);
        return CKR_GENERAL_ERROR;
    }

    unsigned char *buffer = calloc(1, to_len);
    if (!buffer) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    int rc = RSA_public_decrypt(ctextlen, ctext, buffer, r, padding);
    if (rc <= 0) {
        LOGE("Could not perform RSA public decrypt: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }
    assert(rc > 0);

    if (*ptextlen > (CK_ULONG)rc) {
        *ptextlen = rc;
        free(buffer);
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(ptext, buffer, rc);
    *ptextlen = rc;

    rv = CKR_OK;

out:
    free(buffer);
    return rv;
}

static CK_RV common_init_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, operation op, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    check_pointer(mechanism);

    LOGV("mechanism->mechanism: %lu\n"
            "mechanism->ulParameterLen: %lu\n"
            "mechanism->pParameter: %s",
            mechanism->mechanism,
            mechanism->ulParameterLen,
            mechanism->pParameter ? "set" : "(null)");

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    if (!supplied_opdata) {
        bool is_active = session_ctx_opdata_is_active(ctx);
        if (is_active) {
            return CKR_OPERATION_ACTIVE;
        }
    }

    tobject *tobj;
    CK_RV rv = token_load_object(tok, key, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = object_mech_is_supported(tobj, mechanism);
    if (rv != CKR_OK) {
        tobject_user_decrement(tobj);
        return rv;
    }

    encrypt_op_data *opdata;
    if (!supplied_opdata) {
        opdata = encrypt_op_data_new();
        if (!opdata) {
            tobject_user_decrement(tobj);
            return CKR_HOST_MEMORY;
        }
    } else {
        opdata = supplied_opdata;
    }

    /*
     * Objects that don't have a tpm pub pointer blob are things like public key
     * only object and don't go to the TPM.
     */
    if (tobj->pub) {
       rv = tpm_encrypt_data_init(tok->tctx, tobj->handle, tobj->unsealed_auth, mechanism,
               &opdata->cryptopdata.tpm_enc_data);
    } else {
        opdata->use_sw = true;
        rv = sw_encrypt_data_init(mechanism, tobj, &opdata->cryptopdata.sw_enc_data);
    }

    if (rv != CKR_OK) {
        tobject_user_decrement(tobj);
        encrypt_op_data_free(&opdata);
        return rv;
    }

    if (!supplied_opdata) {
        session_ctx_opdata_set(ctx, op, tobj, opdata, (opdata_free_fn)encrypt_op_data_free);
    }

    return CKR_OK;
}

static CK_RV common_update_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, operation op,
        CK_BYTE_PTR part, CK_ULONG part_len,
        CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {

    check_pointer(part);
    check_pointer(encrypted_part_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    twist input = twistbin_new(part, part_len);
    if (!input) {
        return CKR_HOST_MEMORY;
    }

    twist output = NULL;

    encrypt_op_data *opdata = NULL;
    if (!supplied_opdata) {
        rv = session_ctx_opdata_get(ctx, op, &opdata);
        if (rv != CKR_OK) {
            goto out;
        }

        rv = session_ctx_tobject_authenticated(ctx);
        if (rv != CKR_OK) {
            goto out;
        }
    } else {
        opdata = supplied_opdata;
    }

    crypto_op fop;
    switch(op) {
    case operation_encrypt:
        fop = opdata->use_sw ? sw_encrypt : tpm_encrypt;
        break;
    case operation_decrypt:
        fop = opdata->use_sw ? sw_decrypt : tpm_decrypt;
        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    rv = fop(&opdata->cryptopdata, part, part_len,
            encrypted_part, encrypted_part_len);
    if (rv != CKR_OK) {
        goto out;
    }

    rv = CKR_OK;

out:
    twist_free(input);
    twist_free(output);

    return rv;
}

static CK_RV common_final_op(session_ctx *ctx, encrypt_op_data *supplied_opdata, operation op,
        CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {

    /*
     * We have no use for these.
     */
    UNUSED(last_part);
    UNUSED(last_part_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    /* nothing to do if opdata is supplied externally */
    if (supplied_opdata) {
        /* do not goto out, no opdata to clear */
        return CKR_OK;
    }

    encrypt_op_data *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, op, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = session_ctx_tobject_authenticated(ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    tobject *tobj = session_ctx_opdata_get_tobject(ctx);
    assert(tobj);
    tobj->is_authenticated = false;
    rv = tobject_user_decrement(tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    session_ctx_opdata_clear(ctx);

    return CKR_OK;
}

CK_RV encrypt_init_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init_op(ctx, supplied_opdata, operation_encrypt, mechanism, key);
}

CK_RV decrypt_init_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init_op(ctx, supplied_opdata, operation_decrypt, mechanism, key);
}

CK_RV encrypt_update_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {

    return common_update_op(ctx, supplied_opdata, operation_encrypt, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV decrypt_update_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {

    return common_update_op(ctx, supplied_opdata, operation_decrypt, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV encrypt_final_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR last_encrypted_part, CK_ULONG_PTR last_encrypted_part_len) {

    return common_final_op(ctx, supplied_opdata, operation_encrypt, last_encrypted_part, last_encrypted_part_len);
}

CK_RV decrypt_final_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {

    return common_final_op(ctx, supplied_opdata, operation_decrypt, last_part, last_part_len);
}

CK_RV decrypt_oneshot_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR encrypted_data, CK_ULONG encrypted_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {

    CK_RV rv = decrypt_update_op(ctx, supplied_opdata, encrypted_data, encrypted_data_len,
            data, data_len);
    if (rv != CKR_OK || !data) {
        return rv;
    }

    return decrypt_final_op(ctx, supplied_opdata, NULL, NULL);
}

CK_RV encrypt_oneshot_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len) {

    CK_RV rv = encrypt_update_op (ctx, supplied_opdata, data, data_len, encrypted_data, encrypted_data_len);
    if (rv != CKR_OK || !encrypted_data) {
        return rv;
    }

    return encrypt_final_op(ctx, supplied_opdata, NULL, NULL);
}
