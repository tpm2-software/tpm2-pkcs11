/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "checks.h"
#include "encrypt.h"
#include "mech.h"
#include "ssl_util.h"
#include "session.h"
#include "session_ctx.h"
#include "token.h"
#include "tpm.h"
#include "twist.h"

typedef CK_RV (*crypto_op)(crypto_op_data *enc_data, CK_BYTE_PTR in, CK_ULONG inlen, CK_BYTE_PTR out, CK_ULONG_PTR outlen);

static sw_encrypt_data *sw_encrypt_data_new(void) {

    return (sw_encrypt_data *)calloc(1, sizeof(sw_encrypt_data));
}

static void sw_encrypt_data_free(sw_encrypt_data **enc_data) {

    if (!enc_data || !*enc_data) {
        return;
    }

    if ((*enc_data)->key) {
        EVP_PKEY_free((*enc_data)->key);
    }

    twist_free((*enc_data)->label);

    free(*enc_data);
    *enc_data = NULL;
}

encrypt_op_data *encrypt_op_data_new(void) {

    return (encrypt_op_data *)calloc(1, sizeof(encrypt_op_data));
}

void encrypt_op_data_free(encrypt_op_data **opdata) {

    if (opdata) {
        (*opdata)->use_sw ?
                sw_encrypt_data_free(&(*opdata)->cryptopdata.sw_enc_data) :
                tpm_opdata_free(&(*opdata)->cryptopdata.tpm_opdata);
        free(*opdata);
        *opdata = NULL;
    }
}

CK_RV sw_encrypt_data_init(mdetail *mdtl, CK_MECHANISM *mechanism, tobject *tobj, sw_encrypt_data **enc_data) {

    EVP_PKEY *pkey = NULL;
    CK_RV rv = ssl_util_attrs_to_evp(tobj->attrs, &pkey);
    if (rv != CKR_OK) {
        return rv;
    }

    int padding = 0;
    rv = mech_get_padding(mdtl, mechanism, &padding);
    if (rv != CKR_OK) {
        return rv;
    }

    const EVP_MD *md = NULL;
    bool is_hashing_needed = false;
    rv = mech_is_hashing_needed(
            mdtl,
            mechanism,
            &is_hashing_needed);
    if (rv != CKR_OK) {
        return rv;
    }

    if (is_hashing_needed) {
        rv = mech_get_digester(mdtl, mechanism, &md);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    twist label = NULL;
    rv = mech_get_label(mechanism, &label);
    if (rv != CKR_OK) {
        return rv;
    }

    sw_encrypt_data *d = sw_encrypt_data_new();
    if (!d) {
        LOGE("oom");
        twist_free(label);
        EVP_PKEY_free(pkey);
        return CKR_HOST_MEMORY;
    }

    d->key = pkey;
    d->padding = padding;
    d->label = label;
    d->md = md;

    *enc_data = d;

    return CKR_OK;
}

static CK_RV sw_encrypt(crypto_op_data *opdata,
        CK_BYTE_PTR ptext, CK_ULONG ptextlen,
        CK_BYTE_PTR ctext, CK_ULONG_PTR ctextlen) {
    assert(opdata);

    sw_encrypt_data *sw_enc_data = opdata->sw_enc_data;

    assert(sw_enc_data);
    assert(sw_enc_data->key);

    return ssl_util_encrypt(sw_enc_data->key,
            sw_enc_data->padding,
            sw_enc_data->label,
            sw_enc_data->md,
            ptext, ptextlen,
            ctext, ctextlen);
}

static CK_RV common_init_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, operation op, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

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
        CK_RV rv = session_ctx_opdata_can_start(ctx, op);
        if (rv != CKR_OK) {
            return rv;
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

    /*
     * A key's TPM attributes may allow more than its CKA_ENCRYPT and CKA_DECRYPT: an RSA signing key
     * has the TPM's decrypt attribute, for the signatures padded in software, and an AES key that
     * allows neither still has one, since the TPM makes no key without. So C_EncryptInit and
     * C_DecryptInit check them. The internal callers (supplied opdata) are those signatures. A key
     * without the attribute predates this, and is let through.
     */
    if (!supplied_opdata) {
        CK_BBOOL allowed = op == operation_decrypt
                ? attr_list_get_CKA_DECRYPT(tobj->attrs, CK_TRUE)
                : attr_list_get_CKA_ENCRYPT(tobj->attrs, CK_TRUE);
        if (!allowed) {
            LOGE("The key doesn't allow %s (%s=false)",
                    op == operation_decrypt ? "decryption" : "encryption",
                    op == operation_decrypt ? "CKA_DECRYPT" : "CKA_ENCRYPT");
            tobject_user_decrement(tobj);
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
    }

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_CLASS);
    if (!a) {
        LOGE("Expected tobject to have attribute CKA_CLASS");
        return CKR_GENERAL_ERROR;
    }

    CK_OBJECT_CLASS obj_class = 0;
    rv = attr_CK_OBJECT_CLASS(a, &obj_class);
    if (rv != CKR_OK) {
        LOGE("Could not convert CKA_CLASS");
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
     * Public Key Objects don't need to hit the TPM
     */
    if (obj_class == CKO_PUBLIC_KEY) {
        opdata->use_sw = true;
        rv = sw_encrypt_data_init(tok->mdtl, mechanism, tobj, &opdata->cryptopdata.sw_enc_data);
    } else {
        rv = mech_get_tpm_opdata(tok->mdtl,
                tok->tctx, mechanism, tobj,
                &opdata->cryptopdata.tpm_opdata);
    }

    if (rv != CKR_OK) {
        tobject_user_decrement(tobj);
        if (!supplied_opdata) {
            encrypt_op_data_free(&opdata);
        }
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

    encrypt_op_data *opdata = NULL;
    if (!supplied_opdata) {
        rv = session_ctx_opdata_get(ctx, op, &opdata);
        if (rv != CKR_OK) {
            return rv;
        }

        rv = session_ctx_tobject_authenticated(ctx, op);
        if (rv != CKR_OK) {
            return rv;
        }
    } else {
        opdata = supplied_opdata;
    }

    /*
     * Public key crypto operations have the use_sw flag set. Currently,
     * they are restricted to working only with RSA AFAIK. Thus,
     * they only perform RSA Encrypt (RSA operation w/pub key). Thus, the
     * SW path will always call sw_encrypt.
     *
     * If we add proper EC support, we likely need a sw_decrypt interface
     * that does the right thing with respect to EC and RSA. For RSA it
     * should always call Encrypt and for EC, likely can do Encrypt.
     */
    crypto_op fop;
    switch(op) {
    case operation_encrypt:
        fop = opdata->use_sw ? sw_encrypt : tpm_encrypt;
        break;
    case operation_decrypt:
        fop = opdata->use_sw ? sw_encrypt : tpm_decrypt;
        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    rv = fop(&opdata->cryptopdata, part, part_len,
            encrypted_part, encrypted_part_len);

    /*
     * An error ends the operation, as PKCS#11 has it for C_EncryptUpdate/C_DecryptUpdate and for
     * C_Encrypt/C_Decrypt, whose first step this is: else the next C_*Init, after a ciphertext the TPM
     * refused, say, would find the operation still active.
     */
    if (!supplied_opdata && rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
        session_ctx_cancel(ctx, op == operation_encrypt ? CKF_ENCRYPT : CKF_DECRYPT);
    }

    return rv;
}

static CK_RV common_final_op(session_ctx *ctx, encrypt_op_data *supplied_opdata, operation op,
        CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len, bool is_oneshot) {

    check_pointer(last_part_len);

    bool reset_ctx = false;
    CK_RV rv = CKR_GENERAL_ERROR;

    encrypt_op_data *opdata = supplied_opdata;
    if (!opdata) {
        rv = session_ctx_opdata_get(ctx, op, &opdata);
        if (rv != CKR_OK) {
            return rv;
        }

        rv = session_ctx_tobject_authenticated(ctx, op);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    assert(opdata);

    /* the internal callers (supplied opdata) release their key themselves */
    tobject *tobj = NULL;
    if (!supplied_opdata) {
        tobj = session_ctx_opdata_get_tobject(ctx, op);
        assert(tobj);
    }

    /* we may have some TPM symmetric data to deal with */
    if (!opdata->use_sw) {

        rv = (op == operation_encrypt) ?
            tpm_final_encrypt(&opdata->cryptopdata, last_part, last_part_len) :
            tpm_final_decrypt(&opdata->cryptopdata, last_part, last_part_len);
        if (rv != CKR_OK) {
            goto out;
        }

    } else {
        /*
         * RSA with the public key, in software, holds nothing back: there is no last part, whether
         * this is a length query or not. Else C_Encrypt would add the rest of the caller's buffer to
         * the length of the ciphertext.
         */
        *last_part_len = 0;
    }

    rv = CKR_OK;

out:
    /*
     * we're only done if last_part is specified or the buffer isn't too small
     *
     * We also don't want to decrement the tobject unless we're using session ctx
     * not internal routines.
     */
    reset_ctx = (rv == CKR_BUFFER_TOO_SMALL || (!last_part && rv == CKR_OK));
    if (reset_ctx) {
        if (is_oneshot && !opdata->use_sw) {
            tpm_opdata_reset(opdata->cryptopdata.tpm_opdata);
        }
        /*
         * all is well, we reset the command context; a buffer too small for C_EncryptFinal or
         * C_DecryptFinal says so, for the call to be made again with a bigger one. A length query
         * that fails, on bad padding say, ends the operation with its error, as any other call.
         */
        if (is_oneshot) {
            rv = CKR_OK;
        }
    } else if(!supplied_opdata) {
        /* end the command context */
        tobj->is_authenticated = false;
        if (!supplied_opdata) {
            session_ctx_opdata_clear(ctx, op);
        }

        CK_RV tmp_rv = tobject_user_decrement(tobj);
        if (tmp_rv != CKR_OK && rv == CKR_OK) {
            rv = tmp_rv;
        }
    }

    return rv;
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

CK_RV encrypt_final_ex (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR last_encrypted_part, CK_ULONG_PTR last_encrypted_part_len, bool is_oneshot) {

    return common_final_op(ctx, supplied_opdata, operation_encrypt, last_encrypted_part, last_encrypted_part_len, is_oneshot);
}

CK_RV decrypt_final_ex (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len, bool is_oneshot) {

    return common_final_op(ctx, supplied_opdata, operation_decrypt, last_part, last_part_len, is_oneshot);
}

/* Marks the session's operation multi-part once an update succeeds. */
static CK_RV session_update(operation op, session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len,
        CK_BYTE_PTR out, CK_ULONG_PTR out_len) {

    CK_RV rv = op == operation_encrypt
            ? encrypt_update_op(ctx, NULL, part, part_len, out, out_len)
            : decrypt_update_op(ctx, NULL, part, part_len, out, out_len);
    if (rv != CKR_OK) {
        return rv;
    }

    encrypt_op_data *opdata = NULL;
    if (session_ctx_opdata_get(ctx, op, &opdata) == CKR_OK) {
        opdata->updated = true;
    }

    return CKR_OK;
}

CK_RV encrypt_update (session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {
    return session_update(operation_encrypt, ctx, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV decrypt_update (session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
    return session_update(operation_decrypt, ctx, part, part_len, data, data_len);
}

/*
 * C_Encrypt/C_Decrypt are single-part: after an update they are refused, and, as any but a length
 * query, end the operation.
 */
static CK_RV refuse_after_update(operation op, session_ctx *ctx) {

    encrypt_op_data *opdata = NULL;
    if (session_ctx_opdata_get(ctx, op, &opdata) == CKR_OK && opdata->updated) {
        LOGE("Single-part call after an update: end a multi-part operation with its *Final");
        session_ctx_cancel(ctx, op == operation_encrypt ? CKF_ENCRYPT : CKF_DECRYPT);
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    return CKR_OK;
}

CK_RV decrypt_oneshot_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR encrypted_data, CK_ULONG encrypted_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {

    check_pointer(data_len);

    if (!supplied_opdata) {
        CK_RV rv = refuse_after_update(operation_decrypt, ctx);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    bool is_buffer_too_small = false;
    CK_ULONG tmp_len = *data_len;

    CK_RV rv = decrypt_update_op(ctx, supplied_opdata, encrypted_data, encrypted_data_len,
            data, &tmp_len);
    if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
        return rv;
    }

    CK_ULONG update_len = tmp_len;
    if (rv == CKR_BUFFER_TOO_SMALL) {
        data = NULL;
        is_buffer_too_small = true;
    } else {
        if (data) {
            data = &data[update_len];
            assert(tmp_len <= *data_len);
        }
        tmp_len = *data_len - tmp_len;
    }

    rv = decrypt_final_ex(ctx, supplied_opdata, data, &tmp_len, true);
    *data_len = update_len + tmp_len;
    return !is_buffer_too_small ? rv : CKR_BUFFER_TOO_SMALL;
}

CK_RV encrypt_oneshot_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len) {

    check_pointer(encrypted_data_len);

    if (!supplied_opdata) {
        CK_RV rv = refuse_after_update(operation_encrypt, ctx);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    bool is_buffer_too_small = false;
    CK_ULONG tmp_len = *encrypted_data_len;

    CK_RV rv = encrypt_update_op (ctx, supplied_opdata, data, data_len, encrypted_data, &tmp_len);
    if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
        return rv;
    }

    CK_ULONG update_len = tmp_len;
    if (rv == CKR_BUFFER_TOO_SMALL) {
        encrypted_data = NULL;
        is_buffer_too_small = true;
    } else {
        if (encrypted_data) {
            encrypted_data = &encrypted_data[update_len];
            assert(tmp_len <= *encrypted_data_len);
        }
        tmp_len = *encrypted_data_len - tmp_len;
    }

    rv = encrypt_final_ex(ctx, supplied_opdata, encrypted_data, &tmp_len, true);
    *encrypted_data_len = update_len + tmp_len;
    return !is_buffer_too_small ? rv : CKR_BUFFER_TOO_SMALL;
}
