/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include <assert.h>
#include <stdlib.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
 #include <openssl/rsa.h>

#include "attrs.h"
#include "backend.h"
#include "checks.h"
#include "digest.h"
#include "encrypt.h"
#include "log.h"
#include "mech.h"
#include "ssl_util.h"
#include "session.h"
#include "session_ctx.h"
#include "sign.h"
#include "token.h"
#include "tpm.h"

typedef struct sign_opdata sign_opdata;
struct sign_opdata {
    CK_MECHANISM mech;
    bool do_hash;
    twist buffer;
    digest_op_data *digest_opdata;
    encrypt_op_data *crypto_opdata;

    int padding;
    EVP_PKEY *pkey;
    const EVP_MD *md;
};

static sign_opdata *sign_opdata_new(mdetail *mdtl, CK_MECHANISM_PTR mechanism, tobject *tobj) {

    int padding = 0;
    CK_RV rv = mech_get_padding(mdtl,
            mechanism, &padding);
    if (rv != CKR_OK) {
        return NULL;
    }

    const EVP_MD *md = NULL;

    bool is_hashing_needed = false;
    rv = mech_is_hashing_needed(mdtl, mechanism,
            &is_hashing_needed);
    if (rv != CKR_OK) {
        return NULL;
    }

    /*
     * Some algorithms we don't perform the hash, but we need knowledge of
     * the hashing algorithm for verify operations with OSSL
     */
    bool is_hash_knowledge_needed = false;
    rv = mech_is_hashing_knowledge_needed(mdtl, mechanism,
            &is_hash_knowledge_needed);
    if (rv != CKR_OK) {
        return NULL;
    }


    if (is_hashing_needed || is_hash_knowledge_needed) {
        rv = mech_get_digester(mdtl, mechanism, &md);
        if (rv != CKR_OK) {
            return NULL;
        }
    }

    EVP_PKEY *pkey = NULL;
    rv = ssl_util_attrs_to_evp(tobj->attrs, &pkey);
    if (rv != CKR_OK) {
        return NULL;
    }

    sign_opdata *opdata = calloc(1, sizeof(sign_opdata));
    if (!opdata) {
        LOGE("oom");
        return NULL;
    }

    opdata->padding = padding;
    opdata->pkey = pkey;
    opdata->md = md;
    return opdata;
}

static void sign_opdata_free(sign_opdata **opdata) {
    digest_op_data_free(&(*opdata)->digest_opdata);

    if (*opdata && !(*opdata)->do_hash) {
        twist_free((*opdata)->buffer);
    }

    if ((*opdata)->pkey) {
        EVP_PKEY_free((*opdata)->pkey);
    }

    if ((*opdata)->crypto_opdata) {
        encrypt_op_data_free(&(*opdata)->crypto_opdata);
    }

    free(*opdata);

    *opdata = NULL;
}

static CK_RV update_pss_sig_state(token *tok, tobject *tobj) {

    CK_RV rv = CKR_GENERAL_ERROR;

    /*
     * Only test for PSS signature state if it's an RSA object. This avoids printing superfluous errors
     */
    CK_OBJECT_CLASS cka_class = attr_list_get_CKA_CLASS(tobj->attrs, CK_OBJECT_CLASS_BAD);
    if (cka_class != CKK_RSA) {
        return CKR_OK;
    }

    /*
     * Tokens added in previous versions may not have a known PSS signature
     * state, so check and populate here.
     */
    bool pss_sigs_good = false;
    pss_config_state pss_cfg = tok->config.pss_sigs_good;
    if (pss_cfg == pss_config_state_unk) {
        rv = tpm_get_pss_sig_state(tok->tctx, tobj,
                &pss_sigs_good);
        if (rv != CKR_OK) {
            LOGW("Could not determine PSS signature format,"
                    "assuming maximized slen");
            tok->config.pss_sigs_good = pss_sigs_good ?
                    pss_config_state_good : pss_config_state_bad;
        }

        mdetail_set_pss_status(tok->mdtl, pss_sigs_good);
        rv = backend_update_token_config(tok);
        if (rv != CKR_OK) {
            LOGW("Could not update token config backend, moving on");
        }
    }

    return rv;
}

static CK_RV common_init(operation op, session_ctx *ctx, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    check_pointer(mechanism);

    LOGV("mechanism: 0x%lx\n\thas_params: %s\n\tlen: %lu", mechanism->mechanism,
            mechanism->pParameter ? "yes" : "no", mechanism->ulParameterLen);

    CK_RV rv = CKR_GENERAL_ERROR;

    bool is_active = session_ctx_opdata_is_active(ctx);
    if (is_active) {
        return CKR_OPERATION_ACTIVE;
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tobject *tobj = NULL;
    rv = token_load_object(tok, key, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = mech_validate(tok->mdtl, mechanism, tobj->attrs);
    if (rv != CKR_OK) {
        return rv;
    }

    digest_op_data *digest_opdata = NULL;
    bool is_hashing_needed = false;
    rv = mech_is_hashing_needed(tok->mdtl,
            mechanism, &is_hashing_needed);
    if (rv != CKR_OK) {
        return rv;
    }

    if (is_hashing_needed) {

        digest_opdata = digest_op_data_new();
        if (!digest_opdata) {
            return CKR_HOST_MEMORY;
        }

        rv = digest_init_op(ctx, digest_opdata, mechanism);
        if (rv != CKR_OK) {
            digest_op_data_free(&digest_opdata);
            return rv;
        }
    }

    /* TPM is only used on sign operations, not verify. This is because
     * with asymmetric key pairs we can use the public key for verification in SW
     * without needing to involve the TPM. This with HMAC we need to use the TPM
     * verify since the key is only resident in the TPM.
     */
    bool is_hmac = false;
    rv = mech_is_HMAC(tok->mdtl, mechanism, &is_hmac);
    if (rv != CKR_OK) {
        LOGE("Could not determine if algorithm is HMAC or not");
        return rv;
    }

    tpm_op_data *tpm_opdata = NULL;
    if (op == operation_sign || is_hmac) {

        rv = update_pss_sig_state(tok, tobj);
        if (rv != CKR_OK) {
            return rv;
        }

        rv = mech_get_tpm_opdata(tok->mdtl,
                tok->tctx, mechanism, tobj, &tpm_opdata);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    sign_opdata *opdata = sign_opdata_new(tok->mdtl,
            mechanism, tobj);
    if (!opdata) {
        tpm_opdata_free(&tpm_opdata);
        return CKR_HOST_MEMORY;
    }

    opdata->do_hash = is_hashing_needed;
    memcpy(&opdata->mech, mechanism, sizeof(opdata->mech));
    opdata->digest_opdata = digest_opdata;

    opdata->crypto_opdata = encrypt_op_data_new();
    if (!opdata->crypto_opdata) {
        sign_opdata_free(&opdata);
        return CKR_HOST_MEMORY;
    }

    /* Use SW Verify if it's an asymmetric key with pkey set */
    if (op != operation_sign && opdata->pkey) {
        opdata->crypto_opdata->use_sw = true;
        rv = sw_encrypt_data_init(tok->mdtl,
                mechanism, tobj, &opdata->crypto_opdata->cryptopdata.sw_enc_data);
        if (rv != CKR_OK) {
            sign_opdata_free(&opdata);
            return rv;
        }
    } else {
        opdata->crypto_opdata->cryptopdata.tpm_opdata = tpm_opdata;
    }

    /*
     * Store everything for later
     */
    session_ctx_opdata_set(ctx, op, tobj, opdata, (opdata_free_fn)sign_opdata_free);

    return CKR_OK;
}

static CK_RV common_update(operation op, session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len) {

    check_pointer(part);

    CK_RV rv = CKR_GENERAL_ERROR;

    sign_opdata *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, op, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = session_ctx_tobject_authenticated(ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    if (opdata->do_hash) {
        rv = digest_update_op(ctx, opdata->digest_opdata, part, part_len);
        if (rv != CKR_OK) {
            return rv;
        }
    } else {
        twist tmp = twistbin_append(opdata->buffer, part, part_len);
        if (!tmp) {
            return CKR_HOST_MEMORY;
        }
        opdata->buffer = tmp;
    }

    return CKR_OK;
}

CK_RV sign_init(session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_sign, ctx, mechanism, key);
}

CK_RV sign_update(session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len) {

    return common_update(operation_sign, ctx, part, part_len);
}

CK_RV sign_final_ex(session_ctx *ctx, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len, bool is_oneshot) {

    check_pointer(signature_len);

    bool reset_ctx = false;

    CK_RV rv = CKR_GENERAL_ERROR;

    sign_opdata *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, operation_sign, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }
    assert(opdata);

    rv = session_ctx_tobject_authenticated(ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    tobject *tobj = session_ctx_opdata_get_tobject(ctx);
    assert(tobj);

    twist digest_buf = NULL;

    size_t expected_sig_len = 0;
    rv = tobject_get_min_buf_size(tobj, &opdata->mech, &expected_sig_len);
    if (rv != CKR_OK) {
        return rv;
    }

    if (!signature) {
        *signature_len = expected_sig_len;
        goto out;
    }

    if (*signature_len < expected_sig_len) {
        *signature_len = expected_sig_len;
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    if (opdata->do_hash) {

        CK_MECHANISM_TYPE mech_halg;
        rv = mech_get_digest_alg(tok->mdtl,
                &opdata->mech,
                &mech_halg);
        if (rv != CKR_OK) {
            return rv;
        }

        CK_ULONG hash_len = utils_get_halg_size(mech_halg);
        if (!hash_len) {
            LOGE("Hash algorithm cannot have 0 size");
            return CKR_GENERAL_ERROR;
        }

        digest_buf = twist_calloc(hash_len);
        if (!digest_buf) {
            LOGE("oom");
            rv = CKR_HOST_MEMORY;
            goto session_out;
        }

        rv = digest_final_op(ctx, opdata->digest_opdata, (CK_BYTE_PTR)digest_buf, &hash_len);
        if (rv != CKR_OK) {
            goto session_out;
        }
    } else {
        digest_buf = opdata->buffer;
        /* we take ownership of this buffer */
        opdata->buffer = NULL;
    }

    CK_BYTE syn_buf[4096];
    CK_ULONG syn_buf_len = sizeof(syn_buf);
    CK_ULONG digest_buf_len = twist_len(digest_buf);

    bool is_ecc = false;
    rv = mech_is_ecc(tok->mdtl, opdata->mech.mechanism, &is_ecc);
    if (rv != CKR_OK) {
        LOGE("COuld not determine if mechanism is ECC: %lu", rv);
        return rv;
    }

    if (is_ecc && (digest_buf_len > expected_sig_len)) {
        LOGV("Truncating hash for EC Signature from %lu to %lu", digest_buf_len, expected_sig_len);
        digest_buf_len = expected_sig_len;
    }

    rv = mech_synthesize(
            tok->mdtl,
            &opdata->mech, tobj->attrs,
            (CK_BYTE_PTR)digest_buf, digest_buf_len,
            syn_buf, &syn_buf_len);
    if (rv != CKR_OK) {
        goto session_out;
    }

    bool is_synthetic = false;
    rv = mech_is_synthetic(tok->mdtl, &opdata->mech,
            &is_synthetic);
    if (rv != CKR_OK) {
        goto session_out;
    }

    if (is_synthetic) {

        /* sign padded pkcs 1.5 structure */
        encrypt_op_data *encrypt_opdata = encrypt_op_data_new();
        if (!encrypt_opdata) {
            rv = CKR_HOST_MEMORY;
            goto session_out;
        }

        /* perform a RAW RSA encryption */
        CK_MECHANISM mechanism = {
                CKM_RSA_X_509, NULL, 0
        };

        /* RSA Decrypt is the RSA operation with the private key, which is what we want */
        rv = decrypt_init_op(ctx, encrypt_opdata, &mechanism, tobj->obj_handle);
        if (rv != CKR_OK) {
            encrypt_op_data_free(&encrypt_opdata);
            goto session_out;
        }

        rv = decrypt_oneshot_op(ctx, encrypt_opdata, syn_buf, syn_buf_len, signature, signature_len);
        encrypt_op_data_free(&encrypt_opdata);
        if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
            goto session_out;
        }

        /* WORKAROUND / TODO:
           decrypt_init_op above increments the usage counter by one, but never decremented.
           if called for size, decrypt_finalize is never called, thus no decrement.
           if not called for size, decrypt_finalize does not decrement as supplied data was set
           Without reworking the whole logic and breaking other valid use cases it is the easiest
           to decrement the usage counter here.
        */
        CK_RV rv_tmp = tobject_user_decrement(tobj);
        if (rv_tmp != CKR_OK) {
            rv = rv_tmp;
            goto session_out;
        }
    } else {
        rv = tpm_sign(opdata->crypto_opdata->cryptopdata.tpm_opdata,
                syn_buf, syn_buf_len, signature, signature_len);
        if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
            goto session_out;
        }
    }

out:
    /*
     * Detect 1 of 2 states:
     *   - 1 - everything is ok from enc/sign and sig is set (continue normally)
     *   - 2 - buffer too small from enc/sign and sig is set (reset hashing state and keep sign operation alive)
     *   - 3 - everything is ok but sig is NULL, handle like state 2.
     *
     * Reset the hashing state IF we're actually doing the hash internally
     */
    reset_ctx = (rv == CKR_BUFFER_TOO_SMALL || !signature);
    if (reset_ctx) {
        if (opdata->do_hash) {
            /* reset the hashing state */
            digest_op_data *new_digest_state = digest_op_data_new();
            if (!new_digest_state) {
                rv = CKR_HOST_MEMORY;
                reset_ctx = false;
                goto session_out;
            }

            assert(opdata->digest_opdata);

            CK_RV tmp = digest_init_op(ctx, new_digest_state,
                    &opdata->digest_opdata->mechanism);
            if (tmp != CKR_OK) {
                digest_op_data_free(&new_digest_state);
                reset_ctx = false;
                goto session_out;
            }

            digest_op_data_free(&opdata->digest_opdata);
            opdata->digest_opdata = new_digest_state;

        } else if (is_oneshot) {
            twist_free(opdata->buffer);
            opdata->buffer = NULL;
        }
    } else {
        /* not resetting the state, and all is well */
        rv = CKR_OK;
    }

session_out:
    twist_free(digest_buf);
    assert(tobj);
    if (!reset_ctx) {
        tobj->is_authenticated = false;
        CK_RV tmp_rv = tobject_user_decrement(tobj);
        if (tmp_rv != CKR_OK && rv == CKR_OK) {
            rv = tmp_rv;
        }

        encrypt_op_data_free(&opdata->crypto_opdata);
        session_ctx_opdata_clear(ctx);
    }

    return rv;
}

CK_RV sign(session_ctx *ctx, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG *signature_len) {

    CK_RV rv = sign_update(ctx, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }
    return sign_final_ex(ctx, signature, signature_len, true);
}

CK_RV verify_init (session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_verify, ctx, mechanism, key);
}

CK_RV verify_update (session_ctx *ctx, CK_BYTE_PTR part, CK_ULONG part_len) {

    return common_update(operation_verify, ctx, part, part_len);
}

CK_RV verify_final (session_ctx *ctx, CK_BYTE_PTR signature, CK_ULONG signature_len) {

    check_pointer(signature);
    check_pointer(signature_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    sign_opdata *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, operation_verify, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = session_ctx_tobject_authenticated(ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    tobject *tobj = session_ctx_opdata_get_tobject(ctx);
    assert(tobj);

    CK_ULONG data_len = 0;
    CK_BYTE_PTR data = NULL;

    /* buffer has to stay in scope for assignment to data pointer */
    CK_BYTE _buffer[1024];
    if (opdata->do_hash) {
        // TODO mode to buffer size
        CK_ULONG _buffer_len = sizeof(_buffer);
        rv = digest_final_op(ctx, opdata->digest_opdata, _buffer, &_buffer_len);
        if (rv != CKR_OK) {
            goto out;
        }
        data_len = _buffer_len;
        data = _buffer;
    } else {
        data_len = twist_len(opdata->buffer);
        data = (const CK_BYTE_PTR)opdata->buffer;
    }

    if (opdata->pkey) {
        rv = ssl_util_sig_verify(opdata->pkey, opdata->padding, opdata->md,
            data, data_len, signature, signature_len);
    } else {
        rv = tpm_verify(opdata->crypto_opdata->cryptopdata.tpm_opdata, data, data_len, signature, signature_len);
    }

out:
    assert(tobj);
    tobj->is_authenticated = false;
    CK_RV tmp_rv = tobject_user_decrement(tobj);
    if (tmp_rv != CKR_OK && rv == CKR_OK) {
        rv = tmp_rv;
    }

    encrypt_op_data_free(&opdata->crypto_opdata);

    session_ctx_opdata_clear(ctx);

    return rv;
}

CK_RV verify(session_ctx *ctx, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG signature_len) {

    CK_RV rv = verify_update(ctx, data, data_len);
    if (rv != CKR_OK) {
        return rv;
    }

    return verify_final(ctx, signature, signature_len);
}

CK_RV verify_recover_init (session_ctx *ctx, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init(operation_verify_recover, ctx, mechanism, key);
}

CK_RV verify_recover (session_ctx *ctx, CK_BYTE_PTR signature, CK_ULONG signature_len,
        CK_BYTE_PTR data, CK_ULONG_PTR data_len) {

    check_pointer(signature);
    check_pointer(signature_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    sign_opdata *opdata = NULL;
    rv = session_ctx_opdata_get(ctx, operation_verify_recover, &opdata);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = session_ctx_tobject_authenticated(ctx);
    if (rv != CKR_OK) {
        return rv;
    }

    tobject *tobj = session_ctx_opdata_get_tobject(ctx);
    assert(tobj);

    rv = ssl_util_verify_recover(opdata->pkey, opdata->padding, opdata->md,
            signature, signature_len, data, data_len);
    assert(tobj);
    tobj->is_authenticated = false;
    CK_RV tmp_rv = tobject_user_decrement(tobj);
    if (tmp_rv != CKR_OK && rv == CKR_OK) {
        rv = tmp_rv;
    }

    encrypt_op_data_free(&opdata->crypto_opdata);

    session_ctx_opdata_clear(ctx);

    return rv;
}
