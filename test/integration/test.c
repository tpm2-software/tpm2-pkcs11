#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include "test.h"

test_info *test_info_from_state(void **state) {
    return (test_info *)*state;
}

int group_setup(void **state) {
    UNUSED(state);

    /* Initialize the library */
    CK_RV rv = C_Initialize(NULL);
    assert_int_equal(rv, CKR_OK);

    return 0;
}

int group_setup_locking(void **state) {
    UNUSED(state);

    /*
     * Run these tests with locking enabled
     */
    CK_C_INITIALIZE_ARGS args = {
        .CreateMutex = NULL,
        .DestroyMutex = NULL,
        .LockMutex = NULL,
        .UnlockMutex = NULL,
        .flags = CKF_OS_LOCKING_OK
    };

    CK_RV rv = C_Initialize(&args);
    assert_int_equal(rv, CKR_OK);

    return 0;
}

int group_teardown(void **state) {
    UNUSED(state);

    /* Finalize the library */
    CK_RV rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);

    return 0;
}

void logout_expects(CK_SESSION_HANDLE handle, CK_RV expected) {

    CK_RV rv = C_Logout(handle);
    assert_int_equal(rv, expected);
}

void logout(CK_SESSION_HANDLE handle) {

    logout_expects(handle, CKR_OK);
}

void login_expects(CK_SESSION_HANDLE handle, CK_USER_TYPE user_type, CK_RV expected, unsigned char *pin, CK_ULONG len) {

    CK_RV rv = C_Login(handle, user_type, pin, len);
    assert_int_equal(rv, expected);
}

void user_login_expects(CK_SESSION_HANDLE handle, CK_RV expected) {

    unsigned char upin[] = GOOD_USERPIN;
    login_expects(handle, CKU_USER, expected, upin, sizeof(upin) - 1);
}

void user_login_bad_pin(CK_SESSION_HANDLE handle) {

    unsigned char upin[] = BAD_USERPIN;
    login_expects(handle, CKU_USER, CKR_PIN_INCORRECT, upin, sizeof(upin) - 1);
}

void user_login(CK_SESSION_HANDLE handle) {

    user_login_expects(handle, CKR_OK);
}

void context_login_expects(CK_SESSION_HANDLE handle, CK_RV expected) {

    unsigned char upin[] = GOOD_USERPIN;
    login_expects(handle, CKU_CONTEXT_SPECIFIC, expected, upin, sizeof(upin) - 1);
}

void context_login(CK_SESSION_HANDLE handle) {

    unsigned char upin[] = GOOD_USERPIN;
    login_expects(handle, CKU_CONTEXT_SPECIFIC, CKR_OK, upin, sizeof(upin) - 1);
}

void context_login_bad_pin(CK_SESSION_HANDLE handle) {

    unsigned char upin[] = BAD_USERPIN;
    login_expects(handle, CKU_CONTEXT_SPECIFIC, CKR_PIN_INCORRECT, upin, sizeof(upin) - 1);
}


void so_login_expects(CK_SESSION_HANDLE handle, CK_RV expected) {

    unsigned char sopin[] = GOOD_SOPIN;
    login_expects(handle, CKU_SO, expected, sopin, sizeof(sopin) - 1);
}

void so_login(CK_SESSION_HANDLE handle) {

    so_login_expects(handle, CKR_OK);
}

void so_login_bad_pin(CK_SESSION_HANDLE handle) {

    unsigned char sopin[] = BAD_SOPIN;
    login_expects(handle, CKU_SO, CKR_PIN_INCORRECT, sopin, sizeof(sopin) - 1);
}

void get_keypair(CK_SESSION_HANDLE session, CK_KEY_TYPE key_type, CK_OBJECT_HANDLE_PTR pub_handle, CK_OBJECT_HANDLE_PTR priv_handle) {

    assert_non_null(pub_handle);
    assert_non_null(priv_handle);

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_CLASS, &key_class, sizeof(key_class)  },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
    };

    CK_RV rv = C_FindObjectsInit(session, priv_tmpl, ARRAY_LEN(priv_tmpl));
    assert_int_equal(rv, CKR_OK);

    /* Find an RSA key priv at index 0 pub at index 1 */
    CK_ULONG count;
    rv = C_FindObjects(session, priv_handle, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* got private now fnd public based on CKA_ID */
    key_class = CKO_PUBLIC_KEY;
    CK_BYTE _tmp_buf[1024];
    CK_ATTRIBUTE pub_tmpl[] = {
        { .type = CKA_ID, .ulValueLen = sizeof(_tmp_buf), .pValue = _tmp_buf },
        { CKA_CLASS, &key_class, sizeof(key_class)  },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
    };

    /* populate the CKA_ID field for the public object template */
    rv = C_GetAttributeValue(session, *priv_handle, pub_tmpl, 1);
    assert_int_equal(rv, CKR_OK);

    /* use public template + CKA_ID to find proper public object */
    rv = C_FindObjectsInit(session, pub_tmpl, ARRAY_LEN(pub_tmpl));
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjects(session, pub_handle, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);
}

GENERIC_ATTR_TYPE_CONVERT(CK_BBOOL);
GENERIC_ATTR_TYPE_CONVERT(CK_ULONG);

static void verify_missing_common_attrs_rsa(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {

    CK_BYTE tmp[3][256] = { 0 };

    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_MODULUS,  tmp[0]),
            ADD_ATTR_ARRAY(CKA_MODULUS_BITS,  tmp[1]),
            ADD_ATTR_ARRAY(CKA_PUBLIC_EXPONENT, tmp[2]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG count = 0;

    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        case CKA_MODULUS: {
            assert_int_not_equal(0, a->ulValueLen);
            assert_non_null(a->pValue);
            count++;
        } break;
        case CKA_MODULUS_BITS: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, 2048);
            count++;
        } break;
        case CKA_PUBLIC_EXPONENT:
            assert_int_not_equal(0, a->ulValueLen);
            assert_non_null(a->pValue);
            count++;
            break;
        default:
            assert_true(0);
        }
    }

    assert_int_equal(count, ARRAY_LEN(attrs));
}

void verify_missing_priv_attrs_rsa(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {
    verify_missing_common_attrs_rsa(session, h);
}

void verify_missing_pub_attrs_rsa(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {
    verify_missing_common_attrs_rsa(session, h);
}

static void test_ec_params(CK_ATTRIBUTE_PTR ecparams) {

    const unsigned char *p = ecparams->pValue;

    ASN1_OBJECT *a = d2i_ASN1_OBJECT(NULL, &p, ecparams->ulValueLen);
    assert_non_null(a);

    int nid = OBJ_obj2nid(a);
    ASN1_OBJECT_free(a);

    switch (nid) {
    case NID_X9_62_prime192v1:
    case NID_secp224r1:
    case NID_X9_62_prime256v1:
    case NID_secp384r1:
    case NID_secp521r1:
        break;
    default:
        fail_msg("Unsupported nid to tpm EC algorithm mapping, got nid: %d", nid);
    }
}

static void test_ec_point(CK_ATTRIBUTE_PTR ecpoint) {

    assert_int_not_equal(0, ecpoint->ulValueLen);
    assert_non_null(ecpoint->pValue);

    const unsigned char *pp = ecpoint->pValue;
    CK_ULONG len = ecpoint->ulValueLen;

    ASN1_OCTET_STRING *a = NULL;
    a = d2i_ASN1_OCTET_STRING(&a, &pp, len);
    assert_non_null(a);

    const unsigned char *d = ASN1_STRING_get0_data(a);

    /* first byte should be 04 for "uncompressed format" */
    assert_int_equal(d[0], 0x4);

    /* TODO look at curve id and map to expected X and Y sizes */

    ASN1_STRING_free(a);
}

void verify_missing_pub_attrs_ecc(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {

    CK_BYTE tmp[2][256] = { 0 };

    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_EC_PARAMS,  tmp[0]),
            ADD_ATTR_ARRAY(CKA_EC_POINT,    tmp[1]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG count = 0;
    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        /* TODO more robust checking here:
         *  - They match what was expected in generation.
         */
        case CKA_EC_PARAMS:
            test_ec_params(a);
            count++;
            break;
        case CKA_EC_POINT:
            // DER-encoding of ANSI X9.62 ECPoint value Q
            test_ec_point(a);
            count++;
        break;
        default:
            fail_msg("Unknown attribute type to test, got: %lu", a->type);
        }
    }

    assert_int_equal(count, ARRAY_LEN(attrs));
}

void verify_missing_priv_attrs_ecc(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) {

    CK_BYTE tmp[1][256] = { 0 };

    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_EC_PARAMS,  tmp[0]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG count = 0;
    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        /* TODO more robust checking here:
         *  - They match what was expected in generation.
         */
        case CKA_EC_PARAMS:
            test_ec_params(a);
            count++;
            break;
        default:
            fail_msg("Unknown attribute type to test, got: %lu", a->type);
        }
    }

    assert_int_equal(count, ARRAY_LEN(attrs));
}

void verify_missing_priv_attrs_common(CK_SESSION_HANDLE session, CK_KEY_TYPE keytype, CK_OBJECT_HANDLE h, CK_BBOOL extractable) {

    CK_BYTE tmp[5][256] = { 0 };

    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_KEY_TYPE, tmp[0]),
            ADD_ATTR_ARRAY(CKA_CLASS, tmp[1]),
            ADD_ATTR_ARRAY(CKA_ALWAYS_SENSITIVE,  tmp[2]),
            ADD_ATTR_ARRAY(CKA_EXTRACTABLE,  tmp[3]),
            ADD_ATTR_ARRAY(CKA_NEVER_EXTRACTABLE,  tmp[4]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG count = 0;

    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        case CKA_KEY_TYPE: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, keytype);
            count++;
        } break;
        case CKA_CLASS: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CKO_PRIVATE_KEY);
            count++;
        } break;
        case CKA_ALWAYS_SENSITIVE: {
            CK_BBOOL v = CK_FALSE;
            rv = generic_CK_BBOOL(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, !extractable);
            count++;
        } break;
        case CKA_EXTRACTABLE: {
            CK_BBOOL v = CK_TRUE;
            rv = generic_CK_BBOOL(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, extractable);
            count++;
        } break;
        case CKA_NEVER_EXTRACTABLE: {
            CK_BBOOL v = CK_FALSE;
            rv = generic_CK_BBOOL(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, !extractable);
            count++;
        } break;
        default:
            fail_msg("Unknown attribute type to test, got: %lu", a->type);
        }
    }

    assert_int_equal(count, ARRAY_LEN(attrs));
}

void verify_missing_pub_attrs_common(CK_SESSION_HANDLE session, CK_KEY_TYPE keytype, CK_OBJECT_HANDLE h) {

    CK_BYTE tmp[2][256] = { 0 };

    CK_ATTRIBUTE attrs[] = {
            ADD_ATTR_ARRAY(CKA_KEY_TYPE, tmp[0]),
            ADD_ATTR_ARRAY(CKA_CLASS,    tmp[1]),
    };

    CK_RV rv = C_GetAttributeValue(session, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ULONG count = 0;
    CK_ULONG i;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        switch(a->type) {
        case CKA_KEY_TYPE: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, keytype);
            count++;
        } break;
        case CKA_CLASS: {
            CK_ULONG v = 0;
            rv = generic_CK_ULONG(a, &v);
            assert_int_equal(rv, CKR_OK);
            assert_int_equal(v, CKO_PUBLIC_KEY);
            count++;
        } break;
        default:
            fail_msg("Unknown attribute type to test, got: %lu", a->type);
        }
    }

    assert_int_equal(count, ARRAY_LEN(attrs));
}
