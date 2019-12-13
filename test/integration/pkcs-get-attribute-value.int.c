/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2019, Infineon Technologies AG
 *
 * All rights reserved.
 ***********************************************************************/

#include <openssl/x509.h>

#include "test.h"

struct test_info {
    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hObject;
};

static int test_setup(void **state) {

    test_info *info = calloc(1, sizeof(*info));
    assert_non_null(info);

    /* get the slots */
    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, TOKEN_COUNT);

    /* open a session on slot 0 */
    CK_SESSION_HANDLE hSession;
    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
            NULL, &hSession);
    assert_int_equal(rv, CKR_OK);

    /* assign to state */
    info->hSession = hSession;

    /* find a suitable object to work with */
    const char *key_label = "mykeylabel";
    CK_ATTRIBUTE tmpl[] = {
      {CKA_LABEL, (void *)key_label, strlen(key_label)},
    };

    rv = C_FindObjectsInit(hSession, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    user_login(hSession);

    CK_OBJECT_HANDLE objhandles[1024];
    rv = C_FindObjects(hSession, objhandles, ARRAY_LEN(objhandles), &count);
    assert_int_equal(rv, CKR_OK);
    assert_true(count >= 1);

    rv = C_FindObjectsFinal(hSession);
    assert_int_equal(rv, CKR_OK);

    /* store handle for tests*/
    info->hObject = objhandles[0];

    *state = info;

    /* success */
    return 0;
}


static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_CloseSession(ti->hSession);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}


static void test_get_attribute_value_single_okay(void **state) {
    CK_RV rv;
    CK_UTF8CHAR *pLabel = NULL;
    CK_LONG exactsize = 0;
    CK_ATTRIBUTE template[] = {
      {CKA_LABEL, NULL_PTR, 0},
    };

    test_info *ti = test_info_from_state(state);

    // Call for Size
    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 1);
    assert_int_equal(rv, CKR_OK);

    pLabel = malloc(template[0].ulValueLen+1); //+1 for \0
    memset(pLabel, '\0', template[0].ulValueLen+1);
    exactsize = template[0].ulValueLen; //for comparison

    template[0].pValue = pLabel;
    template[0].ulValueLen++; //must be reset to 'exactsize'

    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 1);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(template[0].ulValueLen, exactsize);
    assert_string_equal(template[0].pValue, "mykeylabel");
    free(pLabel);
}

static void test_get_attribute_value_multiple_okay(void **state) {
    CK_RV rv;
    CK_UTF8CHAR *pLabel = NULL;
    CK_BYTE_PTR *pId = NULL;
    CK_ATTRIBUTE template[] = {
      {CKA_LABEL, NULL_PTR, 0},
      {CKA_ID, NULL_PTR, 0},
    };

    test_info *ti = test_info_from_state(state);

    // Call for Size
    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 2);
    assert_int_equal(rv, CKR_OK);

    pLabel = malloc(template[0].ulValueLen+1); //+1 for \0
    memset(pLabel, '\0', template[0].ulValueLen+1);
    template[0].pValue = pLabel;

    pId = malloc(template[1].ulValueLen);
    template[1].pValue = pId;

    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 2);
    assert_int_equal(rv, CKR_OK);
    assert_string_equal(template[0].pValue, "mykeylabel");
    free(pLabel);
    free(pId);
}

static void test_get_attribute_value_buffer_too_small(void **state) {
    CK_RV rv;
    CK_UTF8CHAR *pLabel = NULL;
    CK_ATTRIBUTE template[] = {
      {CKA_LABEL, NULL_PTR, 0},
    };

    test_info *ti = test_info_from_state(state);

    // Call for Size
    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 1);
    assert_int_equal(rv, CKR_OK);

    pLabel = malloc(template[0].ulValueLen+1); //+1 for \0
    memset(pLabel, '\0', template[0].ulValueLen+1);
    template[0].pValue = pLabel;

    //make buffer length too small
    template[0].ulValueLen--;

    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 1);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    free(pLabel);
}

static void test_get_attribute_value_invalid_attribute(void **state) {
    test_info *ti = test_info_from_state(state);
    CK_ATTRIBUTE template[] = {
      {0x0000FFFFUL, NULL_PTR, 0}, //Invalid
    };

    CK_RV rv;

    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 1);

    assert_int_equal(rv, CKR_ATTRIBUTE_TYPE_INVALID);
    assert_int_equal(template[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);
    assert_null(template[0].pValue);
}

/*
 * C_GetAttributeValue must process every attribute in the template,
 * even if CKR_ATTRIBUTE_TYPE_INVALID or CKR_BUFFER_TOO_SMALL is returned.
 * The return value can be any one of the failures.
 * */
static void test_get_attribute_value_multiple_fail(void **state) {
    CK_RV rv;
    CK_UTF8CHAR *pLabel = NULL;
    CK_BYTE_PTR *pId = NULL;
    CK_BYTE_PTR *pInvalid = NULL;
    CK_ATTRIBUTE template[] = {
      {CKA_ID, NULL_PTR, 0},
      {CKA_LABEL, NULL_PTR, 0},
      {0x0000FFFFUL, NULL_PTR, 0}, //Invalid
    };
    LargestIntegralType expected_returns[] = {CKR_BUFFER_TOO_SMALL, CKR_ATTRIBUTE_TYPE_INVALID};

    test_info *ti = test_info_from_state(state);

    // Call for Size, without invalid
    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 2);
    assert_int_equal(rv, CKR_OK);

    // too small
    pId = malloc(template[0].ulValueLen);
    template[0].pValue = pId;
    template[0].ulValueLen--; // make buffer too small

    // this one will be okay
    pLabel = malloc(template[1].ulValueLen+1); //+1 for \0
    memset(pLabel, '\0', template[1].ulValueLen+1);
    template[1].pValue = pLabel;

    // invalid
    pInvalid = malloc(10);
    template[2].pValue = pInvalid;
    template[2].ulValueLen = 10;

    rv = C_GetAttributeValue(ti->hSession, ti->hObject, template, 3);
    // Return should be CKR_ATTRIBUTE_TYPE_INVALID or CKR_BUFFER_TOO_SMALL
    assert_in_set(rv, expected_returns, 2);
    assert_int_equal(template[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);
    assert_string_equal(template[1].pValue, "mykeylabel");
    assert_int_equal(template[2].ulValueLen, CK_UNAVAILABLE_INFORMATION);
    free(pLabel);
    free(pId);
    free(pInvalid);
}

static void test_all_pub_ecc_obj_attrs(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->hSession;

    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keytype = CKK_EC;

    CK_ATTRIBUTE attrs[] = {
        ADD_ATTR_BASE(CKA_KEY_TYPE, keytype),
        ADD_ATTR_BASE(CKA_CLASS, class),
    };

    /* verify we can find it via pub templ */
    CK_RV rv = C_FindObjectsInit(session, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE handles[255];
    CK_ULONG count = ARRAY_LEN(handles);
    rv = C_FindObjects(session, handles, count, &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG i;
    for (i=0; i < count; i++) {

        CK_OBJECT_HANDLE h = handles[i];

        /* verify missing attrs */
        verify_missing_pub_attrs_common(session, keytype, h);
        verify_missing_pub_attrs_ecc(session, h);
    }
}

static void test_all_priv_ecc_obj_attrs(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->hSession;

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keytype = CKK_EC;

    CK_ATTRIBUTE attrs[] = {
        ADD_ATTR_BASE(CKA_KEY_TYPE, keytype),
        ADD_ATTR_BASE(CKA_CLASS, class),
    };

    /* verify we can find it via pub templ */
    CK_RV rv = C_FindObjectsInit(session, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE handles[255];
    CK_ULONG count = ARRAY_LEN(handles);
    rv = C_FindObjects(session, handles, count, &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG i;
    for (i=0; i < count; i++) {

        CK_OBJECT_HANDLE h = handles[i];

        /* verify missing attrs */
        verify_missing_priv_attrs_common(session, keytype, h, CK_FALSE);
        verify_missing_priv_attrs_ecc(session, h);
    }
}

static void test_all_pub_rsa_obj_attrs(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->hSession;

    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keytype = CKK_RSA;

    CK_ATTRIBUTE attrs[] = {
        ADD_ATTR_BASE(CKA_KEY_TYPE, keytype),
        ADD_ATTR_BASE(CKA_CLASS, class),
    };

    /* verify we can find it via pub templ */
    CK_RV rv = C_FindObjectsInit(session, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE handles[255];
    CK_ULONG count = ARRAY_LEN(handles);
    rv = C_FindObjects(session, handles, count, &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG i;
    for (i=0; i < count; i++) {

        CK_OBJECT_HANDLE h = handles[i];

        /* verify missing attrs */
        verify_missing_pub_attrs_common(session, keytype, h);
        verify_missing_pub_attrs_rsa(session, h);
    }
}

static void test_all_priv_rsa_obj_attrs(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->hSession;

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keytype = CKK_RSA;

    CK_ATTRIBUTE attrs[] = {
        ADD_ATTR_BASE(CKA_KEY_TYPE, keytype),
        ADD_ATTR_BASE(CKA_CLASS, class),
    };

    /* verify we can find it via pub templ */
    CK_RV rv = C_FindObjectsInit(session, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE handles[255];
    CK_ULONG count = ARRAY_LEN(handles);
    rv = C_FindObjects(session, handles, count, &count);
    assert_int_equal(rv, CKR_OK);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG i;
    for (i=0; i < count; i++) {

        CK_OBJECT_HANDLE h = handles[i];

        /* verify missing attrs */
        verify_missing_priv_attrs_common(session, keytype, h, CK_FALSE);
        verify_missing_priv_attrs_rsa(session, h);
    }
}

#define ADD_ATTR_HANDLER(a, b, index) .type = a, .ulValueLen = sizeof(b[0]), .pValue= b[index]

static void verify_cert_attrs(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h) {

    CK_BYTE _buf[256][1024] = { 0 };
    CK_ATTRIBUTE attrs[] = {
        { ADD_ATTR_HANDLER(CKA_CLASS, _buf, 0) },
        { ADD_ATTR_HANDLER(CKA_CERTIFICATE_TYPE, _buf, 1) },
        { ADD_ATTR_HANDLER(CKA_TRUSTED, _buf, 2) },
        { ADD_ATTR_HANDLER(CKA_CERTIFICATE_CATEGORY, _buf, 3) },
        { ADD_ATTR_HANDLER(CKA_CHECK_VALUE, _buf, 4) },
        { ADD_ATTR_HANDLER(CKA_START_DATE, _buf, 5) },
        { ADD_ATTR_HANDLER(CKA_END_DATE, _buf, 6) },
        { ADD_ATTR_HANDLER(CKA_PUBLIC_KEY_INFO, _buf, 7) },
        { ADD_ATTR_HANDLER(CKA_SUBJECT, _buf, 8) },
        { ADD_ATTR_HANDLER(CKA_LABEL, _buf, 9) },
        { ADD_ATTR_HANDLER(CKA_ISSUER, _buf, 10) },
        { ADD_ATTR_HANDLER(CKA_SERIAL_NUMBER, _buf, 11) },
        { ADD_ATTR_HANDLER(CKA_VALUE, _buf, 12) },
        { ADD_ATTR_HANDLER(CKA_URL, _buf, 13) },
        { ADD_ATTR_HANDLER(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, _buf, 14) },
        { ADD_ATTR_HANDLER(CKA_HASH_OF_ISSUER_PUBLIC_KEY, _buf, 15) },
        { ADD_ATTR_HANDLER(CKA_JAVA_MIDP_SECURITY_DOMAIN, _buf, 16) },
        { ADD_ATTR_HANDLER(CKA_NAME_HASH_ALGORITHM, _buf, 17) },
    };

    assert_true(ARRAY_LEN(attrs) <= ARRAY_LEN(_buf));

    CK_RV rv = C_GetAttributeValue(s, h, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_ATTRIBUTE_PTR value = NULL;
    CK_ATTRIBUTE_PTR checkvalue = NULL;
    CK_ATTRIBUTE_PTR subject = NULL;

    CK_ULONG i = 0;
    for (i=0; i < ARRAY_LEN(attrs); i++) {
        CK_ATTRIBUTE_PTR a = &attrs[i];

        switch (a->type) {
            case CKA_CLASS: {
                assert_int_equal(a->ulValueLen, sizeof(CK_OBJECT_CLASS));
                CK_OBJECT_CLASS *v = (CK_OBJECT_CLASS *)a->pValue;
                assert_int_equal(*v, CKO_CERTIFICATE);
            }   break;
            case CKA_CERTIFICATE_TYPE: {
                assert_int_equal(a->ulValueLen, sizeof(CK_CERTIFICATE_TYPE));
                CK_CERTIFICATE_TYPE *v = (CK_CERTIFICATE_TYPE *)a->pValue;
                assert_int_equal(*v, CKC_X_509);
            }   break;
            case CKA_TRUSTED: {
                assert_int_equal(a->ulValueLen, sizeof(CK_BBOOL));
                CK_BBOOL *v = (CK_BBOOL *)a->pValue;
                assert_int_equal(*v, CK_FALSE);
            }   break;
            case CKA_CERTIFICATE_CATEGORY: {
                assert_int_equal(a->ulValueLen, sizeof(CK_ULONG));
                CK_ULONG *v = (CK_ULONG *)a->pValue;
                assert_int_equal(*v, CK_CERTIFICATE_CATEGORY_UNSPECIFIED);
            }   break;
            case CKA_CHECK_VALUE: {
                // check value is first three bytes of sha1 hash
               assert_int_equal(a->ulValueLen, 3);
               checkvalue = a;
            }  break;
            case CKA_SUBJECT:
                subject = a;
                break;
            case CKA_LABEL:
                /* a label should be set ? */
                assert_true(a->ulValueLen > 0);
                break;
            case CKA_VALUE:
                value = a;
                break;
            case CKA_JAVA_MIDP_SECURITY_DOMAIN: {
                assert_int_equal(a->ulValueLen, sizeof(CK_JAVA_MIDP_SECURITY_DOMAIN));
                CK_JAVA_MIDP_SECURITY_DOMAIN *v = (CK_ULONG *)a->pValue;
                assert_int_equal(*v, CK_SECURITY_DOMAIN_UNSPECIFIED);
            }   break;
            case CKA_NAME_HASH_ALGORITHM: {
                assert_int_equal(a->ulValueLen, sizeof(CK_MECHANISM_TYPE));
                CK_MECHANISM_TYPE *v = (CK_MECHANISM_TYPE *)a->pValue;
                assert_int_equal(*v, CKM_SHA_1);
            }   break;
            /* expected empty */
            case CKA_URL:
                // falls-thru
            case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
                // falls-thru
            case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
                // falls-thru
            case CKA_PUBLIC_KEY_INFO:
                // falls-thru
            case CKA_ISSUER:
                // falls-thru
            case CKA_SERIAL_NUMBER:
                // falls-thru
            case CKA_START_DATE:
                // falls-thru
            case CKA_END_DATE:
                assert_int_equal(a->ulValueLen, 0);
            break;
            default:
                assert_true(0);
        }
    }

    assert_non_null(subject);

    assert_non_null(value);
    assert_non_null(checkvalue);

    /* verify subject is an ASN1 encoded string */
    const unsigned char *tmp = subject->pValue;
    X509_NAME *ss = d2i_X509_NAME(NULL, &tmp, subject->ulValueLen);
    assert_non_null(ss);
    X509_NAME_free(ss);

    /* verify check value */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    assert_non_null(mdctx);

    int rc = EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
    assert_int_equal(rc, 1);

    rc = EVP_DigestUpdate(mdctx, value->pValue, value->ulValueLen);
    assert_int_equal(rc, 1);

    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned int len = sizeof(md);
    rc = EVP_DigestFinal_ex(mdctx, md, &len);
    assert_int_equal(rc, 1);

    EVP_MD_CTX_destroy(mdctx);

    assert_memory_equal(md, checkvalue->pValue, checkvalue->ulValueLen);
}

static void test_all_cert_attrs(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->hSession;

    CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
    CK_KEY_TYPE cert_type = CKC_X_509;
    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS, &obj_class, sizeof(obj_class)  },
        { CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
    };

    /* verify we can find it via pub templ */
    CK_RV rv = C_FindObjectsInit(session, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE handles[255];
    CK_ULONG count = ARRAY_LEN(handles);
    rv = C_FindObjects(session, handles, count, &count);
    assert_int_equal(rv, CKR_OK);
    assert_true(count > 0);

    /* make sure we got all of them */
    CK_ULONG left = 1;
    CK_OBJECT_HANDLE dummy;
    rv = C_FindObjects(session, &dummy, 1, &left);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(left, 0);

    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG i;
    for (i=0; i < count; i++) {

        CK_OBJECT_HANDLE h = handles[i];

        /* verify missing attrs */
        verify_cert_attrs(session, h);
    }
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_all_cert_attrs,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_all_pub_ecc_obj_attrs,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_all_priv_ecc_obj_attrs,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_all_pub_rsa_obj_attrs,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_all_priv_rsa_obj_attrs,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_attribute_value_single_okay,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_attribute_value_multiple_okay,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_attribute_value_buffer_too_small,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_attribute_value_invalid_attribute,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_attribute_value_multiple_fail,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

