/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#ifndef TEST_INTEGRATION_TEST_H_
#define TEST_INTEGRATION_TEST_H_

/* Set up ALL the headers needed so tests can just use #include "test.h" */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>
#include <tss2/tss2_sys.h>

#include "openssl_compat.h"
#include "pkcs11.h"
#include "openssl_compat.h"
#include "utils.h"

#define TOKEN_COUNT 3

#define GOOD_USERPIN "myuserpin"
#define GOOD_SOPIN   "mysopin"

#define BAD_USERPIN "myBADuserpin"
#define BAD_SOPIN   "myBADsopin"

#define IMPORT_LABEL_USERPIN "anotheruserpin"

typedef struct test_info test_info;

#define ADD_ATTR_BASE(t, x)  { .type = t,   .ulValueLen = sizeof(x),     .pValue = &x }
#define ADD_ATTR_ARRAY(t, x) { .type = t,   .ulValueLen = ARRAY_LEN(x),  .pValue = x }
#define ADD_ATTR_STR(t, x)   { .type = t,   .ulValueLen = sizeof(x) - 1, .pValue = x }

test_info *test_info_from_state(void **state);

int group_setup(void **state);

int group_setup_locking(void **state);

int group_teardown(void **state);

void logout_expects(CK_SESSION_HANDLE handle, CK_RV expected);

void logout(CK_SESSION_HANDLE handle);

void login_expects(CK_SESSION_HANDLE handle, CK_USER_TYPE user_type, CK_RV expected, unsigned char *pin, CK_ULONG len);

void user_login_expects(CK_SESSION_HANDLE handle, CK_RV expected);

void user_login_bad_pin(CK_SESSION_HANDLE handle);

void user_login(CK_SESSION_HANDLE handle);

void context_login(CK_SESSION_HANDLE handle);

void context_login_expects(CK_SESSION_HANDLE handle, CK_RV expected);

void context_login_bad_pin(CK_SESSION_HANDLE handle);

void so_login_expects(CK_SESSION_HANDLE handle, CK_RV expected);

void so_login(CK_SESSION_HANDLE handle);

void so_login_bad_pin(CK_SESSION_HANDLE handle);

void get_keypair(CK_SESSION_HANDLE session, CK_KEY_TYPE key_type, CK_OBJECT_HANDLE_PTR pub_handle, CK_OBJECT_HANDLE_PTR priv_handle);

void verify_missing_pub_attrs_common(CK_SESSION_HANDLE session, CK_KEY_TYPE keytype, CK_OBJECT_HANDLE h);

void verify_missing_priv_attrs_common(CK_SESSION_HANDLE session, CK_KEY_TYPE keytype, CK_OBJECT_HANDLE h, CK_BBOOL extractable);

void verify_missing_pub_attrs_ecc(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h);

void verify_missing_priv_attrs_ecc(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h);

void verify_missing_pub_attrs_rsa(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h);

void verify_missing_priv_attrs_rsa(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h);
#endif /* TEST_INTEGRATION_TEST_H_ */
