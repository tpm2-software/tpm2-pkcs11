/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>

#include "twist.h"
#include "utils.h"

extern void twist_next_alloc_fails(void);

void test_twist_new(void **state) {
    (void) state;

	char *expected = "Hello World";
	twist actual = twist_new(expected);
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	assert_int_equal(strlen(expected), twist_len(actual));

	twist_free(actual);
}

void test_twist_new_0_len(void **state) {
    (void) state;

	char *expected = "";
	twist actual = twist_new(expected);
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	assert_int_equal(strlen(expected), twist_len(actual));

	assert_int_equal(actual[twist_len(actual)], '\0');

	twist_free(actual);
}


void test_twist_new_bad_alloc(void **state) {
    (void) state;

	twist_next_alloc_fails();
	twist actual = twist_new("I should be null");
	assert_null(actual);
}

void test_twist_new_empty(void **state) {
    (void) state;

	char *expected = "";
	twist actual = twist_new(expected);
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	assert_int_equal(strlen(expected), twist_len(actual));

	twist_free(actual);
}

void test_twist_new_null(void **state) {
    (void) state;

	twist actual = twist_new(NULL );
	assert_null(actual);
}

void test_twist_calloc_zero(void **state) {
    UNUSED(state);

    assert_null(twist_calloc(0));
}

void test_twist_calloc_many(void **state) {
    UNUSED(state);

    twist t = twist_calloc(42);
    assert_non_null(t);
    assert_int_equal(42, twist_len(t));
    twist_free(t);
}

void test_twist_create(void **state) {
    (void) state;

	const char *expected = "onetwothreefourfive";

	const char *data[] = { "one", "two", "three", "four", "five" };

	twist actual = twist_create(data, ARRAY_LEN(data));
	assert_non_null(actual);
	assert_string_equal(expected, (char * )actual);

	twist_free(actual);
}

void test_twist_create_null(void **state) {
    (void) state;

	twist actual = twist_create(NULL, 42);
	assert_null(actual);
}

void test_twist_create_embedded_null(void **state) {
    (void) state;

	const char *expected = "onetwothreefourfive";

	const char *data[] = { NULL, "one", NULL, "two", "three", "four", NULL,
			"five", NULL };

	twist actual = twist_create(data, ARRAY_LEN(data));
	assert_non_null(actual);
	assert_string_equal(expected, actual);

	twist_free(actual);
}

void test_twist_dup(void **state) {
    (void) state;

	twist actual = twist_new("Hello World");
	assert_non_null(actual);

	twist expected = twist_dup(actual);
	assert_non_null(expected);

	assert_true(twist_eq(actual, expected));

	twist_free(actual);
	twist_free(expected);
}

void test_twist_dup_empty(void **state) {
    (void) state;

	twist actual = twist_new("");
	assert_non_null(actual);

	twist expected = twist_dup(actual);
	assert_non_null(expected);

	assert_true(twist_eq(actual, expected));

	twist_free(actual);
	twist_free(expected);
}

void test_twist_dup_null(void **state) {
    (void) state;

	twist actual = twist_dup(NULL );
	assert_null(actual);
}

void test_twist_end(void **state) {
    (void) state;

	twist x = twist_new("OMG Its a string!");
	assert_non_null(x);

	char *end = twist_end(x);
	assert_non_null(x);
	assert_ptr_equal((void * )x + twist_len(x) - 1, (void * )end);
	assert_int_equal(*end, '!');
	twist_free(x);
}

void test_twist_end_null(void **state) {
    (void) state;

	char *end = twist_end(NULL );
	assert_null(end);
}

void test_twist_free_null(void **state) {
    UNUSED(state);

	twist_free(NULL);
}

void test_twist_concat(void **state) {
    (void) state;

	const char *expected = "Original String - Concatenated part";

	twist original = twist_new("Original String");
	assert_non_null(original);

	twist actual = twist_concat(original, " - Concatenated part");
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	twist_free(original);
	twist_free(actual);
}

void test_twist_concat_empty(void **state) {
    (void) state;

	const char *expected = "Original String";

	twist original = twist_new(expected);
	assert_non_null(original);

	twist actual = twist_concat(original, "");
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	twist_free(original);
	twist_free(actual);
}

void test_twistbin_create(void **state) {
    (void) state;

	const char ex[] = { 0xAA, 0x00, 0xBB, 0xCC, 0x00, 0xDD, 0xDD, 0x00, 0xEE,
			0xEE, 0x00, 0xFF };

	const binarybuffer data[] = { { .data = ex, .size = 3 }, { .data = &ex[3],
			.size = 3 }, { .data = &ex[6], .size = 3 }, { .data = &ex[9],
			.size = 3 } };

	twist expected = twistbin_new(ex, ARRAY_LEN(ex));
	assert_non_null(expected);

	twist actual = twistbin_create(data, ARRAY_LEN(data));
	assert_non_null(actual);
	assert_true(twist_eq(expected, actual));

	twist_free(expected);
	twist_free(actual);
}

void test_twistbin_new_overflow_1(void **state) {
    (void) state;

	twist actual = twistbin_new((void *) 0xDEADBEEF, ~0);
	assert_null(actual);
}

void test_twistbin_new_overflow_2(void **state) {
    (void) state;

	twist actual = twistbin_new((void *) 0xDEADBEEF, ~0 - sizeof(void *));
	assert_null(actual);
}

void test_twistbin_new_overflow_3(void **state) {
    (void) state;

	twist old = twist_new("hahahahahahahahahahahahaha");
	assert_non_null(old);

	twist actual = twistbin_append(old, (void *) 0xDEADBEEF,
			~0 - sizeof(void *) - 4);
	assert_null(actual);

	twist_free(old);
}

void test_twistbin_new_overflow_4(void **state) {
    (void) state;

	binarybuffer data[] = { { .data = (void *) 0xDEADBEEF, .size = ~0 }, {
			.data = (void *) 0xBADCC0DE, .size = 1 }, };

	twist actual = twistbin_create(data, ARRAY_LEN(data));
	assert_null(actual);
}

void test_twistbin_aappend(void **state) {
    (void) state;

	const char *expected = "No one likes youOMGtests are fun";
	twist old = twist_new("No one likes you");
	assert_non_null(old);

	binarybuffer data[] = { { .data = "OMG", .size = 3 }, { .data =
			"tests are fun", .size = 13 } };

	twist actual = twistbin_aappend(old, data, ARRAY_LEN(data));
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	twist_free(actual);
}

void test_twistbin_aappend_null_array(void **state) {
    (void) state;

	const char *expected = "OMGtests are fun";

	binarybuffer data[] = { { .data = "OMG", .size = 3 }, { .data = NULL,
			.size = 0 }, { .data = "tests are fun", .size = 13 } };

	twist actual = twistbin_aappend(NULL, data, ARRAY_LEN(data));
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	twist_free(actual);
}

void test_twistbin_aappend_twist_null(void **state) {
    (void) state;

	twist expected = twist_new("foo");

	twist actual = twistbin_aappend(expected, NULL, 42);
	assert_ptr_equal((void * )actual, (void * )expected);

	actual = twistbin_aappend(expected, (binarybuffer *) 0xDEADBEEF, 0);
	assert_ptr_equal((void * )actual, (void * )expected);

	twist_free(actual);
}

void test_twistbin_create_null(void **state) {
    (void) state;

	twist actual = twistbin_create(NULL, 010101);
	assert_null(actual);
}

void test_twistbin_create_embedded_null(void **state) {
    (void) state;

	const char ex[] = { 0xAA, 0x00, 0xBB, 0xDD, 0x00, 0xEE, 0xEE, 0x00, 0xFF };

	const binarybuffer data[] = { { .data = ex, .size = 3 }, { .data = NULL,
			.size = 0 }, { .data = &ex[3], .size = 3 }, { .data = &ex[6],
			.size = 3 }, };

	twist expected = twistbin_new(ex, ARRAY_LEN(ex));
	assert_non_null(expected);

	twist actual = twistbin_create(data, ARRAY_LEN(data));
	assert_non_null(actual);
	assert_true(twist_eq(expected, actual));

	twist_free(expected);
	twist_free(actual);
}

void test_twistbin_concat(void **state) {
    (void) state;

	const char old_str[] = { 0xAA, 0xBB, 0x00, 0xCC };
	const char new_str[] = { 0x11, 0x00, 0x22, 0x33 };
	const char expected[] = { 0xAA, 0xBB, 0x00, 0xCC, 0x11, 0x00, 0x22, 0x33 };

	twist original = twistbin_new(old_str, ARRAY_LEN(old_str));
	assert_non_null(original);

	twist actual = twistbin_concat(original, new_str, ARRAY_LEN(new_str));
	assert_non_null(actual);

	assert_memory_equal(expected, actual, ARRAY_LEN(expected));

	twist_free(original);
	twist_free(actual);
}

void test_twistbin_concat_twist_null(void **state) {
    (void) state;

	const char expected[] = { 0xAA, 0xBB, 0x00, 0xCC };

	twist original = twistbin_new(expected, ARRAY_LEN(expected));
	assert_non_null(original);

	twist actual = twistbin_concat(original, NULL, 0);
	assert_non_null(actual);

	assert_memory_equal(expected, actual, ARRAY_LEN(expected));

	twist_free(original);
	twist_free(actual);
}

void test_twistbin_concat_null_data(void **state) {
    (void) state;

	const char expected[] = { 0xAA, 0xBB, 0x00, 0xCC };

	twist actual = twistbin_concat(NULL, expected, ARRAY_LEN(expected));
	assert_non_null(actual);

	assert_memory_equal(expected, actual, ARRAY_LEN(expected));

	twist_free(actual);
}

void test_twist_concat_twist_null(void **state) {
    (void) state;

	twist expected = twist_new("Original String");
	assert_non_null(expected);

	twist actual = twist_concat(expected, NULL );
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	twist_free(actual);
	twist_free(expected);
}

void test_twist_concat_null_null(void **state) {
    (void) state;

	assert_null(twist_concat(NULL, NULL));
}

void test_twist_concat_empty_null(void **state) {
    (void) state;

	twist expected = twist_new("");
	assert_non_null(expected);

	twist actual = twist_concat(expected, NULL );
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	twist_free(actual);
	twist_free(expected);
}

void test_twist_concat_null_empty(void **state) {
    (void) state;

	const char *expected = "";
	twist actual = twist_concat(NULL, expected);
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	twist_free(actual);
}

void test_twist_concat_twist(void **state) {
    (void) state;

	const char *expected = "Original String - Concatenated part";

	twist original = twist_new("Original String");
	assert_non_null(original);

	twist part_to_add = twist_new(" - Concatenated part");

	twist actual = twist_concat_twist(original, part_to_add);
	assert_non_null(actual);

	assert_string_equal(expected, actual);

	twist_free(actual);
	twist_free(original);
	twist_free(part_to_add);
}

void test_twist_concat_twist_null_null(void **state) {
    (void) state;

	assert_null(twist_concat_twist(NULL, NULL));
}

void test_twist_concat_twist_twist_null(void **state) {
    (void) state;

	const char *expected = "Original String";

	twist original = twist_new("Original String");
	assert_non_null(original);

	twist actual = twist_concat_twist(original, NULL );
	assert_non_null(actual);

	assert_string_equal(expected, actual);

	twist_free(actual);
	twist_free(original);
}

void test_twist_concat_twist_null_twist(void **state) {
    (void) state;

	const char *expected = " - Concatenated part";
	twist part_to_add = twist_new(expected);
	assert_non_null(part_to_add);

	twist actual = twist_concat_twist(NULL, part_to_add);
	assert_non_null(actual);

	assert_string_equal(expected, actual);

	twist_free(actual);
	twist_free(part_to_add);
}

void test_twist_eq_equality(void **state) {
    (void) state;

	const char *expected = "im equal";

	twist actual1 = twist_new(expected);
	assert_non_null(actual1);

	twist actual2 = twist_new(expected);
	assert_non_null(actual2);

	assert_string_equal(expected, actual1);
	assert_string_equal(expected, actual2);

	assert_true(twist_eq(actual1, actual2));

	twist_free(actual1);
	twist_free(actual2);
}

void test_twist_eq_equality_null_null(void **state) {
    (void) state;

	assert_true(twist_eq(NULL, NULL));
}

void test_twist_eq_equality_twist_null(void **state) {
    (void) state;

	twist x = twist_new("A twist string");
	assert_non_null(x);
	assert_false(twist_eq(x, NULL));
	twist_free(x);
}

void test_twist_eq_equality_null_twist(void **state) {
    (void) state;

	twist x = twist_new("A twist string");
	assert_non_null(x);
	assert_false(twist_eq(NULL, x));
	twist_free(x);
}

void test_twist_eq_not_equality(void **state) {
    (void) state;

	twist different1 = twist_new("I'm something");
	assert_non_null(different1);

	twist different2 = twist_new("I'm something different");
	assert_non_null(different2);

	assert_false(twist_eq(different1, different2));

	twist_free(different1);
	twist_free(different2);
}

void test_twistbin_new_bin_dup_eq(void **state) {
    (void) state;

	uint8_t expected[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x11, 0x22, 0x33,
			0x44 };

	twist original = twistbin_new(expected, ARRAY_LEN(expected));
	assert_non_null(original);

	assert_int_equal(twist_len(original), ARRAY_LEN(expected));

	twist actual = twist_dup(original);
	assert_non_null(actual);

	assert_memory_equal(expected, actual, ARRAY_LEN(expected));
	assert_true(twist_eq(original, actual));

	twist_free(original);
	twist_free(actual);
}

void test_twistbin_new_null(void **state) {
    (void) state;

	assert_null(twistbin_new(NULL, 0));
}

void test_twistbin_new_not_eq(void **state) {
    (void) state;

	uint8_t data1[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x11, 0x22, 0x33,
			0x44 };
	uint8_t data2[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD,
			0xEE };

	twist x = twistbin_new(data1, ARRAY_LEN(data1));
	assert_non_null(x);

	twist y = twistbin_new(data2, ARRAY_LEN(data2));
	assert_non_null(y);

	assert_int_equal(twist_len(x), ARRAY_LEN(data1));
	assert_int_equal(twist_len(y), ARRAY_LEN(data2));

	assert_memory_not_equal(x, y, twist_len(x));
	assert_false(twist_eq(x, y));

	twist_free(x);
	twist_free(y);
}

void test_twistbin_new_not_eq_diff_lengths(void **state) {
    (void) state;

	uint8_t data1[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x11, 0x22, 0x33,
			0x44 };
	uint8_t data2[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD,
			0xEE, 0x00, 0xAA, 0xBB };

	twist x = twistbin_new(data1, ARRAY_LEN(data1));
	assert_non_null(x);

	twist y = twistbin_new(data2, ARRAY_LEN(data2));
	assert_non_null(y);

    assert_int_equal(twist_len(x), ARRAY_LEN(data1));
    assert_int_equal(twist_len(y), ARRAY_LEN(data2));

	assert_memory_not_equal(x, y, twist_len(x));
	assert_false(twist_eq(x, y));

	twist_free(x);
	twist_free(y);
}

void test_twist_append(void **state) {
    (void) state;

	const char *expected = "My Original String - cool";

	twist original = twist_new("My Original String");
	assert_non_null(original);

	twist actual = twist_append(original, " - cool");
	assert_non_null(actual);

	assert_string_equal(expected, actual);

	twist_free(actual);
}

void test_twist_append_bad_alloc(void **state) {
    (void) state;

	twist original = twist_new("I'm Good");
	assert_non_null(original);

	twist_next_alloc_fails();
	twist actual = twist_append(original, "I fail");
	assert_null(actual);

	twist_free(original);
}

void test_twistbin_append(void **state) {
    (void) state;

	const char first[] = { 0x01, 0x55, 'A', 'B' };
	const char second[] = { 0x00, 'x', 0x00 };
	const char expected[] = { 0x01, 0x55, 'A', 'B', 0x00, 'x', 0x00 };

	twist tfirst = twistbin_new(first, ARRAY_LEN(first));
	assert_non_null(tfirst);

	twist actual = twistbin_append(tfirst, second, ARRAY_LEN(second));
	assert_non_null(actual);

	assert_memory_equal(expected, actual, ARRAY_LEN(expected));
	twist_free(actual);
}

void test_twist_append_twist(void **state) {
    (void) state;

	const char first[] = { 0x01, 0x55, 'A', 'B' };
	const char second[] = { 0x00, 'x', 0x00 };
	const char expected[] = { 0x01, 0x55, 'A', 'B', 0x00, 'x', 0x00 };

	twist tfirst = twistbin_new(first, ARRAY_LEN(first));
	assert_non_null(tfirst);

	twist tsecond = twistbin_new(second, ARRAY_LEN(second));
	assert_non_null(tsecond);

	twist actual = twist_append_twist(tfirst, tsecond);
	assert_non_null(actual);

	assert_memory_equal(expected, actual, ARRAY_LEN(expected));
	twist_free(actual);
	twist_free(tsecond);
}

void test_twist_append_twist_null(void **state) {
    (void) state;

	twist expected = twist_new("My Original String");
	assert_non_null(expected);

	twist actual = twist_append(expected, NULL );
	assert_non_null(actual);

	assert_string_equal(expected, actual);
	assert_true(twist_eq(actual, expected));

	twist_free(actual);
}

void test_twistbin_append_twist_null(void **state) {
    (void) state;

	const char first[] = { 0x01, 0x55, 'A', 'B' };

	twist tfirst = twistbin_new(first, ARRAY_LEN(first));
	assert_non_null(tfirst);

	twist actual = twistbin_append(tfirst, NULL, 0);
	assert_non_null(actual);

	assert_ptr_equal((void * )tfirst, (void * )actual);
	assert_memory_equal(first, actual, ARRAY_LEN(first));

	twist_free(actual);
}

void test_twist_append_twist_twist_null(void **state) {
    (void) state;

	const char first[] = { 0x01, 0x55, 'A', 'B' };

	twist tfirst = twistbin_new(first, ARRAY_LEN(first));
	assert_non_null(tfirst);

	twist actual = twist_append_twist(tfirst, NULL );
	assert_non_null(actual);

	assert_ptr_equal((void * )tfirst, (void * )actual);
    assert_memory_equal(first, actual, ARRAY_LEN(first));

	twist_free(actual);
}

void test_twist_append_null_string(void **state) {
    (void) state;

	const char *expected = "this is some string";

	twist actual = twist_append(NULL, expected);
	assert_non_null(actual);

	assert_string_equal(expected, actual);

	twist_free(actual);
}

void test_twistbin_append_null_string(void **state) {
    (void) state;

	const char second[] = { 0x01, 0x00, 'A', 'B' };

	twist actual = twistbin_append(NULL, second, ARRAY_LEN(second));
	assert_non_null(actual);

	assert_memory_equal(second, actual, ARRAY_LEN(second));

	twist_free(actual);
}

void test_twist_append_twist_null_string(void **state) {
    (void) state;

	const char second[] = { 0x01, 0x00, 'A', 'B' };

	twist tsecond = twistbin_new(second, ARRAY_LEN(second));
	assert_non_null(tsecond);

	twist actual = twist_append_twist(NULL, tsecond);
	assert_non_null(actual);

	assert_memory_equal(second, actual, ARRAY_LEN(second));

	twist_free(actual);
}

void test_twist_append_null_null(void **state) {
    (void) state;

	assert_null(twist_append(NULL, NULL));
}

void test_twistbin_append_null_null(void **state) {
    (void) state;

	assert_null(twistbin_append(NULL, NULL, 0));
}

void test_twist_append_twist_null_null(void **state) {
    (void) state;

	assert_null(twist_append_twist(NULL, NULL));
}

void test_twist_truncate_smaller(void **state) {
    (void) state;

	twist original = twist_new("My Original String");
	assert_non_null(original);

	size_t orig_len = twist_len(original);

	twist actual = twist_truncate(original, orig_len - 4);
	assert_non_null(actual);
	assert_int_equal(orig_len - 4, twist_len(actual));

	twist_free(actual);
}

void test_twist_truncate_bigger(void **state) {
    (void) state;

	twist original = twist_new("My Original String");
	assert_non_null(original);

	size_t orig_len = twist_len(original);

	twist actual = twist_truncate(original, orig_len + 104);
	assert_non_null(actual);
	assert_int_equal(orig_len + 104, twist_len(actual));

	twist_free(actual);
}

void test_twist_truncate_bigger_bad_alloc(void **state) {
    (void) state;

	twist original = twist_new("My Original String");
	assert_non_null(original);

	size_t orig_len = twist_len(original);
	twist_next_alloc_fails();
	twist actual = twist_truncate(original, orig_len + 104);
	assert_null(actual);
	twist_free(original);
}

void test_twist_truncate_same(void **state) {
    (void) state;

	twist original = twist_new("My Original String");
	assert_non_null(original);

	size_t orig_len = twist_len(original);

	twist actual = twist_truncate(original, orig_len);
	assert_non_null(actual);
	assert_int_equal(orig_len, twist_len(actual));
	assert_ptr_equal((void * )original, (void * )actual);

	twist_free(actual);
}

void test_twist_truncate_zero(void **state) {
    (void) state;

	twist original = twist_new("My Original String");
	assert_non_null(original);

	twist actual = twist_truncate(original, 0);
	assert_non_null(actual);
	assert_int_equal(0, twist_len(actual));

	twist_free(actual);
}

void test_twist_truncate_null(void **state) {
    (void) state;

	assert_null(twist_truncate(NULL, 0));
}

void test_twist_unhexlify_null(void **state) {
    (void) state;

	twist null = twistbin_unhexlify(NULL);
	assert_null(null);
}

void test_twist_unhexlify_0_len(void **state) {
    (void) state;

	twist zero_len = twistbin_unhexlify("");
	assert_int_equal(twist_len(zero_len), 0);
	assert_int_equal(zero_len[0], '\0');
	twist_free(zero_len);
}

void test_twist_unhexlify_odd_len(void **state) {
    (void) state;

	twist odd = twistbin_unhexlify("a");
	assert_null(odd);

	odd = twistbin_unhexlify("abc");
	assert_null(odd);


	odd = twistbin_unhexlify("defab");
	assert_null(odd);
}

void test_twist_unhexlify_even_len(void **state) {
    (void) state;

	/* Test all the characters */
	char raw[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xab, 0xcd, 0xef };
	twist even = twistbin_unhexlify("0123456789ABCDEFabcdef");
	assert_non_null(even);
	assert_int_equal(even[twist_len(even)], '\0');
	assert_int_equal(sizeof(raw), twist_len(even));
	assert_memory_equal(even, raw, sizeof(raw));
	twist_free(even);

	/* test smallest valid */
	even = twistbin_unhexlify("01");
	assert_non_null(even);
	assert_int_equal(even[twist_len(even)], '\0');
	twist_free(even);

	even = twistbin_unhexlify("01a2b3c4");
	assert_non_null(even);
	assert_int_equal(even[twist_len(even)], '\0');
	twist_free(even);
}

void test_twist_unhexlify_bad_chars(void **state) {
    (void) state;

	/* Test all bad characters */
	twist bad = twistbin_unhexlify("-(*&");
	assert_null(bad);

	/* Test start good end bad */
	bad = twistbin_unhexlify("abcdef0123-(*&");
	assert_null(bad);

	/* Test start bad end good*/
	bad = twistbin_unhexlify("-+=~`abcdef");
	assert_null(bad);

	/* test upper nibble good lower bad */
	bad = twistbin_unhexlify("a-");
	assert_null(bad);
}

void test_twist_unhexlify_failed_alloc(void **state) {
    (void) state;

	/* Test all bad characters */
	twist_next_alloc_fails();
	twist bad = twistbin_unhexlify("abcd");
	assert_null(bad);
}

void test_twist_hexlify_null(void **state) {
    (void) state;

	twist null = twist_hexlify(NULL);
	assert_null(null);
}

void test_twist_hexlify_0_len(void **state) {
    (void) state;

	twist zero_len = twist_new("");
	twist hex_zero_len = twist_hexlify(zero_len);

	assert_int_equal(twist_len(hex_zero_len), 0);
	assert_int_equal(hex_zero_len[0], '\0');

	twist_free(hex_zero_len);
	twist_free(zero_len);
}

void test_twist_hexlify_good(void **state) {
    (void) state;

	char raw[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
	twist raw_data = twistbin_new(raw, sizeof(raw));
	twist hex_data = twist_hexlify(raw_data);

	assert_int_equal(twist_len(hex_data), sizeof(raw) * 2);
	assert_int_equal(hex_data[twist_len(hex_data)], '\0');
	assert_true(!strcasecmp("0123456789ABCDEF", hex_data));

	twist_free(hex_data);
	twist_free(raw_data);
}

void test_twist_hexlify_alloc_fail(void **state) {
    (void) state;

	char raw[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
	twist raw_data = twistbin_new(raw, sizeof(raw));
	twist_next_alloc_fails();
	twist hex_data = twist_hexlify(raw_data);
	assert_null(hex_data);

	twist_free(raw_data);
}

void test_twist_hexlify_unhelify(void **state) {
    (void) state;

	char *raw_hex = "0123456789ABCDEF";
	char raw_data[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

	twist raw = twistbin_new(raw_data, sizeof(raw_data));
	twist hex = twist_hexlify(raw);

	assert_int_equal(sizeof(raw_data), twist_len(raw));
	assert_int_equal(strlen(raw_hex), twist_len(hex));

	assert_true(!strcasecmp(raw_hex, hex));
	assert_memory_equal(raw_data, raw, sizeof(raw_data));

	twist_free(raw);
	twist_free(hex);
}

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_twist_new),
        cmocka_unit_test(test_twist_new_0_len),
        cmocka_unit_test(test_twist_new_bad_alloc),
        cmocka_unit_test(test_twist_new_empty),
        cmocka_unit_test(test_twist_new_null),
        cmocka_unit_test(test_twist_create),
        cmocka_unit_test(test_twist_create_null),
        cmocka_unit_test(test_twist_create_embedded_null),
        cmocka_unit_test(test_twist_dup),
        cmocka_unit_test(test_twist_dup_empty),
        cmocka_unit_test(test_twist_dup_null),
        cmocka_unit_test(test_twist_end),
        cmocka_unit_test(test_twist_end_null),
        cmocka_unit_test(test_twist_free_null),
        cmocka_unit_test(test_twist_concat),
        cmocka_unit_test(test_twist_concat_empty),
        cmocka_unit_test(test_twistbin_create),
        cmocka_unit_test(test_twistbin_new_overflow_1),
        cmocka_unit_test(test_twistbin_new_overflow_2),
        cmocka_unit_test(test_twistbin_new_overflow_3),
        cmocka_unit_test(test_twistbin_new_overflow_4),
        cmocka_unit_test(test_twistbin_aappend),
        cmocka_unit_test(test_twistbin_aappend_null_array),
        cmocka_unit_test(test_twistbin_aappend_twist_null),
        cmocka_unit_test(test_twistbin_create_null),
        cmocka_unit_test(test_twistbin_create_embedded_null),
        cmocka_unit_test(test_twistbin_concat),
        cmocka_unit_test(test_twistbin_concat_twist_null),
        cmocka_unit_test(test_twistbin_concat_null_data),
        cmocka_unit_test(test_twist_concat_twist_null),
        cmocka_unit_test(test_twist_concat_null_null),
        cmocka_unit_test(test_twist_concat_empty_null),
        cmocka_unit_test(test_twist_concat_null_empty),
        cmocka_unit_test(test_twist_concat_twist),
        cmocka_unit_test(test_twist_concat_twist_null_null),
        cmocka_unit_test(test_twist_concat_twist_twist_null),
        cmocka_unit_test(test_twist_concat_twist_null_twist),
        cmocka_unit_test(test_twist_eq_equality),
        cmocka_unit_test(test_twist_eq_equality_null_null),
        cmocka_unit_test(test_twist_eq_equality_twist_null),
        cmocka_unit_test(test_twist_eq_equality_null_twist),
        cmocka_unit_test(test_twist_eq_not_equality),
        cmocka_unit_test(test_twistbin_new_bin_dup_eq),
        cmocka_unit_test(test_twistbin_new_null),
        cmocka_unit_test(test_twistbin_new_not_eq),
        cmocka_unit_test(test_twistbin_new_not_eq_diff_lengths),
        cmocka_unit_test(test_twist_append),
        cmocka_unit_test(test_twist_append_bad_alloc),
        cmocka_unit_test(test_twistbin_append),
        cmocka_unit_test(test_twist_append_twist),
        cmocka_unit_test(test_twist_append_twist_null),
        cmocka_unit_test(test_twistbin_append_twist_null),
        cmocka_unit_test(test_twist_append_twist_twist_null),
        cmocka_unit_test(test_twist_append_null_string),
        cmocka_unit_test(test_twistbin_append_null_string),
        cmocka_unit_test(test_twist_append_twist_null_string),
        cmocka_unit_test(test_twist_append_null_null),
        cmocka_unit_test(test_twistbin_append_null_null),
        cmocka_unit_test(test_twist_append_twist_null_null),
        cmocka_unit_test(test_twist_truncate_smaller),
        cmocka_unit_test(test_twist_truncate_bigger),
        cmocka_unit_test(test_twist_truncate_bigger_bad_alloc),
        cmocka_unit_test(test_twist_truncate_same),
        cmocka_unit_test(test_twist_truncate_zero),
        cmocka_unit_test(test_twist_truncate_null),
        cmocka_unit_test(test_twist_unhexlify_null),
        cmocka_unit_test(test_twist_unhexlify_0_len),
        cmocka_unit_test(test_twist_unhexlify_odd_len),
        cmocka_unit_test(test_twist_unhexlify_even_len),
        cmocka_unit_test(test_twist_unhexlify_bad_chars),
        cmocka_unit_test(test_twist_unhexlify_failed_alloc),
        cmocka_unit_test(test_twist_hexlify_null),
        cmocka_unit_test(test_twist_hexlify_0_len),
        cmocka_unit_test(test_twist_hexlify_good),
        cmocka_unit_test(test_twist_hexlify_alloc_fail),
        cmocka_unit_test(test_twist_hexlify_unhelify),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
