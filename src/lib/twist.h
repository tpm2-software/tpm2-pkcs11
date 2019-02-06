/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2016-2018, William Roberts
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef TWIST_H_
#define TWIST_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Standard twist tstrings are safe to pass to C string routines. twist tstrings
 * created from twistbin_new() are safe to pass as well, since twist guarantees
 * all buffers are NULL terminated. however, they may contain NULL bytes in
 * between the start and end, so the C string routines might not give you what
 * you expect.
 */
typedef const char* twist;

/**
 * Binary buffers are used to create a binary safe string
 * from many sources.
 */
typedef struct binarybuffer binarybuffer;
struct binarybuffer {
	const void *data; /* data to store */
	size_t size; /* length of that data */
};

/**
 * Creates a new twist tstring from a C string.
 * @param tstring
 *  The C string to convert to a twist tstring.
 * @return
 *  A new twist tstring on success, NULL on error or if string is NULL.
 *  Call twist_free() on the return when done.
 */
extern twist twist_new(const char *string);

/**
 * Creates a twist string of size bytes filled with zeroes.
 * @param size
 *  The size of the string to allocate.
 * @return
 *  A new twiest string on success or NULL on error. Like twist_new(), the
 *  allocated string should be freed by twist_free().
 */
extern twist twist_calloc(size_t size);

/**
 * Creates a new, binary safe string. This string, like all
 * twist tstrings, is NULL terminated. However, this twist tstring
 * can have NULL bytes within its bounds. It is safe to pass to
 * C string routines and all twist routines, but note the the
 * C routines are not binary safe, so one should always use
 * twist routines.
 *
 * @param data
 *  The data to create the new twist tstring from.
 * @param len
 *  The length of the data.
 * @return
 *  A new twist tstring to pass to twist_free() when done. On error, it
 *  returns NULL or if NULL is passed for data.
 */
extern twist twistbin_new(const void *data, size_t len);

/**
 * Creates a new twist string from an array of strings, concatenating
 * them as it goes. The resulting string is like so:
 * data[0] + data[1] + .. + data[n]
 * @param data
 * 	The array of string to initialize and concatenate the twist string from.
 * @param len
 *  The length of the array given by data.
 * @return
 *  A new twist string or NULL on error. Should be passed to twist_free()
 */
extern twist twist_create(const char *data[], size_t len);

/**
 * Creates a new, binary safe twist string, similair to twist_create().
 * @param data
 * 	An array of data pointers with lengths.
 * @param len
 * 	The length of the data array.
 * @return
 *  A new twist string or NULL on error. Should be passed to twist_free()
 */
extern twist twistbin_create(const binarybuffer data[], size_t len);

/**
 * Returns the length of a twist tstring in O(1) time.
 * @param tstring
 * 	The twist tstring to check the length of.
 * @return
 *  The length of the string.
 */
extern size_t twist_len(twist tstring);

/**
 * Duplicates a twist tstring.
 * Note that assigning to the parameter results in a memory leak.
 * @param tstring
 * 	The twist tstring to duplicate.
 * @return
 *  A new twist tstring or NULL on error or if string is NULL. Call twist_free()
 *  on the return when done.
 */
extern twist twist_dup(twist tstring);

/**
 * Frees a twist tstring. It is safe to pass NULL.
 * @param tstring
 *  The twist tstring to free.
 */
extern void twist_free(twist tstring);

/**
 * Concatenates a new string onto old string
 * @param old_str
 * 	The old string to concatenate to.
 * @param new_str
 *  The new string to append to the old string.
 * @return
 *  A new string to be passed to twist_free() or NULL on error.
 *  Note: If you wish to reuse the same memory, see twist_append().
 *  It reurns NULL on error or if old_str and new_str are NULL.
 */
extern twist twist_concat(twist old_str, const char *new_str);

/**
 * Like twist_concat() but allows appending binary safe data.
 * @param old_str
 * 	The twist tstring to append to.
 * @param data
 * 	The data to append.
 * @param len
 * 	The length of that data.
 * @return
 */
extern twist twistbin_concat(twist old_str, const void *data, size_t len);

/**
 * Concatenates two twist tstrings together. Never assign back to a specified
 * parameter or a memory leak will ensue (orphaned pointer).
 * @param old_str
 *	The first part of the string.
 * @param new_str
 *  The second part of the string.
 * @return
 *  A new twist tstring of new_str appended to old_str, that should be
 *  be passed to twist_free() when done. It returns NULL on error
 *  or if both old_str and new_str are NULL.
 */
extern twist twist_concat_twist(twist old_str, twist new_str);

/**
 * Tests for equivalence and avoids a comparison if the
 * lengths alter. Thus tests like strcmp('fool', 'foo')
 * are performed in O(1). If the lengths are equal,
 * a O(N) (worst case) comparison is done (memcmp)
 * @param x
 * 	A twist tstring to test.
 * @param y
 * A twist tstring to test.
 * @return
 *  true on equivalence, false otherwise.
 */
extern bool twist_eq(twist x, twist y);

/**
 * Appends a new string to a twist tstring preserving the already allocated
 * memory space. Use this if a new string (aka heap allocation) is not required.
 * Do not assign old_str to the return value without checking for NULL, or a
 * memory leak will ensue.
 * @param old_str
 * 	The string to append to.
 * @param new_str
 * 	The new string data to append.
 * @return
 *  A re-allocated version of old_str with new_str appended onto it. One no longer
 *  needs to twist_free(old_str), but merely the return. Returns NULL on error or
 *  of old_str and new_str are NULL.
 */
extern twist twist_append(twist old_str, const char *new_str);

/**
 * Like twist_append() but works with binary safe data.
 * @param old_str
 *  The string data to append to.
 * @param data
 *  The data to append.
 * @param len
 *  The length of the data.
 * @return
 *  A re-allocated version of old_str with data appended onto it. One no longer
 *  needs to twist_free(old_str), but merely the return. Returns NULL on error or
 *  of old_str and data are NULL.
 */
extern twist twistbin_append(twist old_str, const void *data, size_t len);

/**
 * like twistbin_append but takes an array of binarybuffer's.
 * @param old_str
 *  The old string to reallocate and append to.
 * @param data
 * 	The data to add, in order from index 0 to N.
 * @param num_of_args
 * 	The number of items in the data array.
 * @return
 * 	NULLon failure or a reallocated twist string.
 */
extern twist twistbin_aappend(twist old_str, binarybuffer data[], size_t num_of_args);

/**
 * Like twistbin_append() but the data to append is another twist tstring.
 * @param old_str
 *  The twist tstring to append to.
 * @param new_str
 *  The new string to append.
 * @return
 *  A re-allocated version of old_str with new_str appended onto it. One no longer
 *  needs to twist_free(old_str), but merely the return. Returns NULL on error or
 *  of old_str and new_str are NULL.
 */
extern twist twist_append_twist(twist old_str, twist new_str);

/**
 * Truncates a string to the giben length, preserving the trailing NULL byte.
 * If the new length is larger than the original length, the new memory is 0
 * allocated.
 * @param tstring
 * 	The twist tstring to truncate to a given size.
 * @param len
 *  The length to truncate it to.
 * @return
 */
extern twist twist_truncate(twist tstring, size_t len);

/**
 * Returns a pointer to the right hand end of the string,
 * before the terminating null byte.
 * @param tstring
 * 	The twist tstring to get the right hand pointer of.
 * @return
 * 	The pointer to the end of the string on the first valid
 * 	byte before the guaranteed NULL byte.
 */
extern char *twist_end(twist tstring);

/**
 * Given a C style string encoded in base 16, without the trailing 0x,
 * return a raw data representation of it.
 * @param hexdata
 *  The data to convert to raw bytes from ASCII encoded hex.
 * @return
 *  A binary twist, this could contain interleaved NULL bytes, but
 *  is guaranteed to end in a NULL byte.
 */
twist twistbin_unhexlify(const char *hexdata);

/**
 * The opposite of unhexlify. Converts a binary twist to a hex string without
 * a leading 0x.
 * @param data
 *  The binary data to base 16 encode.
 * @return
 *  A twist on success, NULL on failure.
 */
twist twist_hexlify(const twist data);

/**
 * Given a binary data string, converts it to a hex encoded string without a leaded 0x
 * and is guaranteed to be NULL terminated.
 *
 * @param data
 *  The data to encode as hex.
 * @param len
 *  The length of the data.
 * @return
 *  A twist on success, NULL on failure.
 */
twist twist_hex_new(const char *data, size_t len);

#endif /* TWIST_H_ */
