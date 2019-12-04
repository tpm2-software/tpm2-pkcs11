/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2018, William Roberts
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <config.h>

#include <alloca.h>
#include <ctype.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "twist.h"

#ifdef UNIT_TESTING
    static int _next_alloc_fails = 0;
    void twist_next_alloc_fails(void) {
        _next_alloc_fails = 1;
    }

    static int alloc_fails(void) {
        int x = _next_alloc_fails;
        _next_alloc_fails = 0;
        return x;
    }
#else
    static int alloc_fails(void) {
        return 0;
    }
#endif

#define LEN(x) (sizeof(x)/sizeof(*x))

typedef struct twist_hdr twist_hdr;
struct twist_hdr {
	char *end;
	char data[];
};

#define safe_add(r, a, b) __builtin_add_overflow(a, b, &r)
#define safe_mul(r, a, b) __builtin_mull_overflow(a, b, &r)

static inline twist_hdr *from_twist_to_hdr(twist tstring) {
	return (twist_hdr *) (tstring - sizeof(char *));
}

static inline twist from_hdr_to_twist(twist_hdr *str) {
	return (twist) str->data;
}

static void *twist_realloc(void *ptr, size_t size) {
    if (alloc_fails()) {
        return NULL;
    }

    return realloc(ptr, size);
}

static twist_hdr *internal_realloc(twist old, size_t size) {

	/* add header to size */
	bool fail = safe_add(size, size, sizeof(twist));
	if (fail) {
		return NULL ;
	}

	/* add null byte space */
	fail = safe_add(size, size, 1);
	if (fail) {
		return NULL ;
	}

	twist_hdr *old_hdr = old ? from_twist_to_hdr(old) : NULL;

	return (twist_hdr *) twist_realloc(old_hdr, size);
}

static twist internal_append(twist orig, const binarybuffer data[],
		const size_t len) {

	size_t i;
	size_t size = 0;
	for (i = 0; i < len; i++) {
		const binarybuffer *b = &data[i];
		if (!b->size) {
			continue;
		}

		bool fail = safe_add(size, size, b->size);
		if (fail) {
			return NULL ;
		}
	}

	/* account for the space in the original string if specified */
	size_t offset = 0;
	if (orig) {
		offset = twist_len(orig);
		bool fail = safe_add(size, size, offset);
		if (fail) {
			return NULL ;
		}
	}

	twist_hdr *hdr = internal_realloc(orig, size);
	if (!hdr) {
		return NULL ;
	}

	for (i = 0; i < len; i++) {
		const binarybuffer *b = &data[i];
		if (b->data) {
	        memcpy(&hdr->data[offset], data[i].data, data[i].size);
		} else {
		    memset(&hdr->data[offset], 0, data[i].size);
		}
		offset += data[i].size;
	}

	hdr->end = hdr->data + offset;
	*hdr->end = '\0';

	return from_hdr_to_twist(hdr);
}

static inline twist internal_create(const binarybuffer data[], const size_t len) {
	return internal_append(NULL, data, len);
}

twist twist_new(const char *str) {

	if (!str) {
		return NULL ;
	}

	const binarybuffer things[1] = { { .size = strlen(str), .data = str } };

	return internal_create(things, LEN(things));
}

twist twist_calloc(size_t size) {

    if (!size) {
        return NULL;
    }

    const binarybuffer things[1] = { { .size = size, .data = NULL } };

    return internal_create(things, LEN(things));
}

size_t twist_len(twist tstring) {

	twist_hdr *str = from_twist_to_hdr(tstring);

	size_t len = str->end - str->data;
	return len;
}

twist twist_dup(twist tstring) {

	if (!tstring) {
		return NULL ;
	}

	const binarybuffer things[1] = { { .size = twist_len(tstring), .data =
			tstring } };

	return internal_create(things, LEN(things));
}

void twist_free(twist tstring) {

	if (!tstring) {
		return;
	}

	free(from_twist_to_hdr(tstring));
}

extern char *twist_end(twist tstring) {

	if (!tstring) {
		return NULL ;
	}

	twist_hdr *hdr = from_twist_to_hdr(tstring);
	return hdr->end - 1;
}

twist twist_concat_twist(twist a, twist b) {

	if (!b) {
		return twist_dup(a);
	}

	if (!a) {
		return twist_dup(b);
	}

	binarybuffer things[2] = { { .size = twist_len(a), .data = a }, { .size =
			twist_len(b), .data = b } };

	return internal_create(things, LEN(things));
}

static twist twist_concat_internal(twist old_str, const void *data, size_t len) {

	const binarybuffer things[2] = { { .size = twist_len(old_str), .data =
			old_str }, { .size = len, .data = data }, };

	return internal_create(things, LEN(things));
}

twist twistbin_concat(twist old_str, const void *data, size_t len) {

	if (!data) {
		return twist_dup(old_str);
	}

	if (!old_str) {
		return twistbin_new(data, len);
	}

	return twist_concat_internal(old_str, data, len);
}

twist twist_concat(twist old_str, const char *new_str) {

	if (!new_str) {
		return twist_dup(old_str);
	}

	if (!old_str) {
		return twist_new(new_str);
	}

	size_t new_len = strlen(new_str);
	if (new_len == 0) {
		return twist_dup(old_str);
	}

	return twist_concat_internal(old_str, new_str, new_len);
}

bool twist_eq(twist x, twist y) {

	if (x == y) {
		return true;
	}

	if (!x || !y) {
		return false;
	}

	if (twist_len(x) != twist_len(y)) {
		return false;
	}

	return !memcmp(x, y, twist_len(x));
}

twist twistbin_new(const void *data, size_t size) {

	if (!data) {
		return NULL ;
	}

	const struct binarybuffer things[1] = { { .size = size, .data = data } };

	return internal_create(things, LEN(things));
}

twist twist_append(twist old_str, const char *new_str) {

	if (!old_str) {
		return twist_new(new_str);
	}

	if (!new_str) {
		return old_str;
	}

	binarybuffer data[1] = { { .data = new_str, .size = strlen(new_str) } };

	return internal_append(old_str, data, LEN(data));
}

twist twistbin_append(twist old_str, const void *new_data, size_t len) {

	if (!old_str) {
		return twistbin_new(new_data, len);
	}

	if (!new_data) {
		return old_str;
	}

	binarybuffer data[1] = { { .data = new_data, .size = len } };

	return internal_append(old_str, data, LEN(data));
}

twist twistbin_aappend(twist old_str, binarybuffer data[], size_t num_of_args) {

	if (!data || !num_of_args) {
		return old_str;
	}

	return internal_append(old_str, data, num_of_args);
}

twist twist_append_twist(twist old_str, twist new_str) {

	if (!old_str) {
		return new_str;
	}

	if (!new_str) {
		return old_str;
	}

	return twistbin_append(old_str, new_str, twist_len(new_str));
}

twist twist_truncate(twist tstring, size_t len) {

	if (!tstring) {
		return NULL ;
	}

	size_t old_len = twist_len(tstring);
	if (old_len == len) {
		return tstring;
	}

	twist_hdr *hdr = internal_realloc(tstring, len);
	if (!hdr) {
		return NULL ;
	}

	hdr->end = hdr->data + len;

	if (old_len < len) {
		memset(&hdr->data[old_len], 0, len - old_len);
	} else {
		*hdr->end = '\0';
	}

	return from_hdr_to_twist(hdr);
}

twist twist_create(const char *data[], size_t len) {

	if (!data || !len) {
		return NULL ;
	}

	size_t i;
	size_t found = 0;
	binarybuffer *bindata = calloc(len, sizeof(bindata[0]));
	if (!bindata) {
	    return NULL;
	}

	for (i = 0; i < len; i++) {
		const char *arg = data[i];
		if (arg) {
			bindata[found].data = arg;
			bindata[found].size = strlen(arg);
			found++;
		}
	}

	twist tmp = internal_create(bindata, found);
	free(bindata);
	return tmp;
}

twist twistbin_create(const binarybuffer data[], size_t len) {

	if (!data || !len) {
		return NULL ;
	}
	return internal_create(data, len);
}

static twist hexlify(const char *data, size_t datalen) {

    twist_hdr *hdr = internal_realloc(NULL, datalen * 2);
    if (!hdr) {
        return NULL;
    }

    size_t i;
    for (i = 0; i < datalen; i++) {
        sprintf(hdr->data + (i * 2), "%02x", 255 & data[i]);
    }

    hdr->data[datalen *2] = '\0';
    hdr->end = &hdr->data[datalen * 2];

    return from_hdr_to_twist(hdr);

}

twist twist_hex_new(const char *data, size_t len) {

    if (!data) {
        return NULL;
    }

    return hexlify(data, len);
}

twist twist_hexlify(const twist data) {

	if (!data) {
		return NULL;
	}

	size_t datalen = twist_len(data);

	return hexlify(data, datalen);
}

static bool hex2bin(char hexchr, char *out) {

	char p = tolower(hexchr);
    if (p >= '0' && p <= '9') {
        *out = p - 0x30;
        return true;
    } else if(p >= 'a' && p <= 'f') {
        *out = p - 0x61 + 0xA;
        return true;
    }

    return false;
}

twist twistbin_unhexlify(const char *hexdata) {

	if (!hexdata) {
		return NULL;
	}

	size_t hexlen = strlen(hexdata);
	if (hexlen & 0x1) {
		return NULL;
	}

	size_t rawlen = hexlen/2;
	twist_hdr *hdr = internal_realloc(NULL, rawlen);
	if (!hdr) {
		return NULL;
	}

	char *raw = hdr->data;

	size_t i, j;
	for (i=0, j=0; i < rawlen; i++, j+=2) {
		char upper_nibble;
		bool result = hex2bin(hexdata[j], &upper_nibble);
		if (!result) {
			goto error;
		}
		upper_nibble <<= 4;

		char lower_nibble;
		result = hex2bin(hexdata[j + 1], &lower_nibble);
		if (!result) {
			goto error;
		}

		raw[i] = upper_nibble | lower_nibble;
	}

	raw[rawlen] = '\0';
	hdr->end = &raw[rawlen];

	return from_hdr_to_twist(hdr);

error:
	twist_free(from_hdr_to_twist(hdr));
	return NULL;
}
