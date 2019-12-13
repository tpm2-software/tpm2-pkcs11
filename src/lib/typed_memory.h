/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SRC_LIB_TYPED_MEMORY_H_
#define SRC_LIB_TYPED_MEMORY_H_

#define TYPE_BYTE_INT ((CK_BYTE)1)
#define TYPE_BYTE_BOOL ((CK_BYTE)2)
#define TYPE_BYTE_INT_SEQ ((CK_BYTE)3)
#define TYPE_BYTE_HEX_STR ((CK_BYTE)4)
/*
 * if we ever need wrap templates we will define a special type.
 * The parser would also need to be updated to recognize a seq
 * of attribute template pointers.
 */
#define TYPE_BYTE_TEMP_SEQ ((CK_BYTE)5)

void *type_calloc(size_t nmemb, size_t size, CK_BYTE type);
void *type_realloc(void *orig, size_t size, CK_BYTE type);
CK_BYTE type_from_ptr(void *ptr, size_t len);
CK_RV type_mem_dup(void *in, size_t len, void **dup);
void type_mem_cpy(void *dest, void *in, size_t size);

#endif /* SRC_LIB_TYPED_MEMORY_H_ */
