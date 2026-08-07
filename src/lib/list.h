/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef LIST_H_
#define LIST_H_

#include <stddef.h>

typedef struct list list;
struct list {
    list *next;
    list *prev;
};

#define list_entry(element, type, name) \
        (type *)((uint8_t *)(element) - offsetof(type, name))

#define list_for_each(list, var) \
    for(var = list; var != NULL; var = var->next)

#endif /* LIST_H_ */
