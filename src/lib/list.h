/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef LIST_H_
#define LIST_H_

typedef struct list list;
struct list {
    list *next;
};

#define list_entry(element, type, name) \
        (type *)(((uint8_t *)(element)) - (uint8_t *)&(((type *)NULL)->name))

#define list_for_each(list, var) \
    for(var = list; var != NULL; var = var->next)

#endif /* LIST_H_ */
