/* SPDX-License-Identifier: BSD-2-Clause */
#include <config.h>

#include <stdbool.h>
#include <stdlib.h>

#include "attrs.h"
#include "parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    attr_list *attrs = NULL;

    parse_attributes_from_string(data, size,
            &attrs);
    attr_list_free(attrs);

    return 0;
}
