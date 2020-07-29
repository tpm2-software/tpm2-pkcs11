/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"
#include "debug.h"

/*
 * Drop WEAK or the parse_attributes_from_string is NULL
 * This command below will be empty without this. I am not
 * 100% sure why its not getting resolved properly, but this
 * fixes it for now.
 * nm --defined ./test/fuzz/yaml-parser.fuzz | grep parse
   00000000005558d0 T parse_attributes_from_string
 */
#undef WEAK
#define WEAK

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
