/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_LIB_DEBUG_H_
#define SRC_LIB_DEBUG_H_
#include "config.h"

#if defined(FUZZING) || defined(UNIT_TESTING) || !defined(NDEBUG)
#define WEAK __attribute__((weak))
#define DEBUG_VISIBILITY
#define TESTING 1
#else
#define WEAK
#define DEBUG_VISIBILITY static
#endif

#endif /* SRC_LIB_DEBUG_H_ */
