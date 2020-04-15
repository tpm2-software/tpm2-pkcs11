#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
set -u
set +o nounset
set -x

# see:
#  - https://stackoverflow.com/questions/1215538/extract-parameters-before-last-parameter-in
# for details on this. it moves the last argument (the fuzz-target) the front and the
# AM_FUZZ_LOG_FLAGS after the executable fuzz target...whew.
env ${@:$#} ${*%${!#}}

exit $?
