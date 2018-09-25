#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2
#
# Copyright (c) 2017-2018 Intel Corporation
# All rights reserved.
#

if [ "$ENABLE_COVERAGE" != "true" ]; then
  echo "ENABLE_COVERAGE not true, got "$ENABLE_COVERAGE""
  echo "Exiting..."
  exit 0
fi

if [ -z "$COVERALLS_REPO_TOKEN" ]; then
  echo "COVERALLS_REPO_TOKEN *not* set"
  exit 0
fi

echo "COVERALLS_REPO_TOKEN set"

coveralls --build-root=build --gcov-options '\-lp'
exit $?
