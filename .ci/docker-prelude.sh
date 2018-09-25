#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2
#
# Copyright (c) 2017-2018 Intel Corporation
# All rights reserved.
#

# all command failures are fatal
set -e

WORKSPACE=`dirname $TRAVIS_BUILD_DIR`

echo "Workspace: $WORKSPACE"

source $TRAVIS_BUILD_DIR/.ci/download-deps.sh

get_deps "$WORKSPACE"

export LD_LIBRARY_PATH=/usr/local/lib/
export PATH=/root/.local/bin/:/ibmtpm974/src:$PATH

echo "echo changing to $TRAVIS_BUILD_DIR"
# Change to the the travis build dir
cd $TRAVIS_BUILD_DIR
