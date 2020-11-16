#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

# all command failures are fatal
set -e

WORKSPACE=`dirname $DOCKER_BUILD_DIR`

echo "Workspace: $WORKSPACE"

source $DOCKER_BUILD_DIR/.ci/download-deps.sh

get_deps "$WORKSPACE"

export LD_LIBRARY_PATH=/usr/local/lib/

# Unfortunately, p11tool unlearned the option for $HOME/.config/pkcs11/modules
# This is true for Fedora 30 container and upstream
# Thus we have to define it system-wide in this container
if [ ! -e /etc/pkcs11/modules/tpm2_pkcs11.module ]; then
  echo "Creating /etc/pkcs11/modules/tpm2_pkcs11.module"
  mkdir -p /etc/pkcs11/modules || true
  echo "module: $DOCKER_BUILD_DIR/build/src/.libs/libtpm2_pkcs11.so" \
       >/etc/pkcs11/modules/tpm2_pkcs11.module
fi

echo "echo changing to $DOCKER_BUILD_DIR"
# Change to the the travis build dir
cd $DOCKER_BUILD_DIR
