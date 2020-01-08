#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -e

if [ "$ASAN_ENABLED" = "true" ]; then
  # Skip this test when ASAN is enabled
  exit 77
fi

export CLASSPATH="$CLASSPATH:$TEST_JAVA_ROOT"

echo "CLASSPATH=$CLASSPATH"

#dont use -cp here, it causes env CLASSPATH not to be used
java PKCS11JavaTests

exit 0
