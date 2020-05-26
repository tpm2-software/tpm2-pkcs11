# SPDX-License-Identifier: BSD-2-Clause
#!/usr/bin/env bash

setup_asan() {
  if [ "$ASAN_ENABLED" != "true" ]; then
    return 0
  fi

  # To get line numbers set up the asan symbolizer
  clang_version=`$CC --version | head -n 1 | cut -d\  -f 3-3 | cut -d\. -f 1-3 | cut -d- -f 1-1`
  # Sometimes the version string has an Ubuntu on the front of it and the field
  # location changes
  if [ $clang_version == "version" ]; then
    clang_version=`$CC --version | head -n 1 | cut -d\  -f 4-4 | cut -d\. -f 1-3`
  fi
  echo "Detected clang version: $clang_version"
  minor_maj=`echo "$clang_version" | cut -d\. -f 1-2`
  maj=`echo "$clang_version" | cut -d\. -f 1-1`

  p="/usr/lib/llvm-$minor_maj/lib/clang/$clang_version/lib/linux/libclang_rt.asan-$(arch).so"
  echo "Looking for libasan to LD_PRELOAD at: $p"
  if [ ! -f "$p" ]; then
    p="/usr/lib/llvm-$maj/lib/clang/$clang_version/lib/linux/libclang_rt.asan-$(arch).so"
  fi
  if [ ! -f "$p" ]; then
    p="/usr/lib64/clang/$clang_version/lib/linux/libclang_rt.asan-$(arch).so"
  fi

  if [ ! -f "$p" ]; then
    echo "Couldn't find libasan.so"
    return -1
  fi
  echo "Found libasan at: $p"

  export LD_PRELOAD="$p"
  echo "export LD_PRELOAD=\"$LD_PRELOAD\""
  export ASAN_OPTIONS=detect_leaks=0
  echo "turning off asan detection for running commands..."

  return 0
}

clear_asan() {
    unset LD_PRELOAD
    unset ASAN_OPTIONS
}

setup_ca() {
  CA_DIR=`mktemp -d -t tpm2tmpca.XXXXXX`

  export CA_DIR
  export CA_PEM="$CA_DIR/ca.pem"
  export CA_KEY="$CA_DIR/ca.key"

  # Generate CA CERT and CA KEY
  openssl req \
    -x509 \
    -nodes \
    -days 3650 \
    -newkey rsa:2048 \
    -keyout "$CA_KEY" \
    -out "$CA_PEM" \
    -subj "/C=US/ST=Radius/L=Somewhere/O=Example Inc./CN=example.com"

  # make the DB
  touch "$CA_DIR"/index.txt
  touch "$CA_DIR"/index.txt.attr
  echo "01" >> "$CA_DIR"/serial
}

cleanup_ca()
{
  test -n "$CA_DIR" || return 0
  rm -rf "$CA_DIR"
}
