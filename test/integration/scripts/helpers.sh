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

  p="/usr/lib/llvm-$minor_maj/lib/clang/$clang_version/lib/linux/libclang_rt.asan-$(arch).so"
  echo "Looking for libasan to LD_PRELOAD at: $p"
  if [ ! -f "$p" ]; then
    p="/usr/lib64/clang/$clang_version/lib/linux/libclang_rt.asan-$(arch).so"
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
  local SERIAL="${1:-02}"
  export CA_PEM="ca.pem"
  export CA_KEY="ca.key"

  export SERVER_PEM="server.pem"
  export SERVER_KEY="server.key"

  # Generate CA CERT and CA KEY
  openssl req \
    -x509 \
    -nodes \
    -days 3650 \
    -newkey rsa:2048 \
    -keyout "$CA_KEY" \
    -out "$CA_PEM" \
    -subj "/C=US/ST=Radius/L=Somewhere/O=Example Inc./CN=example.com"

  # Create the SERVER key
  openssl genrsa -out "$SERVER_KEY" 2048
  openssl req -new \
    -key "$SERVER_KEY" \
    -out server.csr \
    -subj "/C=US/ST=Radius/L=Somewhere/O=Example Inc./CN=server.example.com"

  # Create the SERVER certificate
  openssl x509 -req -days 1460 -in server.csr \
    -CA "$CA_PEM" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$SERVER_PEM"

  # make the DB
  touch index.txt
  touch index.txt.attr
  echo "$SERIAL" >> serial
}
