# SPDX-License-Identifier: BSD-2-Clause
#!/usr/bin/env bash

setup_asan() {
  if [ -z "$ASAN_ENABLED" ]; then
    return 0
  fi

  # To get line numbers set up the asan symbolizer
  clang_version=$("$CC" --version | head -n 1 | cut -d' ' -f 3 | cut -d'.' -f 1-3 | cut -d'-' -f 1 )
  # Sometimes the version string has an Ubuntu on the front of it and the field
  # location changes
  if [ "$clang_version" == "version" ]; then
    clang_version=$("$CC" --version | head -n 1 | cut -d' ' -f 4 | cut -d'.' -f 1-3 )
  fi

  # Sometimes there is an rc version
  if grep -qi '\-+rc' <<< "$clang_version"; then
    clang_version=$( echo "$clang_version" | cut -d'-' -f 1 )
  fi

  echo "Detected clang version: $clang_version"
  minor_maj=$(echo "$clang_version" | cut -d'.' -f 1-2 )
  maj=$(echo "$clang_version" | cut -d'.' -f 1 )

  resource_dir="$(${CC} --print-resource-dir)"
  search_dir="${resource_dir}/lib"

  # Find the ASan runtime by first looking into the resource directory
  found=$(find "${search_dir}" -name "libclang_rt.asan*.so" 2>/dev/null | head -n 1)

  # If not found in resource dir, try some common fallback locations
  if [ -z "${found}" ]; then
    possible_dirs=(
      "/usr/lib/llvm-${minor_maj}/lib/clang/${clang_version}"
      "/usr/lib/llvm-${maj}/lib/clang"
      "/usr/lib/clang/${clang_version}/lib"
      "/usr/lib64/clang/${clang_version}/lib"
      "/usr/lib/llvm*/lib/clang"
      "/usr/local/lib/clang"
    )

    for dir in "${possible_dirs[@]}"; do
      found=$(find "${dir}" -name "libclang_rt.asan*.so" 2>/dev/null | head -n 1)
      if [ -n "${FOUND}" ]; then
        break
      fi
    done
  fi

  if [ -n "${found}" ]; then
    echo "libasan found: ${found}"
  else
    echo "libclang_rt.asan.so not found"
    exit 1
  fi

  export LD_PRELOAD="${found}"
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

check_openssl_version()
{
  # do this in an if statement so it can fail and not cause
  # set -e (execfail) to exit the script
  if pkg-config --exists 'libcrypto < 3'; then
    OSSL3_DETECTED=0
  else
    OSSL3_DETECTED=1
  fi
}

