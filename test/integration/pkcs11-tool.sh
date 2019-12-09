#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -e

setup_asan()
{
    if [ "$ASAN_ENABLED" = "true" ]; then
        # To get line numbers set up the asan symbolizer
        clang_version=`$CC --version | head -n 1 | cut -d\  -f 3-3 | cut -d\. -f 1-3 | cut -d- -f 1-1`
        # Sometimes the version string has an Ubuntu on the front of it and the field
        # location changes
        if [ $clang_version == "version" ]; then
            clang_version=`$CC --version | head -n 1 | cut -d\  -f 4-4 | cut -d\. -f 1-3`
        fi
        echo "Detected clang version: $clang_version"
        minor_maj=`echo "$clang_version" | cut -d\. -f 1-2`
        export LD_PRELOAD=/usr/lib/llvm-$minor_maj/lib/clang/$clang_version/lib/linux/libclang_rt.asan-$(arch).so
        echo "export LD_PRELOAD=\"$LD_PRELOAD\""
        export ASAN_OPTIONS=detect_leaks=0
        echo "turning off asan detection for running commands..."
    fi
}

setup_asan

if [ -z "$modpath" ]; then
  modpath="$PWD/src/.libs/libtpm2_pkcs11.so"
fi

echo "modpath=$modpath"

pkcs11_tool() {
  pkcs11-tool --module "$modpath" "$@"
  return $?
}

cert=$(pkcs11_tool --label label --list-objects --type cert)

id=$(echo $cert | cut -d: -f 5- | sed s/' '//g)

# a public key with a cert label should exist
pkcs11_tool --slot=1 --list-objects --type pubkey | grep "$id"

# a private key with a cert label should exist
pkcs11_tool --slot=1 --list-objects --type privkey --pin myuserpin | grep "$id"

# test pin change
pkcs11_tool --slot=1 --login --pin myuserpin --change-pin --new-pin mynewpin

# change userpin from sopin
pkcs11_tool --slot=1 --init-pin --so-pin=mysopin --pin=myuserpin

# test getting random data w/o login
pkcs11_tool --slot=1 --generate-random 4 | xxd

# test generating RSA keypair
pkcs11_tool --slot=1 --label="myrsakey" --pin=myuserpin --keypairgen

# test generating EC keypair
pkcs11_tool --slot=1 --label="myecckey" --pin=myuserpin --keypairgen --usage-sign --key-type EC:prime256v1

pkcs11_tool --slot=1 --pin=myuserpin --delete-object --type=privkey --label=myecckey
pkcs11_tool --slot=1 --pin=myuserpin --delete-object --type=pubkey --label=myecckey

exit 0
