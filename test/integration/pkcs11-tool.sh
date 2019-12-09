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

echo "Finding cert"
id=$(pkcs11_tool --label label --list-objects --type cert | grep 'ID:' | cut -d':' -f2- | sed s/' '//g)
echo "Found cert: $id"

# a public key with a cert label should exist
echo "Looking for public key with id: $id"
pkcs11_tool --slot=1 --list-objects --type pubkey | grep "$id"
echo "Found pubkey"

# a private key with a cert label should exist
echo "Looking for private key with id: $id"
pkcs11_tool --slot=1 --list-objects --type privkey --login --pin myuserpin | grep "$id"
echo "Found privkey"

# test pin change
echo "Attempting pin change"
pkcs11-tool --module "$modpath" --slot=1 --login --pin myuserpin --change-pin --new-pin mynewpin
echo "Pin changed"

# change userpin from sopin
echo "Reseting pin"
pkcs11_tool --slot=1 --init-pin --login --so-pin=mysopin --pin=myuserpin
echo "Pin Reset"

# test getting random data w/o login
echo "Getting random"
pkcs11_tool --slot=1 --generate-random 4 | xxd
echo "Random got"

# test generating RSA keypair
echo "Generating RSA keypair"
pkcs11_tool --slot=1 --label="myrsakey" --login --pin=myuserpin --keypairgen
echo "RSA Keypair generated"

# test generating EC keypair
echo "Generating EC keypair"
pkcs11_tool --slot=1 --label="myecckey" --login --pin=myuserpin --keypairgen --usage-sign --key-type EC:prime256v1
echo "EC Keypair generated"

echo "Deleting privkey"
pkcs11_tool --slot=1 --pin=myuserpin --login --delete-object --type=privkey --label=myecckey
echo "Privkey deleted"

echo "Deleting pubkey"
pkcs11_tool --slot=1 --pin=myuserpin --login --delete-object --type=pubkey --label=myecckey
echo "Pubkey deleted"

exit 0
