#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -eo pipefail

if [ -z "$T" ]; then
    export T="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
fi

source "$T/test/integration/scripts/helpers.sh"

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
echo "Resetting pin"
pkcs11_tool --slot=1 --init-pin --login --so-pin=mysopin --pin=myuserpin
echo "Pin Reset"

# test getting random data w/o login
if [[ "${DOCKER_IMAGE:-nodocker}" != "ubuntu-16.04" && "${DOCKER_IMAGE:-nodocker}" != "ubuntu-18.04" ]]; then
    echo "Getting random"
    pkcs11_tool --slot=1 --generate-random 4 | xxd
    echo "Random got"
else
    echo "Skipping pkcs11-tool --generate-random, not supported on ${DOCKER_IMAGE}"
fi

# test generating RSA key pair
echo "Generating RSA key pair"
pkcs11_tool --slot=1 --label="myrsakey" --login --pin=myuserpin --keypairgen
echo "RSA Key pair generated"

# test generating EC key pair
echo "Generating EC key pair"
pkcs11_tool --slot=1 --label="myecckey" --login --pin=myuserpin --keypairgen --usage-sign --key-type EC:prime256v1
echo "EC Key pair generated"

echo "Deleting privkey"
pkcs11_tool --slot=1 --pin=myuserpin --login --delete-object --type=privkey --label=myecckey
echo "Privkey deleted"

echo "Deleting pubkey"
pkcs11_tool --slot=1 --pin=myuserpin --login --delete-object --type=pubkey --label=myecckey
echo "Pubkey deleted"

# Verify we can add a certificate, since this is a setup a test, the store should contain a cert to use.
echo "Writing certificate"
# Not all versions of pkcs11-tool handle PEM to DER conversions, 0.15 doesn't, 0.19 does. So always
# convert to DER
openssl x509 -inform PEM -outform DER -in "$TPM2_PKCS11_STORE/cert.pem.rsa1" -out "$TPM2_PKCS11_STORE/cert.der.rsa1"
pkcs11_tool --slot=1 -l --pin=myuserpin --write-object="$TPM2_PKCS11_STORE/cert.der.rsa1" \
    --type=cert --id=01 --label=device-cert
echo "Certificate wrote"

# Run the --test and ensure nothing breaks
# Note that pkcs11-tools 0.15 have invalid OAEP params size of things like
# mechanism->ulParameterLen: 4225.
if [[ "${DOCKER_IMAGE:-nodocker}" != "ubuntu-16.04" && "${DOCKER_IMAGE:-nodocker}" != "ubuntu-18.04" ]]; then
    pkcs11_tool --test --login --pin=myuserpin 2>&1 | tee logz
    # this command doesn't ALWAYS return rc's for status, so we have to peek into the logz
    # pkcs11-tool is inconsistent in outputs, older ones don't provide any success
    # output of 'No errors', se we search that the last line *isn't* '<N> errors' where
    # N is a base10 digit.
    tail -n1 logz | grep -vE '[0-9]+ errors'
else
    echo "Skipping  pkcs11-tool --test due to errors on ${DOCKER_IMAGE}"
fi

# verify that RSA3072 keys work if supported, turn off set -e so we can check the rc
set +e
tpm2_testparms rsa3072
if [ $? -ne 0 ]; then
	echo "TPM Does not support RSA3072, skipping"
    exit 0
fi
set -e

#
# pkcs11-tool is always fun, it seems to be ignoring --label, so things like --label="fake" will still work.
# set an id as it seems to respect that.
#
tpm2_ptool addkey --label="label" --id="myrsa3072key" --key-label="myrsa3072key" --userpin="myuserpin" --algorithm="rsa3072" --path="$TPM2_PKCS11_STORE"

# Since the PKCS11 Store gets automagically cleaned up, use that as our tempdir scratch space
tempdir=$TPM2_PKCS11_STORE

# pkcs11-tool --id is hex encoded input, so encode "myrsa3072key" as hex: 6d79727361333037326b6579
# python -c 'print("6d79727361333037326b6579".decode("hex"))'
# myrsa3072key
echo "testdata">${tempdir}/data
pkcs11_tool --sign --login --slot=1 --id="6d79727361333037326b6579" --pin="myuserpin" \
            --input-file ${tempdir}/data --output-file ${tempdir}/sig \
            --mechanism SHA256-RSA-PKCS

size="$(stat --printf="%s" ${tempdir}/sig)"
test "$size" -eq "384"

# Test that we can generate a RSA3072 key via the CAPI
pkcs11_tool --slot=1 --login --pin=myuserpin --keypairgen --id="11223344556677889900" --label="myrsa3072CKey" --key-type rsa:3072

# validate key is 384 bytes and usable
rm ${tempdir}/sig
echo "testdata">${tempdir}/data
pkcs11_tool --sign --login --slot=1 --id="6d79727361333037326b6579" --pin="myuserpin" \
            --input-file ${tempdir}/data --output-file ${tempdir}/sig \
            --mechanism SHA256-RSA-PKCS

size="$(stat --printf="%s" ${tempdir}/sig)"
test "$size" -eq "384"

#
# Test that the imported SSH keys are useable
#
pkcs11_tool --token-label="import-keys" --login --pin=anotheruserpin --list-objects

# pkcs11-tool --label doesn't always work, so use id's which are hex encoded.
echo "testdata">${tempdir}/data
pkcs11_tool --sign --login --token-label="import-keys" --id="696d706f727465645f7373685f7273615f6b6579" --pin="anotheruserpin" \
            --input-file ${tempdir}/data --output-file ${tempdir}/sig \
            --mechanism SHA256-RSA-PKCS

size="$(stat --printf="%s" ${tempdir}/sig)"
test "$size" -eq "256"

echo "testdata">${tempdir}/data
pkcs11_tool --sign --login --token-label="import-keys" --id="696d706f727465645f7373685f6563635f6b6579" --pin="anotheruserpin" \
            --input-file ${tempdir}/data --output-file ${tempdir}/sig \
            --mechanism ECDSA-SHA1

size="$(stat --printf="%s" ${tempdir}/sig)"
test "$size" -eq "64"

#
# Test that the keys with empty PIN are useable
#
pkcs11_tool --token-label="empty-pin" --list-objects
# The Private Key Objects are enumerated without login
pkcs11_tool --token-label="empty-pin" --list-objects | grep 'Private Key Object'

echo "testdata">${tempdir}/data
pkcs11_tool --sign --token-label="empty-pin" --id="7273615f6b6579" \
            --input-file ${tempdir}/data --output-file ${tempdir}/sig \
            --mechanism SHA256-RSA-PKCS

size="$(stat --printf="%s" ${tempdir}/sig)"
test "$size" -eq "256"

echo "testdata">${tempdir}/data
pkcs11_tool --sign --token-label="empty-pin" --id="6563635f6b6579" \
            --input-file ${tempdir}/data --output-file ${tempdir}/sig \
            --mechanism ECDSA-SHA1

size="$(stat --printf="%s" ${tempdir}/sig)"
test "$size" -eq "64"

exit 0
