#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -e

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

# Verify we can add a certifcate, since this is a setup a test, the store should contain a cert to use.
echo "Writing certificate"
# Not all versions of pkcs11-tool handle PEM to DER conversions, 0.15 doesn't, 0.19 does. So always
# convert to DER
openssl x509 -inform PEM -outform DER -in "$TPM2_PKCS11_STORE/cert.pem.rsa1" -out "$TPM2_PKCS11_STORE/cert.der.rsa1"
pkcs11_tool --slot=1 -l --pin=myuserpin --write-object="$TPM2_PKCS11_STORE/cert.der.rsa1" \
    --type=cert --id=01 --label=device-cert
echo "Certificate wrote"

# Run the --test and ensure nothing breaks
pkcs11_tool --test --login --pin=myuserpin 2>&1 | tee logz

# this command doesn't return rc's for status, so we have to peek into the logz
# So do a search of the last line that is 'No errors' as the tool outputs that
# on success.
set -o pipefail
tail -n1 logz | grep -q 'No errors'

exit 0
