#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -xo pipefail

if [ -z "$T" ]; then
    export T="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
fi

EXT_FILE="$TEST_FIXTURES/smimeextensions"
CLIENT_CNF="$TEST_FIXTURES/client.cnf"

source "$T/test/integration/scripts/helpers.sh"

export NSS_DEFAULT_DB_TYPE=sql

if [ "$ASAN_ENABLED" = "true" ]; then
  # Skip this test when ASAN is enabled
  exit 77
fi

function pinentry() {
  expect <<END
spawn $*
expect {
  "Password or Pin *label*:" {
    sleep 1; send -- "myuserpin\r"; exp_continue
  } "Password or Pin *import-keys*:" {
    sleep 1; send -- "anotheruserpin\r"; exp_continue
  } "Password or Pin *esys-tr*:" {
    sleep 1; send -- "userpin3\r"; exp_continue
  } "Is this a CA certificate*" {
    sleep 1; send -- "y\r"; exp_continue
  } "Enter the path length constraint, enter to skip*" {
    sleep 1; send -- "\r"; exp_continue
  } "Is this a critical extension*" {
    sleep 1; send -- "y\r"; exp_continue
  } eof
}
catch wait result
exit [ lindex \$result 3 ]
END
}

function cleanup() {
  if [ "$1" != "no-kill" ]; then
      pkill -P $$ || true
  fi
  cleanup_ca
  rm -f smimeclient.csr smimeclient.crt smimeclient.key smimeclient.pem \
        pkcs11.txt cert9.db key4.db userpin.txt
}
trap cleanup EXIT

onerror() {
  echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
  exit 1
}
trap onerror ERR

cleanup "no-kill"

if [ -z "$modpath" ]; then
  modpath="$PWD/src/.libs/libtpm2_pkcs11.so"
fi

echo "modpath=$modpath"

# setup the CA BEFORE EXPORTING THE CA CONF for the clients
setup_ca

echo "Creating S/MIME certificate for testuser@example.org"
openssl req -new -newkey rsa:2048 -nodes -keyout smimeclient.key \
  -out smimeclient.csr \
  -subj "/C=US/ST=Radius/L=Somewhere/O=Example Inc./CN=smimetesting/emailAddress=testuser@example.org"

echo "Signing S/MIME certificate with test CA"
openssl ca -batch -keyfile "$CA_KEY" -cert "$CA_PEM" -in smimeclient.csr \
  -key "$PASSWORD_CA" -out smimeclient.crt -extensions smime \
  -extfile "$EXT_FILE" -config "$CLIENT_CNF"

echo "Converting signed S/MIME certificate to PEM format"
openssl x509 -in smimeclient.crt -out smimeclient.pem -outform pem

echo "Initializing temporary NSS DB"
certutil -N -d . --empty-password

echo "Adding PKCS11 module in $modpath to NSS configuration"
#modutil will first ask about a running browser which we acknowledge with \n
#sometimes it will then ask because p11-kit already knows tpm2 which we then abort with q\n
echo -ne "\nq\n" | modutil -add tpm2 -libfile "$modpath" -dbdir .

echo "Adding S/MIME trust for test CA"
certutil -A -d . -n testca -t ,C, -a -i "$CA_PEM"

echo "Importing S/MIME key to TPM2 token"
tpm2_ptool import --userpin anotheruserpin --privkey smimeclient.key \
  --label import-keys --key-label smimetest --algorithm rsa

echo "Importing S/MIME certificate to TPM2 token"
tpm2_ptool addcert --label import-keys --key-label smimetest smimeclient.pem

echo "Testing S/MIME certificate lookup in NSS DB via label"
pinentry certutil -L -d . -n import-keys:smimetest

# See: https://github.com/tpm2-software/tpm2-pkcs11/issues/444
echo "Testing S/MIME certificate lookup in NSS DB via mail address"
pinentry certutil -L -d . -h import-keys --email testuser@example.org

echo "Testing if S/MIME certificate in NSS DB has user trust"
pinentry certutil -L -d . -h import-keys | \
   grep import-keys:smimetest | grep -q u,u,u

echo "Testing if S/MIME certificate in NSS DB is valid for mail signing"
pinentry certutil -V -d . -n import-keys:smimetest -u S

echo "Testing if S/MIME certificate in NSS DB is valid for mail reception"
pinentry certutil -V -d . -n import-keys:smimetest -u R

echo "Generating a noise file for seeding purposes"
dd if=/dev/random of=noise.bin bs=32 count=1

# A non-fatal error in the log is caused by the current tpm2-pkcs11
# implementation not supporting the vendor-defined object class CKO_NSS_TRUST.
echo "Create a self-signed certificate and its associated keypair on a TPM2 token using NSS tools"
pinentry certutil -S -d . -h import-keys -n "tpm2-ca" \
  -s "C=US,ST=Radius,L=Somewhere,O=Example Inc.,CN=TPM2 CA" \
  -x -t "C,C,C" -2 -7 tpm2-ca@example.org \
  --keyUsage certSigning,crlSigning,critical \
  --nsCertType objectSigningCA,critical \
  -z noise.bin

echo "Testing tpm2-ca certificate lookup in NSS DB via label"
pinentry certutil -L -d . -n import-keys:tpm2-ca

echo "Testing tpm2-ca certificate lookup in NSS DB via mail address"
pinentry certutil -L -d . -h import-keys --email tpm2-ca@example.org

echo "Creating a CSR and its associated keypair on a TPM2 token"
pinentry certutil -R -d . -h import-keys -k rsa -g 2048 \
  -s "C=US,ST=Radius,L=Somewhere,O=Example Inc.,CN=TPM2 Client" \
  -7 tpm2-client@example.org \
  -z noise.bin -a -o tpm2-client.csr.pem

echo "Converting the CSR to DER format"
openssl req -in tpm2-client.csr.pem -outform DER -out tpm2-client.csr.der

echo "Signing TPM2 Client certificate with tpm2-ca"
pinentry certutil -C -d . -c "import-keys:tpm2-ca" \
   -v 12 -w -1 -7 tpm2-client@example.org \
   --keyUsage digitalSignature,keyEncipherment,critical \
   -i tpm2-client.csr.der -o tpm2-client.crt.der

# The same non-fatal error related to CKO_NSS_TRUST will be seen here.
echo "Importing TPM2 Client certificate to TPM2 token"
pinentry certutil -A -d . -h import-keys -n tpm2-client -t ",," -i tpm2-client.crt.der

echo "Testing TPM2 Client certificate lookup in NSS DB via label"
pinentry certutil -L -d . -n import-keys:tpm2-client

echo "Testing TPM2 Client certificate lookup in NSS DB via mail address"
pinentry certutil -L -d . -h import-keys --email tpm2-client@example.org

exit 0
