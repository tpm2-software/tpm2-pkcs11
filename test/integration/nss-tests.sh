#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -xo pipefail

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

exit 0
