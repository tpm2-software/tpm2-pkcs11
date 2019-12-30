#!/usr/bin/env bash

set -xo pipefail

# SPDX-License-Identifier: BSD-2-Clause
CA_PEM="$TEST_FIXTURES/ca.pem"
CA_KEY="$TEST_FIXTURES/ca.key"

SERVER_PEM="$TEST_FIXTURES/server.pem"
SERVER_KEY="$TEST_FIXTURES/server.key"

CLIENT_CNF="$TEST_FIXTURES/client.cnf"
PASSWORD_CA=whatever
EXT_FILE="$TEST_FIXTURES/xpextensions"
# details on the PKCS11 URI can be found here: https://tools.ietf.org/html/rfc7512
PKCS11_KEY="pkcs11:model=SW%20%20%20TPM;manufacturer=IBM;serial=0000000000000000;token=label;object=rsa0;type=private"

if [ "$ASAN_ENABLED" = "true" ]; then
  # Skip this test when ASAN is enabled
  exit 77
fi

function cleanup() {
  if [ "$1" != "no-kill" ]; then
      pkill -P $$ || true
  fi
  rm -f index.txt index.txt.attr serial serial.old index.txt.old index.txt.attr.old \
        02.pem client.csr client.crt client_tpm.pem
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

osslconf="$TPM2_PKCS11_STORE/ossl.cnf"
cat << EOF > "$osslconf"
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
MODULE_PATH = $modpath
PIN=myuserpin
init = 0

[ req ]
distinguished_name = req_dn
string_mask = utf8only
utf8 = yes

[ req_dn ]
commonName = Mr Test Harness
EOF

export OPENSSL_CONF="$osslconf"

# make the DB
touch index.txt
touch index.txt.attr
echo "02" >> serial

openssl req -new -engine pkcs11 -keyform engine -key "$PKCS11_KEY" -out client.csr -subj "/C=FR/ST=Radius/L=Somewhere/O=Example Inc./CN=testing/emailAddress=testing@123.com"

openssl ca -batch -keyfile "$CA_KEY" -cert "$CA_PEM" -in client.csr -key "$PASSWORD_CA" -out client.crt -extensions xpclient_ext -extfile "$EXT_FILE" -config "$CLIENT_CNF"

openssl x509 -in client.crt -out client_tpm.pem -outform pem

# OpenSSL version 1.0.2g ends up in a state where it tries to read from stdin instead of the ssl connection.
# Feeding it one byte as stdin avoids this condition which is described in more detail here:
# https://github.com/tpm2-software/tpm2-pkcs11/pull/366
openssl s_server -debug -CAfile "$CA_PEM" -cert "$SERVER_PEM" -key "$SERVER_KEY" -Verify 1 <<< '1' &
sleep 1

# default connects to 127.0.0.1:443
openssl s_client -engine pkcs11 -keyform engine -key "$PKCS11_KEY" -CAfile "$CA_PEM" -cert client_tpm.pem <<< 'Q'

exit 0
