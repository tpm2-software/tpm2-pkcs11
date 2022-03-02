#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -exo pipefail

if [ -z "$T" ]; then
    export T="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
fi

source "$T/test/integration/scripts/helpers.sh"

# Don't test with OSSL3, since we dont have an engine to call us through,
# we would have to port everything over to the provider, which then doesn't
# test tpm2-pkcs11 code anyways.
check_openssl_version
if [ "$OSSL3_DETECTED" -eq "1" ]; then
    exit 77
fi


PIN="myuserpin"
token_label="label"
key_label="rsa1"

function cleanup() {
    rm -f objlist.yaml key.attrs.yaml certificate.der.hex certificate.der certificate.pem \
      pubkey.pem data.txt
}
trap cleanup EXIT

onerror() {
  echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
  exit 1
}
trap onerror ERR

cleanup

setup_asan

if [ -z "$modpath" ]; then
  modpath="$PWD/src/.libs/libtpm2_pkcs11.so"
fi

echo "modpath=$modpath"

function yaml_get_id() {

"${PYTHON_INTERPRETER:-python3}" << pyscript
from __future__ import print_function

import sys
import yaml

with open("$1") as f:
    try:
        y = yaml.load(f, Loader=yaml.BaseLoader)

        for x in y:
            if x['CKA_LABEL'] == "$2" and x['CKA_CLASS'] == "$3":
                print(x['id'])
    except yaml.YAMLError as exc:
        sys.exit(exc)
pyscript
}

function yaml_get_kv() {

    third_arg=""
    if [ $# -eq 3 ]; then
        third_arg=$3
    fi

"${PYTHON_INTERPRETER:-python3}" << pyscript
from __future__ import print_function

import sys
import yaml

with open("$1") as f:
    try:
        y = yaml.load(f, Loader=yaml.BaseLoader)
        if $# == 3:
            print(y["$2"]["$third_arg"])
        else:
            print(y["$2"])
    except yaml.YAMLError as exc:
        sys.exit(exc)
pyscript
}

pkcs11_tool() {
  pkcs11-tool --module "$modpath" "$@"
  return $?
}

# step 1 is to get the id by listing the objects
tpm2_ptool listobjects --label="$token_label" > "objlist.yaml"

cert_db_id=$(yaml_get_id objlist.yaml "$key_label" CKO_CERTIFICATE)

echo "cert db id: $cert_db_id"

tpm2_ptool objmod --id="$cert_db_id" > "key.attrs.yaml"

# 17 is the raw attribute value for CKA_VALUE which contains the certificate
yaml_get_kv "key.attrs.yaml" 17 > "certificate.der.hex"

# 258 is CKA_ID, get the key id
cka_id_hex=$(yaml_get_kv "key.attrs.yaml" 258)

# convert the hex to binary
cat "certificate.der.hex" | xxd -p -r > "certificate.der"

# convert to a pem, which helps verify the der
openssl x509 -inform DER -in "certificate.der" -outform PEM -out "certificate.pem"

# extract the pubkey
openssl x509 -pubkey -noout -in "certificate.pem" > "pubkey.pem"

# do an rsa-pss signature on data
echo "sig data" > "data.txt"

export OPENSSL_CONF="$TEST_FIXTURES/ossl.cnf"

PKCS11_KEY="pkcs11:model=SW%20%20%20TPM;manufacturer=IBM;serial=0000000000000000;token=$token_label;object=$key_label;type=private"

openssl dgst -engine pkcs11 -keyform engine -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sign "$PKCS11_KEY" -out data.sig data.txt

openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -signature data.sig -verify pubkey.pem data.txt

rm data.sig

# The above for me always takes the raw signing path, either via C_Sign or C_Encrypt interfaces. So we will use pkcs11tool to force it
# pkcs11tool is dumb, even though --label should be the object label, it only really is coded to know --id.
# A bug in older OpenSC versions (like 0.15.0), map the _PSS identifiers wrong except for SHA1. This bug was fixed in OpenSC in:
#  https://github.com/OpenSC/OpenSC/pull/1146
#
# Their is no generic way to really figure out the OpenSC version AFAICT to we code this to the common denominator of SHA1
pkcs11_tool --pin "$PIN" --token-label "$token_label" --id "$cka_id_hex" --sign --mechanism SHA1-RSA-PKCS-PSS -i data.txt -o data.sig

openssl dgst -sha1 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -signature data.sig -verify pubkey.pem data.txt

rm data.sig

# verify that importing certificates do not modify them
# NB. OpenSSL never verified the signature of self-signed certificate:
# https://github.com/openssl/openssl/blob/openssl-3.0.0/ssl/t1_lib.c#L2970
# This is why two certificates are needed
cert_db_id="$(yaml_get_id objlist.yaml rsa1 CKO_CERTIFICATE)"
tpm2_ptool objmod --id="$cert_db_id" > "key.attrs.yaml"
yaml_get_kv "key.attrs.yaml" 17 | xxd -p -r > "ca.der"
openssl x509 -inform DER -in "ca.der" -outform PEM -out "ca.pem"
cert_db_id="$(yaml_get_id objlist.yaml rsa2 CKO_CERTIFICATE)"
tpm2_ptool objmod --id="$cert_db_id" > "key.attrs.yaml"
yaml_get_kv "key.attrs.yaml" 17 | xxd -p -r > "cert.der"
openssl x509 -inform DER -in "cert.der" -outform PEM -out "cert.pem"
openssl verify -CAfile ca.pem cert.pem

exit 0
