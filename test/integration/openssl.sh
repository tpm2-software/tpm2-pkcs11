#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -exo pipefail

PIN="myuserpin"
token_label="label"
key_label="rsa1"

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

python << pyscript
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

python << pyscript
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
PIN=$PIN
init = 0

[ req ]
distinguished_name = req_dn
string_mask = utf8only
utf8 = yes

[ req_dn ]
commonName = Mr Test Harness
EOF

export OPENSSL_CONF="$osslconf"

PKCS11_KEY="pkcs11:model=SW%20%20%20TPM;manufacturer=IBM;serial=0000000000000000;token=$token_label;object=$key_label;type=private"

openssl dgst -engine pkcs11 -keyform engine -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto -sign "$PKCS11_KEY" -out data.sig data.txt

openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto -signature data.sig -verify pubkey.pem data.txt

osslversion=$(openssl version | awk '{print $2}')

if [[ "$osslversion" =~ ^0|^1\.0+ ]]; then
  echo "OpenSSL versions less than 1.1.0 are known not to work with externally generate PSS signatures"
  echo "See this PR for the gory details: https://github.com/tpm2-software/tpm2-pkcs11/pull/403"
  exit 0
fi;

rm data.sig

# The above for me always takes the raw signing path, either via C_Sign or C_Encrypt interfaces. So we will use pkcs11tool to force it
# pkcs11tool is dumb, even though --label should be the object label, it only really is coded to know --id.
# A bug in older OpenSC versions (like 0.15.0), map the _PSS identifiers wrong except for SHA1. This bug was fixed in OpenSC in:
#  https://github.com/OpenSC/OpenSC/pull/1146
#
# Their is no generic way to really figure out the OpenSC version AFAICT to we code this to the common denominator of SHA1
pkcs11_tool --pin "$PIN" --token-label "$token_label" --id "$cka_id_hex" --sign --mechanism SHA1-RSA-PKCS-PSS -i data.txt -o data.sig

openssl dgst -sha1 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto -signature data.sig -verify pubkey.pem data.txt

exit 0
