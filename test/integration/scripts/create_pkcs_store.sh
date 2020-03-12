# SPDX-License-Identifier: BSD-2-Clause
#!/usr/bin/env bash

echo source "$T/test/integration/scripts/helpers.sh"
source "$T/test/integration/scripts/helpers.sh"

echo "SETUP SCRIPT - DBUS_SESSION_BUS_ADDRESS: $DBUS_SESSION_BUS_ADDRESS"
echo "SETUP SCRIPT - TPM2TOOLS_TCTI: $TPM2TOOLS_TCTI"
echo "SETUP SCRIPT - PYTHONPATH: $PYTHONPATH"

usage_error ()
{
    echo "$0: $*" >&1
    print_usage >&1
    exit 2
}
print_usage ()
{
    cat <<END
Usage:
	create_pkcs_store.sh --tmpdir=TEMPDIR

END
}

TPM2_PKCS11_STORE=""
while test $# -gt 0; do
    echo $1
    case $1 in
    --help) print_usage; exit $?;;
    -t|--tmpdir) TPM2_PKCS11_STORE=$2; shift;;
    -t=*|--tmpdir=*) TPM2_PKCS11_STORE="${1#*=}";;
    --) shift; break;;
    -*) usage_error "invalid option: '$1'";;
     *) break;;
    esac
    shift
done

# Check that tools is on path
which tpm2_create > /dev/null
if [ $? -ne 0 ]; then
  echo "TPM2 TOOLS NOT ON PATH, ADD TO PATH"
  exit 1
fi

# check that tpm2_ptool is on path
which tpm2_ptool > /dev/null
if [ $? -ne 0 ]; then
  echo "tpm2_ptool NOT ON PATH, ADD TO PATH"
  exit 1
fi

set -e

# init
tpm2_ptool init --primary-auth=mypobjpin --path=$TPM2_PKCS11_STORE

echo one

# Test the existing primary object init functionality using a raw handle
tpm2_createprimary -p foopass -c $TPM2_PKCS11_STORE/primary.ctx -g sha256 -G rsa
handle=`tpm2_evictcontrol -C o -c $TPM2_PKCS11_STORE/primary.ctx | grep -Po '(?<=persistent-handle: )\S+'`

echo 2

echo "tpm2_ptool init --primary-auth=anotherpobjpin --primary-handle=$handle --primary-auth=foopass --path=$TPM2_PKCS11_STORE"
tpm2_ptool init --primary-auth=anotherpobjpin --primary-handle=$handle --primary-auth=foopass --path=$TPM2_PKCS11_STORE

echo 3

# Test the existing primary object init functionality using an esys_tr
tpm2_createprimary -c $TPM2_PKCS11_STORE/primary.ctx -g sha256 -G rsa
esys_tr_file="$TPM2_PKCS11_STORE/primary3.handle"
tpm2_evictcontrol -C o -c $TPM2_PKCS11_STORE/primary.ctx -o "$esys_tr_file"

echo "tpm2_ptool init --primary-handle="$esys_tr_file" --path=$TPM2_PKCS11_STORE"
tpm2_ptool init --primary-handle="$esys_tr_file" --path=$TPM2_PKCS11_STORE

# add 3 tokens
tpm2_ptool addtoken --pid=1 --sopin=myBADsopin --userpin=myBADuserpin --label=label --path $TPM2_PKCS11_STORE
tpm2_ptool addtoken --pid=2 --sopin=anothersopin --userpin=anotheruserpin --label=import-keys --path $TPM2_PKCS11_STORE
tpm2_ptool addtoken --pid=3 --sopin=sopin3 --userpin=userpin3 --label=esys-tr --path $TPM2_PKCS11_STORE

# Change the bad pins to something good (test tpm2_ptool changepin commandlet)
tpm2_ptool changepin --label=label --user=user --old=myBADuserpin --new=myuserpin --path=$TPM2_PKCS11_STORE
tpm2_ptool changepin --label=label --user=so --old=myBADsopin --new=mysopin --path=$TPM2_PKCS11_STORE

# verify the token w/o objects
tpm2_ptool verify --label=label --sopin=mysopin --userpin=myuserpin --path=$TPM2_PKCS11_STORE

# Use initpin to change the user pin
tpm2_ptool initpin --label=label --sopin=mysopin --userpin=myverynewuserpin --path=$TPM2_PKCS11_STORE

# verify the pin change
tpm2_ptool verify --label=label --sopin=mysopin --userpin=myverynewuserpin --path=$TPM2_PKCS11_STORE

# change it back
tpm2_ptool initpin --label=label --sopin=mysopin --userpin=myuserpin --path=$TPM2_PKCS11_STORE

echo "Adding 3 AES 256 keys under token \"label\""
tpm2_ptool addkey --algorithm=aes256 --label="label" --userpin=myuserpin --path=$TPM2_PKCS11_STORE
tpm2_ptool addkey --algorithm=aes256 --label="label" --key-label=mykeylabel --userpin=myuserpin --path=$TPM2_PKCS11_STORE
tpm2_ptool addkey --algorithm=aes256 --label="label" --userpin=myuserpin --attr-always-authenticate --path=$TPM2_PKCS11_STORE
echo "Added AES Keys"

echo "Adding 3 RSA 2048 keys under token \"label\""
for i in `seq 0 1`; do
  tpm2_ptool addkey --algorithm=rsa2048 --label="label" --key-label="rsa$i" --userpin=myuserpin --path=$TPM2_PKCS11_STORE
done;
tpm2_ptool addkey --algorithm=rsa2048 --label="label" --userpin=myuserpin --attr-always-authenticate --path=$TPM2_PKCS11_STORE
echo "Added RSA Keys"

echo "Adding 2 EC p256 keys under token \"label\""
for i in `seq 0 1`; do
  tpm2_ptool addkey --algorithm=ecc256 --label="label" --key-label="ec$i" --userpin=myuserpin --path=$TPM2_PKCS11_STORE
done;
echo "Added EC Keys"

echo "Adding 1 x509 Certificate under token \"label\""

# verify the token and all the objects
tpm2_ptool verify --label=label --sopin=mysopin --userpin=myuserpin --path=$TPM2_PKCS11_STORE

#
# Build an OpenSSL config file
#
modpath="$PWD/src/.libs/libtpm2_pkcs11.so"
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

#
# generate cert
#
cert="$TPM2_PKCS11_STORE/cert.pem"

# since we use the shared lib in a non-asan executable via dlopen() we need to set up
# asan so we have defined symbols and we don't worry about leaks (since the tools are
# often silly and leak.
setup_asan
TPM2_PKCS11_STORE="$TPM2_PKCS11_STORE" openssl \
    req -new -x509 -days 365 -subj '/CN=my key/' -sha256 -engine pkcs11 -keyform engine -key slot_1-label_ec1 -out "$cert.ec1"

TPM2_PKCS11_STORE="$TPM2_PKCS11_STORE" openssl \
    req -new -x509 -days 365 -subj '/CN=my key/' -sha256 -engine pkcs11 -keyform engine -key slot_1-label_rsa1 -out "$cert.rsa1"
clear_asan

#
# insert cert to token
#
echo "Adding EC Certificate"
tpm2_ptool addcert --label=label --key-label=ec1 --path=$TPM2_PKCS11_STORE "$cert.ec1"
echo "added x509 Certificate"

echo "Adding RSA Certificate"
tpm2_ptool addcert --label=label --key-label=rsa1 --path=$TPM2_PKCS11_STORE "$cert.rsa1"
echo "added x509 Certificate"

# add 1 aes key under label "import-keys"
tpm2_ptool addkey --algorithm=aes128 --label="import-keys" --userpin=anotheruserpin --path=$TPM2_PKCS11_STORE

# import 1 rsa2048 key under label "import-keys"
echo "importing rsa2048 key under token 'import-keys'"
openssl genrsa -out "$TPM2_PKCS11_STORE/private.pem" 2048
tpm2_ptool import --privkey="$TPM2_PKCS11_STORE/private.pem" --algorithm=rsa --key-label="imported_key" --label="import-keys" --userpin=anotheruserpin --path=$TPM2_PKCS11_STORE

echo "RUN COMMAND BELOW BEFORE make check"
echo "export TPM2_PKCS11_STORE=$TPM2_PKCS11_STORE"

exit 0
