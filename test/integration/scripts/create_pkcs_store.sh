#!/usr/bin/env bash

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
tpm2_ptool init --pobj-pin=mypobjpin --path=$TPM2_PKCS11_STORE

# Test the existing primary object init functionality
tpm2_createprimary -p foopass -c $TPM2_PKCS11_STORE/primary.ctx -g sha256 -G rsa
handle=`tpm2_evictcontrol -C o -c $TPM2_PKCS11_STORE/primary.ctx | grep -Po '(?<=persistent-handle: )\S+'`

tpm2_ptool init --pobj-pin=anotherpobjpin --primary-handle=$handle --primary-auth=foopass --path=$TPM2_PKCS11_STORE

# add 3 tokens
tpm2_ptool addtoken --pid=1 --pobj-pin=mypobjpin --sopin=myBADsopin --userpin=myBADuserpin --label=label --path $TPM2_PKCS11_STORE
tpm2_ptool addtoken --wrap=software --pid=1 --pobj-pin=mypobjpin --sopin=mysopin --userpin=myuserpin --label=wrap-sw --path $TPM2_PKCS11_STORE
tpm2_ptool addtoken --pid=2 --pobj-pin=anotherpobjpin --sopin=anothersopin --userpin=anotheruserpin --label=import-keys --path $TPM2_PKCS11_STORE

# Change the bad pins to something good (test tpm2_ptool changepin commandlet)
tpm2_ptool changepin --label=label --user=user --old=myBADuserpin --new=myuserpin --path=$TPM2_PKCS11_STORE
tpm2_ptool changepin --label=label --user=so --old=myBADsopin --new=mysopin --path=$TPM2_PKCS11_STORE

# verify the token
tpm2_ptool verify --label=label --sopin=mysopin --userpin=myuserpin --path=$TPM2_PKCS11_STORE

# Use initpin to change the user pin
tpm2_ptool initpin --label=label --sopin=mysopin --userpin=myverynewuserpin --path=$TPM2_PKCS11_STORE

# verify the pin change
tpm2_ptool verify --label=label --sopin=mysopin --userpin=myverynewuserpin --path=$TPM2_PKCS11_STORE

# change it back
tpm2_ptool initpin --label=label --sopin=mysopin --userpin=myuserpin --path=$TPM2_PKCS11_STORE

# add 2 aes and 2 rsa keys under tokens 1 and 2
for t in "label" "wrap-sw"; do
	echo "Adding 2 AES 256 keys under token \"$t\""
	tpm2_ptool addkey --algorithm=aes256 --label="$t" --userpin=myuserpin --path=$TPM2_PKCS11_STORE
	tpm2_ptool addkey --algorithm=aes256 --label="$t" --key-label=mykeylabel --userpin=myuserpin --path=$TPM2_PKCS11_STORE
	echo "Added AES Keys"

	echo "Adding 2 RSA 2048 keys under token \"$t\""
	for i in `seq 0 1`; do
	  tpm2_ptool addkey --algorithm=rsa2048 --label="$t" --userpin=myuserpin --path=$TPM2_PKCS11_STORE
	done;
	echo "Added RSA Keys"

	echo "Adding 2 EC p256 keys under token \"$t\""
	for i in `seq 0 1`; do
	  tpm2_ptool addkey --algorithm=ecc256 --label="$t" --userpin=myuserpin --path=$TPM2_PKCS11_STORE
	done;
	echo "Added EC Keys"
done;

# add 1 aes key under label "import-keys"
tpm2_ptool addkey --algorithm=aes128 --label="import-keys" --userpin=anotheruserpin --path=$TPM2_PKCS11_STORE

# import 1 rsa2048 key under label "import-keys"
echo "importing rsa2048 key under token 'import-keys'"
openssl genrsa -out "$TPM2_PKCS11_STORE/private.pem" 2048
tpm2_ptool import --privkey="$TPM2_PKCS11_STORE/private.pem" --algorithm=rsa --key-label="imported_key" --label="import-keys" --userpin=anotheruserpin --path=$TPM2_PKCS11_STORE

echo "RUN COMMAND BELOW BEFORE make check"
echo "export TPM2_PKCS11_STORE=$TPM2_PKCS11_STORE"

exit 0
