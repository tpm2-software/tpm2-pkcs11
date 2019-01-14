#!/usr/bin/env bash

echo "SETUP SCRIPT - DBUS_SESSION_BUS_ADDRESS: $DBUS_SESSION_BUS_ADDRESS"
echo "SETUP SCRIPT - TPM2TOOLS_TCTI: $TPM2TOOLS_TCTI"

echo "---- DBUS SERVICE LISTING ----"
dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames
echo "---- END ----"

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
which tpm2_ptool.py > /dev/null
if [ $? -ne 0 ]; then
  echo "tpm2_ptool NOT ON PATH, ADD TO PATH"
  exit 1
fi

set -e

# init
tpm2_ptool.py init --pobj-pin=mypobjpin --path=$TPM2_PKCS11_STORE

# Test the existing primary object init functionality
tpm2_createprimary -p foopass -o $TPM2_PKCS11_STORE/primary.ctx -g sha256 -G rsa
handle=`tpm2_evictcontrol -a o -c $TPM2_PKCS11_STORE/primary.ctx | cut -d\: -f2-2 | sed 's/^ *//g'`

tpm2_ptool.py init --pobj-pin=anotherpobjpin --primary-handle=$handle --primary-auth=foopass --path=$TPM2_PKCS11_STORE

# add 3 tokens
tpm2_ptool.py addtoken --pid=1 --pobj-pin=mypobjpin --sopin=mysopin --userpin=myuserpin --label=label --path $TPM2_PKCS11_STORE
tpm2_ptool.py addtoken --wrap=software --pid=1 --pobj-pin=mypobjpin --sopin=mysopin --userpin=myuserpin --label=wrap-sw --path $TPM2_PKCS11_STORE
tpm2_ptool.py addtoken --pid=2 --pobj-pin=anotherpobjpin --sopin=anothersopin --userpin=anotheruserpin --label=import-keys --path $TPM2_PKCS11_STORE

# add 2 aes and 2 rsa keys under tokens 1 and 2
for t in "label" "wrap-sw"; do
	echo "Adding 2 AES 256 keys under token \"$t\""
	tpm2_ptool.py addkey --algorithm=aes256 --label="$t" --userpin=myuserpin --path=$TPM2_PKCS11_STORE
	tpm2_ptool.py addkey --algorithm=aes256 --label="$t" --key-label=mykeylabel --userpin=myuserpin --path=$TPM2_PKCS11_STORE
	echo "Added AES Keys"

	echo "Adding 2 RSA 2048 keys under token \"$t\""
	for i in `seq 0 1`; do
	  tpm2_ptool.py addkey --algorithm=rsa2048 --label="$t" --userpin=myuserpin --path=$TPM2_PKCS11_STORE
	done;
	echo "Added RSA Keys"

	echo "Adding 2 EC p256 keys under token \"$t\""
	for i in `seq 0 1`; do
	  tpm2_ptool.py addkey --algorithm=ecc256 --label="$t" --userpin=myuserpin --path=$TPM2_PKCS11_STORE
	done;
	echo "Added EC Keys"
done;

# add 1 aes key under label "import-keys"
tpm2_ptool.py addkey --algorithm=aes128 --label="import-keys" --userpin=anotheruserpin --path=$TPM2_PKCS11_STORE

# import 1 rsa2048 key under label "import-keys"
echo "importing rsa2048 key under token 'import-keys'"
openssl genrsa -out private.pem 2048
tpm2_ptool.py import --privkey='private.pem' --algorithm=rsa --key-label="imported_key" --label="import-keys" --userpin=anotheruserpin --path=$TPM2_PKCS11_STORE

#Passwordless Primary
tpm2_ptool.py init --path=$TPM2_PKCS11_STORE
##Add token
tpm2_ptool.py addtoken --pid=3 --sopin=mysopin --userpin=myuserpin --label=pwless --path $TPM2_PKCS11_STORE
###Add aes key under token
tpm2_ptool.py addkey --algorithm=aes256 --label=pwless --userpin=myuserpin --path=$TPM2_PKCS11_STORE
##Verify setup
tpm2_ptool.py verify --sopin=mysopin --userpin=myuserpin --label=pwless --path=$TPM2_PKCS11_STORE

echo "RUN COMMAND BELOW BEFORE make check"
echo "export TPM2_PKCS11_STORE=$TPM2_PKCS11_STORE"

exit 0
