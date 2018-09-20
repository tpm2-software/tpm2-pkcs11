#!/usr/bin/env bash

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

# add 2 tokens
tpm2_ptool.py addtoken --pid=1 --pobj-pin=mypobjpin --sopin=mysopin --userpin=myuserpin --label=label --path $TPM2_PKCS11_STORE
tpm2_ptool.py addtoken --pid=1 --pobj-pin=mypobjpin --sopin=mysopin --userpin=myuserpin --label=label1 --path $TPM2_PKCS11_STORE

# add 2 aes keys under token 1
echo "Adding 2 AES 256 keys"
for i in `seq 0 1`; do
  tpm2_ptool.py addkey --algorithm=aes256 --label=label --userpin=myuserpin --path=$TPM2_PKCS11_STORE
done;
echo "Added AES Keys"

echo "Adding 2 RSA 2048 keys"
for i in `seq 0 1`; do
  tpm2_ptool.py addkey --algorithm=rsa2048 --label=label --userpin=myuserpin --path=$TPM2_PKCS11_STORE
done;
echo "Added RSA Keys"

echo "RUN COMMAND BELOW BEFORE make check"
echo "export TPM2_PKCS11_STORE=$TPM2_PKCS11_STORE"

exit 0
