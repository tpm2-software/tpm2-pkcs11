#!/usr/bin/env bash

echo "SETUP SCRIPT - DBUS_SESSION_BUS_ADDRESS: $DBUS_SESSION_BUS_ADDRESS"
echo "SETUP SCRIPT - TPM2FAPI_TCTI: $TSS2FAPI_TCTI"

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
	create_fapi_store.sh --tmpdir=TEMPDIR

END
}

while test $# -gt 0; do
    echo $1
    case $1 in
    --help) print_usage; exit $?;;
    -t|--tmpdir) tmp_dir=$2; shift;;
    -t=*|--tmpdir=*) tmp_dir="${1#*=}";;
    --) shift; break;;
    -*) usage_error "invalid option: '$1'";;
     *) break;;
    esac
    shift
done

export TSS2_FAPICONF=$tmp_dir/fapi-config.json

#TODO: Fix upstream that this mkdir is not needed
mkdir $tmp_dir/system

cat >$tmp_dir/fapi-config.json <<EOF
{
     "profile_name": "P_RSA256",
     "profile_dir": "$tmp_dir/profiles/",
     "user_dir": "$tmp_dir/usr",
     "system_dir": "$tmp_dir/system",
     "system_pcrs" : [],
     "log_dir" : "$tmp_dir/log",
     "tcti": "$TSS2FAPI_TCTI",
}
EOF

mkdir -p $tmp_dir/profiles

cat >$tmp_dir/profiles/P_RSA256.json <<EOF
{
    "type": "TPM2_ALG_RSA",
    "nameAlg":"TPM2_ALG_SHA256",
    "srk_template": "system,restricted,decrypt,0x81000000",
    "srk_persistent": 0,
    "ek_template":  "system,restricted,decrypt",
    "ecc_signing_scheme": {
        "scheme":"TPM2_ALG_ECDSA",
        "details":{
            "hashAlg":"TPM2_ALG_SHA1"
        },
    },
    
    "rsa_signing_scheme": {
                    "scheme":"TPM2_ALG_RSAPSS",
                    "details":{
                        "hashAlg":"TPM2_ALG_SHA256"
                    }
                },
    "rsa_decrypt_scheme": {
        "scheme":"TPM2_ALG_OAEP",
        "details":{
            "hashAlg":"TPM2_ALG_SHA1"
        }
    },
    "sym_mode":"TPM2_ALG_CFB",
    "sym_parameters": {
        "algorithm":"TPM2_ALG_AES",
        "keyBits":"128",
        "mode":"TPM2_ALG_CFB"
    },
    "sym_block_size": 16,
    "pcr_selection": [
       { "hash": "TPM2_ALG_SHA1",
         "pcrSelect": [ 9, 15, 13]
       },
       { "hash": "TPM2_ALG_SHA256",
         "pcrSelect": [ 8, 16, 14 ]
       }
    ],
    "exponent": 0,
    "keyBits": 2048
}
EOF

tss2_provision
