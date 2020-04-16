#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

# This file contains a collection of support functions used by the automake
# test harness to execute our integration tests.

# This function takes a PID as a parameter and determines whether or not the
# process is currently running. If the daemon is running 0 is returned. Any
# other value indicates that the daemon isn't running.
daemon_status ()
{
    local pid=$1

    if [ $(kill -0 "${pid}" 2> /dev/null) ]; then
        echo "failed to detect running daemon with PID: ${pid}";
        return 1
    fi
    return 0
}

# This is a generic function to start a daemon, setup the environment
# variables, redirect output to a log file, store the PID of the daemon
# in a file and disconnect the daemon from the parent shell.
daemon_start ()
{
    local daemon_bin="$1"
    local daemon_opts="$2"
    local daemon_log_file="$3"
    local daemon_pid_file="$4"
    local daemon_env="$5"

    printf "starting daemon: %s\n  environment: %s\n  options: %s\n" "${daemon_bin}" "${daemon_env}" "${daemon_opts}"
    env ${daemon_env} ${daemon_bin} ${daemon_opts} > ${daemon_log_file} 2>&1 &
    local ret=$?
    local pid=$!
    if [ ${ret} -ne 0 ]; then
        echo "failed to start daemon: \"${daemon_bin}\" with env: \"${daemon_env}\""
        exit ${ret}
    fi
    sleep 1
    daemon_status "${pid}"
    if [ $? -ne 0 ]; then
        echo "daemon died after successfully starting in background, check " \
             "log file: ${daemon_log_file}"
        return 1
    fi
    echo ${pid} > ${daemon_pid_file}
    echo "successfully started daemon: ${daemon_bin} with PID: ${pid}"
    return 0
}
# function to start the simulator
# This also that we have a private place to store the NVChip file. Since we
# can't tell the simulator what to name this file we must generate a random
# directory under /tmp, move to this directory, start the simulator, then
# return to the old pwd.
simulator_start ()
{
    local sim_bin="$1"
    local sim_port="$2"
    local sim_log_file="$3"
    local sim_pid_file="$4"
    local sim_tmp_dir="$5"
    # simulator port is a random port between 1024 and 65535

    cd ${sim_tmp_dir}
    daemon_start "${sim_bin}" "-port ${sim_port}" "${sim_log_file}" \
        "${sim_pid_file}" ""
    local ret=$?
    cd -
    return $ret
}
# function to start the tabrmd
# This is little more than a call to the daemon_start function with special
# command line options and an environment string.
tabrmd_start ()
{
    local tabrmd_bin=$1
    local tabrmd_log_file=$2
    local tabrmd_pid_file=$3
    local tabrmd_opts="$4"
    local tabrmd_env="G_MESSAGES_DEBUG=all"

    daemon_start "${tabrmd_bin}" "${tabrmd_opts}" "${tabrmd_log_file}" \
        "${tabrmd_pid_file}" "${tabrmd_env}" "${VALGRIND}" "${LOG_FLAGS}"
}
# function to stop a running daemon
# This function takes a single parameter: a file containing the PID of the
# process to be killed. The PID is extracted and the daemon killed.
daemon_stop ()
{
    local pid_file=$1
    local pid=0
    local ret=0

    if [ ! -f ${pid_file} ]; then
        echo "failed to stop daemon, no pid file: ${pid_file}"
        return 1
    fi
    pid=$(cat ${pid_file})
    daemon_status "${pid}"
    if [ $? -ne 0 ]; then
        echo "failed to detect running daemon with PID: ${pid}";
        return ${ret}
    fi
    kill ${pid}
    ret=$?
    if [ ${ret} -eq 0 ]; then
        wait ${pid}
        ret=$?
    else
        echo "failed to kill daemon process with PID: ${pid}"
    fi
    return ${ret}
}

function setup_fapi() {
    tempdir=${1:-$(mktemp -d tpm2-pkcs11-test-fapistore.XXXXXX)}

    KEYSTORE_USER=keystore_user
    KEYSTORE_SYSTEM=keystore_system
    LOG_DIR=log
    PROFILE_NAME=P_RSA

    mkdir -p $tempdir/$KEYSTORE_USER/policy $tempdir/$KEYSTORE_SYSTEM/policy \
        $tempdir/$LOG_DIR

cat > $tempdir/fapi_config.json <<EOF
{
    "profile_name": "${PROFILE_NAME}",
    "profile_dir": "$tempdir/",
    "user_dir": "$tempdir/${KEYSTORE_USER}",
    "system_dir": "$tempdir/${KEYSTORE_SYSTEM}",
    "tcti": "${TPM2_PKCS11_TCTI}",
    "system_pcrs" : [],
    "ek_cert_less": "yes",
    "log_dir" : "$tempdir/${LOG_DIR}",
}
EOF

    export TSS2_FAPICONF=$tempdir/fapi_config.json
    export TEMP_DIR=$tempdir

    setup_profile $tempdir
}
function setup_profile() {
# Setup Profile
cat > $tempdir/${PROFILE_NAME}.json <<EOF
{
    "type": "TPM2_ALG_RSA",
    "nameAlg":"TPM2_ALG_SHA256",
    "srk_template": "system,restricted,decrypt,0x81000001",
    "srk_persistent": 1,
    "ek_template":  "system,restricted,decrypt",
    "ecc_signing_scheme": {
        "scheme":"TPM2_ALG_ECDSA",
        "details":{
            "hashAlg":"TPM2_ALG_SHA256"
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
            "hashAlg":"TPM2_ALG_SHA256"
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
          "pcrSelect": [ 9, 15, 13 ]
        },
        { "hash": "TPM2_ALG_SHA256",
          "pcrSelect": [ 8, 16, 14 ]
        }
    ],
    "exponent": 0,
    "keyBits": 2048
}
EOF
}
