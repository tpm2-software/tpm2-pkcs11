#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
set -u
set +o nounset

# default int-test-funcs script, overridden in TEST_FUNCTIONS env variable
TEST_FUNC_LIB=${TEST_FUNC_LIB:-int-test-funcs.sh}
if [ -e ${TEST_FUNC_LIB} ]; then
    . ${TEST_FUNC_LIB}
else
    echo "Error: Unable to locate support test function library: " \
         "${TEST_FUNC_LIB}"
    exit 1
fi

usage_error ()
{
    echo "$0: $*" >&3
    print_usage >&3
    exit 2
}
print_usage ()
{
    cat <<END
Usage:
    int-test-setup.sh --tabrmd-tcti=[mssim|device] --tsetup-script=[create_pkcs_store.sh] TEST-SCRIPT
        [TEST-SCRIPT-ARGUMENTS]
The '--tabrmd-tcti' option defaults to 'mssim'.
END
}


SIM_BIN=""
TABRMD_BIN=""
TABRMD_TCTI="mssim"
TSETUP_SCRIPT=""
while test $# -gt 0; do
    echo $1
    case $1 in
    --help) print_usage; exit $?;;
    -t|--tsetup-script) TSETUP_SCRIPT=$2; shift;;
    -t=*|--tsetup-script=*) TSETUP_SCRIPT="${1#*=}";;
    --) shift; break;;
    -t|--tabrmd-tcti) TABRMD_TCTI=$2; shift;;
    -t=*|--tabrmd-tcti=*) TABRMD_TCTI="${1#*=}";;
    --) shift; break;;
    -*) usage_error "invalid option: '$1'";;
     *) break;;
    esac
    shift
done

# Once option processing is done, $@ should be the name of the test executable
# followed by all of the options passed to the test executable.
TEST_BIN=$(realpath "$1")
TEST_DIR=$(dirname "$1")
TEST_NAME=$(basename "${TEST_BIN}")
SIM_BIN=$(which tpm_server)
TABRMD_BIN=$(which tpm2-abrmd)

# If run against the simulator we need min and max values when generating port
# numbers. We select random port values to enable parallel test execution.
PORT_MIN=1024
PORT_MAX=65534


# sanity tests

if [ -z "${TABRMD_BIN}" ]; then
    echo "no tabrmd binary provided or not executable"
    exit 1
fi
if [ ! -x "${TEST_BIN}" ]; then
    echo "no test binary provided or not executable"
    exit 1
fi
case "${TABRMD_TCTI}"
in
    "mssim")
        if [ -z "${SIM_BIN}" ]; then
            echo "mssim TCTI requires simulator binary / executable"
            exit 1
        fi
        ;;
    "device")
        if [ `id -u` != "0" ]; then
            echo "device TCTI requires root privileges"
            exit 1
        fi
        ;;
    *)
        echo "Invalid TABRMD_TCTI, see --help."
        exit 1
        ;;
esac

#export PATH=$PATH:/home/khushboo/tpm2-pkcs11_otc/tpm2-pkcs11_79/tpm2-pkcs11/tools
# Set up test environment and dependencies that are TCTI specific.
# Create a temporary directory
SIM_TMP_DIR=$(mktemp --directory --tmpdir=/tmp tpm_server_XXXXXX)

case "${TABRMD_TCTI}"
in
    "mssim")
        TABRMD_OPTS="--session"
        TABRMD_TEST_TCTI_CONF="bus_type=session"
        # start an instance of the simulator for the test, have it use a random port
        SIM_LOG_FILE="$SIM_TMP_DIR/simulator.log"
        SIM_PID_FILE="$SIM_TMP_DIR/simulator.pid"
        BACKOFF_FACTOR=2
        BACKOFF=1
        for i in $(seq 10); do
            SIM_PORT_DATA=`shuf -i ${PORT_MIN}-${PORT_MAX} -n 1`
            SIM_PORT_CMD=$((${SIM_PORT_DATA}+1))
            echo "Starting simulator on port ${SIM_PORT_DATA}"
            simulator_start ${SIM_BIN} ${SIM_PORT_DATA} ${SIM_LOG_FILE} ${SIM_PID_FILE} ${SIM_TMP_DIR}
            sleep 1 # give daemon time to bind to ports
            PID=$(cat ${SIM_PID_FILE})
            echo "simulator PID: ${PID}";
            ss -lt4pn 2> /dev/null | grep "${PID}" | grep -q "${SIM_PORT_DATA}"
            ret_data=$?
            ss -lt4pn 2> /dev/null | grep "${PID}" | grep -q "${SIM_PORT_CMD}"
            ret_cmd=$?
            if [ \( $ret_data -eq 0 \) -a \( $ret_cmd -eq 0 \) ]; then
                echo "Simulator with PID ${PID} bound to port ${SIM_PORT_DATA} and " \
                     "${SIM_PORT_CMD} successfully.";
                break
            fi
            echo "Port conflict? Cleaning up PID: ${PID}"
            kill "${PID}"
            BACKOFF=$((${BACKOFF}*${BACKOFF_FACTOR}))
            echo "Failed to start simulator: port ${SIM_PORT_DATA} or " \
                 "${SIM_PORT_CMD} probably in use. Retrying in ${BACKOFF}."
            sleep ${BACKOFF}
            if [ $i -eq 10 ]; then
                echo "Failed to start simulator after $i tries. Giving up.";
                exit 1
            fi
        done

        TABRMD_NAME="com.intel.tss2.Tabrmd${SIM_PORT_DATA}"
        TABRMD_OPTS="${TABRMD_OPTS} --dbus-name=${TABRMD_NAME}"
        TABRMD_OPTS="${TABRMD_OPTS} --tcti=${TABRMD_TCTI}:port=${SIM_PORT_DATA}"

		# if the user is root, the daemon won't start without --allow-root option
        if [ $UID -eq 0 ]; then
            TABRMD_OPTS="--allow-root ${TABRMD_OPTS}"
        fi

        TABRMD_TEST_TCTI_CONF="${TABRMD_TEST_TCTI_CONF},bus_name=${TABRMD_NAME}"
        ;;
    "device")
        TABRMD_OPTS="--allow-root --tcti=device:/dev/tpm0"
        SIM_PORT_DATA=$(od -A n -N 2 -t u2 /dev/urandom | \
                        awk -v min=${PORT_MIN} -v max=${PORT_MAX} \
                        '{print ($1 % (max - min)) + min}')
        ;;
    *)
        echo "whoops"
        exit 1
        ;;
esac

# start tpm2-abrmd daemon
TABRMD_LOG_FILE="$SIM_TMP_DIR/tabrmd.log"
TABRMD_PID_FILE="$SIM_TMP_DIR/tabrmd.pid"
tabrmd_start ${TABRMD_BIN} ${TABRMD_LOG_FILE} ${TABRMD_PID_FILE} "${TABRMD_OPTS}"
if [ $? -ne 0 ]; then
    echo "failed to start tabrmd with name ${TABRMD_NAME}"
fi

export TPM2TOOLS_TCTI="tabrmd:${TABRMD_TEST_TCTI_CONF}"
echo ${TPM2TOOLS_TCTI}

export TPM2_PKCS11_TCTI="tabrmd:${TABRMD_TEST_TCTI_CONF}"
echo ${TPM2_PKCS11_TCTI}

setup_fapi ${SIM_TMP_DIR}
tss2_provision

# if provided, run the test script
if [ -z "${TSETUP_SCRIPT}" ]; then
    echo "No setup script provided"
    # execute the test script and capture exit code
    echo $@
    env $@
    ret_test=$?
else
	echo "Run setup script ${TSETUP_SCRIPT}"
    bash ${TSETUP_SCRIPT} --tmpdir=${SIM_TMP_DIR}
    ret_test=$?
    if [ $ret_test -ne 0 ]; then
        echo "Failed to run the setup script"
    else
        echo "Successfully ran ${TSETUP_SCRIPT}"
        export TPM2_PKCS11_STORE="${SIM_TMP_DIR}"
        echo "export TPM2_PKCS11_STORE=${SIM_TMP_DIR}"
        # execute the test script and capture exit code
        echo $@
        env $@
        ret_test=$?
    fi
fi

tss2_list

# This sleep is sadly necessary: If we kill the tabrmd w/o sleeping for a
# second after the test finishes the simulator will die too. Bug in the
# simulator?
sleep 1

# teardown tabrmd
daemon_stop ${TABRMD_PID_FILE}
ret_tabrmd=$?
rm -rf ${TABRMD_PID_FILE}

# do configuration specific tear-down
case "${TABRMD_TCTI}"
in
    # when testing against the simulator we must shut it down
    "mssim")
        # ignore exit code (it's always 143 AFAIK)
        daemon_stop ${SIM_PID_FILE}
        rm -rf ${SIM_TMP_DIR} ${SIM_PID_FILE}
        ;;
esac


# handle exit codes
if [ $ret_test -ne 0 ]; then
    echo "Execution of $@ failed: $ret_test"
    exit $ret_test
fi
if [ $ret_tabrmd -ne 0 ]; then
    echo "Execution of tabrmd failed: $ret_tabrmd"
    exit $ret_tabrmd
fi

exit 0
