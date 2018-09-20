#!/usr/bin/env bash
#;**********************************************************************;
# Copyright (c) 2018, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

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
    local valgrind_bin="$6"
    local valgrind_flags="$7"

    printf "starting daemon: %s\n  environment: %s\n  options: %s\n" "${daemon_bin}" "${daemon_env}" "${daemon_opts}"
    env ${daemon_env} ${valgrind_bin} ${valgrind_flags} ${daemon_bin} ${daemon_opts} > ${daemon_log_file} 2>&1 &
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
# function to start the dbus-daemon
# This dbus-daemon creates a session message bus used by the
# communication between tpm2-abrmd and testcase. The dbus info
# is told to testcase through DBUS_SESSION_BUS_ADDRESS and
# DBUS_SESSION_BUS_PID.
dbus_daemon_start ()
{
    local dbus_log_file="$1"
    local dbus_pid_file="$2"
    local dbus_opts="--session --print-address 3 --nofork --nopidfile"
    local dbus_addr_file=`mktemp`
    local dbus_env="DBUS_VERBOSE=1"

    exec 3<>$dbus_addr_file
    daemon_start dbus-daemon "${dbus_opts}" "${dbus_log_file}" "${dbus_pid_file}" \
        "${dbus_env}"
    local ret=$?
    if [ $ret -eq 0 ]; then
        export DBUS_SESSION_BUS_ADDRESS=`cat "${dbus_addr_file}"`
        export DBUS_SESSION_BUS_PID=`cat "${dbus_pid_file}"`
    fi
    rm -f $dbus_addr_file
    return $ret
}
