#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -eo pipefail

if [ -z "$T" ]; then
    export T="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
fi

source "$T/test/integration/scripts/helpers.sh"

setup_asan

if [ -z "$modpath" ]; then
  modpath="$PWD/src/.libs/libtpm2_pkcs11.so"
fi

echo "modpath=$modpath"

# PKCS11 Store setup (if not already set by int-test-setup.sh)
if [ -z "$TPM2_PKCS11_STORE" ]; then
    export TPM2_PKCS11_STORE=$(mktemp -d)
    # Note: we don't have a cleanup trap here because int-test-setup.sh usually handles it
fi

# Tools setup
export PYTHONPATH="$T/tools:$PYTHONPATH"
PTOOL="python3 -m tpm2_pkcs11.tpm2_ptool"

# Initialize store and add token
$PTOOL init --path="$TPM2_PKCS11_STORE"
$PTOOL addtoken --path="$TPM2_PKCS11_STORE" --label=test --sopin=123456 --userpin=123456 --pid=1

# Get current PCR 0 value
PCR0=$(tpm2_pcrread sha256:0 | grep '0 :' | awk '{print $3}')

# Initialize to something random
PCR0_EXTEND=$(openssl rand -hex 32)

# Calculate what PCR0 is going to be
# (This is to ensure we don't lock against current PCR's, but rather the ones in the policy
FUTURE_PCR=$(echo "${PCR0/0x/}${PCR0_EXTEND}" | xxd -r -p -c 32 | sha256sum -)

# Define PCR policy (FAPI format used by ptool)
POLICY_JSON='{"description":"pcr policy","policy":[{"type":"pcr","pcrs":[{"pcr":0,"hashAlg":"sha256","digest":"'${FUTURE_PCR/  -/}'"}]}]}'

# Add PCR-locked key
$PTOOL addkey --path="$TPM2_PKCS11_STORE" --label=test --userpin=123456 --algorithm=rsa2048 --key-label=polkey --policy="$POLICY_JSON"

# Extend it with that
tpm2_pcrextend 0:sha256=${PCR0_EXTEND}

# Get current PCR 0 value
PCR0=$(tpm2_pcrread sha256:0 | grep '0 :' | awk '{print $3}' | tr '[A-F]' '[a-f]')

# Verify that it's what we calculated
if [ "${PCR0/0x/}" != "${FUTURE_PCR/  -/}" ] ; then
    echo "ERROR: Actual and calculated future PCR missmatch!"
    echo "${PCR0/0x/}" != "${FUTURE_PCR/  -/}"
    exit 1
fi

echo ">>> Attempting access with CORRECT PCR state (should succeed)"
if p11tool --provider "$modpath" --login --set-pin=123456 --test-sign "pkcs11:token=test;object=polkey;type=private" > /dev/null; then
    echo "SUCCESS: Initial access worked."
else
    echo "FAILURE: Initial access failed!"
    exit 1
fi

echo ">>> Changing PCR 0 state"
tpm2_pcrextend 0:sha256=$(openssl rand -hex 32)

echo ">>> Attempting access with INCORRECT PCR state (should fail)"
# We expect this to fail because the TPM enforces the policy and userwithauth is gone.
# We'll try to sign something to force a real policy check.
if p11tool --provider "$modpath" --login --set-pin=123456 --test-sign "pkcs11:token=test;object=polkey;type=private"; then
    echo "FAILURE: Policy bypass detected! Key accessible despite PCR change."
    exit 1
else
    echo "SUCCESS: Policy enforced! Access denied as expected."
fi

exit 0
