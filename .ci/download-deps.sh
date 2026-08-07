#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

function get_deps() {

	source "${DOCKER_BUILD_DIR}/test/integration/scripts/helpers.sh"
	check_openssl_version
	if [ "$OSSL3_DETECTED" -eq "1" ]; then
		engine_pkg="tpm2-openssl"
		engine_flags=""
	else
		engine_pkg="tpm2-tss-engine"
		engine_flags="--enable-tctienvvar"
	fi

	# The list order is important and thus we can't use the keys of the dictionary as order is not preserved.
	local github_deps=("tpm2-tss" "tpm2-abrmd" "tpm2-tools" "${engine_pkg}")
	declare -A local config_flags=( ["tpm2-tss"]="--disable-doxygen-doc --enable-debug" ["tpm2-abrmd"]="--enable-debug" ["tpm2-tools"]="--disable-hardening --enable-debug" ["${engine_pkg}"]="${engine_flags}")
	declare -A local versions=( ["tpm2-tss"]="master" ["tpm2-abrmd"]="master" ["tpm2-tools"]="master" ["${engine_pkg}"]="master")

	echo "pwd starting: `pwd`"
	pushd "$1"

	for p in ${github_deps[@]}; do
		configure_flags=${config_flags[$p]}
		echo "project: $p"
		echo "conf-flags: $configure_flags"
		if [ -d "$p" ]; then
			echo "Skipping project "$p", already downloaded"
			continue
		fi
		v=${versions[$p]}
		git clone --branch $v "https://github.com/tpm2-software/$p.git"

		pushd "$p"

		./bootstrap
		./configure $configure_flags
		make -j$(nproc) install

		# leave the git clone directory
		popd

	done;

	# install Python helper packages. tpm2-pytss must match the tpm2-tss
	# headers installed above, so build it from master instead of the stale
	# PyPI wheel.
	# older versions of clang cannot build the wheel, gcc is always present, use it.
	OLD_CC="$CC"
	CC=gcc
	python3 -m pip install --break-system-packages pyasn1 pyasn1_modules python-pkcs11
	if [ -d "tpm2-pytss" ]; then
		echo "Skipping tpm2-pytss, already downloaded"
	else
		git clone --branch master "https://github.com/tpm2-software/tpm2-pytss.git"
	fi
	# Run ldconfig so tpm2-pytss can find the tss2 libs built above
	ldconfig

	pushd tpm2-pytss
	python3 -m pip install --break-system-packages .
	popd
	CC="$OLD_CC"

	# leave the download location directory
	popd
	echo "pwd done: `pwd`"

}
