#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

function get_deps() {

	source "${DOCKER_BUILD_DIR}/test/integration/scripts/helpers.sh"
	check_openssl_version
	if [ "$OSSL3_DETECTED" -eq "1" ]; then
		engine_pkg="tpm2-openssl"
		engine_flags=""
		engine_version="master"
		tpm2_tss_version="3.2.0"
	else
		engine_pkg="tpm2-tss-engine"
		engine_flags="--enable-tctienvvar"
		engine_version="v1.1.0"
		tpm2_tss_version="3.0.0"
        fi

	# The list order is important and thus we can't use the keys of the dictionary as order is not preserved.
	local github_deps=("tpm2-tss" "tpm2-abrmd" "tpm2-tools" "${engine_pkg}")
	declare -A local config_flags=( ["tpm2-tss"]="--disable-doxygen-doc --enable-debug" ["tpm2-abrmd"]="--enable-debug" ["tpm2-tools"]="--disable-hardening --enable-debug" ["${engine_pkg}"]="${engine_flags}")
	declare -A local versions=( ["tpm2-tss"]="${tpm2_tss_version}" ["tpm2-abrmd"]="2.3.3" ["tpm2-tools"]="5.2" ["${engine_pkg}"]="${engine_version}")

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
		git clone --depth 1 --branch $v "https://github.com/tpm2-software/$p.git"

		pushd "$p"

		./bootstrap
		./configure $configure_flags
		make -j$(nproc) install

		# leave the git clone directory
		popd

	done;

        # install tpm2-pytss package
	# older versions of clang cannot build the wheel, gcc is always present, use it.
	OLD_CC="$CC"
	CC=gcc
	pip install 'git+https://github.com/tpm2-software/tpm2-pytss.git'
	CC="$OLD_CC"

	# leave the download location directory
	popd
	echo "pwd done: `pwd`"

}
