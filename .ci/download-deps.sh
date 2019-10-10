#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2
#
# Copyright (c) 2017-2018 Intel Corporation
# All rights reserved.
#

function get_deps() {

    (apt-get update && apt-get --yes install opensc) || \
    dnf -y install opensc || \
    zypper --non-interactive install opensc

	git clone --depth=1 --branch "json-c-0.13.1-20180305" https://github.com/json-c/json-c.git
	pushd json-c
	sh autogen.sh
	./configure
	make -j$(nproc) install
	popd

	git clone --depth=1 --branch=fapi-rfc "https://github.com/AndreasFuchsSIT/tpm2-tss.git"
	pushd "tpm2-tss"
	./bootstrap
	./configure --disable-doxygen-doc CFLAGS=-g
	make -j$(nproc) install
	popd

	git clone --depth=1 --branch=fapi-rfc "https://github.com/AndreasFuchsSIT/tpm2-tools.git"
	pushd "tpm2-tools"
	./bootstrap
	./configure --disable-hardening CFLAGS=-g
	make -j$(nproc) install
	popd

	# The list order is important and thus we can't use the keys of the dictionary as order is not preserved.
#	local github_deps=("tpm2-tss" "tpm2-abrmd" "tpm2-tools")
	local github_deps=("tpm2-abrmd")
	declare -A local config_flags=( ["tpm2-tss"]="--disable-doxygen-doc CFLAGS=-g" ["tpm2-abrmd"]="CFLAGS=-g" ["tpm2-tools"]="--disable-hardening CFLAGS=-g")

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
		git clone "https://github.com/tpm2-software/$p.git"

		pushd "$p"

		./bootstrap
		./configure $configure_flags
		make -j$(nproc) install

		# leave the git clone directory
		popd

	done;

	# leave the download location directory
	popd
	echo "pwd done: `pwd`"

}
