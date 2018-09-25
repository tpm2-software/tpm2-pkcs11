#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2
#
# Copyright (c) 2017-2018 Intel Corporation
# All rights reserved.
#

function get_deps() {

	local github_deps=("tpm2-tss" "tpm2-abrmd" "tpm2-tools")

	echo "pwd starting: `pwd`"
	pushd "$1"

	for p in ${github_deps[@]}; do
		if [ -d "$p" ]; then
			echo "Skipping project "$p", already downloaded"
			continue
		fi
		git clone "https://github.com/tpm2-software/$p.git"

		pushd "$p"

		./bootstrap
		./configure CFLAGS=-g
		make -j$(nproc) install

		# leave the git clone directory
		popd

	done;

	# leave the download location directory
	popd
	echo "pwd done: `pwd`"

}
