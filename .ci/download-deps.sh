#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2
#
# Copyright (c) 2017-2018 Intel Corporation
# All rights reserved.
#

function install_m4_deps() {
	# all of our projects need auto-conf archive up-to-date and
	# distros tend to be outdated.
	mkdir -p m4
	cp /usr/share/gnulib/m4/ld-version-script.m4 m4/
	cp -r /workspace/autoconf-archive-*/m4/* m4/
}

function get_autoconf_archive() {

	if [ -f autoconf-archive-*.tar.xz ]; then
		return
	fi

	wget https://download.01.org/tpm2/autoconf-archive-2017.09.28.tar.xz
	sha256sum autoconf-archive-2017.09.28.tar.xz | grep -q 5c9fb5845b38b28982a3ef12836f76b35f46799ef4a2e46b48e2bd3c6182fa01 || travis_terminate 1
	tar -xavf autoconf-archive-2017.09.28.tar.xz
}

function get_deps() {

	# The list order is important and thus we can't use the keys of the dictionary as order is not preserved.
	local github_deps=("tpm2-tss" "tpm2-abrmd" "tpm2-tools")
	declare -A local config_flags=( ["tpm2-tss"]="--disable-doxygen-doc CFLAGS=-g" ["tpm2-abrmd"]="CFLAGS=-g" ["tpm2-tools"]="CFLAGS=-g")

	echo "pwd starting: `pwd`"
	pushd "$1"

	get_autoconf_archive

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

		install_m4_deps

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
