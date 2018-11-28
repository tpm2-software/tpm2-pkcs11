#;**********************************************************************;
# Copyright (c) 2018 Intel Corporation
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

AC_INIT([tpm2-pkcs11],
        [m4_esyscmd_s([git describe --tags --always --dirty])],
        [https://github.com/tpm2-software/<todo>/issues],
        [],
        [https://github.com/tpm2-software/<todo>])

AC_CONFIG_MACRO_DIR([m4])

AX_IS_RELEASE([dash-version])
AX_CHECK_ENABLE_DEBUG([no])

AC_PROG_CC
LT_INIT()
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
# enable "silent-rules" option by default
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AX_CODE_COVERAGE
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([src/lib/config.h])

PKG_CHECK_MODULES([TSS2_ESYS],[tss2-esys])
PKG_CHECK_MODULES([TCTI_DEVICE], [tss2-tcti-device])
PKG_CHECK_MODULES([TCTI_MSSIM], [tss2-tcti-mssim])
PKG_CHECK_MODULES([SQLITE3],[sqlite3])
PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 1.0.2g])
AX_PTHREAD([],[AC_MSG_ERROR([Cannot find pthread])])

gl_LD_VERSION_SCRIPT

AC_ARG_ENABLE([unit],
            [AS_HELP_STRING([--enable-unit],
                            [build cmocka unit tests (default is no)])],
            [enable_unit=$enableval],
            [enable_unit=no])
AS_IF([test "x$enable_unit" = "xyes"],
      [PKG_CHECK_MODULES([CMOCKA],
                         [cmocka],
                         )])
AM_CONDITIONAL([UNIT], [test "x$enable_unit" = "xyes"])

#
# enable integration tests and check for simulator binary
#
AC_ARG_ENABLE([integration],
    [AS_HELP_STRING([--enable-integration],
        [build and execute integration tests (default is no)])],
    [enable_integration=$enableval],
    [enable_integration=no])
AS_IF([test "x$enable_integration" = "xyes"],
      [AC_CHECK_PROG([tpm_server], [tpm_server], [yes], [no])
       AS_IF([test "x$tpm_server" != "xyes"],
             [AC_MSG_ERROR([Integration tests enabled but tpm_server not found, try setting PATH])])
       AC_CHECK_PROG([tpm2_ptool], [tpm2_ptool.py], [yes], [no])
       AS_IF([test "x$tpm2_ptool" != "xyes"],
             [AC_MSG_ERROR([Integration tests enabled but tpm2_ptool not found, try setting PATH])])
       AC_CHECK_PROG([netstat], [netstat], [yes], [no])
       AS_IF([test "x$netstat" != "xyes"],
             [AC_MSG_ERROR([Integration tests enabled but netstat executable not found.])])
       PKG_CHECK_MODULES([LIBCRYPTO],[libcrypto])
       AC_SUBST([ENABLE_INTEGRATION], [$enable_integration])])
AM_CONDITIONAL([ENABLE_INTEGRATION],[test "x$enable_integration" = "xyes"])

#####


AC_ARG_ENABLE([dlclose],
  [AS_HELP_STRING([--disable-dlclose],
                            [Some versions of libc cause a sigsegv on exit with dlclose(),
                            this disables the dlclose() and works around that bug])],
  []
  [AC_DEFINE([DISABLE_DLCLOSE], [1],
  [Some versions of libc cause a sigsegv on exit with dlcolse(), this disables the dlclose()
  and works around that bug])]
 )

AC_DEFUN([handle_store_dir],[
    AX_NORMALIZE_PATH([with_storedir])
    AC_DEFINE_UNQUOTED([TPM2_PKCS11_STORE_DIR], ["$with_storedir"],
    [Changes the store directory to search. Defaults to /etc/tpm2_pkcs11])
])

AC_ARG_WITH([storedir],
            [AS_HELP_STRING([--with-storedir=DIR],[Store directory for searching, defaults to /etc/tpm2_pkcs11])],
            [handle_store_dir],
            []
)

AC_ARG_ENABLE([pack],
            [AS_HELP_STRING([--enable-pack=]@<:@yes/no@:>@,
                            [Pack the structures. (default is no, except on Windows, where it defaults to packing)])],
            [enable_pack=$enableval],
            [enable_pack=no])
AS_IF([test "x$enable_pack" = "xyes"],
  [AC_DEFINE([PKCS11_PACK], [1],
    [Define to enable 1 byte structure packing. Default for Windows builds.])
  ])

AC_DEFUN([unit_test_checks],[

  PKG_CHECK_MODULES([CMOCKA],[cmocka])

  AC_DEFINE([UNIT_TESTING], [1],
    [Define when unit testing. libtwist uses this to define a debug interface for alloc failures])
])

AS_IF([test "x$enable_unit" = "xyes"],
       [unit_test_checks])

# If P11 kit is installed we want to detect it and install
# the module config file and change the library install location.
AC_DEFUN([do_p11kit_config], [

  PKG_CHECK_VAR([P11_MODULE_PATH], [p11-kit-1], [p11_module_path])
  AC_MSG_CHECKING([p11 module path])
  AS_IF([test "x$P11_MODULE_PATH" = "x"], [
    AC_MSG_FAILURE([Unable to identify p11 module path.])
  ])
  AC_MSG_RESULT([$P11_MODULE_PATH])

  PKG_CHECK_VAR([P11_CONFIGS_PATH], [p11-kit-1], [p11_module_configs])
  AC_MSG_CHECKING([p11 configs path])
  AS_IF([test "x$P11_CONFIGS_PATH" = "x"], [
    AC_MSG_FAILURE([Unable to identify p11 configs path.])
  ])
  AC_MSG_RESULT([$P11_CONFIGS_PATH])
])

# set havep11kit based on if P11kit is installed, then:
# 1. execute function do_p11kit_config
# 2. set the makefile flag HAVE_P11_KIT
PKG_CHECK_MODULES([P11KIT],
                  [p11-kit-1],
                  [have_p11kit=yes],
                  [have_p11kit=no])

AS_IF([test "x$have_p11kit" = "xyes"], [
  do_p11kit_config
])

AM_CONDITIONAL([HAVE_P11KIT], [test "x$have_p11kit" = "xyes"])

AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--enable-hardening],
    [Enable compiler and linker options to frustrate memory corruption exploits @<:@yes@:>@])],
  [hardening="$enableval"],
  [hardening="yes"])

# Good information on adding flags, and dealing with compilers can be found here:
#   https://github.com/zcash/zcash/issues/1832
#   https://github.com/kmcallister/autoharden/
AS_IF([test x"$hardening" != x"no"], [

  AC_DEFUN([add_hardened_c_flag], [
    AX_CHECK_COMPILE_FLAG([$1],
      [EXTRA_CFLAGS="$EXTRA_CFLAGS $1"],
      [AC_MSG_ERROR([Cannot enable $1, consider configuring with --disable-hardening])]
    )
  ])

  AC_DEFUN([add_hardened_ld_flag], [
    AX_CHECK_LINK_FLAG([$1],
      [EXTRA_LDFLAGS="$EXTRA_LDFLAGS $1"],
      [AC_MSG_ERROR([Cannot enable $1, consider configuring with --disable-hardening])]
    )
  ])

  AC_DEFUN([add_hardened_define_flag], [
    AX_CHECK_PREPROC_FLAG([$1],
      [EXTRA_CFLAGS="$EXTRA_CFLAGS $1"],
      [AC_MSG_ERROR([Cannot enable $1, consider configuring with --disable-hardening])]
    )
  ])

  add_hardened_c_flag([-Wall])
  add_hardened_c_flag([-Wextra])
  add_hardened_c_flag([-Werror])

  add_hardened_c_flag([-Wformat])
  add_hardened_c_flag([-Wformat-security])
  add_hardened_c_flag([-Wstack-protector])
  add_hardened_c_flag([-fstack-protector-all])

  add_hardened_define_flag([-U_FORTIFY_SOURCE])
  add_hardened_define_flag([-D_FORTIFY_SOURCE=2])

  add_hardened_c_flag([-fPIC])
  add_hardened_ld_flag([[-shared]])

  add_hardened_c_flag([-fPIE])
  add_hardened_ld_flag([[-pie]])

  add_hardened_ld_flag([[-Wl,-z,relro]])
  add_hardened_ld_flag([[-Wl,-z,now]])

], [
  AC_MSG_WARN([Compiling with --disable-hardening is dangerous!
you should consider fixing the configure script compiler flags
and submitting patches upstream!])
])

# Best attempt, strip unused stuff from the binary to reduce size.
# Rather than nesting these and making them ugly just use a counter.
AX_CHECK_COMPILE_FLAG([-fdata-sections], [strip+="y"])
AX_CHECK_COMPILE_FLAG([-ffunction-sections], [strip+="y"])
AX_CHECK_LINK_FLAG([[-Wl,--gc-sections]], [strip+="y"])

AS_IF([test x"$strip" == x"yyy"], [
  EXTRA_CFLAGS="$EXTRA_CFLAGS -fdata-sections -ffunction-sections"
  EXTRA_LDFLAGS="$EXTRA_LDFLAGS -Wl,--gc-sections"
],
  AC_MSG_NOTICE([Not using compiler options to reduce binary size!])
)

AC_SUBST([EXTRA_CFLAGS])
AC_SUBST([EXTRA_LDFLAGS])

AC_OUTPUT
