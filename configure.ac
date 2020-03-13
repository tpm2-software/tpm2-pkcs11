# SPDX-License-Identifier: BSD-2-Clause

AC_INIT([tpm2-pkcs11],
  [m4_esyscmd_s([git describe --tags --always --dirty])],
  [https://github.com/tpm2-software/tpm2-pkcs11/issues],
  [],
  [https://github.com/tpm2-software/tpm2-pkcs11])

AC_CONFIG_MACRO_DIR([m4])

# propagate configure arguments to distcheck
AC_SUBST([DISTCHECK_CONFIGURE_FLAGS],[$ac_configure_args])

AX_IS_RELEASE([dash-version])
AX_CHECK_ENABLE_DEBUG([info])

AC_PROG_CC
LT_INIT
AM_INIT_AUTOMAKE([foreign subdir-objects])

PKG_INSTALLDIR()

# enable "silent-rules" option by default
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AX_CODE_COVERAGE
m4_ifdef([_AX_CODE_COVERAGE_RULES],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [true])],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [false])])
AX_ADD_AM_MACRO_STATIC([])

AC_CONFIG_FILES([Makefile lib/tpm2-pkcs11.pc])

# enable autoheader config.h file
AC_CONFIG_HEADERS([src/lib/config.h])

# test for TSS dependecies
PKG_CHECK_MODULES([TSS2_ESYS],   [tss2-esys >= 2.0])
PKG_CHECK_MODULES([TSS2_MU],     [tss2-mu])
PKG_CHECK_MODULES([TSS2_TCTILDR], [tss2-tctildr])
PKG_CHECK_MODULES([TSS2_RC], [tss2-rc])

AC_DEFUN([do_esapi_manage_flags], [
  AC_DEFINE([ESAPI_MANAGE_FLAGS], [1],
    [ESAPI versions below 2.2.1 are known to require manual session flag management.])
])

# Check for ESYS version below 2.2.1 which requires us to manage ESYS session flags
PKG_CHECK_EXISTS([tss2-esys < 2.2.1], [do_esapi_manage_flags])

# require sqlite3 and libcrypto
PKG_CHECK_MODULES([SQLITE3],     [sqlite3])
PKG_CHECK_MODULES([YAML],        [yaml-0.1])
PKG_CHECK_MODULES([CRYPTO],      [libcrypto >= 1.0.2g])

# check for pthread
AX_PTHREAD([],[AC_MSG_ERROR([Cannot find pthread])])

# gnulib m4 dependency: check for linker script support
gl_LD_VERSION_SCRIPT

AC_ARG_ENABLE(
  [esapi-session-manage-flags],
  [AS_HELP_STRING([--enable-esapi-session-manage-flags],
    [Force the TPM module to manage ESAPI session flags (default is autodetect)])],
  [esapi_sf=$enableval])
AS_IF([test "x$esapi_sf" = "xyes"],
       [do_esapi_manage_flags])

# START ENABLE UNIT
#
# Enable --with-unit option for unit testing
#
AC_ARG_ENABLE(
  [unit],
  [AS_HELP_STRING([--enable-unit],
    [build cmocka unit tests])],,
  [enable_unit=no])

AC_DEFUN([unit_test_checks],[

  PKG_CHECK_MODULES([CMOCKA],[cmocka])

  AC_DEFINE([UNIT_TESTING], [1],
    [Define when unit testing. libtwist uses this to define a debug interface for alloc failures])
]) # end function unit_test_checks

AS_IF([test "x$enable_unit" = "xyes"],
       [unit_test_checks])

AM_CONDITIONAL([UNIT], [test "x$enable_unit" = "xyes"])

# END ENABLE UNIT

# START ENABLE INTEGRATION
#
# enable integration tests and check for simulator binary
#
AC_ARG_ENABLE(
  [integration],
  [AS_HELP_STRING([--enable-integration],
    [build and execute integration tests])],,
  [enable_integration=no])

# Test for Java compiler and interpreter without throwing fatal errors (since
# these macros are defined using AC_DEFUN they cannot be called conditionally)
m4_pushdef([AC_MSG_ERROR], [have_javac=no])
AX_PROG_JAVAC()
AX_PROG_JAVA()
m4_popdef([AC_MSG_ERROR])

AC_DEFUN([integration_test_checks], [

  PKG_CHECK_MODULES([CMOCKA],[cmocka])
  PKG_CHECK_MODULES([OPENSC_PKCS11],[opensc-pkcs11],,
    [AC_CHECK_FILE([/usr/lib/engines/engine_pkcs11.so])])

  AC_CHECK_PROG([tpm_server], [tpm_server], [yes], [no])
  AS_IF([test "x$tpm_server" != "xyes"],
    [AC_MSG_ERROR([Integration tests enabled but tpm_server not found, try setting PATH])])

  AC_CHECK_PROG([ss], [ss], [yes], [no])
    AS_IF([test "x$ss" != "xyes"],
      [AC_MSG_ERROR([Integration tests enabled but ss executable not found.])])

  AC_CHECK_PROG([certutil], [certutil], [yes], [no])
    AS_IF([test "x$certutil" != "xyes"],
      [AC_MSG_ERROR([Integration tests enabled but certutil executable not found.])])

  AC_CHECK_PROG([modutil], [modutil], [yes], [no])
    AS_IF([test "x$modutil" != "xyes"],
      [AC_MSG_ERROR([Integration tests enabled but modutil executable not found.])])
  
  AC_CHECK_PROG([expect], [expect], [yes], [no])
    AS_IF([test "x$expect" != "xyes"],
      [AC_MSG_ERROR([Integration tests enabled but expect executable not found.])])

  AC_CHECK_PROG([pkcs11_tool], [pkcs11-tool], [yes], [no])
    AS_IF([test "x$pkcs11_tool" != "xyes"],
      [AC_MSG_ERROR([Integration tests enabled but pkcs11-tool executable not found.])])
  
  AC_CHECK_PROG([bash], [bash], [yes], [no])
    AS_IF([test "x$bash" != "xyes"],
      [AC_MSG_ERROR([Integration tests enabled but bash executable not found.])])

  AC_CHECK_PROG([sqlite3], [sqlite3], [yes], [no])
    AS_IF([test "x$sqlite3" != "xyes"],
      [AC_MSG_ERROR([Integration tests enabled but sqlite3 executable not found.])])

  AM_PATH_PYTHON([3.7],
    [AC_SUBST([PYTHON_INTERPRETER], [$PYTHON])],
    [AC_MSG_ERROR([Integration tests enabled but python >= 3.7 executable not found.])]
  )

  AS_IF([test "x$have_javac" = "xno"],
    [AC_MSG_ERROR([Integration tests enabled but no Java compiler was found])])
  AX_CHECK_CLASS([org.junit.Assert], ,
    [AC_MSG_ERROR([Integration tests enabled but JUnit not found, try setting CLASSPATH])])
  AX_CHECK_CLASS([org.hamcrest.SelfDescribing], ,
    [AC_MSG_ERROR([Integration tests enabled but Hamcrest not found, try setting CLASSPATH])])

  AC_SUBST([ENABLE_INTEGRATION], [$enable_integration])
]) # end function integration_test_checks

AS_IF([test "x$enable_integration" = "xyes"],
  [integration_test_checks])

AM_CONDITIONAL([ENABLE_INTEGRATION],[test "x$enable_integration" = "xyes"])

# END ENABLE INTEGRATION

AC_DEFUN([handle_store_dir],[
  AX_NORMALIZE_PATH([with_storedir])
  AC_DEFINE_UNQUOTED([TPM2_PKCS11_STORE_DIR], ["$with_storedir"],
    [Changes the store directory to search. Defaults to /etc/tpm2_pkcs11])
])

# START WITH STOREDIR
#
# Enable --with-storedir for changing the default store directory search path
#
AC_ARG_WITH(
  [storedir],
  [AS_HELP_STRING([--with-storedir=DIR],[Store directory for searching, defaults to /etc/tpm2_pkcs11])],
    [handle_store_dir]
)

# END WITH STOREDIR

# START ENABLE PACK
#
# Enable --enable-pack for forcing structure packing
#
AC_ARG_ENABLE(
  [pack],
  [AS_HELP_STRING([--enable-pack=]@<:@yes/no@:>@,
    [Pack the structures. (default is no, except on Windows, where it defaults to packing)])],,
  [enable_pack=no])

AS_IF([test "x$enable_pack" = "xyes"],
  [AC_DEFINE([PKCS11_PACK], [1],
    [Define to enable 1 byte structure packing. Default for Windows builds.])
])

# END ENABLE PACK

# START P11 CONFIG
# If P11 kit is installed we want to detect it and install
# the module config file and change the library install location.
AC_DEFUN([do_p11kit_config], [

  AS_IF([test -z "$1"], [
    PKG_CHECK_VAR([P11_MODULE_PATH], [p11-kit-1], [p11_module_path])
    AC_MSG_CHECKING([p11 module path])
    AS_IF([test "x$P11_MODULE_PATH" = "x"], [
      AC_MSG_FAILURE([Unable to identify p11 module path.])
    ])
    AC_MSG_RESULT([$P11_MODULE_PATH])
  ], [
    AC_SUBST(P11_MODULE_PATH, [$1])
  ])

  AS_IF([test -z "$2"], [
    PKG_CHECK_VAR([P11_CONFIGS_PATH], [p11-kit-1], [p11_module_configs])
    AC_MSG_CHECKING([p11 configs path])
    AS_IF([test "x$P11_CONFIGS_PATH" = "x"], [
      AC_MSG_FAILURE([Unable to identify p11 configs path.])
    ])
    AC_MSG_RESULT([$P11_CONFIGS_PATH])
  ], [
    AC_SUBST(P11_CONFIGS_PATH, [$2])
  ])
])

AC_ARG_WITH([p11kitconfigdir],
            AS_HELP_STRING([--with-p11kitconfigdir=DIR], [directory for p11kit config]))
AC_SUBST(p11kitconfigdir, [$with_p11kitconfigdir])

AC_ARG_WITH([p11kitmoduledir],
            AS_HELP_STRING([--with-p11kitmoduledir=DIR], [directory for p11 libraries]))
AC_SUBST(p11kitmoduledir, [$with_p11kitmoduledir])

# set havep11kit based on if P11kit is installed, then:
# 1. execute function do_p11kit_config
# 2. set the makefile flag HAVE_P11_KIT
PKG_CHECK_MODULES(
  [P11KIT],
  [p11-kit-1],
  [have_p11kit=yes],
  [have_p11kit=no])

AS_IF([test "x$have_p11kit" = "xyes"], [
  do_p11kit_config([$p11kitmoduledir], [$p11kitconfigdir])
])

AM_CONDITIONAL([HAVE_P11KIT], [test "x$have_p11kit" = "xyes"])

# END P11 CONFIG

AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--disable-hardening],
    [Disable compiler and linker options to frustrate memory corruption exploits])],,
  [enable_hardening="yes"])

# Good information on adding flags, and dealing with compilers can be found here:
#   https://github.com/zcash/zcash/issues/1832
#   https://github.com/kmcallister/autoharden/
AS_IF([test x"$enable_hardening" != xno], [

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
  add_hardened_c_flag([-Wstrict-overflow=5])

  add_hardened_c_flag([-O2])
  AX_ADD_FORTIFY_SOURCE

  add_hardened_c_flag([-fPIC])
  add_hardened_ld_flag([[-shared]])

  add_hardened_c_flag([-fPIE])
  add_hardened_ld_flag([[-pie]])

  add_hardened_ld_flag([[-Wl,-z,relro]])
  add_hardened_ld_flag([[-Wl,-z,now]])

], [
  AC_MSG_WARN([Compiling with --disable-hardening is dangerous!
You should consider fixing the configure script compiler flags
and submitting patches upstream!])
])

# Best attempt, strip unused stuff from the binary to reduce size.
# Rather than nesting these and making them ugly just use a counter.
AX_CHECK_COMPILE_FLAG([-fdata-sections], [strip=y])
AX_CHECK_COMPILE_FLAG([-ffunction-sections], [strip="y$strip"])
AX_CHECK_LINK_FLAG([[-Wl,--gc-sections]], [strip+="y$strip"])

AS_IF([test x"$strip" = xyyy], [
  EXTRA_CFLAGS="$EXTRA_CFLAGS -fdata-sections -ffunction-sections"
  EXTRA_LDFLAGS="$EXTRA_LDFLAGS -Wl,--gc-sections"
],
  AC_MSG_NOTICE([Not using compiler options to reduce binary size!])
)

AC_SUBST([EXTRA_CFLAGS])
AC_SUBST([EXTRA_LDFLAGS])

AC_OUTPUT
