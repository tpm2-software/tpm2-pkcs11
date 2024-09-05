# SPDX-License-Identifier: BSD-2-Clause

INCLUDE_DIRS    = -I$(srcdir)/src -I$(top_srcdir)/src/lib
ACLOCAL_AMFLAGS = -I m4 --install
AM_CFLAGS       = $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(CODE_COVERAGE_CFLAGS) \
                  $(TSS2_ESYS_CFLAGS) $(TSS2_MU_CFLAGS) $(TSS2_TCTILDR_CFLAGS) \
		  $(TSS2_RC_CFLAGS) $(SQLITE3_CFLAGS) $(PTHREAD_CFLAGS) \
		  $(CRYPTO_CFLAGS) $(YAML_CFLAGS) $(TSS2_FAPI_CFLAGS)

AM_LDFLAGS      = $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS) $(TSS2_ESYS_LIBS) \
                  $(TSS2_MU_LIBS) $(TSS2_TCTILDR_LIBS) $(TSS2_RC_LIBS) \
		  $(SQLITE3_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(YAML_LIBS) $(TSS2_FAPI_LIBS)

check-programs: $(check_PROGRAMS)

JAVAROOT=$(top_builddir)/test/integration

# ax_code_coverage
if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

# Add source code files from bootstrap
include src_vars.mk

EXTRA_DIST = \
    LICENSE \
    docs \
    test/fake-tpm \
    test/integration/scripts \
    misc/p11-kit \
    tools \
    VERSION

# Generate the AUTHORS file from git log
AUTHORS :
	$(AM_V_GEN)git log --format='%aN <%aE>' | grep -v 'users.noreply.github.com' | sort | \
	    uniq -c | sort -nr | sed 's/^\s*//' | cut -d" " -f2- > $@
EXTRA_DIST += AUTHORS
CLEANFILES = AUTHORS

# pkg-config setup. pc-file declarations happen in the corresponding modules
pkgconfig_DATA =
DISTCLEANFILES = $(pkgconfig_DATA)

### PKCS#11 Library Definition ###
libtpm2_pkcs11 = src/libtpm2_pkcs11.la
pkgconfig_DATA += lib/tpm2-pkcs11.pc
EXTRA_DIST += lib/tpm2-pkcs11.map

if HAVE_LD_VERSION_SCRIPT
src_libtpm2_pkcs11_la_LDFLAGS = -Wl,--version-script=$(srcdir)/lib/tpm2-pkcs11.map
endif # HAVE_LD_VERSION_SCRIPT
src_libtpm2_pkcs11_la_LIBADD = $(AM_LDFLAGS)
src_libtpm2_pkcs11_la_SOURCES = $(LIB_PKCS11_SRC) $(LIB_PKCS11_INTERNAL_LIB_SRC)

if HAVE_PREFIX
  # Use standard install location when using --prefix
  lib_LTLIBRARIES = $(libtpm2_pkcs11)
else
if HAVE_P11KIT
  # Use P11 kit library module install location
  p11libdir=$(P11_MODULE_PATH)
  p11lib_LTLIBRARIES = $(libtpm2_pkcs11)

  # Use P11 kit module config file install location
  p11configdir=$(P11_CONFIGS_PATH)
  p11config_DATA = $(top_srcdir)/misc/p11-kit/tpm2_pkcs11.module
else
  # Use standard install location when P11Kit is not found
  lib_LTLIBRARIES = $(libtpm2_pkcs11)
endif
endif

AM_DISTCHECK_CONFIGURE_FLAGS = --with-p11kitconfigdir='$$(datarootdir)/p11kitconfigdir' --with-p11kitmoduledir='$$(libdir)'

# The key_import tool
bin_PROGRAMS = tools/key_import/key_import
if ENABLE_ASAN
  tools_key_import_key_import_LDFLAGS = $(AM_LDFLAGS) -shared-libasan
else
  tools_key_import_key_import_LDFLAGS = $(AM_LDFLAGS)
endif
tools_key_import_key_import_LDADD = $(libtpm2_pkcs11)
tools_key_import_key_import_SOURCES = tools/key_import/import.c

#
# Due to limitations in how cmocka works, we build a separate library here so we
# can have a PKCS11 shared object with undefined calls into the rest of the lib
# code. This allows us to deploy a single library, but be able to intercept calls
# during linking with ld wrap to mock out various functions.
#
# UNIT, INTEGRATION and/or FUZZ can use this library.
#

# src/lib stuff as a separate archive
libtpm2_test_pkcs11 = src/libtpm2_test_pkcs11.la
src_libtpm2_test_pkcs11_la_LIBADD =  $(AM_LDFLAGS) $(libtpm2_test_internal)
src_libtpm2_test_pkcs11_la_SOURCES = $(LIB_PKCS11_SRC)

# Internal Testing Unit
libtpm2_test_internal = src/libtpm2_test_internal.la
src_libtpm2_test_internal_la_LIBADD = $(AM_LDFLAGS)
src_libtpm2_test_internal_la_SOURCES = $(LIB_PKCS11_INTERNAL_LIB_SRC)

noinst_LTLIBRARIES = $(libtpm2_test_pkcs11) $(libtpm2_test_internal)

if ENABLE_ASAN
    ASAN_ENABLED="true"
else
    ASAN_ENABLED=""
endif

if HAVE_FAPI
    FAPI_ENABLED="true"
else
    FAPI_ENABLED=""
endif

# test harness configuration
AM_TESTS_ENVIRONMENT = \
    ASAN_ENABLED=$(ASAN_ENABLED) \
    FAPI_ENABLED=$(FAPI_ENABLED) \
    T=$(abs_top_srcdir) \
    PYTHON_INTERPRETER=@PYTHON_INTERPRETER@ \
    TEST_FUNC_LIB=$(srcdir)/test/integration/scripts/int-test-funcs.sh \
    TEST_FIXTURES=$(abs_top_srcdir)/test/integration/fixtures \
    PATH=$(abs_top_srcdir)/tools/tpm2_ptool:$(abs_builddir)/tools/key_import:./src:$(PATH) \
    PYTHONPATH=$(abs_top_srcdir)/tools/tpm2_ptool:$(PYTHONPATH) \
    TPM2_PKCS11_MODULE=$(abs_builddir)/src/.libs/libtpm2_pkcs11.so \
    TEST_JAVA_ROOT=$(JAVAROOT) \
    PACKAGE_URL=$(PACKAGE_URL) \
    CC=$(CC) \
    dbus-run-session

TESTS_LDADD = $(noinst_LTLIBRARIES) $(lib_LTLIBRARIES) $(p11lib_LTLIBRARIES) $(AM_LDFLAGS) $(CMOCKA_LIBS) $(CRYPTO_LIBS)

TESTS_CFLAGS = $(CMOCKA_CFLAGS)

# Intentionally empty so INTEGRATION and UNIT tests can append to it.
check_PROGRAMS =
check_SCRIPTS =

# include integration tests
include Makefile-integration.am

# include unit tests
include Makefile-unit.am

# Include fuzz tests
include Makefile-fuzz.am

TESTS= \
    $(check_PROGRAMS) \
    $(check_SCRIPTS)
