# SPDX-License-Identifier: BSD-2-Clause

INCLUDE_DIRS    = -I$(srcdir)/src -I$(top_srcdir)/src/lib
ACLOCAL_AMFLAGS = -I m4 --install
AM_CFLAGS       = $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(CODE_COVERAGE_CFLAGS) \
                  $(TSS2_ESYS_CFLAGS) $(TSS2_MU_CFLAGS) $(TSS2_TCTILDR_CFLAGS) \
		  $(TSS2_RC_CFLAGS) $(SQLITE3_CFLAGS) $(PTHREAD_CFLAGS) \
		  $(CRYPTO_CFLAGS) $(YAML_CFLAGS)

AM_LDFLAGS      = $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS) $(TSS2_ESYS_LIBS) \
                  $(TSS2_MU_LIBS) $(TSS2_TCTILDR_LIBS) $(TSS2_RC_LIBS) \
		  $(SQLITE3_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(YAML_LIBS)

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
    test/integration/scripts \
    misc/p11-kit \
    tools

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

AM_DISTCHECK_CONFIGURE_FLAGS = --with-p11kitconfigdir='$$(datarootdir)/p11kitconfigdir' --with-p11kitmoduledir='$$(libdir)'

# test harness configuration
AM_TESTS_ENVIRONMENT = \
    TEST_FUNC_LIB=$(srcdir)/test/integration/scripts/int-test-funcs.sh \
    TEST_FIXTURES=$(abs_top_srcdir)/test/integration/fixtures \
    PATH=$(abs_top_srcdir)/tools:./src:$(PATH) \
    PYTHONPATH=$(abs_top_srcdir)/tools \
    dbus-run-session

TESTS_LDADD = $(noinst_LTLIBRARIES) $(lib_LTLIBRARIES) $(p11lib_LTLIBRARIES) $(AM_LDFLAGS) $(CMOCKA_LIBS) $(CRYPTO_LIBS)

TESTS_CFLAGS = $(CMOCKA_CFLAGS)

# Intentionally empty so INTEGRATION and UNIT tests can append to it.
check_PROGRAMS =
check_SCRIPTS =

TEST_EXTENSIONS = .sh .int

### Integration Tests ###
if ENABLE_INTEGRATION

#
# Common integration test static lib
#
LIB_TEST := test/integration/libtest.a
noinst_LIBRARIES = $(LIB_TEST)
test_integration_libtest_a_SOURCES = $(LIB_SRC)
test_integration_libtest_a_CFLAGS = -fPIC $(AM_CFLAGS)
TESTS_LDADD += $(LIB_TEST)

check_PROGRAMS += \
    test/integration/pkcs-find-objects.int \
    test/integration/pkcs-get-mechanism.int \
    test/integration/pkcs-get-attribute-value.int \
    test/integration/pkcs-login-logout.int \
    test/integration/pkcs-sign-verify.int \
    test/integration/pkcs-initialize-finalize.int \
    test/integration/pkcs-misc.int \
    test/integration/pkcs-crypt.int \
    test/integration/pkcs-keygen.int \
    test/integration/pkcs-session-state.int

# add test scripts
check_SCRIPTS += \
    test/integration/pkcs11-tool.sh \
    test/integration/tls-tests.sh

AM_INT_LOG_FLAGS = --tabrmd-tcti=mssim --tsetup-script=$(top_srcdir)/test/integration/scripts/create_pkcs_store.sh
INT_LOG_COMPILER = $(srcdir)/test/integration/scripts/int-test-setup.sh

AM_SH_LOG_FLAGS = --tabrmd-tcti=mssim --tsetup-script=$(top_srcdir)/test/integration/scripts/create_pkcs_store.sh
SH_LOG_COMPILER = $(srcdir)/test/integration/scripts/int-test-setup.sh

test_integration_pkcs_find_objects_int_CFLAGS  = $(AM_CFLAGS) $(TESTS_CFLAGS)
test_integration_pkcs_find_objects_int_LDADD   = $(TESTS_LDADD)
test_integration_pkcs_find_objects_int_SOURCES = test/integration/pkcs-find-objects.int.c test/integration/test.c

test_integration_pkcs_get_mechanism_int_CFLAGS  = $(AM_CFLAGS) $(TESTS_CFLAGS)
test_integration_pkcs_get_mechanism_int_LDADD   = $(TESTS_LDADD)  $(SQLITE3_LIBS)
test_integration_pkcs_get_mechanism_int_SOURCES = test/integration/pkcs-get-mechanism.int.c test/integration/test.c

test_integration_pkcs_get_attribute_value_int_CFLAGS  = $(AM_CFLAGS) $(TESTS_CFLAGS)
test_integration_pkcs_get_attribute_value_int_LDADD   = $(TESTS_LDADD)  $(SQLITE3_LIBS)
test_integration_pkcs_get_attribute_value_int_SOURCES = test/integration/pkcs-get-attribute-value.int.c test/integration/test.c

test_integration_pkcs_login_logout_int_CFLAGS  = $(AM_CFLAGS) $(TESTS_CFLAGS)
test_integration_pkcs_login_logout_int_LDADD   = $(TESTS_LDADD)  $(SQLITE3_LIBS)
test_integration_pkcs_login_logout_int_SOURCES = test/integration/pkcs-login-logout.int.c test/integration/test.c

test_integration_pkcs_sign_verify_int_CFLAGS  = $(AM_CFLAGS) $(TESTS_CFLAGS)
test_integration_pkcs_sign_verify_int_LDADD   = $(TESTS_LDADD)  $(SQLITE3_LIBS)
test_integration_pkcs_sign_verify_int_SOURCES = test/integration/pkcs-sign-verify.int.c test/integration/test.c

test_integration_pkcs_initialize_finalize_int_CFLAGS  = $(AM_CFLAGS) $(TESTS_CFLAGS)
test_integration_pkcs_initialize_finalize_int_LDADD   = $(TESTS_LDADD)  $(SQLITE3_LIBS)
test_integration_pkcs_initialize_finalize_int_SOURCES = test/integration/pkcs-initialize-finalize.int.c test/integration/test.c

test_integration_pkcs_misc_int_CFLAGS  = $(AM_CFLAGS) $(TESTS_CFLAGS)
test_integration_pkcs_misc_int_LDADD   = $(TESTS_LDADD)  $(SQLITE3_LIBS)
test_integration_pkcs_misc_int_SOURCES = test/integration/pkcs-misc.int.c test/integration/test.c

test_integration_pkcs_crypt_int_CFLAGS  = $(AM_CFLAGS) $(TESTS_CFLAGS)
test_integration_pkcs_crypt_int_LDADD   = $(TESTS_LDADD)  $(SQLITE3_LIBS)
test_integration_pkcs_crypt_int_SOURCES = test/integration/pkcs-crypt.int.c test/integration/test.c

test_integration_pkcs_keygen_int_CFLAGS  = $(AM_CFLAGS) $(TESTS_CFLAGS)
test_integration_pkcs_keygen_int_LDADD   = $(TESTS_LDADD)  $(SQLITE3_LIBS)
test_integration_pkcs_keygen_int_SOURCES = test/integration/pkcs-keygen.int.c test/integration/test.c

test_integration_pkcs_session_state_int_CFLAGS  = $(AM_CFLAGS) $(TESTS_CFLAGS)
test_integration_pkcs_session_state_int_LDADD   = $(TESTS_LDADD)  $(SQLITE3_LIBS)
test_integration_pkcs_session_state_int_SOURCES = test/integration/pkcs-session-state.c test/integration/test.c

endif
# END INTEGRATION

### Unit Tests ###
if UNIT

#
# Due to limitations in how cmocka works, we build a seperate library here so we
# can have a PKCS11 shared object with undefined calls into the rest of the lib
# code. This allows us to deploy a single library, but be able to dissect it for
# testing.
#
### PKCS#11 TEST Library Definitions ###
libtpm2_test_internal = src/libtpm2_test_internal.la
src_libtpm2_test_internal_la_LIBADD = $(AM_LDFLAGS)
src_libtpm2_test_internal_la_SOURCES = $(LIB_PKCS11_INTERNAL_LIB_SRC)

libtpm2_test_pkcs11 = src/libtpm2_test_pkcs11.la
src_libtpm2_test_pkcs11_la_LIBADD =  $(AM_LDFLAGS) $(libtpm2_test_internal)
src_libtpm2_test_pkcs11_la_SOURCES = $(LIB_PKCS11_SRC)

noinst_LTLIBRARIES = $(libtpm2_test_pkcs11) $(libtpm2_test_internal)

## End of test libraries, start tests ##

check_PROGRAMS += \
    test/unit/test_twist\
    test/unit/test_log \
    test/unit/test_parser \
    test/unit/test_attr

test_unit_test_twist_CFLAGS    = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_twist_LDADD     = $(CMOCKA_LIBS) $(libtpm2_test_internal) $(libtpm2_test_pkcs11)
test_unit_test_log_CFLAGS      = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_log_LDADD       = $(CMOCKA_LIBS) $(libtpm2_test_internal) $(libtpm2_test_pkcs11)
test_unit_test_parser_CFLAGS   = $(AM_CFLAGS) $(YAML_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_parser_LDADD    = $(CMOCKA_LIBS) $(YAML_LIBS) $(libtpm2_test_internal) $(libtpm2_test_pkcs11)
test_unit_test_attr_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_attr_LDADD    = $(CMOCKA_LIBS) $(libtpm2_test_internal) $(libtpm2_test_pkcs11)

endif
# END UNIT

TESTS= \
    $(check_PROGRAMS) \
    $(check_SCRIPTS)

### Helper Functions ###
define make_parent_dir
    if [ ! -d $(dir $1) ]; then mkdir -p $(dir $1); fi
endef
