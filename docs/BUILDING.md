# Building

Instructions for building and configuring tpm2-pkcs11.

## Step 1 - Satisfy Dependencies

The project depends on:

1. [Automake](https://www.gnu.org/software/automake)
2. [Make](https://www.gnu.org/software/make/)
3. A C compiler. Known working compilers are:
    1. [gcc](https://www.gnu.org/software/gcc/)
    2. [clang](https://clang.llvm.org/)
4. [SQLite3](https://www.sqlite.org/)
5. [tpm2-tss](https://github.com/tpm2-software/tpm2-tss): **Requires >= 2.0, recomended >= 2.3.0**
6. A Resource Manager, one of:
  - [tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd): **Requires version >= 2.1.0**
  - Linux kernel version >= 4.12 for /dev/tpmrm[0-9]+ nodes.
    - Note that the device TCTI must be configured for this.
7. [openssl](https://www.openssl.org/): **Requires version >= 1.0.2g**
8. [autoconf-archive](https://github.com/autoconf-archive/autoconf-archive): **Tested with release v2018.03.13**
     Others may not work, some distros package versions too old. Either install or just copy the contents of the
     autoconf-archive's m4 directory to the m4 subdirectory of the tpm2-pkcs11 project. If the m4 folder is not
     present, simply create it with mkdir.

### Optional Dependencies for tpm2_ptool:
1. [tpm2-tools](https://github.com/tpm2-software/tpm2-tools): **Requires version >= 4.0.1**
2. [Python](https://www.python.org/): **Requires version >= 3.7**

### Notes:
The tpm2-tss and tpm2-tools projects must be obtained via source. Packaged versions existing
in known package managers are likely too old.

### Optional Dependencies for Enabling Testing
1. [CMocka](https://cmocka.org/)
2. [swtpm](https://github.com/stefanberger/swtpm) or
   [tpm_server](https://sourceforge.net/projects/ibmswtpm2/) TPM 2.0 simulator
3. [tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd)
4. Dependencies for [tpm2-ptool](# Optional Dependencies for tpm2_ptool)

## Step 2 - Bootstrapping

Run the `bootstrap` command.

```sh
$ ./bootstrap
```

## Step 3 - Configuring

For people wanting to just build the library, the command:
```sh
./configure
```

Should be sufficient. However, the following configure options will be useful for those wishing to do more, like
testing, or those running into issues to work around. The following are known configure options that can be added
that *are outside of normal autoconf/automake options*, which are documented [here](https://sourceware.org/autobook/autobook/autobook_14.html).

### Configure Options
1. `--enable-unit` - Enables the unit tests when running `make check`
2. `--enable-integration` - Enables the integration tests when running `make check`
  * Requires the following items to be found on PATH:
    * [tpm2-ptool](../tools/tpm2_ptool.py)
    * [tpm2-tools](#step-1---satisfy-dependencies)
  * Example:
    ```sh
    export PATH="/home/wcrobert/workspace/tpm2-tools/tools:/home/wcrobert/workspace/tpm2-pkcs11/tools:$HOME/workspace/ibmtpm974/src:$PATH"
    ```
    **Normally** only tpm2-tools, swtpm/tpm_server and tpm2-ptool need to be added to `PATH`. Most other things, like CMocka and ss, are already
    installed and thus on `PATH`. Your results will very based on what you build from source and/or install in non-standard locations.
3. `--disable-hardening` - Compiler flag hardening options, this is enabled by default. Disabling hardening is **NOT RECOMMENDED FOR PRODUCTION BUILDS**,
      however, is often useful when adding in compiler flags for testing via `CFLAGS`. For example, one would need to disable this if configuring
      [clang](#step-1---satisfy-dependencies) with [ASAN](https://clang.llvm.org/docs/AddressSanitizer.html).
4. `--disable-esapi-session-manage-flags` - Disables ESAPI session flag management and causes the pkcs11 library to do it. This is autodetected and
      overiding it should only be done in specific coditions
      This can also be configured at run time by setting the environment variable `TPM2_PKCS11_ESAPI_MANAGE_FLAGS` to any value.
      **These options may go away in future versions**.

## Step 4 - Building

The next step after [configuring](#step-3---configuring) is to compile the source code.

## Step 5 - Testing

To enable testing, run `make check`.

**Note:** If make check runs 0 tests, you likely need the configure options `--enable-unit` and `--enable-integration`. See [Configure Options](#configure-options)
for more details.
