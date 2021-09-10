# Changelog

### 1.7.0-rc1 - 2021-09-10
  * DB Schema Change from 5 to 7.
    - **Backup your DB before upgrading**
  * Fixed compilation issues with GCC11.
  * Fixed errors on releases due to newer compilers from failing by only adding `-Werror` for non-release builds.
  * Fixed error message when the DB is too new in tpm2\_ptool.
  * Added support for tpm2\_ptool import with ssh-keygen format keys. Note: Requires cryptography >= 3.0.
  * Changed default long level from error to warning.
  * Added better error message for FAPI backend errors along with [docs/FAPI.md](docs/FAPI.md) document.
  * Changed `tpm2_ptool` make `--algorithm` optional.
  * Fixed error message of wrong attribute name on expected attribute check to be false.
  * Added support for ECDSA 256, 384 and 512.
  * Fixed a bug in the Python code DB upgrade path from 4 to 5 where it didn't add AES mode CTR to
    CKA\_ALLOWED\_MECHANISMS.
  * Added tpm2\_ptool support for ECC key size 192.
  * Added support passwordless login for tokens, ie not setting CKF\_LOGIN\_REQUIRED.
  * Fixed Running integration tests when Java version has the `-ea`, like on Debian 11 and OpenJDK 17.
  * Added support for HMAC keys using tpm2\_ptool and the C\_Sign and C\_Verify interfaces.
    The following interfaces in ptool have support:
      - addkey: previous working versions of tpm2-tools will support this.
      - link: previous working versions of tpm2-tools will support this.
      - import: requires tpm2-tools 5.2+ for support.
  * Fixed leaking of temp file descriptors in tpm2\_ptool.
  * Fixed wrong free in tpm code, should use Esys\_Free.
  * Fixed a space formatting issue in tpm2\_ptool verify.
  * Fixed leaked file descriptor in tpm2\_ptool.
  * Fixed a few suspicious sizeof usages in str\_padded\_copy
  * Fixed a memory leak of the token list on a failure condition in initialization.

### 1.6.0 - 2021-05-03
  * Spelling and grammar fixes throughout the project.
  * tpm2_ptool: fix bug in verify commandlet where `--sopin` leads to local variable referenced before assignment. See #624.
  * Docs: add a document describing SSH Hostkey configuration using tpm2-pkcs11.
  * Support changes in tpm2-tss-engine using TPM2_RH_OWNER instead of 0.
    * Since upstream commit tpm2-software/tpm2-tss-engine@06f57a3.
  * Fix endian issue in test_db.
  * Fix tpm2_ptool error messages when exceptions are raised during execution of tpm2-tools commands.
  * Support CKA_DERIVE=true which will support the newest pkcs11-tool EC template.
  * Fix requirement of having ESYS >= 2.4, see #632 for details.
  * Fix docs/INITIALIZING.md reference to `--pobj-pin`, should be `--hierarchy-auth`.
  * Fix missing libyaml dependency in documentation.
  * Fix bug in DB update logic where errors in handlers were ignored.
  * Fix NPD bug when ESAPI and FAPI return 0 tokens.
  * Add support for over TPM sized AES buffers.
  * Add support for mechanism CKM_AES_CBC_PAD.
  * Add support for mechanism CKM_AES_CTR.
  * Add support for RSA 3072 (3k) keys.
  * Remove usage of function Esys_TR_GetTpmHandle. FAPI Backend will no longer depend on ESAPI 2.4 or
    greater.
  * Add **Experimental** RSA 4096 support. **Use at your own risk**.

### 1.5.0 - 2020-11-16
  * C_Decrypt: Fix CKM_RSA_PKCS11 scheme not removing PKCS v1.5 block padding from returned plaintext.
  * C_Digest/C_DigestFinal: Fix Section 5.2 style returns.
  * C_OpenSession: fix valid session handles starting at 0, 0 is invalid per the spec.
  * C_OpenSession: fix handle issuance bug where handles could be exhausted at out of bounds.
  * Support swtpm in testing infrastructure.
  * Fix C_Encrypt/C_Decrypt interface not setting size when output buffer in NULL.
  * Fix warning ../configure: line 14383: ]: command not found
  * Fix CKM_RSA_PKCS_PSS mechanism.
  * C_GetMechanismList: Fix index 0 of the returned list being invalid.
  * C_GetMechanismInfo: Fix errors like ERROR: Unknown mechanism, got: 0xd.
  * Docs: use full paths from project root to help fix 404 errors.
  * tpm2_ptool init to attempt to persistent created primary object at 0x81000001 and fallback to
    first available address on failure.

### 1.4.0 - 2020-08-24
  * Fix superfluous error message when falling back from TPM2\_EncryptDecrypt2 interface.
  * Support importing EC keys via tpm2\_ptool import.
  * C\_InitToken: Fix improper SRK handle of 0x81000000, it should be 0x81000001.
  * Fix a leak in in tpm.c of an EVP\_PKEY object.
  * C\_GenerateKeyPair: was not adding PSS signatures as supported by RSA objects, add it.
  * Fix PSS signatures. Non-FIPS mode TPMs produce PSS signatures with a
    max salt len that poses interoperability issues with verifying clients,
    notably TLS in OpenSSL.
  * Fix Java PKCS11 Provider Signature Verification: #401
  * VerifyRecover support, known working with Public Key RSA objects and
    mechanism CKM_RSA_PKCS.
  * db: Modify search and create behavior. See
    [docs/INITIALIZING.md](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/INITIALIZING.md)
    for details.
  * Fix printf(3) format specifier errors.
  * ci: increase CI coverage to: Fedora 30, Ubuntu 16.04, Ubuntu 18.04.
  * configure: check for Python version >= 3.7 and pass to Automake. No
    need to set PYTHON\_INTERPRETER anymore.
  * Fix segfault/memory corruption bugs in C\_Destroy().
  * Fix segfault when no user pin is provisioned.
  * Support C\_SetAttributeValue.
  * Support for selectable backend using TPM2\_PKCS11\_BACKEND=esysdb being current version.
  * Support for backend fapi that uses the tss2-fapi keystore instead of an sqlite db.
    - This is auto-detected based on tss2-fapi being installed at configure time, and can be controlled
      via --enable/disable-fapi.
  * C\_CreateObject: Support for CKO\_DATA objects only with CKA\_PRIVATE set to CK\_TRUE. Token
    defaults to CK_TRUE.
  * Fix: src/lib/ssl\_util.c:555:54: error: passing argument 3 of ‘EVP\_PKEY\_verify\_recover’ from incompatible pointer type
  * Added tpm2\_ptool link commandlet for linking existing tpm2 objects into a compatible token. For details see
    [this](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/INTEROPERABILITY.md) document.

    Supported tpm2 objects are:
      - serialized TPM2B_PUBLIC and TPM2B_PRIVATE data structures, as produced by
      [tpm2_create](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_create.1.md) -u and -r outputs
      respectively.
      - PEM encoded keys produced by
      [tpm2tss-genkey](https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md)

### 1.3.2 - 2020-08-10
  * Fix C\_InitToken, ensure no embedded nul byte.
  * Fix free of mutex being held in C\_InitToken failures: #573
  * Fix C\_Login CKU\_USER login attempt before pin is setup: #563
  * Fix C\_InitToken double init issues #577

### 1.3.1 - 2020-07-27
  * Fix double free.

### 1.3.0 - 2020-07-7
  * C\_CreateObject: Support for CKO\_DATA objects only with CKA\_PRIVATE set to CK\_TRUE.
    Token defaults to CK\_TRUE.
  * Fix Tests against simulator that support RSA 3072 keys

### 1.2.0 - 2020-03-30
  * Fix PSS signatures. Non-FIPS mode TPMs produce PSS signatures with a
    max salt len that poses interoperability issues with verifying clients,
    notably TLS in OpenSSL.
  * Handle Esys\_LoadExternal() API change where the hierarchy handle switches to an
    ESYS\_TR rather than a TPM2\_RH\_.

### 1.1.1 - 2020-06-19

  * test/pkcs-get-mechanism: allow a maximum key size of 3072 bits.

### 1.1.0 - 2020-03-09
  * DB Schema Change from 1 to 3.
    - **Backup your DB before upgrading**
  * Support C_InitToken interface.
  * Add Java PKCS11 Keystore support for RSA/ECB/RSAPKCS1.5
    via public encrypt and private decrypt.
  * Decouple handles from db primary keys. Key handles are
    no longer stable between runs.
  * tpm2_ptool objmod:
    - Support adding an attribute.
    - Fix bug in variable name vtype over type.
  * C_Sign: support mechanism CKM_RSA_X_509.
  * C_GetTokenInfo: add missing mechanism CKM_SHA512_RSA_PKCS.
  * Fix store search logic to fail when TPM2_PKCS11_STORE cannot be accessed.
  * Fix potential double free in token_free() logic.
  * Fix -Werror=format-truncation with GCC >= 7 #415
  * Fix uninitialized variable warnings #416
  * test: use release tarball vs source code.
  * build: clean leftover file in make clean.
  * release: add missing tests to tarball no matter configure options.
  * test: fix invalid flags on CKM_SHA512_RSA_PKCS causing test failures.
  * Switch OASIS pkcs11 headers to FSF Unlimited License Headers.

### 1.0.3 - 2020-06-15

  * test/pkcs-get-mechanism: allow a maximum key size of 3072 bits.

### 1.0.2 - 2020-06-09

  * Fix build issue about unused variable config. Notably fixes gcc10 builds.

### 1.0.1 - 2020-1-6

  * stop linking against libdl
  * add missing test integration scripts to dist tarball.

## 1.0 - 2019-12-28

  * Initial Release
