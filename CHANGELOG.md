# Changelog

### next - next
  * C_InitToken: Fix improper SRK handle of 0x81000000, it should be 0x81000001.
  * Fix a leak in in tpm.c of an EVP_PKEY object.
  * C_GenerateKeyPair: was not adding PSS signatures as supported by RSA objects, add it.
  * Fix PSS signatures. Non-FIPS mode TPMs produce PSS signatures with a
    max salt len that poses interoperability issues with verifying clients,
    notably TLS in OpenSSL.
  * Fix Java PKCS11 Provider Signature Verification: #401
  * VerifyRecover support, known working with Public Key RSA objects and
    mechanism CKM_RSA_PKCS.
  * db: Modfiy search and create behavior. See
    [docs/INITIALIZING.md](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/INITIALIZING.md)
    for details.
  * Fix printf(3) format specifier errors.
  * ci: increase CI coverage to: Fedora 30, Ubuntu 16.04, Ubuntu 18.04.
  * configure: check for Python version >= 3.7 and pass to Automake. No
    need to set PYTHON\_INTERPRETER anymore.
  * Fix segfault/memory corruption bugs in C_Destroy().
  * Fix segfault when no user pin is provisioned.
  * Support C_SetAttributeValue.
  * Support for selectable backend using TPM2_PKCS11_BACKEND=esysdb being current version.
  * Support for backend fapi that uses the tss2-fapi keystore instead of an sqlite db.
    - This is auto-detected based on tss2-fapi being installed at configure time, and can be controlled
      via --enable/disable-fapi.
  * C_CreateObject: Support for CKO_DATA objects only with CKA_PRIVATE set to CK_TRUE. Token
    defaults to CK_TRUE.
  * Fix: src/lib/ssl_util.c:555:54: error: passing argument 3 of ‘EVP_PKEY_verify_recover’ from incompatible pointer type
  * Added tpm2_ptool link commandlet for linking existing tpm2 objects into a compatible token. For details see
    [this](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/INTEROPERABILITY.md) document.

    Supported tpm2 objects are:
      - serialized TPM2B_PUBLIC and TPM2B_PRIVATE data structures, as produced by
      [tpm2_create](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_create.1.md) -u and -r outputs
      respectively.
      - PEM encoded keys produced by
      [tpm2tss-genkey](https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md)

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
  * Fix unitialized variable warnings #416
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
