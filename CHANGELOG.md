# Changelog

### 1.3.2-RC0 - 2020-08-04
  * Fix C_InitToken, ensure no embedded nul byte.
  * Fix free of mutex being held in C_InitToken failures: #573
  * Fix C_Login CKU_USER login attempt before pin is setup: #563
  * Fix C_InitToken double init issues #577

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
    
### 1.0.1 - 2020-1-6

  * stop linking against libdl
  * add missing test integration scripts to dist tarball.

## 1.0 - 2019-12-28

  * Initial Release
