# Changelog

### 1.1.0-RC1 - next
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
