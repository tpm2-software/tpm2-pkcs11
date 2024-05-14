# The key_import Tool

The `key_import` tool in this project is a C program that serves as an example for importing TPM keys into a tpm2-pkcs11 token. The key import mechanism uses PKCS #11 vendor-specific attributes and works with both FAPI and ESYSDB backends.

Supported modes:
- Key to be imported: Ordinary TPM key with or without an auth value.
- Key Import Formats: Keys can be imported as persistent handle or TSS key objects obtained from `tpm2 create` (`TPM2B_PUBLIC` and `TPM2B_PRIVATE` blobs).
    - If key objects are used, the associated parent key must be the same primary key used for token initialization. Parent keys with or without an auth value are supported.

The PKCS #11 vendor-specific attributes used during the key import procedure are:
- Persistent Handle: `CKA_TPM2_PERSISTENT_HANDLE` and `CKA_TPM2_OBJAUTH`.
- TSS Key Objects: `CKA_TPM2_PUB_BLOB`, `CKA_TPM2_PRIV_BLOB`, and `CKA_TPM2_OBJAUTH`.

For more details, please refer to `test/integration/key_import-link.sh.nosetup`.
