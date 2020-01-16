# DB Upgrade

The tools and libraries for tpm2-pkcs11 are designed in a way where they can automatically detect
and upgrade DBs. This document describes the internals of this functionality and what to do when
things go wrong.

## Design Summary

The DB contains the table "schema", which contains a coloumn "schema_version" that contains the
current schema version of that DB. The C library itself is statically set at build time with the
maximum DB version that it knows how to read. The C library and Python tools are both equiped to
upgrade the DB version from schema_version 1 to the current max version they know of.

When the DB is accessed, a cooperative file lock is taken to prevent races on DB schema_version
checks and upgrading the DB, thus only one process accessing the TPM2_PKCS11_STORE will perform
the upgrade if needed. This lock is held during the schema_version check and upgrade period only,
after this the normal sqlite3 read/write lock semantics are in effect.

During the upgrade period, a backup copy of the db is created in $TPM2_PKCS11_STORE with the ".bak"
suffix.


If the DB version mismatch is detected, one of two things can happen:

1. The tool or library is built for an older schema_version than the current TPM2_PKCS11_STORE
   schema_version, the tool or library will cause an error.

2. The tool or library is built for a newer schema_version than the current TPM2_PKCS11_STORE
   schema_version, the tool or library will cause a DB upgrade to occur.

To rectify the first case, simply upgrade your tools to a version >= to the DB schema_version
of the TPM2_PKCS11_STORE.

To rectify the second case, nothing should be required of the user, unless an unforseen error
occurs.

## Error Recovery on DB Upgrade

The biggest thing to remember if you encounter an error, is that a file with ".bak" will exist
in the $TPM2_PKCS11_STORE directory. That is your original, unmodified db. The original db,
slightly modified will exist, allowing you to manually correct it, or roll back to the original
db via a simple mv command of the ".bak" suffixed file to the ".sqlite3" suffixed file.

```bash
mv $TPM2_PKCS11_STORE/tpm2_pkcs11.sqlite3.bak $TPM2_PKCS11_STORE/tpm2_pkcs11.sqlite3
```

If you you roll back the db, it would be best to also roll back the tpm2-pkcs11 version to the
last version successfully used.
