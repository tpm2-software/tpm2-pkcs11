# tpm2-pkcs11 architecture design

This document aims to describe the fundamental design of the TPM2.0 PKCS11 internals.

## Store

In order to fullfill the PKCS11 interface, some additional metadata needs to be store to disk.
The data is stored in the "store", which is controllable via:
- ENV Variable TPM2_PKCS11_STORE
- Search Operation of:
  - $HOME/tpm2_pkcs11
  - /etc/tpm2-pkcs11

The store contains all the metdata required, and currently is stored in sqlite3 database.

## Primary Key Root

Internally, all objects are stored under a **persistent** primary key in the owner hiearchy.
The choice of a persistent object was done to prevent requirements of knowing the owner
hierarchy auth to use the pkcs11 token. This authorization value is usually owned by
an IT orginization in enterprise environments. The auth value for this primary key
is stored in the store on disk and is only protected with filesystem access controls. Thus,
use of the primary key should be considered a given and in most cases the auth value is
empty or a known value. The primary key handle is stored as a serialized ESYS_TR in the
store and is used for encrypted and bound sessions with the TPM.

## Login Flow
For each token in the store, a token maintains 2 objects under the primary key. One for
each of the PKCS11 users the SO and USER. The authorization value for these objects is
the so or user pin respectively, mixed with a salt via sha256. This auth value is used
to unseal an aes256 wrapping key. The wrapping key is used to encrypt all object auth
values in the token.

## Token Objects
The actual keys and certificates that the token exposes for cryptographic operations.
These keys all have an auth value that is wrapped with the token wide wrapping key.

## Expanding the Auth Model
Currently, the wrapping model should make it easy to bring in existing keys into the model
if needed. Most keys just use a simple password. However, in the fuure, we are looking
to add policy support for internally created keys, see:
  - https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/tpm2-pkcs11_object_auth_model.md


