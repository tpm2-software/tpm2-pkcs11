# Integration with the Feature API (FAPI)

## Introduction

The feature API is a high level API for interacting with the TPM 2.0 device. It exposes a subset of the TPM operations as well as provided on disk key management,
automatic encrypted sessions and format conversions (PEM) where possible, among other things. The tpm2-pkcs11 project predates the Feature API, and the original
code was implemented using the Enhanced System API and for on disk storage of TPM protected keys, a sqlite3 database. Because of this

## Configuring

## Build Time

At the time the package is built, it will detect tss2-fapi library and automatically configure it's inclusion into the tpm2-pkcs11 library. One can *explicitly* configure this
with `--with-fapi=yes|no`.

## Run Time

If the tss2-fapi library is configured, it will dynamically attempt to locate and list tokens provisioned with tss2-fapi. Because FAPI might be in a bad state, this could cause
superfluous errors and warnings. The library is built to ignore these errors, like:
  - https://github.com/tpm2-software/tpm2-pkcs11/issues/655

You can take a few actions if you run into this issue:
1. Ignore them, and optionally disable FAPI error logging:
    - export TSS2\_LOG=fapi+NONE

2. Reconfigure the package with `--with-fapi=no`:
    - `./configure --with-fapi=no`

3. Provision FAPI using `tss2_provision`. See the tpm2-tools project for more information:
    - https://github.com/tpm2-software/tpm2-tools/blob/master/man/tss2\_provision.1.md


Additionally at run time, the token creation function, C\_InitToken, may be invoked to create a new token. By default, the token always using the original
mechanism of the SQLite3 database. This is to preserve backwards compatibility and behavior. To use the FAPI backend, one *must* set the environment
variable `TPM2_PKCS11_BACKEND` to `fapi`. If empty, or set to `esysdb` the SQLite3 backend is used. Any other value is an error.

