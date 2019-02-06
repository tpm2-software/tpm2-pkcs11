# tpm2-pkcs11

[![Build Status](https://travis-ci.org/tpm2-software/tpm2-pkcs11.svg?branch=master)](https://travis-ci.org/tpm2-software/tpm2-pkcs11)
[![Coverage Status](https://coveralls.io/repos/github/tpm2-software/tpm2-pkcs11/badge.svg?branch=master)](https://coveralls.io/github/tpm2-software/tpm2-pkcs11?branch=master)

**This is currently being developed and is not production ready, patches welcome**

PKCS #11 is a Public-Key Cryptography Standard that defines a standard method to
access cryptographic services from tokens/ devices such as hardware security
modules (HSM), smart cards, etc. In this project we intend to use a TPM2 device
as the cryptographic token.

# Navigation

* [Building](BUILDING.md) - How to get it to build
* [Initializing](INITIALIZING.md) - How to configure it

# Example Usages
* [SSH](SSH.md) - How to configure and use it with SSH.
* [P11](P11.md) - How to configure and use it with various P11 components.
* [PKCS11-TOOL](PKCS11_TOOL.md) - How to configure and use it with OpenSC's pkcs11-tool.