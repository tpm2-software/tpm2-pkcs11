# tpm2-pkcs11

[![Build Status](https://travis-ci.com/tpm2-software/tpm2-pkcs11.svg?branch=master)](https://travis-ci.com/tpm2-software/tpm2-pkcs11)
[![Coverage Status](https://codecov.io/gh/tpm2-software/tpm2-pkcs11/branch/master/graph/badge.svg)](https://codecov.io/gh/tpm2-software/tpm2-pkcs11)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/tpm2-software/tpm2-pkcs11.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-pkcs11/context:cpp)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/tpm2-software/tpm2-pkcs11.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-pkcs11/context:python)
[![Coverity Scan](src="https://img.shields.io/coverity/scan/16909.svg")](https://scan.coverity.com/projects/tpm2-pkcs11)

PKCS #11 is a Public-Key Cryptography Standard that defines a standard method to
access cryptographic services from tokens/ devices such as hardware security
modules (HSM), smart cards, etc. In this project we intend to use a TPM2 device
as the cryptographic token.

# Getting Started

* [Building](/docs/BUILDING.md) - How to get it to build
* [Initializing](/docs/INITIALIZING.md) - How to configure it
* [Installing](/docs/INSTALL.md) - How to install it

# Example Usages
* [SSH](/docs/SSH.md) - How to configure and use it with SSH.
* [P11](/docs/P11.md) - How to configure and use it with various P11 components.
* [PKCS11-TOOL](/docs/PKCS11_TOOL.md) - How to configure and use it with OpenSC's pkcs11-tool.
* [EAP-TLS](/docs/EAP-TLS.md) - How to configure and use it for Wi-Fi authentication using EAP-TLS.
* [INTEROPERABILITY](/docs/INTEROPERABILITY.md) - Configuration details for interoperability with
  [tss2-engine](https://github.com/tpm2-software/tpm2-tss-engine) and
  [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) projects. Note, the *tpm2-tools* interoperability
  could cover other projects that use raw *marshalled* TPM 2.0 structures.

# Advanced Knowledge
* [Architecture](/docs/ARCHITECTURE.md) - Internal Overview
* [DB Upgrades](/docs/DB_UPGRADE.md) - What happens on a DB Version Upgrade
* [Release Process](/docs/RELEASE.md) - How releases are conducted
