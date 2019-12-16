# Installing

Instructions on building installing from source.

# Dependencies
Step one is to satisfy the following dependencies:

## C Dependencies
  - LibYAML
  - libtpm2-esapi
  - libtpm2-mu
  - cmocka (optional for testing)

## Python Dependencies
  - cryptography
  - pyyaml
  - pyasn1
  - pyasn1_modules

## Executable Dependencies
  - python2 or python3
  - tpm2-tools >= 4.0
  - bash (optional for testing)
  - pkcs11-tool (optional for testing)
  - openssl (optional for testing)
  - libp11 (optional for testing)

After satisfying the dependencies one invoke the regular autotools build process:
```bash
./bootstrap
./configure
make
make install
```
