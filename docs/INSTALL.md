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
  - java (optional for testing)
  - junit (optional for testing)
  - hamcrest (optional for testing)

Details on building can be found in [BUILDING.md](BUILDING.md).

After satisfying the dependencies one invokes the regular autotools build process:
```bash
./bootstrap
./configure
make
make install
```
# Installing tpm2_ptool.py

To install tpm2_ptool.py, one can use various python installation methodologies as a setup.py file is provided.
Below are the common ways to install, but are not exhaustive.

First cd to the tools folder:
```bash
cd tools
```
Then perform one of:
1. ```bash
   # pip allows for easy user installs via option --user and thus doesn't require root
   pip install .
   ```
2. ```bash
   easy_install setup.py
   ```
