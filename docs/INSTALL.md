# Installing

Instructions on building installing from source.

# Dependencies
Step one is to satisfy the following dependencies:

## C Dependencies
  - LibYAML
  - libtpm2-esapi
  - libtpm2-mu

## Python Dependencies
  - cryptography
  - pyyaml
  - pyasn1
  - pyasn1_modules

## Testing Dependencies
  - cmocka
  
After satisfying the dependencies one invoke the regular autotools build process:
```bash
./bootstrap
./configure
make
make install
```
