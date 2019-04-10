# pkcs11 tool Configuration

Below, will be examples and discussion on how to use tpm2-pkcs11 with pkcs11-tool.

pkcs11-tool is part of OpenSC and can be installed on ubuntu by issuing the command:
```sh
sudo apt-get install opensc
```

# Step 1 - Initializing a Store

Start by reading the document on initialization [here](INITIALIZING.md). Only brief commands
will be provided here, so a a basic understanding of the initialization process is paramount.

We start by creating a tpm2-pkcs11 *store* and set up an empty token.

```sh
tpm2_ptool.py init --pobj-pin=mypobjpin --path=~/tmp

tpm2_ptool.py addtoken --pid=1 --pobj-pin=mypobjpin --sopin=mysopin --userpin=myuserpin --label=label --path ~/tmp

```

# Step 2 - Exporting the Store

Since we didn't use the default store location by setting `--path` in the `tpm2-ptool` tool, we must export the
store so the library can find it. We do this via:
```sh
export TPM2_PKCS11_STORE=$HOME/tmp
```

**Note**: The tpm2-pkcs11.so library *WILL NOT EXPAND `~`* and thus you have to use something the shell will expand,
like `$HOME`.

# Examples of pkcs11-tool

This will not be exhaustive, as we don't wish to duplicate opensc's documentation of their tool. But we will show case
a few commands for users wishing to use this tool with tpm2-pkcs11 project.

**For each example below, --module is the path to the pkcs11.so library and will be machine dependent. Note that default builds
will provide the library under src/.libs**

## Changing USER pin

How to change the user pin from *myuserpin* to *mynewpin*

```sh
pkcs11-tool --module ./src/.libs/libtpm2_pkcs11.so --label="label" --login --pin myuserpin --change-pin --new-pin mynewpin
Using slot 0 with a present token (0x1)
PIN successfully changed
```
You can see [Checking USER pin](#checking-user-pin) for example of checking the pin.

## Checking USER pin

How to check that the pin is valid. The pin value shown is based off of section [Changing USER pin](#changing-user-pin)

```sh
pkcs11-tool --module ./src/.libs/libtpm2_pkcs11.so --label="label" --test --pin mynewpin
```

## Initializing USER pin

How to reset or initialize the user pin given the so pin.
```sh
pkcs11-tool --module ./src/.libs/libtpm2_pkcs11.so --label="label" --init-pin --so-pin mysopin --pin mynewpin
```

## Generating Random Data

The below example will generate 4 bytes of random data and assumes the pin has been changed as in section
[Checking USER pin](#checking-user-pin) for example of checking the pin.

```sh
$ pkcs11-tool --module ./src/.libs/libtpm2_pkcs11.so --label="label" --pin mynewpin --generate-random 4 | xxd
Using slot 0 with a present token (0x1)
00000000: 2e50 bc47                                .P.G
```

## Listing Objects

To list objects, we simply use the `--list-objects` option:
```
pkcs11-tool --module ./src/.libs/libtpm2_pkcs11.so --list-objects
Private Key Object; EC
  label:      p11-templ-key-label-ecc
  ID:         7031312d74656d706c2d6b65792d69642d65636300
  Usage:      sign
Public Key Object; EC  EC_POINT 256 bits
  EC_POINT:   04410452526c163439c3c5e5a943466a606439fbc7284eafd12221c4473ecb2fba3c586816d54f9ff108489877c5cfa857ba05cfba33dfe3e9b739107f672f787838d6
  EC_PARAMS:  06082a8648ce3d030107
  label:      p11-templ-key-label-ecc
  ID:         7031312d74656d706c2d6b65792d69642d65636300
  Usage:      verify
...
```

**Note**: Your output will likely differ, but the tool should output a list of objects and some attributes.

## Creating Objects

Outside of using [tpm2_ptool.py](PKCS11_TOOL.md) to add objects, p11tool supports creating objects
through the PKCS#11 interface.

### Generating RSA Keypair

This will generate an RSA keypair using pkcs11-tool:
```
pkcs11-tool --module ./src/.libs/libtpm2_pkcs11.so --label="label" --login --pin=myuserpin --keypairgen
Using slot 0 with a present token (0x1)
Key pair generated:
Private Key Object; RSA
  label:      label
  ID:         3332
  Usage:      none
Public Key Object; RSA 2048 bits
  label:      label
  ID:         3333
  Usage:      none
```

### Generating ECC Keypair

This will generate an EC keypair using pkcs11-tool:
```
pkcs11-tool --module ./src/.libs/libtpm2_pkcs11.so --label="my-ecc-keypair" --login --pin=myuserpin --keypairgen --usage-sign --key-type EC:prime256v1
Using slot 0 with a present token (0x1)
Key pair generated:
Private Key Object; EC
  label:      my-ecc-keypair
  ID:         3436
  Usage:      sign
Public Key Object; EC  EC_POINT 256 bits
  EC_POINT:   04410436e7d2c84725234ec8d4b14bc31a50d382eb578cbc7315ae95561875314eb5a22a390bbfabef6269a35a18b1d95b2abc553071c419c3e866db0c3f13c0288ac6
  EC_PARAMS:  06082a8648ce3d030107
  label:      my-ecc-keypair
  ID:         3437
  Usage:      verify
```

## Destroying Objects

Let's destroy the key we created in the *Generating ECC Keypair* segment, IDs 3436 and 3437 for both the private and public portions
respectively.

### Private Key
```
pkcs11-tool --module ./src/.libs/libtpm2_pkcs11.so --login --pin=myuserpin --delete-object --type=privkey --id 3436
Using slot 0 with a present token (0x1)
```
### Public Key
```
pkcs11-tool --module ./src/.libs/libtpm2_pkcs11.so --login --pin=myuserpin --delete-object --type=pubkey --id 3437
Using slot 0 with a present token (0x1)
```

**Note**: The tool doesn't have any output about successful delete, only when it fails. However, you can run the command
in *Listing Objects* to verify that it is indeed deleted.
