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