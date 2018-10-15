# Initialization

In order to use the tpm2-pkcs11 library, you need to initialize a store. The store contains
metadata for the library on what tokens and subordinate objects to expose.

To facilitate creating this store, a tool called [tpm2-ptool](../tools/tpm2_ptool.py) exists.

The store itself defaults to `$HOME/.tpm2_pkcs11` unless specified via the environment variable
`TPM2_PKCS11_STORE`.

**IMPORTANT**
* For all the illustrations below, we create a store under `~/tmp`.
* We assume some working TPM connection. Under the hood the `tpm2-ptool` command calls `tpm2-tools`
  binaries. Thus configuring the `TCTI` is important. The easiest way to do this for testing is
  to use the IBM TPM Simulator and tpm2-abrmd as documented in
  [dependencies](BUILDING.md#step-1---satisfy-dependencies).

  Their is no requirement to use the simulator and abrmd, this is all configuration dependent.

## Example Setup
I use the simulator and tpm2-abrmd to set all of this up, like so:
```sh
tpm_server &
tpm2-abrmd --tcti=mssim &
```
See the respective projects for details on how to get them running. Note that `tpm2-abrmd` uses dbus,
and dbus configuration is required.

## Step 1 - Initializing a Store and Creating a Slot

Initializing a store creates a primary object under the owner hierarchy. Each primary object is mapped
to a slot, and multiple initializations can occur for generating more than one slot.

**Example**:
```sh
tpm2_ptool.py init --pobj-pin=mypobjpin --path=~/tmp
Created a primary object of id: 1
```

The output of the command to *stdout* is important. It describes the id of the primary object
that one can associate subsequent commands to. Again, to create N > 1 slots, just run this command
N times.

## Step 2 - Creating a Token

After creating a slot or slots, now one needs to create a token. This is accomplished with the `addtoken` command for `tpm2-ptool`,
using the primary object ID from [Step 1](#step-1---initializing-a-store-and-creating-a-slot). A token is created and a unique
name called a *label* is provided. The *label* is used in subsequent commands to reference the token.

**Example**:
```sh
tpm2_ptool.py addtoken --pid=1 --pobj-pin=mypobjpin --sopin=mysopin --userpin=myuserpin --label=label --path ~/tmp
Created token: label
```

To create N tokens under a given `--pid` or primary object id, just run the command N times. Thus it is possible to have
*S* number of slots, with *T* number of tokens under each slot.

## Step 3 - Creating Objects Under a Token

To create objects, like keys, under a token, the `tpm2-ptool` command-let `add` is invoked. You can direct which token
to create the object under by using the `--label` option.

**Example**:
```sh
tpm2_ptool.py addkey --algorithm=aes256 --label=label --userpin=myuserpin --path=~/tmp
Added key: 1
```

This command can be run N times to create N objects within a token. Tokens can have an arbitrary number of tokens. The tool
outputs to *stdout* the objects id. This is the object handle used later.

**Note**: To view all the types of objects one can create run command:
```sh
tpm2_ptool.py addkey --help
```
And review the enumerated options allowed for `--algorithm`.
