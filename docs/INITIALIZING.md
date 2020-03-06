# Initialization

In order to use the tpm2-pkcs11 library, you need to initialize a store. The store contains
metadata for the library on what tokens and subordinate objects to expose.

PKCS#11 was designed to work with smart cards, and has a few concepts that are pivitol to understanding how to use it.
The first concept is a *slot*. The slot, would be the physical smart card reader slot you would insert the smart card into.
Then, for each slot, you can have a smart card inserted or not. So you could have N reader slots with X smart cards inserted
where X <= N. For each smart card in X, it provides a *token*. The token is the actual device the PKCS#11 calls operate on.
The token itself can be in one of two states, *initialized* or *not initialized*.

The tpm2-pkcs11 library will always provide at least one *not-initialized* token that can be used to initialize the token.
You can initialize the token with an external client via the PKCS11 interface call C_Initialize, like
[pkcs11-tool](https://linux.die.net/man/1/pkcs11-tool) or you can use the provided
[tpm2_ptool](https://github.com/tpm2-software/tpm2-pkcs11/tree/master/tools) to perform an initialization through a
side-channel mechanism.

Note, that most initializations can be done through C_Initialize() calls via tools like pkcs11-tool. However, more complex
initializations are better handled throught tpm2_ptool.

The tpm2-pkcs11 library requires some metadata to operate correctly. It stores this metadata in what is known as a *store*.
The store is automatically searched for in the following locations:

1. env variable TPM2_PKCS11_STORE
  This is optional, and if not set is skipped. However, if you want a store in a custom path, this is how you set it.
  a. Example: `export TPM2_PKCS11_STORE='path/to/where/i/want/the/store'`
2. /etc/tpm2_pkcs11 or whatever was configured at build time with --with-storedir.
3. Users $HOME/.tpm2_pkcs11 directory.
4. Current Working Directory.

If no existing store is found, it will:
1. If env variable TPM2_PKCS11_STORE is set, attempt to use that path directory or create it if it doesn't exist.
   On failure, it continues to number 2.
2. /etc/tpm2_pkcs11 or whatever was configured at build time with --with-storedir.
3. if $HOME is set, attempts to use that path directory. If the directory doesn't exist it will be created.
   This almost always exceeds for most users, so this ends up as the default store most of the time. If it fails,
   continues on to number 4.
4. Use the Current Working Directory.

To facilitate creating this store, a tool called [tpm2-ptool](../tools/tpm2_ptool.py) exists.

The store itself defaults to `$HOME/.tpm2_pkcs11` unless specified via the environment variable
`TPM2_PKCS11_STORE`.

**IMPORTANT**
* For all the illustrations below, we create a store under `~/tmp`.
* We assume some working TPM connection. Under the hood the `tpm2_ptool` command calls `tpm2-tools`
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
mkdir ~/tmp
tpm2_ptool.py init --path=~/tmp
action: Created
id: 1
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
```

To create N tokens under a given `--pid` or primary object id, just run the command N times. Thus it is possible to have
*S* number of slots, with *T* number of tokens under each slot.

## Step 3 - Creating Objects Under a Token

To create objects, like keys, under a token, the `tpm2-ptool` command-let `add` is invoked. You can direct which token
to create the object under by using the `--label` option.

**Example**:
```sh
action: add
private:
  CKA_ID: '62663630653733656336316363386535'
```

This command can be run N times to create N objects within a token. Tokens can have an arbitrary number of tokens. The tool
outputs to *stdout* the objects CKA_ID hex encoded.

**Note**: To view all the types of objects one can create run command:
```sh
tpm2_ptool.py addkey --help
```
And review the enumerated options allowed for `--algorithm`.
