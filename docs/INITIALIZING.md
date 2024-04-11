# Initialization

In order to use the tpm2-pkcs11 library, you need to initialize a store. The store contains
metadata for the library on what tokens and subordinate objects to expose.

PKCS#11 was designed to work with smart cards, and has a few concepts that are pivital to understanding how to use it.
The first concept is a *slot*. The slot, would be the physical smart card reader slot you would insert the smart card into.
Then, for each slot, you can have a smart card inserted or not. So you could have N reader slots with X smart cards inserted
where X <= N. For each smart card in X, it provides a *token*. The token is the actual device the PKCS#11 calls operate on.
The token itself can be in one of two states, *initialized* or *not initialized*.

The tpm2-pkcs11 library will always provide at least one *not-initialized* token that can be used to initialize the token.
You can initialize the token with an external client via the PKCS#11 interface call C_Initialize, like
[pkcs11-tool](https://linux.die.net/man/1/pkcs11-tool) or you can use the provided
[tpm2_ptool](https://github.com/tpm2-software/tpm2-pkcs11/tree/master/tools) to perform an initialization through a
side-channel mechanism.

Note, that most initializations can be done through C_Initialize() calls via tools like pkcs11-tool. However, more complex
initializations are better handled through tpm2_ptool.

The tpm2-pkcs11 library requires some metadata to operate correctly. It stores this metadata in what is known as a *store*.
The store is automatically searched for in the following locations:

1. env variable `TPM2_PKCS11_STORE`
  This is optional, and if not set is skipped. However, if you want a store in a custom path, this is how you set it:
  - Example: `export TPM2_PKCS11_STORE='path/to/where/i/want/the/store'`
2. `/etc/tpm2_pkcs11` or whatever was configured at build time with `--with-storedir`.
3. Users `$HOME/.tpm2_pkcs11` directory.
4. Current Working Directory.

If no existing store is found, it will:
1. If env variable `TPM2_PKCS11_STORE` is set, attempt to use that path directory or create it if it doesn't exist.
   On failure, it continues to number 2.
2. `/etc/tpm2_pkcs11` or whatever was configured at build time with --with-storedir.
3. if `$HOME` is set, attempts to use that path directory. If the directory doesn't exist it will be created.
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
  to use a TPM Simulator and tpm2-abrmd as documented in
  [dependencies](BUILDING.md#step-1---satisfy-dependencies).

  Their is no requirement to use the simulator and abrmd, this is all configuration dependent.

**LOCKING**

When the SQL database is on the disk, the lock is set within the same folder than the SQL file.
It can lead to some issues if the lock is not released (system crash, reboot), mostly on embedded
systems. Another folder, for instance a tmpfs one, can be enforced using the env `PKCS11_SQL_LOCK=/var/run/pkcs11_sql_locks`.

## Example Setup With tpm2_ptool
I use the simulator and tpm2-abrmd to set all of this up, like so:
```sh
tpm_server &
tpm2-abrmd --tcti=mssim &
```
See the respective projects for details on how to get them running. Note that `tpm2-abrmd` uses dbus,
and dbus configuration is required.

### Step 1 - Initializing a Store and Creating a Slot

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

### Transient Primary Keys

By default, and suitable for most users, primary keys are persistent objects in TPM non-volatile memory. However,
under certain situations, one may wish to use a transient primary key. The upside is that this consumes no
non-volatile memory in the TPM. So this would be suitable in situations where all NV space is consumed. The downside
is that initialization of the token will be slower and that it requires authentication to the owner hierarchy. `tpm2_ptool`
commands that need to leverage a transient primary object have been augmented to take the `--hierarchy-auth` option to
supply this. However, token initialization will need this in tools consuming the PKCS#11 library. This can be supplied
via the environment variable `TPM2_PKCS11_OWNER_AUTH`.

### Step 2 - Creating a Token

After creating a slot or slots, now one needs to create a token. This is accomplished with the `addtoken` command for `tpm2-ptool`,
using the primary object ID from [Step 1](#step-1---initializing-a-store-and-creating-a-slot). A token is created and a unique
name called a *label* is provided. The *label* is used in subsequent commands to reference the token.

**Example**:
```sh
tpm2_ptool.py addtoken --pid=1 --hierarchy-auth=mypobjpin --sopin=mysopin --userpin=myuserpin --label=label --path ~/tmp
```

To create N tokens under a given `--pid` or primary object id, just run the command N times. Thus it is possible to have
*S* number of slots, with *T* number of tokens under each slot.

### Step 3 - Creating Objects Under a Token

To create objects, like keys, under a token, the `tpm2-ptool` command-let `add` is invoked. You can direct which token
to create the object under by using the `--label` option.

**Example**:
```sh
action: add
private:
  CKA_ID: '62663630653733656336316363386535'
```

This command can be run N times to create N objects within a token. Tokens can have an arbitrary number of objects. The tool
outputs to *stdout* the objects CKA_ID hex encoded.

**Note**: To view all the types of objects one can create run command:
```sh
tpm2_ptool.py addkey --help
```
And review the enumerated options allowed for `--algorithm`.

## Example Setup With pkcs11-tool

We start the simulator and tpm2-abrmd as shown [here](#Example Setup With tpm2_ptool).
I add an alias in my `~/.bashrc` file so that way pkcs11-tool is setup and running the tpm2-pkcs11 library.
The alias is:
```bash
alias tpm2pkcs11-tool="pkcs11-tool --module $HOME/workspace/tpm2-pkcs11/src/.libs/libtpm2_pkcs11.so.0.0.0"
```
Alter that alias as needed, so that `--module` points to the location of the tpm2-pkc11 shared library.

### Initialization Details

This method of initialization does not provide the granularity of control over the primary key that
`tpm2_ptool` does. The initialization will currently look to see if a *store* is already configured with
a primary key, and if so uses the first one. If it is not, it attempts to use the *SRK* at address 0x81000001
as defined by various TCG specifications:
- https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
- https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
- https://trustedcomputinggroup.org/wp-content/uploads/TCG_PC_Client_Platform_TPM_Profile_PTP_2.0_r1.03_v22.pdf
- https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf

### Step 1 - Creating a Token

Optional, list the current tokens to figure out what slot to use:
```bash
tpm2pkcs11-tool --list-token-slots
Available slots:
Slot 0 (0x1):                                 IBM
  token state:   uninitialized
```

Initialize a token at Slot Index 0.
```bash
tpm2pkcs11-tool --slot-index=0 --init-token --label="my first token" --so-pin="mysopin"
Token successfully initialized
```

Optional, list the tokens again:
```bash
tpm2pkcs11-tool --list-token-slots
Available slots:
Slot 0 (0x1): my first token                  IBM
  token label        : my first token
  token manufacturer : IBM
  token model        : SW   TPM
  token flags        : login required, rng, token initialized, PIN initialized
  hardware version   : 1.46
  firmware version   : 22.17
  serial num         : 0000000000000000
  pin min/max        : 0/128
Slot 1 (0x2):                                 IBM
  token state:   uninitialized
```

### Step 3 - Setting a User PIN

One must set the user PIN for the token after initializing, like so:
```bash
tpm2pkcs11-tool --slot-index=0 --init-pin --so-pin="mysopin" --login --pin="myuserpin"
Using slot with index 0 (0x1)
User PIN successfully initialized
```

### Step 4 - Creating Objects Under a Token

Optional, list objects:
```bash
tpm2pkcs11-tool --slot-index=0 --list-objects
Using slot 0 with a present token (0x1)
```

Create an RSA Key pair:
```bash
tpm2pkcs11-tool --slot-index=0 --login --pin="myuserpin" --label="myrsakey" --keypairgen
Using slot with index 0 (0x1)
Key pair generated:
Private Key Object; RSA 
  label:      myrsakey
  Usage:      decrypt, sign
Public Key Object; RSA 2048 bits
  label:      myrsakey
  Usage:      encrypt, verify
```

Optional, list objects again:
```bash
tpm2pkcs11-tool --slot-index=0 --list-objects
Using slot with index 0 (0x1)
Public Key Object; RSA 2048 bits
  label:      myrsakey
  Usage:      encrypt, verify
```
Note: To see private objects you need to login.
