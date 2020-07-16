# Interoperability with Existing TPM2 Objects

A user may have existing TPM2 objects created with the [tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine) project.
In order to use these objects in a token one can use the tpm2_ptool link commandlet. Below is an example of doing so.

### Linking a TPM2 TSS Engine Key with a persistent primary object

tpm2-tss-engine's *tpm2tss-genkey* command has the ability to create TPM2 objects using an existing primary key. The only requirement
that the tpm2-pkcs11 project requires is that the handle be persistent. The example below creates a persistent primary key and creates
a tpm2-tss-engine key under the persistent primary key to use. Many TPM's come provisioned with what is known as the storage root key (SRK).
This is a key defined by the [provisioning guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf).
This is a particularly useful key, and is set to an empty auth value. Thus owner authorization is not needed.

Also in the examples below we use specific primary key handles, but if one has existing objects, just substitute the values.

```bash
#
# Note: below we create/use a store in ~/tmp, however one can use a store wherever they would like.
#

# Create a primary key
tpm2_createprimary -c primary.ctx

# Persistent primary key at handle 0x81000001
tpm2_evictcontrol -c primary.ctx 0x81000001

# Create the tpm2-tss-engine key under the persistent primary key
tpm2tss-genkey -P 0x81000001 tss2key-rsa2048.pem

# Create a primary object in a store compatible for this key
pid="$(tpm2_ptool init --primary-handle=0x81000001 --path=~/tmp | grep id | cut -d' ' -f 2-2)"

# Create a token associated with the primary object
# Note: in production set userpin and sopin to other values.
tpm2_ptool addtoken --pid=$pid --sopin=mysopin --userpin=myuserpin --label=mytoken --path=~/tmp

# Link the key
tpm2_ptool link --label=mytoken --userpin=myuserpin --key-label="link-key" tss2key-rsa2048.pem
```

From there, one can use that key as they would in other tutorials.


## Linking a TPM2 TSS Engine Key with a transient primary object

It may be desirable to use the transient primary key that *tpm2tss-genkey* utilizes by default. Either as
a way to avoid using Non-Volatile memory with a persistent key, or for interoperability with existing
*tpm2tss-genkey* generated keys using this default parent.

Also in the examples below we create tpm2-tss-engine key, existing keys may also be used.

```bash
#
# Note: below we create/use a store in ~/tmp, however one can use a store wherever they would like.
#

# Create the tpm2-tss-engine key under the default transient primary key or use existing similar key
tpm2tss-genkey tss2key-rsa2048.pem

# Create a token associated with a transient primary object that is compatible with tpm2-tss-engine
pid="$(tpm2_ptool init --transient-parent=tss2-engine-key --path=~/tmp | grep id | cut -d' ' -f 2-2)"

# Create a token associated with the primary object
# Note: in production set userpin and sopin to other values.
tpm2_ptool addtoken --pid=$pid --sopin=mysopin --userpin=myuserpin --label=mytoken --path=~/tmp

# Link the key
tpm2_ptool link --label=mytoken --userpin=myuserpin --key-label="link-key" tss2key-rsa2048.pem
```

From there, one can use that key as they would in other tutorials.

### Linking a TPM2 Tools Key with a persistent primary object

[tpm2-tools](https://github.com/tpm2-software/tpm2-tools) has the ability to create primary keys
via [tpm2\_createprimary](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_createprimary.1.md)
and persist them via [tpm2\_evictcontrol](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_evictcontrol.1.md).

You can create tokens and link keys generated with *tpm2-tools* as illustraded below. One crucial benefit of persisten objects,
besides token speed as it doesn't need to invoke the TPM2_CreatePrimary command, is that any template can be used for the
persistent object; one is not limited to the few pre-defined templates.


```bash
#
# Note: below we create/use a store in ~/tmp, however one can use a store wherever they would like.
#

# Create a primary key
tpm2_createprimary -c primary.ctx

# Persistent primary key at handle 0x81000001
tpm2_evictcontrol -c primary.ctx 0x81000001

# Create the tpm2-tools key under the persistent primary key
tpm2_create -C 0x81000001 -u key.pub -r key.priv

# Create a primary object in a store compatible for this key
pid="$(tpm2_ptool init --primary-handle=0x81000001 --path=~/tmp | grep id | cut -d' ' -f 2-2)"

# Create a token associated with the primary object
# Note: in production set userpin and sopin to other values.
tpm2_ptool addtoken --pid=$pid --sopin=mysopin --userpin=myuserpin --label=mytoken --path=~/tmp

# Link the key
# Note: order of keypair objects does not matter
tpm2_ptool link --label=mytoken --userpin=myuserpin --key-label="link-key" key.pub key.priv
```

### Linking a TPM2 Tools Key with a transient primary object

Since transient primary objects need exacting templates each time, currently only two tpm2-tools primary
object templates are supported:

| Command                             | Template Name          |
|-------------------------------------|------------------------|
| `tpm2_create -c primary.ctx`        | tpm2-tools-default     |
| `tpm2_create -Gecc -c primary.ctx`  | tpm2-tools-ecc-default |


```bash
#
# Note: below we create/use a store in ~/tmp, however one can use a store wherever they would like.
#

# Create a primary key according to the template table above
tpm2_createprimary -c primary.ctx

# Create the tpm2-tools key under the persistent primary key
tpm2_create -C primary.ctx -u key.pub -r key.priv

# Create a primary object in a store compatible for this key
pid="$(tpm2_ptool init --transient-parent="tpm2-tools-default" --path=~/tmp | grep id | cut -d' ' -f 2-2)"

# Create a token associated with the primary object
# Note: in production set userpin and sopin to other values.
tpm2_ptool addtoken --pid=$pid --sopin=mysopin --userpin=myuserpin --label=mytoken --path=~/tmp

# Link the key
# Note: order of keypair objects does not matter
tpm2_ptool link --label=mytoken --userpin=myuserpin --key-label="link-key" key.pub key.priv
```

From there, one can use that key as they would in other tutorials.
