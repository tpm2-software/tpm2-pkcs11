# Using TPM2 PKCS11 with OpenSSL

## Introduction

OpenSSL has the ability to load dynamic engines to control where the underlying cryptographic
operations occur. Additionally, [OpenSC LibP11](https://github.com/OpenSC/libp11) has an engine
that can load arbitrary PKCS11 libraries. Thus, through a few layer of indirections, you can use
OpenSSL with the tpm2-pkcs11 library. This is a less complete tutorial, and assumes you have
been through the [pkcs11-tool](PKCS11_TOOL.md) tutorial.

## Setup

Yubico has very complete instructions for configuring, see:
  - https://developers.yubico.com/YubiHSM2/Usage_Guides/OpenSSL_with_pkcs11_engine.html

These instructions are mostly applicable, the only thing that needs to change is that the
MODULE_PATH needs to point to the tpm2-pkcs11 library.

A sample OSSL config file is provided at [openssl.conf](../misc/tpm2-pkcs11.openssl.sample.conf).

Note:
  - The Yubico instructions use rand. Rand will not hit the tpm because the OpenSC engine does
    not support it.
  - Systems with PKCS11 kit installed may need additional tweaks to get it to work.

For the examples below, I followed Yubico's advice and set up an alias in my `~/.bashrc` file
called tpm2ssl, like so:
```bash
alias tpm2ssl='OPENSSL_CONF=$HOME/tpm2-pkcs11.openssl.conf openssl'
```

You'll also need to set up a `TPM2_PKCS11_STORE` and have an asymmetric key pair generated. This is all
shown in the [pkcs11-tool](PKCS11_TOOL.md) tutorial.

Setting up an alias makes life easier, so lets do that:
```bash
alias tpm2pkcs11-tool='pkcs11-tool --module /path/to/libtpm2_pkcs11.so
```
Note: You need to update `--module` option to point to the tpm2-pcks11 shared object.

## Generating a Certificate

First thing first, identify the private key to use to generate the certificate or CSR from. With pkcs11-tool, one can
do:
```bash
pkcs11-tool --module /path/to/libtpm2_pkcs11.so --slot 1 --login -O
```
You should see output like so:
```bash
Private Key Object; EC
  label:      my-ecc-keypair
  ID:         61366566303531343635636138663035
  Usage:      decrypt, sign
```

Note: You need to login to see private key objects.

If you don't have a key, we can create one:
```bash
tpm2pkcs11-tool --label="my-ecc-keypair" --login --keypairgen --usage-sign --key-type EC:prime256v1
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

Your key could be RSA, that's fine. The imporant thing is to look at the label and pass it via the `-key` argument
in openssl below. Note that this is key my-ecc-keypair in slot 1, even though the output says slot 0. In PKCS11, the slotid is what matters, which is the 0x1. A slot id of 0x0 is not valid.

To generate a self signed certificate, one can simply use the `req` command with `openssl`.

``` bash
tpm2ssl req -new -x509 -days 365 -subj '/CN=my key/' -sha256 -engine pkcs11 -keyform engine -key slot_1-label_my-ecc-keypair -out cert.pem
engine "pkcs11" set.
Enter PKCS#11 token PIN for label:
```

Note: OpenSSL can also find the key by using the `id` field. For example, update the key to:
```
-key slot_1-id_38316235653539316533633232383139
```

## Generating a CSR

Most users will likely require certificates signed by a CA. To do this, we can generate a CSR that gets uploaded to a CA. The CA
then returns the certificate. The steps to upload the CSR and retrieve it from the CA are CA dependent and will not be covered
here.

```bash
tpm2ssl req -new -subj '/CN=my key/' -sha256 -engine pkcs11 -keyform engine -key slot_1-label_my-ecc-keypair -out csr.pem
```

The next steps after generating the CSR would be to go to a CA, get a certificate generated and signed using it.

Note:
 - OpenSSL config file can be used for specifying default values when using the req command.
   [See the man page](https://www.openssl.org/docs/man1.1.1/man1/openssl-req.html).

## Inserting a Certificate

At this point, you have a certificate, either self signed or signed via a CA. The certificate may be in many forms,
if you followed the steps above, it's in the PEM format. You need to convert any version you have to PEM, information
on how to do this can be found at:
  - https://knowledge.digicert.com/solution/SO26449.html

Once you obtain a PEM certificate, you can use the ptool command.

```bash
tpm2_ptool addcert --label=label --key-id=38316235653539316533633232383139 --path=$TPM2_PKCS11_STORE ~/pem
action: add
cert:
  CKA_ID: '38316235653539316533633232383139'
```

## Listing a Certificate

After this, view your cert object, you can again just list the objects with pkcs11-tool.

```bash
tpm2pkcs11-tool --slot 1 -O
```

You should see, amongst other output, output like:

```bash
Certificate Object; type = X.509 cert
  label:      1
  subject:    DN: CN=my key
  ID:         38316235653539316533633232383139
```
