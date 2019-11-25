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

These instructions are mostly applicable, the only thing that needs to change is the
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

You'll also need to set up a `TPM2_PKCS11_STORE` and have an assymetric keypair generated. This is all
shown in the [pkcs11-tool](PKCS11_TOOL.md) tutorial.


## Generating a Certificate

First thing first, identify the private key to use to generate the certificate or CSR from. With pkcs11-tool, one can
do:
```bash
pkcs11-tool --module /path/to/libtpm2_pkcs11.so --slot 1 --login -O
```

Note: You need to login to see private key objects.

You should see output like so:
```bash
Private Key Object; EC
  label:      12
  ID:         61366566303531343635636138663035
  Usage:      decrypt, sign
```

You're key could be RSA, thats fine. The imporant thing is to look at the label and pass it via the -key argument
in openssl below. Note that this is key 12 in slot 1.

To generate a self signed certificate, one can simply use the `req` command with openssl.

``` bash
tpm2ssl req -new -x509 -days 365 -subj '/CN=my key/' -sha256 -engine pkcs11 -keyform engine -key slot_1-label_12 -out cert.pem
engine "pkcs11" set.
Enter PKCS#11 token PIN for label:
```

## Generating a CSR

Most users will likely require certificates signed by a CA. To do this, we can generate a CSR that gets uploaded to a CA. The CA
then returns the certificate. The steps to upload the CSR and retrieve it from the CA are CA dependent and will not be covered
here.

```bash
tpm2ssl req -new -subj '/CN=my key/' -sha256 -engine pkcs11 -keyform engine -key slot_1-label_12 -out csr.pem
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
tpm2_ptool addcert --label=todo --id=todo cert.pem
```

## Listing a Certficiate

After this, veiw your cert object, you can again just list the objects with pkcs11-tool.

```bash
pkcs11-tool --module /path/to/libtpm2_pkcs11.so --slot 1 --login -O
```

You should see output like:

```bash
Certificate Object; type = X.509 cert
  label:      12
  subject:    DN: CN=my key
  ID:         3132
```