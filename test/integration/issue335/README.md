This scripts help to reproduce issue #335.

**NOTE** Most PKI stuff was taken from freeradius sample setup. Don't use these certificates for anything else but testing this issue...

The server.sh script runs an OpenSSL s\_server process waiting for connections.
The client.sh script runs an OpenSSL s\_client process that connects to the server using a client certificate. The corresponding private key of the certificate is held in the TPM and accessed using pkcs#11 engine.

To run the script you need to create the pkcs11 store, token and key and then create the CSR. The CSR must be signed by the CA.

## Creating TPM2 objects:

```
tpm2_ptool init
tpm2_ptool addtoken --pid=1 --sopin=mysopin --userpin=myuserpin --label=label
tpm2_ptool addkey --algorithm=rsa2048 --label=label --userpin=myuserpin
```

## Create certificate:

There is a Makefile for creating it all. It uses the TPM key from the PKCS11\_KEY env var:

```
export PKCS11_KEY="pkcs11:model=Intel;manufacturer=Intel;serial=0000000000000000;token=label;id=%64%64%32%63%35%61%34%32%66%64%62%36%32%66%63%31;object=1;type=public"
make
```

This should ask the token PIN: enter `myuserpin`

## Run server

```
bash server.sh
```

## Run client

In a different terminal:

```
bash client.sh
```

First lines of sample output:

```
engine "pkcs11" set.
Enter PKCS#11 token PIN for label:
CONNECTED(0000000C)
depth=1 C = FR, ST = Radius, L = Somewhere, O = Example Inc., emailAddress = admin@example.org, CN = Example Certificate Authority
verify return:1
depth=0 C = FR, ST = Radius, O = Example Inc., CN = Example Server Certificate, emailAddress = admin@example.org
verify return:1
140586585149888:error:8207A070:PKCS#11 module:pkcs11_private_encrypt:Mechanism invalid:p11_rsa.c:120:
140586585149888:error:141F0006:SSL routines:tls_construct_cert_verify:EVP lib:../ssl/statem/statem_lib.c:298:
---
```

Check the error line that reads "Mechanism invalid".

