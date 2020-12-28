# OpenVPN

OpenVPN is an Open source VPN daemon and client. In this tutorial, we will show an example of setting it
up and using it with tpm2-pkcs11. **Note: This configuration has not been evaluated for production use.**

If you use TLS-1.1, it should just work, if you want TLS-1.2, you may need to fiddle more with package versions.

This write up stemmed from https://github.com/tpm2-software/tpm2-pkcs11/issues/67, so if you would like more details,
please look through the conversation on the issue.

## Requirements

In this tutorial, we will be using Fedora-32 as the example. Other distros should be similar but will
require distro specific examples.

- OS: [Fedora 32](https://getfedora.org/en/workstation/download/)
- TPM2 Bits:
  - This is known to work with the following versions, however other previous versions may work too.
    - tpm2-pkcs11, 1.4
    - tpm2-tools: 4.2
    - tpm2-abrmd: 2.3.3
    - tpm2-tss: 3.0
- Others:
  - EasyRSA on the **server** machine.
    ```bash
       wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.5/EasyRSA-nix-3.0.5.tgz \
         -O EasyRSA-nix-3.0.5.tgz
       tar -zxvf EasyRSA-nix-3.0.5.tgz
       cd EasyRSA-3.0.5

       # Don't forget to add EasyRSA to your path
       export PATH="$PATH:$(realpath EasyRSA-3.0.5)"
     ```
   - OpenVPN
     ```bash
        dnf install openvpn
     ```

The major issue is that pkcs11-helper library has a bug (P11 PKCS11 URI handling) and a missing feature (RSA_NO_PADDING support).
However, if you use the Fedora packaged version with certain patches applied, and re-install, it should work. To do this, I first
got the upstream pkcs11-helper and checked out version 1.22, which is the packaged version, and applied the following patches:

```bash
# clone pkcs11-helper
git clone https://github.com/OpenSC/pkcs11-helper.git

# Checkout the same version that Fedora Packaged at the time of this tutorial
# Note this could change, so check pkg-config --modversion libpkcs11-helper-1
git checkout pkcs11-helper-1.22

# Get the Patches that RPM built with. Note that this PR could change, and do to
# rebase conflicts do not apply cleanly anymore.
wget https://github.com/OpenSC/pkcs11-helper/pull/4.patch

# Apply the patches
git am 4.patch
Applying: Stop _pkcs11h_util_hexToBinary() checking for trailing NUL
Applying: Accept RFC7512-compliant PKCS#11 URIs as serialized token/certificate IDs
Applying: Serialize to RFC7512-compliant PKCS#11 URIs

# Get PSS support.
git cherry-pick c192bb4
```
**Note**: The above does not apply cleanly, but the conflict is on:
`both modified:   ChangeLog`
So one can just ignore it.

**Note**: There are other ways to do this, and your mileage may vary.

After you have pkcs11-helper patched, you need to build and optionally install it:
  - https://github.com/OpenSC/pkcs11-helper/wiki/How-to-compile-pkcs11-helper

If you don't install it, you can set `LD_LIBRARY_PATH` or `LD_PRELOAD` variables to the location of the parent
directory containing the library or the library path itself respectively.

## Configuring

The major headaches are configuring OpenVPN. I configured the client and server on the same machine; however,
the steps will generally be the same if they are running on different machines.

### Step 1 - Server Setup

```bash
#!/bin/bash

mkdir ~/openvpn-server
cd ~/openvpn-server

firewall-cmd --add-service=openvpn --permanent
firewall-cmd --reload

# Create PKI and Initial CA
./easyrsa init-pki
./easyrsa build-ca

# Generate Server Certs and Artifacts
./easyrsa build-server-full server
./easyrsa gen-dh

cd ..

# Configure Server
cp /usr/share/doc/openvpn/sample/sample-config-files/server.conf .
cp ./EasyRSA-3.0.5/pki/private/server.key .
cp ./EasyRSA-3.0.5/pki/issued/server.crt .
cp ./EasyRSA-3.0.5/pki/dh.pem dh2048.pem
cp ./EasyRSA-3.0.5/pki/ca.crt .
openvpn --genkey --secret ta.key
```

### Step 2 - Client CSR Setup

```shell
#!/bin/bash
mkdir ~/openvpn-client
cd ~/openvpn-client

# Create certificate Signing Request Configuration

cat > client.cnf << EOF
[ req ]
default_bits           = 2048
distinguished_name     = req_distinguished_name
prompt                 = no
[ req_distinguished_name ]
C                      = US
ST                     = Foo
L                      = Bar
O                      = Widget Co
OU                     = Internet of Widgets Group
CN                     = $(hostname)
EOF

# Create the TPM2 PKCS11 Key

# Note: you may need to configure the TCTI for your environment, I used ibmtpm1563 server
# and tpm2-abrmd.
#export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
#export TPM2_PKCS11_TCTI="device:/dev/tpmrm0"

# Set up the store location
export TPM2_PKCS11_STORE=/etc/tpm2_pkcs11

# Set the log-level for debugging so we get more info
export TPM2_PKCS11_LOG_LEVEL=2

rm ${TPM2_PKCS11_STORE} -fr || true
mkdir -p ${TPM2_PKCS11_STORE} || true
tpm2_clear
tpm2_ptool init
tpm2_ptool addtoken --pid=1 --sopin=sopin --userpin=userpin --label=openvpn
tpm2_ptool addkey --algorithm=rsa2048 --label=openvpn --userpin=userpin

# Set the token TCTI if needed.
# tpm2_ptool config --key tcti --value "device:/dev/tpmrm0" --label=openvpn

# Create the Certificate Signing Request

TOKEN=$(p11tool --list-token-urls | grep "token=openvpn")
export GNUTLS_PIN=userpin
export GNUTLS_SO_PIN=sopin
p11tool --login --list-all "${TOKEN}" --outfile p11tool.out
PRIVATE_KEY=$(cat p11tool.out | grep private | awk '{ print $2 }')
openssl req -new -engine pkcs11 -keyform engine \
        -key "${PRIVATE_KEY};pin-value=userpin" \
        -config client.cnf -out client.csr
```

### Step 3 - Generate Client Cert in the Server

Copy the generated client.csr to the server, and sign it.

```bash
cd openvpn-server/EasyRSA-3.0.5
./easyrsa import-req ./client.csr client
./easyrsa sign-req client client
cat ./pki/issued/client.crt
```

### Step 4 - Configure OpenVPN Client

```bash
cd ~/openvpn-client

# Get certificates from server. Whatever works scp, cp, etc.
# Since I did it on the same machine, cp will work just fine.
cp ~/openssl-server/client.crt .
cp ~/openssl-server/ca.crt .
cp ~/openssl-server/ta.key .

# Configure Client REPLACE IP ADDRESS
remote_ip="192.168.0.43"
cp /usr/share/doc/openvpn/sample/sample-config-files/client.conf .
sed -i "s/remote my-server-1 1194/remote $remote_ip 1194/g" client.conf
```

### Step 5 - Import the certificate into the PKCS11 Store

```bash
#!/bin/bash
cd ~/openvpn-client

TOKEN=$(p11tool --list-token-urls | grep "token=openvpn")
export GNUTLS_PIN=userpin
export GNUTLS_SO_PIN=sopin
KEY_ID=$(p11tool --login --list-all "${TOKEN}" | grep ID: | uniq | awk '{ print $2 }' | sed 's/://g')
tpm2_ptool addcert --label=openvpn --key-id=${KEY_ID} ./client.crt
SERIALIZED_ID=$(openvpn --show-pkcs11-ids /usr/lib64/pkcs11/libtpm2_pkcs11.so.0.0.0 | grep "Serialized id:" | awk '{ print $3 }')

cat << EOF

# Comment the cert and key lines and add the following to the config:
pkcs11-providers /usr/lib64/pkcs11/libtpm2_pkcs11.so.0.0.0
pkcs11-id '${SERIALIZED_ID}'
EOF
```

The following diff illustrates the changes needed to the client openvpn config file.
One needs to comment out the config file lines for cert and key. Your specific
values for pkcs11-id, pkcs11-providers and remote may vary on distro and local
configurations.

```diff
diff /usr/share/doc/openvpn/sample/sample-config-files/client.conf client.conf
42c42
< remote my-server-1 1194
---
> remote 192.168.0.43 1194
89,90c89,93
< cert client.crt
< key client.key
---
> #cert client.crt
> #key client.key
> # Comment the cert and key lines and add the following to the config:
> pkcs11-providers /usr/lib64/pkcs11/libtpm2_pkcs11.so.0.0.0
> pkcs11-id 'pkcs11:model=Intel;token=openvpn;manufacturer=Intel;serial=0000000000000000;id=e3dac3f1de50d109'
```

## Step 6 - Start the Server

On the **server machine**, do:

```bash
cd ~/openvpn-server

# note you need root
openvpn --config server.conf --verb 11
```

## Step 7 - Start the Client:

Note that since I did everything as local client, one might want to remove the `--no-bind` option.

On the **client** machine do:

```bash
cd ~/openvpn-client
openvpn --config client.conf --verb 11 --nobind
```

You should see on the server, similar output on success:

```
Fri Aug 21 09:45:43 2020 Initialization Sequence Completed
Fri Aug 21 09:45:53 2020 127.0.0.1:60283 TLS: Initial packet from [AF_INET]127.0.0.1:60283, sid=c0481798 843a43da
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 VERIFY OK: depth=1, CN=Easy-RSA CA
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 VERIFY OK: depth=0, C=US, ST=Oregon, L=Hillsboro, O=Intel Corp, OU=Internet of Things Group, CN=openvpn.mshome.net
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 peer info: IV_VER=2.4.9
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 peer info: IV_PLAT=linux
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 peer info: IV_PROTO=2
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 peer info: IV_NCP=2
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 peer info: IV_LZ4=1
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 peer info: IV_LZ4v2=1
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 peer info: IV_LZO=1
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 peer info: IV_COMP_STUB=1
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 peer info: IV_COMP_STUBv2=1
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 peer info: IV_TCPNL=1
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, 2048 bit RSA
Fri Aug 21 09:45:56 2020 127.0.0.1:60283 [openvpn.mshome.net] Peer Connection Initiated with [AF_INET]127.0.0.1:60283
```
