# SSH host keys configuration

This example will go through using a TPM 2.0 for the OpenSSH sshd host keys.
As the SSH daemon supports using the SSH agent protocol we will use tpm2-pkcs11 with an ssh-agent.

# Create a store and key
The PIN is currently needed as ssh-agent doesn't seem to support an empty string PIN (just no PIN at all)
```
# mkdir /tmp/teststore-pkcs11
# tpm2_ptool init --path=/tmp/teststore-pkcs11
# tpm2_ptool addtoken --pid=1 --label=hostkey --sopin="mysopin" --userpin="myuserpin" --path=/tmp/teststore-pkcs11
# tpm2_ptool addkey --algorithm=rsa2048 --label=hostkey --userpin="myuserpin" --path=/tmp/teststore-pkcs11
```

# Run a ssh agent
The ssh agent should have a specific path for its socket, lets use /tmp/hostagent.sock for this example.
```
# export TPM2_PKCS11_STORE=/tmp/teststore-pkcs11 
# ssh-agent -a /tmp/hostagent.sock
```

# Add the token to the agent
```
# SSH_AUTH_SOCK=/tmp/hostagent.sock ssh-add -s /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so
```

# Get the public key in SSH format
```
# SSH_AUTH_SOCK=/tmp/hostagent.sock ssh-add -L
ssh-rsa ....
```
Where `....` is the public key in ssh key format.
Store the whole output from ssh-add -L in `/etc/ssh/ssh_hostkey_rsa.pub` as sshd requires the public key outside the agent.

# Configure sshd
Add the following to /etc/ssh/sshd_config
```
HostKey /etc/ssh/ssh_hostkey_rsa.pub
HostHostKeyAgent /tmp/hostagent.sock
```
(Re)start sshd and run:
```
# ssh-keyscan localhost
```
You should now be able to see the same key as you saw with `ssh-add -L`.

