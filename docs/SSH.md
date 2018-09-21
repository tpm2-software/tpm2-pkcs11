# SSH Configuration

Below, will be examples and discussion on how to configure SSH with tpm2-pkcs11 to ssh to
the local host. The Example described here could be extended for remote ssh login as well.

We assume a machine configured in such a state where a user can ssh locally and login with
a password prompt, ala:
```sh
ssh user@127.0.0.1
user@127.0.0.1's password:
Last login: Thu Sep  6 12:23:07 2018 from 127.0.0.1
```
works.

**Thus we assume a working ssh server, client and ssh-keygen services and utilities are present.**

# Step 1 - Initializing a Store

Start by reading the document on initialization [here](INITIALIZING.md). Only brief commands
will be provided here, so a a basic understanding of the initialization process is paramount.

We start by creating a tpm2-pkcs11 *store* and set up an RSA2048 key that SSH can used.
**Note**: Most SSH configurations allow RSA2048 keys to be used, but this can be turned off
  in the config, but this is quite rare.

```sh
tpm2_ptool.py init --pobj-pin=mypobjpin --path=~/tmp

tpm2_ptool.py addtoken --pid=1 --pobj-pin=mypobjpin --sopin=mysopin --userpin=myuserpin --label=label --path ~/tmp

tpm2_ptool.py addkey --algorithm=rsa2048 --label=label --userpin=myuserpin --path=~/tmp
```

# Step 2 - Exporting the Store

Since we didn't use the default store location by setting `--path` in the `tpm2-ptool` tool, we must export the
store so the library can find it. We do this via:
```sh
export TPM2_PKCS11_STORE=$HOME/tmp
```

**Note**: The tpm2-pkcs11.so library *WILL NOT EXPAND `~`* and thus you have to use something the shell will expand,
like `$HOME`.

# Step 3 - Generating the SSH key public portion

The next step will use `ssh-keygen` comand to generate the public portion of an ssh key. The command is slightly complicated
as we use tee to redirect the output to both a file called `my.pub` and to *stdout* for viewing.

```sh
ssh-keygen -D ./src/.libs/libtpm2_pkcs11.so | tee my.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0CTmUAAB8jfNNHrw99m7K3U/+qbV1pAb7es3L+COqDh4eDqqekCm8gKHV4PFM9nW7z6CEfqzpUxYi5VvRFdYaU460bhye7NJbE0t9wjOirWtQbI6XMCKFiv/v8ThAtROT+KKYso7BK2A6spkCQwcHoaQU72C1vGouqtP5l/XRIYydp3P1wUdgQDZ8FoGhdH5dL3KnRpKR2d301GcbxMxKg5yhc/mTNkv1ZoLIcwMY7juAjzin/BhcYIDSz3sJ9C2VsX8FZXmbEo3olYU4ZfBZ+45KJ81MtWgrkXSzetwUfiH6eeTqNfqGT2IpSwDLFHTX2TsJyFDcM7Q+QR44lEU/
```

# Step 4 - Configuring SSH to Accept the Key

Now that the public portion of the key is in ssh format and located in file `my.pub` we can add this to the authorized_keys2 file for the user:
```sh
cat my.pub >> ~/.ssh/authorized_keys2
```

SSH consults this file and trusts private keys corresponding with the public entries.

# Step 5 - Ensuring the Library is in a Good Path

Using the ssh client, we login. Note that ssh won't accept pkcs11 libraries outside of "trusted" locations. So we copy the PKCS\#11 library to
a trusted location. Thus you can either do `sudo make install` to move the binary to a trusted location or just do it manually.

Manual Method:
```sh
sudo cp src/.libs/libtpm2_pkcs11.so /usr/local/lib/libtpm2_pkcs11.so
```

On Ubuntu 16.04 with no configuration options specified to alter installation locations, they end up in the same location for both the *manual method*
and `sudo make install` method.

# Step 6 - Logging In via SSH

To log in, one used the `ssh` client application and specifies the path to the PKCS11 library via the `-I` option. It will prompt for the user pin, which
in the example is set to `myuserpin`.

```sh
ssh -I /usr/local/lib/libtpm2_pkcs11.so 127.0.0.1
Enter PIN for 'label': myuserpin
Last login: Fri Sep 21 13:28:31 2018 from 127.0.0.1
```

You are now logged in with a key resident in the TPM being exported via the tpm2-pkcs11 library.
