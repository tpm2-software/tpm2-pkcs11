The purpose of this file is to describe the functional and key architecture of
this project. It is spiced with some rational throughout.

# Slots & Tokens

This library shall provide multiple tokens for the user(s). Any given slot can
only contain one token at any given time. In case of smartcards the slot is a
reader whilst the token is the actual smartcard. Since this project won't
implement a separate tool for "virtual swapping" of tokens, each token is
associated with its own slot. Thus, the library offers a set of slots with a
token inside each of these.

In order to allow the creation of new tokens using the pkcs11 means, this
library presents one more slot/token pair than tokens currently exist. The
additional token is a blank token that can be initialized using the C_InitToken
function.
(Note: This is not implemented yet)

# Objects

Each token can contain an arbitrary amount of keys and other object. (Note:
other objects are not implemented yet). The keys are TPM-based keys, i.e. they
are only known to the TPM and also the key operations are executed inside the
TPM. The other objects are encrypted using hybrid encryption with the outer
key being sealed to the TPM.

Note: Since the TPM's object are stored (encrypted) external to the TPM on the
HDD, it is not possible to delete them, if your attacker model allows access to
the HDD.

# Key Authorizations

For each token, two TPM seal blobs exist one for the SO and one for the User.
The authValue for these seal blobs are SO's PIN and the User's PIN. The data
sealed inside is an intermediate key that is used to decrypt a second authValue
stored on disk.

This second authValue is then used to authenticate the use of
the key objects. In case of a PIN-change only the seal blobs need to be changed,
which is an atomic operation.

Note: Since the TPM's object are stored (encrypted) external to the TPM on the
HDD, it is not possible to invalidate the copy of the blob with the old PIN, if
your attacker model allows access to the HDD.

# Key Hierarchies

All keys reside under the so-called SRK. This is an (optionally persistent)
primary key inside the TPM as specified by the TCG Provisioning Guidance.

Note: Currently there is an additional intermediate storage per token that will
be removed.

# Storage

All TPM-encrypted key blobs, the meta-data and the encrypted second authValue
are stored in the OS-user's personal storage (i.e. HOME directory).





