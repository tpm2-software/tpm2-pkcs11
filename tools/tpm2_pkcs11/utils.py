import binascii
import hashlib
import os
import argparse
import sys
import shutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from tempfile import mkdtemp

import sys
if sys.version_info.major < 3:
    input = raw_input


# The delimiter changes based on nesting level to make parsing easier. We assume one key-value entry per line
# where a key can have N KVPs as a CSV.
# For instance:
#   9=hashalg=43,mgf=67\n
#
def kvp_row(d, delim=" "):
    x = delim.join([
        "=".join([
            str(key), kvp_row(val, ",") if isinstance(val, dict) else str(val)
        ]) for key, val in d.items()
    ])
    return x


def list_dict_to_kvp(l):
    x = "\n".join(kvp_row(d) for d in l)
    return x


def dict_from_kvp(kvp):
    return dict(x.split('=') for x in kvp.split('\n'))


def rand_hex_str(num=32):
    if num % 2:
        raise RuntimeError("Expected even number of bytes, got: %u", num)

    return binascii.hexlify(os.urandom(num // 2))


def hash_pass(password, salt=None):

    if salt is None:
        # get a 32 bit salt hex encoded (hex len 64)
        salt = rand_hex_str(64)

    # python 3.5.2 (doesn't seem to affect >= 3.5.6) is dumb...
    if isinstance(password, str):
         password = password.encode()

    if isinstance(salt, str):
         salt = salt.encode()

    m = hashlib.sha256(password)
    m.update(salt)

    # the TPM auth size is limited to 32 bytes in most cases 
    hash = m.hexdigest()[:32]

    return {
        'salt': salt,
        'hash': hash,
    }


def query_yes_no(question, default="no"):
    """Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def load_sealobject(token, tpm2, db, pobjauth, pin, is_so):

    pobj = db.getprimary(token['pid'])
    sealobject = db.getsealobject(token['id'])
    if is_so:
        sealpub = sealobject['sopub']
        sealpriv = sealobject['sopriv']
        salt = sealobject['soauthsalt']
    else:
        sealpub = sealobject['userpub']
        sealpriv = sealobject['userpriv']
        salt = sealobject['userauthsalt']

    sealauth = hash_pass(pin.encode(), salt)['hash']

    # Load the so sealobject using the PARENTS AUTH (primaryobject)
    sealctx = tpm2.load(pobj['handle'], pobjauth, sealpriv, sealpub)

    return pobj, sealctx, sealauth


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        # Generate a random 96-bit IV.
        iv = os.urandom(12)

        # Construct an AES-GCM Cipher object with the given key and a
        # randomly generated IV.
        encryptor = Cipher(
            algorithms.AES(self.key), modes.GCM(iv),
            backend=default_backend()).encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        iv = binascii.hexlify(iv).decode()
        ciphertext = binascii.hexlify(ciphertext).decode()
        tag = binascii.hexlify(encryptor.tag).decode()
        return ':'.join((iv, tag, ciphertext))

    def decrypt(self, ciphertext):

        iv, tag, ciphertext = ciphertext.split(':')
        iv = binascii.unhexlify(iv)
        tag = binascii.unhexlify(tag)
        ciphertext = binascii.unhexlify(ciphertext)

        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=default_backend()).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext


class TemporaryDirectory(object):
    """Context manager for tempfile.mkdtemp() so it's usable with "with" statement."""

    def __enter__(self):
        self.name = mkdtemp()
        return self.name

    def __exit__(self, exc_type, exc_value, traceback):
        shutil.rmtree(self.name)


class AESAuthUnwrapper(object):
    def __init__(self, key):

        self._cipher = AESCipher(binascii.unhexlify(key))

    def unwrap(self, value):
        return self._cipher.decrypt(value)

    def wrap(self, value):
        return self._cipher.encrypt(value)


# XXX
# TODO move to the argparse handler module
def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def get_ec_params(alg):
    """Return a string representation of a hex encoded ASN1 object X9.62 EC parameter

    http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html

    Indicates that EC paramaters are byte arrays of a DER encoded ASN1 objects X9.62 parameter.
    This function will return a hex string without the leading 0x representing this encoding.
    """

    if alg == "ecc256":
        obj = "2A8648CE3D030107"
    elif alg == "ecc224":
        obj = "2B81040021"
    elif alg == "ecc384":
        obj = "2B81040022"
    elif alg == "ecc521":
        obj = "2B81040023"
    else:
        raise RuntimeError("alg %s has no EC params mapping" % alg)

    # start building the DER object tag + len + obj in hex
    der = "06{:02x}{}".format(len(obj) // 2, obj)

    return der


def asn1_format_ec_point_uncompressed(x, y):

    len_y = len(y)
    len_x = len(x)

    # normalize hex input to ensure no odd count hex strings
    if len_y % 2:
        len_y = len_y + 1
        y = "00" + y

    if len_x % 2:
        len_x = len_x + 1
        x = "00" + x

    # convert hex length to binary length
    len_y = len_y // 2
    len_x = len_x // 2

    # ensure that the binary representation fits into a byte
    total_len = len_y + len_x + 1
    if (total_len > 255):
        raise RuntimeError(
            "Length of X and Y plus uncompressed format byte greater than 255")

    # The uncompressed point format is:
    # <asn1 octet hdr> <len> <uncompressed point format byte> <X> <Y>
    # 04 <len> <X> <Y>

    s = "04{len:02x}04{X}{Y}".format(len=total_len, X=x, Y=y)

    return s
