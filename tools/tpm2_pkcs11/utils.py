# SPDX-License-Identifier: BSD-2-Clause
import binascii
import hashlib
import os
import argparse
import sys
import shutil
import yaml
from tempfile import mkdtemp

from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.asymmetric import (rsa, padding)
from cryptography.hazmat.primitives import hashes

from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder
from pyasn1.codec.ber import encoder as berenc
from pyasn1.codec.der import encoder as derenc

from .pkcs11t import *  # noqa

if sys.version_info.major < 3:
    input = raw_input

def str2bytes(s):
    if isinstance(s, str) or \
        (sys.version_info.major < 3 and isinstance(s, unicode)):
        return s.encode()
    return s

def bytes_to_file(bites, tmpdir):
    path = os.path.join(tmpdir, "primary.handle")
    open(path, 'w+b').write(bites)
    return path

def rand_hex_str(num=32):
    if num % 2:
        raise RuntimeError("Expected even number of bytes, got: %u", num)

    return binascii.hexlify(os.urandom(num // 2)).decode()


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
    digest = m.hexdigest()[:32]

    return {
        'salt': salt,
        'hash': digest,
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


def load_sealobject(token, db, tpm2, pobjhandle, pobjauth, pin, is_so):

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
    sealctx = tpm2.load(pobjhandle, pobjauth, sealpriv, sealpub)

    return sealctx, sealauth


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

    if alg == "NIST p256":
        obj = "2A8648CE3D030107"
    elif alg == "NIST p224":
        obj = "2B81040021"
    elif alg == "NIST p384":
        obj = "2B81040022"
    elif alg == "NIST p521":
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

def pemcert_to_attrs(certpath):
            # rather than use pycryptography x509 parser, which gives native type access to certficiate
        # fields use pyASN1 to get raw ASN1 encoded values for the fields as the spec requires them
        with open(certpath, "r") as f:
            substrate = pem.readPemFromFile(f)
            cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]

        c = cert['tbsCertificate']

        # print(cert.prettyPrint())

        h = binascii.hexlify
        b = berenc.encode
        d = derenc.encode

        bercert = b(cert)
        hexbercert = h(bercert).decode()

        # the CKA_CHECKSUM attrs is the first 3 bytes of a sha1hash
        m = hashlib.sha1()
        m.update(bercert)
        bercertchecksum = m.digest()[0:3]
        hexbercertchecksum = h(bercertchecksum).decode()

        subj = c['subject']
        hexsubj = h(d(str2bytes(subj))).decode()

        issuer = c['issuer']
        hexissuer = h(d(str2bytes(issuer))).decode()

        serial = c['serialNumber']
        hexserial = h(d(str2bytes(serial))).decode()

        return {
            # The attrs of this attribute is derived by taking the first 3 bytes of the CKA_VALUE
            # field.
            CKA_CHECK_VALUE: hexbercertchecksum,
            # Start date for the certificate (default empty)
            CKA_START_DATE : "",
            # End date for the certificate (default empty)
            CKA_END_DATE : "",
            # DER-encoding of the SubjectPublicKeyInfo for the public key
            # contained in this certificate (default empty)
            CKA_PUBLIC_KEY_INFO : "",
            # DER encoded subject
            CKA_SUBJECT : hexsubj,
            # DER encoding of issuer
            CKA_ISSUER : hexissuer,
            # DER encoding of the cert serial
            CKA_SERIAL_NUMBER : hexserial,
            # BER encoding of the certificate
            CKA_VALUE : hexbercert,
            # RFC2279 string to URL where cert can be found, default empty
            CKA_URL : '',
            # hash of pub key subj, default empty
            CKA_HASH_OF_SUBJECT_PUBLIC_KEY : '',
            # Hash of pub key, default empty
            CKA_HASH_OF_ISSUER_PUBLIC_KEY : '',
            # Java security domain, default CK_SECURITY_DOMAIN_UNSPECIFIED
            CKA_JAVA_MIDP_SECURITY_DOMAIN : CK_SECURITY_DOMAIN_UNSPECIFIED,
            # Name hash algorithm, defaults to SHA1
            CKA_NAME_HASH_ALGORITHM : CKM_SHA_1
        }

def _pkcs11_to_str(value, prefix):

    g = globals()
    submap = dict(filter(lambda elem: elem[0].startswith(prefix), g.items()))
    inv_map = {v: k for k, v in submap.items()}

    if value in inv_map:
        return inv_map[value]
    else:
        return '0x{:X}'.format(cko_value)

def pkcs11_cko_to_str(cko_value):

    return _pkcs11_to_str(cko_value, 'CKO_')

def pkcs11_ckk_to_str(ckk_value):

    return _pkcs11_to_str(ckk_value, 'CKK_')

def check_pss_signature(tpm2, pctx, pauth):

        (priv, pub, _) = tpm2.create(pctx, pauth=pauth)
        kctx = tpm2.load(pctx, pauth, priv, pub)
        (details, _) = tpm2.readpublic(kctx, False)
        y = yaml.safe_load(details)
        e = y['exponent'] if y['exponent'] != 0 else 65537
        n = int(y['rsa'], 16)

        pub_numbers = rsa.RSAPublicNumbers(e, n)
        public_key = pub_numbers.public_key(default_backend())

        message = b'message'
        signature = tpm2.sign(kctx, 'sha256', 'rsapss', message)

        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size
                ),
                hashes.SHA256()
            )
            return True
        except crypto_exceptions.InvalidSignature:
            # saltLen = key_size_bytes - hash_size_bytes - 2;
            # If this fails, we're in some messed up position
            # PSS sigs are neither hlen == slen nor max(slen),
            # so we will fail loudly
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return False
