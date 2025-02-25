# SPDX-License-Identifier: BSD-2-Clause
import binascii
import hashlib
import io
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
from pyasn1.codec.der import decoder as derdecoder, encoder as derencoder

from tpm2_pytss.ESAPI import ESAPI
from tpm2_pytss.tsskey import TSSPrivKey
from tpm2_pytss.constants import (
    TPM2_RH,
    ESYS_TR
)
from tpm2_pytss.types import (
    TPM2B_PUBLIC,
    TPM2B_PRIVATE,
)

from .pkcs11t import *  # noqa

def str2bytes(s):
    if isinstance(s, str):
        return s.encode()
    return s

def bytes_to_file(bites, tmpdir):
    path = os.path.join(tmpdir, "primary.handle")
    open(path, 'w+b').write(bites)
    return path

def rand_hex_str(num=32):
    if num % 2:
        raise RuntimeError("Expected even number of bytes, got: %u" % num)

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

    Indicates that EC parameters are byte arrays of a DER encoded ASN1 objects X9.62 parameter.
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
    # rather than using pycryptography x509 parser, which gives native type access to certificate
    # fields use pyASN1 to get raw ASN1 encoded values for the fields as the spec requires them
    with open(certpath, "r") as f:
        bercert = pem.readPemFromFile(f)

    cert = derdecoder.decode(bercert, asn1Spec=rfc2459.Certificate())[0]
    c = cert['tbsCertificate']

    h = binascii.hexlify
    d = derencoder.encode

    hexbercert = h(bercert).decode()

    # the CKA_CHECKSUM attrs is the first 3 bytes of a sha1hash
    bercertchecksum = hashlib.sha1(bercert).digest()[0:3]
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
        CKA_START_DATE: "",
        # End date for the certificate (default empty)
        CKA_END_DATE: "",
        # DER-encoding of the SubjectPublicKeyInfo for the public key
        # contained in this certificate (default empty)
        CKA_PUBLIC_KEY_INFO: "",
        # DER encoded subject
        CKA_SUBJECT: hexsubj,
        # DER encoding of issuer
        CKA_ISSUER: hexissuer,
        # DER encoding of the cert serial
        CKA_SERIAL_NUMBER: hexserial,
        # BER encoding of the certificate
        CKA_VALUE: hexbercert,
        # RFC2279 string to URL where cert can be found, default empty
        CKA_URL: '',
        # hash of pub key subj, default empty
        CKA_HASH_OF_SUBJECT_PUBLIC_KEY: '',
        # Hash of pub key, default empty
        CKA_HASH_OF_ISSUER_PUBLIC_KEY: '',
        # Java security domain, default CK_SECURITY_DOMAIN_UNSPECIFIED
        CKA_JAVA_MIDP_SECURITY_DOMAIN: CK_SECURITY_DOMAIN_UNSPECIFIED,
        # Name hash algorithm, defaults to SHA1
        CKA_NAME_HASH_ALGORITHM: CKM_SHA_1
    }

def _pkcs11_to_str(value, prefix):

    g = globals()
    submap = dict(filter(lambda elem: elem[0].startswith(prefix), g.items()))
    inv_map = {v: k for k, v in submap.items()}

    if value in inv_map:
        return inv_map[value]
    else:
        return '0x{:X}'.format(value)

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

def create_primary(tpm2, hierarchyauth, pobjauth, template=None):

        details = tpm2.TEMPLATES[template]
        alg = details['alg']
        attrs = details['attrs']
        
        if template == 'tss2-engine-key':
            supported = tpm2.getcap('algorithms')
            supported = yaml.safe_load(supported)
            if 'ecc' in supported:
                alg = 'ecc256'
            elif 'rsa' in supported:
                alg = 'rsa2048'
            else:
                sys.exit('TPM Supports neither RSA nor ECC')
        
        return tpm2.createprimary(hierarchyauth, pobjauth, alg=alg, attrs=attrs)

def get_pobject(pobject, tpm2, hierarchyauth, d):

    pobjconf = yaml.safe_load(pobject['config'])
    pobjauth = pobject['objauth']

    if pobjconf['transient'] is True:
        selection = pobjconf['template-name']
        pobj_handle = create_primary(tpm2, hierarchyauth, pobjauth, selection)
    else:
        tr_handle = binascii.unhexlify(pobjconf['esys-tr'])
        pobj_handle = bytes_to_file(tr_handle, d)

    return pobj_handle


def hierarchy_tpm_value(hierarchy):
    
    hierarchies = {
        'o' : TPM2_RH.OWNER
    }
           
    try:
        return hierarchies[hierarchy]
    except KeyError:
        raise RuntimeError(f'Hierarchy not supported, got: f{hierarchy}')

def getauth(db, obj, pin, is_sopin, hierarchyauth):
    
    from .tpm2 import Tpm2
    
    tokid = obj['tokid']
    pid = db.getpid_by_tokid(tokid)
    pobject = db.getprimary(pid)
    token = db.gettoken(id=tokid)

    attrs = yaml.safe_load(io.StringIO(obj['attrs']))
    
    with TemporaryDirectory() as d:
        tpm2 = Tpm2(d)
        
        token_config = yaml.safe_load(io.StringIO(token['config']))
        
        if pin is None:
            if token_config.get('empty-user-pin'):
                pin = ''
            else:
                sys.exit('error: at least one of the arguments --sopin --userpin is required')
        
        tobjauth=""
        pobj_handle = None
        encauth = None
        if CKA_TPM2_OBJAUTH_ENC in attrs:
            encauth = binascii.unhexlify(attrs[CKA_TPM2_OBJAUTH_ENC])

            pobjauth = pobject['objauth']

            pobj_handle = get_pobject(pobject, tpm2, hierarchyauth, d)

            sealctx, sealauth = load_sealobject(token, db, tpm2, pobj_handle, pobjauth,
                                                      pin, is_sopin)

            # get the ESYS_TR file into a state that can be used outside of the
            # temporary directory context tied to tpm2
            with open(pobj_handle, "rb") as f:
                pobj_handle = f.read()

            wrappingkey = tpm2.unseal(sealctx, sealauth)
        
            wrapper = AESAuthUnwrapper(wrappingkey)
                
            tobjauth=""
            if encauth:
                encauth=encauth.decode()
                tobjauth = wrapper.unwrap(encauth).decode()
        
        
        return (tobjauth, pobj_handle)

def _dump_outputs(objauth, pobj):
    
    config = yaml.safe_load(io.StringIO(pobj['config']))
    is_transient = 'esys-tr' not in config

    hierarchy = str(hierarchy_tpm_value(pobj['hierarchy']))

    output = {
        'object-auth' : f'{objauth}',
        'primary-object' : {
            'is_transient' : is_transient,
            'hierarchy' : hierarchy,
            'auth'      : pobj['objauth'] 
        }
    }
    
    document = yaml.safe_dump(output, default_flow_style=False)
    print(document)

def dump_blobs(db, obj, pin, is_sopin, output_prefix):

    tokid = obj['tokid']
    pid = db.getpid_by_tokid(tokid)
    pobj = db.getprimary(pid)

    attrs = yaml.safe_load(io.StringIO(obj['attrs']))

    pub_blob = TPM2B_PUBLIC.unmarshal(binascii.unhexlify(attrs[CKA_TPM2_PUB_BLOB]))[0]
    priv_blob = TPM2B_PRIVATE.unmarshal(binascii.unhexlify(attrs[CKA_TPM2_PRIV_BLOB]))[0]

    objauth = getauth(db, obj, pin, is_sopin, attrs)[0]    

    with open(output_prefix+ ".priv", "wb") as f:
        b = priv_blob.marshal()
        f.write(b)

    with open(output_prefix+ ".pub", "wb") as f:
        b = pub_blob.marshal()
        f.write(b)

    config = yaml.safe_load(io.StringIO(pobj['config']))
    is_transient = 'esys-tr' not in config
    if not is_transient:
        esys_tr = binascii.unhexlify(config['esys-tr'])
        with open(output_prefix+ ".tr", "wb") as f:
            f.write(esys_tr)

    _dump_outputs(objauth, pobj)

def dump_tsspem(db, obj, pin, is_sopin, output_prefix):

    tokid = obj['tokid']
    pid = db.getpid_by_tokid(tokid)
    pobj = db.getprimary(pid)

    attrs = yaml.safe_load(io.StringIO(obj['attrs']))

    pub_blob = TPM2B_PUBLIC.unmarshal(binascii.unhexlify(attrs[CKA_TPM2_PUB_BLOB]))[0]
    priv_blob = TPM2B_PRIVATE.unmarshal(binascii.unhexlify(attrs[CKA_TPM2_PRIV_BLOB]))[0]
    
    objauth, pobj_handle = getauth(db, obj, pin, is_sopin, attrs)    

    with ESAPI(os.getenv('TPM2TOOLS_TCTI', None)) as e:
        tr_handle = ESYS_TR.deserialize(e, pobj_handle)
        
        tpm_handle = e.tr_get_tpm_handle(tr_handle)

    key = TSSPrivKey(priv_blob, pub_blob, empty_auth=len(objauth) == 0,
                     parent=tpm_handle)

    with open(output_prefix + ".pem", "wb") as f:
        f.write(key.to_pem())

    _dump_outputs(objauth, pobj)

def dump_pubpem(db, obj, pin, is_sopin, output_prefix):
    
    attrs = yaml.safe_load(io.StringIO(obj['attrs']))
    
    pub_blob = TPM2B_PUBLIC.unmarshal(binascii.unhexlify(attrs[CKA_TPM2_PUB_BLOB]))[0]

    with open(output_prefix + ".pem", "wb") as f:
        f.write(pub_blob.to_pem())

def get_serialized_tr(tpm2_handle):

    with ESAPI(os.getenv('TPM2TOOLS_TCTI', None)) as e:
        esys_tr = e.tr_from_tpmpublic(tpm2_handle)
        serialized_buffer = e.tr_serialize(esys_tr)
        hex_string = binascii.hexlify(serialized_buffer).decode()
        
        return hex_string
    
