# python stdlib dependencies
import binascii
import os
import sys
import yaml

# local imports
from .command import Command
from .command import commandlet
from .db import Db
from .utils import bytes_to_file
from .utils import AESAuthUnwrapper
from .utils import TemporaryDirectory
from .utils import hash_pass
from .utils import rand_hex_str
from .utils import get_ec_params
from .utils import asn1_format_ec_point_uncompressed

from .tpm2 import Tpm2

from .pkcs11t import *  # noqa


class NewKeyCommandBase(Command):
    '''
    creates a key to a token within a tpm2-pkcs11 store.
    '''

    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--id',
            help='The key id. Defaults to a random 8 bytes of hex.\n',
            default=binascii.hexlify(os.urandom(8)).decode())
        group_parser.add_argument(
            '--attr-always-authenticate',
            action='store_true',
            help='Sets the CKA_ALWAYS_AUTHENTICATE attribute to CK_TRUE.\n')
        pinopts = group_parser.add_mutually_exclusive_group(required=True)
        pinopts.add_argument('--sopin', help='The Administrator pin.\n'),
        pinopts.add_argument('--userpin', help='The User pin.\n'),

    # Implemented by derived class
    def new_key_create(self, pobj, objauth, tpm2, path, alg, privkey, d):
        raise NotImplementedError('Implement: new_key')

    @staticmethod
    def new_key_init(label, sopin, userpin, pobj, sealobjects, tpm2, d):

        tr_handle = bytes_to_file(pobj['handle'], d)

        # Get the primary object encrypted auth value and sokey information
        # to decode it. Based on the incoming pin
        is_so = sopin != None
        pin = sopin if is_so else userpin

        pubkey = '%spub' % ('so' if is_so else 'user')
        privkey = '%spriv' % ('so' if is_so else 'user')
        saltkey = '%sauthsalt' % ('so' if is_so else 'user')

        sealpub = sealobjects[pubkey]
        sealpriv = sealobjects[privkey]
        sealsalt = sealobjects[saltkey]

        sealctx = tpm2.load(tr_handle, pobj['objauth'], sealpriv, sealpub)

        sealauth = hash_pass(pin, salt=sealsalt)['hash']

        wrappingkey = tpm2.unseal(sealctx, sealauth)

        wrapper = AESAuthUnwrapper(wrappingkey)

        #create an auth value for the tertiary object.
        objauth = rand_hex_str()

        encobjauth = wrapper.wrap(objauth)

        return (encobjauth, objauth)

    @staticmethod
    def new_key_save(alg, keylabel, tid, label, tertiarypriv, tertiarypub,
                     tertiarypubdata, encobjauth, objauth, db, tpm2, extra_privattrs=None, extra_pubattrs=None):
        token = db.gettoken(label)

        #
        # Cache the objects attributes from the public structure and other sources
        # and populate the db with the data. This allows use of the public data
        # without needed to load any objects which requires a pin to do.
        #
        y = yaml.safe_load(tertiarypubdata)

        pubattrs = None
        privattrs = None

        if alg.startswith('rsa'):
            pubattrs = [
                {
                    CKA_KEY_TYPE: CKK_RSA
                },
                {
                    CKA_CLASS: CKO_PUBLIC_KEY
                },
                {
                    CKA_VERIFY: True
                },
                {
                    CKA_ENCRYPT: True
                },
                {
                    CKA_VERIFY_RECOVER: False
                },
                {
                    CKA_WRAP: False
                },
                {
                    CKA_TRUSTED: False
                },
            ]

            privattrs = [
                {
                    CKA_KEY_TYPE: CKK_RSA
                },
                {
                    CKA_CLASS: CKO_PRIVATE_KEY
                },
                {
                    CKA_MODULUS_BITS: y['bits']
                },
                {
                    CKA_SIGN: True
                },
                {
                    CKA_DECRYPT: True
                },
                {
                    CKA_SIGN_RECOVER : False
                },
                {
                    CKA_UNWRAP : False
                },
                {
                    CKA_WRAP_WITH_TRUSTED : False
                },
            ]

            moddetails = [{
                CKA_MODULUS: y['rsa']
            }, {
                CKA_MODULUS_BITS: y['bits']
            }, {
                CKA_PUBLIC_EXPONENT: 65537
            }]

            pubattrs.extend(moddetails)
            privattrs.extend(moddetails)

            pubmech = [{
                CKM_RSA_X_509: ""
            }, {
                CKM_RSA_PKCS_OAEP: {
                    "hashalg": CKM_SHA_1,
                    "mgf": CKG_MGF1_SHA1
                }
            }, {
                CKM_RSA_PKCS_OAEP: {
                    "hashalg": CKM_SHA256,
                    "mgf": CKG_MGF1_SHA256
                }
            }, {
                CKM_RSA_PKCS: ""
            }]

            privmech = [{
                CKM_RSA_X_509: ""
            }, {
                CKM_RSA_PKCS_OAEP: {
                    "hashalg": CKM_SHA_1,
                    "mgf": CKG_MGF1_SHA1
                }
            }, {
                CKM_RSA_PKCS_OAEP: {
                    "hashalg": CKM_SHA256,
                    "mgf": CKG_MGF1_SHA256
                }
            }, {
                CKM_RSA_PKCS: ""
            }]
        elif alg.startswith('ecc'):

            ecparams = get_ec_params(alg)
            ecpoint = asn1_format_ec_point_uncompressed(y['x'], y['y'])

            pubattrs = [
                {
                    CKA_KEY_TYPE: CKK_EC
                },
                {
                    CKA_CLASS: CKO_PUBLIC_KEY
                },
                {
                    CKA_EC_PARAMS: ecparams
                },
                {
                    CKA_EC_POINT: ecpoint
                },
                {
                    CKA_VERIFY: True
                },
                {
                    CKA_ENCRYPT: True
                },
                {
                    CKA_VERIFY_RECOVER: False
                },
                {
                    CKA_WRAP: False
                },
                {
                    CKA_TRUSTED: False
                },
            ]

            privattrs = [
                {
                    CKA_KEY_TYPE: CKK_EC
                },
                {
                    CKA_CLASS: CKO_PRIVATE_KEY
                },
                {
                    CKA_EC_PARAMS: ecparams
                },
                {
                    CKA_EC_POINT: ecpoint
                },
                {
                    CKA_SIGN: True
                },
                {
                    CKA_DECRYPT: True
                },
                {
                    CKA_SIGN_RECOVER : False
                },
                {
                    CKA_UNWRAP : False
                },
                {
                    CKA_WRAP_WITH_TRUSTED : False
                },
            ]

            pubmech = [{CKM_ECDSA: ""}]
            privmech = pubmech
        elif alg.startswith('aes'):
            privattrs = [{
                CKA_CLASS: CKO_SECRET_KEY
            }, {
                CKA_KEY_TYPE: CKK_AES
            }, {
                CKA_VALUE_LEN: y['sym-keybits'] / 8
            },
            {
                CKA_ENCRYPT: True
            },
            {
                CKA_DECRYPT: True
            },
            {
                CKA_SIGN: False
            },
            {
                CKA_VERIFY: False
            },
            {
                CKA_WRAP: False
            },
            {
                CKA_UNWRAP: False
            },
            {
                CKA_WRAP_WITH_TRUSTED: False
            },
            ]

            privmech = [{CKM_AES_CBC: ""}, ]
        else:
            sys.exit('Cannot handle algorithm: "{}"'.format(alg))

        # add the id
        privattrs.append({CKA_ID: binascii.hexlify(tid.encode()).decode()})
        if pubattrs:
            pubattrs.append({CKA_ID: binascii.hexlify(tid.encode()).decode()})
            pubattrs.append({CKA_DERIVE: False})

        privattrs.append({CKA_TOKEN: True})
        privattrs.append({CKA_SENSITIVE: True})
        privattrs.append({CKA_ALWAYS_SENSITIVE: True})
        privattrs.append({CKA_EXTRACTABLE: False})
        privattrs.append({CKA_NEVER_EXTRACTABLE: True})
        privattrs.append({CKA_DERIVE: False})

        # Add keylabel for ALL objects if set
        if keylabel is not None:
            privattrs.append({
                CKA_LABEL: binascii.hexlify(keylabel.encode()).decode()
            })
            if pubattrs:
                pubattrs.append({
                    CKA_LABEL: binascii.hexlify(keylabel.encode()).decode()
                })

        # add additional attrs
        if extra_privattrs:
            privattrs.extend(extra_privattrs)

        if pubattrs and extra_pubattrs:
            pubattrs.extend(extra_pubattrs)

        # Store private to database
        privrowid = db.addtertiary(token['id'], tertiarypriv, tertiarypub,
                                   encobjauth, privmech, privattrs)

        # if it's asymmetric, add a public object too
        if pubattrs:
            pubrowid = db.addtertiary(token['id'], None, tertiarypub,
                                      encobjauth, pubmech, pubattrs)

        # if the keylabel is not set, use the tertiary object tid as the keylabel
        # Normally we would use a transaction to make this atomic, but Pythons
        # sqlite3 transaction handling is quite odd. So when the keylabel is None, just insert
        # into the db without that attribute, retrieve the primary key, and then issue an
        # update. A possible race exists if someone is looking for the key by label between
        # these operations.
        # See:
        #   - https://stackoverflow.com/questions/107005/predict-next-auto-inserted-row-tid-sqlite
        if keylabel is None:
            keylabel = str(privrowid)
            privattrs.append({
                CKA_LABEL: binascii.hexlify(keylabel.encode()).decode()
            })
            db.updatetertiaryattrs(privrowid, privattrs)
            if pubattrs:
                pubattrs.append({
                    CKA_LABEL: binascii.hexlify(keylabel.encode()).decode()
                })
                db.updatetertiaryattrs(pubrowid, pubattrs)

        db.commit()

        return keylabel

    def __call__(self, args):
        path = args['path']

        with Db(path) as db:

            with TemporaryDirectory() as d:
                tpm2 = Tpm2(d)

                label = args['label']
                sopin = args['sopin']
                userpin = args['userpin']
                alg = args['algorithm']
                key_label = args['key_label']
                tid = args['id']

                privkey = None
                try:
                    privkey = args['privkey']
                except KeyError:
                    privkey = None

                path = args['path']

                token = db.gettoken(label)
                pobjectid = token['pid']
                pobj = db.getprimary(pobjectid)

                sealobjects = db.getsealobject(token['id'])

                encobjauth, objauth = NewKeyCommandBase.new_key_init(
                    label, sopin, userpin, pobj, sealobjects, tpm2, d)

                tertiarypriv, tertiarypub, tertiarypubdata = self.new_key_create(
                    pobj, objauth, tpm2, path, alg, privkey, d)

                # handle options that can add additional attributes
                priv_attrs = None
                always_auth = args['attr_always_authenticate']
                priv_attrs = [{CKA_ALWAYS_AUTHENTICATE : always_auth}]

                final_key_label = NewKeyCommandBase.new_key_save(
                    alg, key_label, tid, label, tertiarypriv, tertiarypub,
                    tertiarypubdata, encobjauth, objauth, db, tpm2, extra_privattrs=priv_attrs)

                return final_key_label


@commandlet("import")
class ImportCommand(NewKeyCommandBase):
    '''
    Imports a rsa key to a token within a tpm2-pkcs11 store.
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        super(ImportCommand, self).generate_options(group_parser)
        group_parser.add_argument(
            '--privkey',
            help='Full path of the private key to be imported.\n',
            required=True)
        group_parser.add_argument(
            '--label',
            help='The tokens label to import the key too.\n',
            required=True)
        group_parser.add_argument(
            '--key-label',
            help='The label of the key imported. Defaults to an integer value.\n'
        )
        group_parser.add_argument(
            '--algorithm',
            help='The type of the key.\n',
            choices=['rsa'],
            required=True)

    # Imports a new key
    def new_key_create(self, pobj, objauth, tpm2, path, alg, privkey, d):
        if alg != 'rsa':
            sys.exit('Unknown algorithm or algorithm not supported, got "%s"' %
                     alg)

        if privkey is None:
            sys.exit("Invalid private key path")

        tr_handle = bytes_to_file(pobj['handle'], d)

        tertiarypriv, tertiarypub, tertiarypubdata = tpm2.importkey(
            tr_handle, pobj['objauth'], objauth, privkey=privkey, alg=alg)

        return (tertiarypriv, tertiarypub, tertiarypubdata)

    def __call__(self, args):
        keylabel = super(ImportCommand, self).__call__(args)
        print('Imported key as label: "{keylabel}"'.format(keylabel=keylabel))


@commandlet("addkey")
class AddKeyCommand(NewKeyCommandBase):
    '''
    Adds a key to a token within a tpm2-pkcs11 store.
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        super(AddKeyCommand, self).generate_options(group_parser)
        group_parser.add_argument(
            '--label',
            help='The tokens label to add a key too.\n',
            required=True)
        group_parser.add_argument(
            '--algorithm',
            help='The type of the key.\n',
            choices=[
                'rsa1024', 'rsa2048', 'aes128', 'aes256', 'ecc224', 'ecc256',
                'ecc384', 'ecc521'
            ],
            required=True)
        group_parser.add_argument(
            '--key-label',
            help='The key label to identify the key. Defaults to an integer value.\n'
        )

    # Creates a new key
    def new_key_create(self, pobj, objauth, tpm2, path, alg, privkey, d):

        tr_handle = bytes_to_file(pobj['handle'], d)

        tertiarypriv, tertiarypub, tertiarypubdata = tpm2.create(
            tr_handle, pobj['objauth'], objauth, alg=alg)

        return (tertiarypriv, tertiarypub, tertiarypubdata)

    def __call__(self, args):
        keylabel = super(AddKeyCommand, self).__call__(args)
        print('Added key as label: "{keylabel}"'.format(keylabel=keylabel))
