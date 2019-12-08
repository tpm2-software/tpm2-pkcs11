# python stdlib dependencies
import binascii
import io
import os
import sys
import yaml

# local imports
from .command import Command
from .command import commandlet
from .db import Db
from .objects import PKCS11ObjectFactory as PKCS11ObjectFactory
from .objects import PKCS11X509
from .utils import bytes_to_file
from .utils import AESAuthUnwrapper
from .utils import TemporaryDirectory
from .utils import hash_pass
from .utils import rand_hex_str
from .utils import pemcert_to_attrs

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
    def new_key_save(alg, keylabel, tid, label, privblob, pubblob,
                     tertiarypubdata, encobjauth, db, tpm2, extra_privattrs=None, extra_pubattrs=None):
        token = db.gettoken(label)

        #
        # Cache the objects attributes from the public structure and other sources
        # and populate the db with the data. This allows use of the public data
        # without needed to load any objects which requires a pin to do.
        #
        y = yaml.safe_load(tertiarypubdata)

        initial_pubattrs = {}
        initial_privattrs = {}

        # add the id
        initial_privattrs.update({CKA_ID: binascii.hexlify(tid.encode()).decode()})
        initial_pubattrs.update({CKA_ID: binascii.hexlify(tid.encode()).decode()})

        # Add keylabel for ALL objects if set
        if keylabel is not None:
            initial_privattrs.update({
                CKA_LABEL: binascii.hexlify(keylabel.encode()).decode()
            })
            initial_pubattrs.update({
                CKA_LABEL: binascii.hexlify(keylabel.encode()).decode()
            })

        # add additional attrs
        if extra_privattrs:
            initial_privattrs.update(extra_privattrs)

        if initial_pubattrs and extra_pubattrs:
            initial_pubattrs.update(extra_pubattrs)

        objects = PKCS11ObjectFactory(y, tpm2, encobjauth, initial_pubattrs, initial_privattrs, tpm_pub=pubblob, tpm_priv=privblob)

        # Store private to database
        db.addtertiary(token['id'], objects['private'])

        # if it's asymmetric, add a public object too
        if 'public' in objects and objects['public'] is not None:
            db.addtertiary(token['id'], objects['public'])

        return objects

    @staticmethod
    def output(objects, action):
        d = {
            'action' : action,
        }

        for k, v in objects.items():
            if v is not None:
                d[k] = { 'CKA_ID' : objects[k][CKA_ID] }

        yaml.safe_dump(d, sys.stdout, default_flow_style=False)

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
                always_auth = args['attr_always_authenticate']
                priv_attrs = {CKA_ALWAYS_AUTHENTICATE : always_auth}

                return NewKeyCommandBase.new_key_save(
                    alg, key_label, tid, label, tertiarypriv, tertiarypub,
                    tertiarypubdata, encobjauth, db, tpm2, extra_privattrs=priv_attrs)


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
        objects = super(ImportCommand, self).__call__(args)
        NewKeyCommandBase.output(objects, 'import')

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
        objects = super(AddKeyCommand, self).__call__(args)
        NewKeyCommandBase.output(objects, 'add')


@commandlet("addcert")
class AddCert(Command):
    '''
    Adds a certificate object
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--label', help='The profile label to remove.\n', required=True)

        group_parser.add_argument(
            'cert', help='The x509 PEM certificate to add.\n')

        sub_group = group_parser.add_mutually_exclusive_group()

        sub_group.add_argument(
            '--key-label',
            help='The associated private key label.\n')

        group_parser.add_argument(
            '--key-id',
            help='The associated private key id in hex.\n')


    def __call__(self, args):

        path = args['path']
        label = args['label']
        keylabel = args['key_label']
        keyid = args['key_id']
        certpath = args['cert']

        if (keylabel is None) == (keyid is None):
            sys.exit('Expected --key-label or --key-id to be specified')

        attrs = pemcert_to_attrs(certpath)

        pkcs11_object = PKCS11X509(attrs)

        with Db(path) as db:

            # get token to add to
            token = db.gettoken(label)

            # verify that key is existing
            # XXX we should be verifying that it's expected, but I guess one could always load up a cert
            # not associated with a key.
            tobjs = db.gettertiary(token['id'])

            # look up the private key
            missing_id_or_label = None
            for t in tobjs:
                if keylabel is not None:
                    missing_id_or_label = AddCert.get_id_by_label(t, keylabel)
                else:
                    missing_id_or_label = AddCert.get_label_by_id(t, keyid)
                if missing_id_or_label is not None:
                    break

            if missing_id_or_label is None:
                raise RuntimeError('Cannot find key with id "%s"' % keylabel)

            # have valid keylabel needed id
            if keylabel:
                pkcs11_object.update({CKA_ID: missing_id_or_label})
                pkcs11_object.update({CKA_LABEL: missing_id_or_label})
            # have valid id needed keylabel
            else:
                pkcs11_object.update({CKA_LABEL: missing_id_or_label})
                pkcs11_object.update({CKA_ID: keyid})

            # TODO verify that cert is cryptographically bound to key found

            # add the cert
            db.addtertiary(token['id'], pkcs11_object)

        NewKeyCommandBase.output({'cert' : pkcs11_object}, 'add')

    @staticmethod
    def get_id_by_label(tobj, keylabel):

        attrs = yaml.safe_load(io.StringIO(tobj['attrs']))

        if CKA_LABEL in attrs:
            x = attrs[CKA_LABEL]
            x = binascii.unhexlify(x).decode()
            if x == keylabel:
                return attrs[CKA_ID]

        return None

    @staticmethod
    def get_label_by_id(tobj, keyid):

        attrs = yaml.safe_load(io.StringIO(tobj['attrs']))

        if CKA_ID in attrs:
            x = attrs[CKA_ID]
            if x == keyid:
                return attrs[CKA_LABEL] if CKA_LABEL in attrs else ''

        return None