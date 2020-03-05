# SPDX-License-Identifier: BSD-2-Clause
# python stdlib dependencies
import binascii
import io
import sys

# External dependencies
import yaml

# local imports
from .command import Command
from .command import commandlet
from .db import Db
from .utils import bytes_to_file
from .utils import TemporaryDirectory
from .utils import hash_pass
from .utils import rand_hex_str
from .utils import AESAuthUnwrapper
from .utils import load_sealobject
from .utils import pkcs11_cko_to_str
from .utils import pkcs11_ckk_to_str
from .tpm2 import Tpm2

from .pkcs11t import *  # noqa

@commandlet("rmtoken")
class RmTokenCommand(Command):
    '''
    Removes a token from a tpm2-pkcs11 store
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--label', help='The profile label to remove.\n', required=True)

    def __call__(self, args):

        path = args['path']
        label = args['label']

        with Db(path) as db:
            token = db.gettoken(label)
            db.rmtoken(token['label'])


@commandlet("verify")
class VerifyCommand(Command):
    '''
    Verifies the userpin and/or sopin for a given profile.
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--sopin',
            help='The Administrator pin. This pin is used for object recovery.\n'
        )
        group_parser.add_argument(
            '--userpin',
            help='The user pin. This pin is used for authentication for object use.\n'
        )
        group_parser.add_argument(
            '--label', help='The label to verify.\n', required=True)

    @staticmethod
    def verify(db, args):

        label = args['label']

        token = db.gettoken(label)
        if token is None:
            sys.exit('No token labeled "%s"' % label)

        sopin = args['sopin']
        userpin = args['userpin']

        verify_output = {}
        verify_output['label'] = label

        pobj = db.getprimary(token['pid'])
        sealobj = db.getsealobject(token['id'])

        wrappingkeyauth = None

        verify_output['config'] = yaml.safe_load(io.StringIO(token['config']))

        verify_output['pin'] = {}

        with TemporaryDirectory() as d:
            tpm2 = Tpm2(d)

            pobjauth = pobj['objauth']
            tr_handle = bytes_to_file(pobj['handle'], d)

            if sopin != None:

                sosealctx = tpm2.load(tr_handle, pobjauth,
                                      sealobj['sopriv'], sealobj['sopub'])

                # Unseal the wrapping key auth
                sosealauthsalt = sealobj['soauthsalt']

                sosealauth = hash_pass(sopin, salt=sosealauthsalt)

                wrappingkeyauth = tpm2.unseal(sosealctx, sosealauth['hash'])

                verify_output['pin']['so'] = {'seal-auth' : sosealauth['hash'] }

            if userpin != None:

                usersealctx = tpm2.load(tr_handle, pobjauth,
                                        sealobj['userpriv'],
                                        sealobj['userpub'])

                # Unseal the wrapping key auth
                usersealauthsalt = sealobj['userauthsalt']

                usersealauth = hash_pass(userpin, salt=usersealauthsalt)

                wrappingkeyauth = tpm2.unseal(usersealctx,
                                              usersealauth['hash'])

                verify_output['pin']['user'] = {'seal-auth' : usersealauth['hash'] }

            wrapper = AESAuthUnwrapper(wrappingkeyauth)

            tobjs = db.gettertiary(token['id'])

            verify_output['objects'] = []

            for tobj in tobjs:

                attrs = yaml.safe_load(tobj['attrs'])

                priv=None
                if CKA_TPM2_PRIV_BLOB in attrs:
                    priv = binascii.unhexlify(attrs[CKA_TPM2_PRIV_BLOB])

                pub = None
                if CKA_TPM2_PUB_BLOB in attrs:
                    pub = binascii.unhexlify(attrs[CKA_TPM2_PUB_BLOB])

                encauth = None
                if CKA_TPM2_OBJAUTH_ENC in attrs:
                    encauth = binascii.unhexlify(attrs[CKA_TPM2_OBJAUTH_ENC])

                tobjauth=None
                if encauth:
                    encauth=encauth.decode()
                    tpm2.load(tr_handle, pobjauth, priv, pub)
                    tobjauth = wrapper.unwrap(encauth).decode()

                verify_output['objects'].append({
                    'id: ' : tobj['id'],
                    'auth: ' : tobjauth
                })

        yaml_dump = yaml.safe_dump(verify_output, default_flow_style=False)
        print(yaml_dump)

    def __call__(self, args):
        if args['userpin'] is None and args['sopin'] is None:
            sys.exit("Expected one or both of sopin or userpin")

        with Db(args['path']) as db:
            VerifyCommand.verify(db, args)


@commandlet("addtoken")
class AddTokenCommand(Command):
    '''
    Adds an initialized token to a tpm2-pkcs11 store
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--pid',
            type=int,
            help='The primary object id to associate with this token.\n',
            required=True),
        group_parser.add_argument(
            '--sopin',
            help='The Administrator pin. This pin is used for object recovery.\n',
            required=True),
        group_parser.add_argument(
            '--userpin',
            help='The user pin. This pin is used for authentication for object use.\n',
            required=True),
        group_parser.add_argument(
            '--label',
            help='A unique label to identify the profile in use, must be unique.\n',
            required=True)

    @staticmethod
    def do_token_init(db, path, args):

        userpin = args['userpin']
        sopin = args['sopin']
        label = args['label']
        pid = args['pid']

        # Verify pid is in db
        pobject = db.getprimary(pid)

        with TemporaryDirectory() as d:
            tpm2 = Tpm2(d)

            # generate a wrapping key to be sealed to the TPM.
            # AES 256 key is 32 bytes, or 64 hex chars.
            wrappingkey = rand_hex_str(64)

            # We generate one auth for the sosealobj and the usersealobj
            sosealauth = hash_pass(sopin)
            usersealauth = hash_pass(userpin)

            # Now we generate the two seal objects, using the sealauths as their
            # auth values and sealing the wrappingkey value to it.
            # soobject will be an AES key used for decrypting tertiary object
            # auth values.

            tr_handle = bytes_to_file(pobject['handle'], d)

            usersealpriv, usersealpub, _ = tpm2.create(
                tr_handle,
                pobject['objauth'],
                usersealauth['hash'],
                seal=wrappingkey)
            sosealpriv, sosealpub, _ = tpm2.create(
                tr_handle,
                pobject['objauth'],
                sosealauth['hash'],
                seal=wrappingkey)

            # If this succeeds, we update the token table
            config = {'token-init': True}
            tokid = db.addtoken(pobject['id'], config, label=label)

            # now we update the sealobject table with the tokid to seal objects mapping
            db.addsealobjects(tokid, usersealauth, usersealpriv, usersealpub,
                              sosealauth, sosealpriv, sosealpub)

    @staticmethod
    def do_token_noninit(db, args):

        pid = args['pid']

        pobject = db.getprimary(pid)

        config = [{'token-init': False}]

        db.addtoken(pobject['id'], config)

    def __call__(self, args):

        path = args['path']
        do_token_init = not args.get('no_init', False)

        with Db(path) as db:

            if do_token_init:
                AddTokenCommand.do_token_init(db, path, args)
            else:
                AddTokenCommand.do_token_noninit(db, args)

@commandlet("addemptytoken")
class AddEmptyTokenCommand(AddTokenCommand):
    '''
    Adds an un-initialized token to a tpm2-pkcs11 store.
    '''

    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--pid',
            type=int,
            help='The primary object id to associate with this token.\n',
            required=True),
        group_parser.add_argument(
            '--pobj-pin',
            help='The primary object password. This password is use for authentication to the primary object.\n',
            default="")
        group_parser.add_argument(
            "--wrap",
            choices=['auto', 'software', 'tpm'],
            default='auto',
            help='Configure usage of SW based crypto for internal object protection.\n'
            +
            'This is not recommended for production environments,as the tool will'
            + 'auto-configure this option based on TPM support.')

    def __call__(self, args):
        args['no_init'] = True
        super(AddEmptyTokenCommand, self).__call__(args)


@commandlet("changepin")
class ChangePinCommand(Command):
    '''
    Changes the userpin and/or sopin for a given token.
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--user',
            choices=['so', 'user'],
            default='user',
            help='Which pin to change. Defaults to "user".\n')
        group_parser.add_argument(
            '--old', type=str, help='The old pin.\n', required=True)
        group_parser.add_argument(
            '--new', type=str, help='The new pin.\n', required=True)
        group_parser.add_argument(
            '--label',
            type=str,
            help='The label of the token.\n',
            required=True)

    @staticmethod
    def changepin(db, tpm2, args):

        label = args['label']

        is_so = args['user'] == 'so'
        oldpin = args['old']
        newpin = args['new']

        token = db.gettoken(label)

        pobjectid = token['pid']
        pobject = db.getprimary(pobjectid)
        pobjauth = pobject['objauth']

        with TemporaryDirectory() as d:

            tr_handle = bytes_to_file(pobject['handle'], d)

            sealctx, sealauth = load_sealobject(token, db, tpm2, tr_handle, pobjauth,
                                                      oldpin, is_so)

            newsealauth = hash_pass(newpin)

            # call tpm2_changeauth and get new private portion
            newsealpriv = tpm2.changeauth(tr_handle, sealctx, sealauth,
                                          newsealauth['hash'])

        # update the database
        db.updatepin(is_so, token, newsealauth, newsealpriv)

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            with TemporaryDirectory() as d:
                tpm2 = Tpm2(d)
                ChangePinCommand.changepin(db, tpm2, args)


@commandlet("initpin")
class InitPinCommand(Command):
    '''
    Resets the userpin given a sopin for a given token.
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--sopin', type=str, help='The current sopin.\n', required=True)
        group_parser.add_argument(
            '--userpin', type=str, help='The new user pin.\n', required=True)
        group_parser.add_argument(
            '--label',
            type=str,
            help='The label of the token.\n',
            required=True)

    @staticmethod
    def initpin(db, tpm2, args):

        label = args['label']

        sopin = args['sopin']
        newpin = args['userpin']

        token = db.gettoken(label)

        # load and unseal the data from the SO seal object
        pobjectid = token['pid']
        pobject = db.getprimary(pobjectid)
        pobjauth = pobject['objauth']

        with TemporaryDirectory() as d:

            tr_handle = bytes_to_file(pobject['handle'], d)

            sealctx, sealauth = load_sealobject(token, db, tpm2, tr_handle, pobjauth,
                                                  sopin, True)
            wrappingkeyauth = tpm2.unseal(sealctx, sealauth)

            # call tpm2_create and create a new sealobject protected by the seal auth and sealing
            #    the wrapping key auth value
            newsealauth = hash_pass(newpin)


            newsealpriv, newsealpub, _ = tpm2.create(
                tr_handle,
                pobjauth,
                newsealauth['hash'],
                seal=wrappingkeyauth)

        # update the database
        db.updatepin(False, token, newsealauth, newsealpriv, newsealpub)

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            with TemporaryDirectory() as d:
                tpm2 = Tpm2(d)
                InitPinCommand.initpin(db, tpm2, args)

@commandlet("listprimaries")
class ListPrimaryCommand(Command):
    '''
    Lists primary objects in  a specified store.
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        pass

    @staticmethod
    def list(db):
        output=[]
        primaries = db.getprimaries()
        for p in primaries:
            output.append({'id': p['id']})

        if len(output):
            print(yaml.safe_dump(output, default_flow_style=False))

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            ListPrimaryCommand.list(db)

@commandlet("listtokens")
class ListTokenCommand(Command):
    '''
    Lists tokens in  a specified store.
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--pid',
            type=int,
            help='The primary object id to associate with this token.\n',
            required=True),

    @staticmethod
    def list(db, args):
        output = []
        tokens = db.gettokens(args['pid'])

        for t in tokens:
            output.append({
                'id': t['id'],
                'label': t['label']
            })

        if len(output):
            print(yaml.safe_dump(output, default_flow_style=False))

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            ListTokenCommand.list(db, args)

@commandlet("listobjects")
class ListObjectsCommand(Command):
    '''
    Lists Objects (keys, certificates, etc.) associated with a token.
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--label',
            type=str,
            help='The label of the token.\n',
            required=True)

    @staticmethod
    def list(db, args):
        output = []
        token = db.gettoken(args['label'])
        objects = db.getobjects(token['id'])
        for o in objects:
            y = yaml.safe_load(o['attrs'])
            d = {
                'id': o['id'],
                'CKA_ID' : y[CKA_ID],
                'CKA_LABEL' : binascii.unhexlify(y[CKA_LABEL]).decode(),
                'CKA_CLASS' : pkcs11_cko_to_str(y[CKA_CLASS]),
            }

            if CKA_KEY_TYPE in y:
                d['CKA_KEY_TYPE'] = pkcs11_ckk_to_str(y[CKA_KEY_TYPE])

            output.append(d)

        if len(output):
            print(yaml.safe_dump(output, default_flow_style=False))

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            ListObjectsCommand.list(db, args)
