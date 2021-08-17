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
from .utils import check_pss_signature
from .utils import TemporaryDirectory
from .utils import hash_pass
from .utils import rand_hex_str
from .utils import AESAuthUnwrapper
from .utils import load_sealobject
from .utils import str2bool
from .utils import pkcs11_cko_to_str
from .utils import pkcs11_ckk_to_str
from .utils import get_pobject
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
        group_parser.add_argument(
            '--hierarchy-auth',
            help='The authorization password for the owner hierarchy when using a token with a transient primary object\n',
            default="")
    @staticmethod
    def verify(db, args):

        label = args['label']

        token = db.gettoken(label)
        if token is None:
            sys.exit('No token labeled "%s"' % label)

        token_config = yaml.safe_load(io.StringIO(token['config']))

        sopin = args['sopin']
        userpin = args['userpin']
        hierarchyauth = args['hierarchy_auth']

        if userpin is None and sopin is None:
            # Use empty PIN if the token has an empty user PIN
            if token_config.get('empty-user-pin'):
                userpin = ''
            else:
                sys.exit('error: at least one of the arguments --sopin --userpin is required')

        verify_output = {}
        verify_output['label'] = label

        pobj = db.getprimary(token['pid'])
        sealobj = db.getsealobject(token['id'])

        wrappingkeyauth = None

        verify_output['config'] = token_config

        verify_output['pin'] = {}

        with TemporaryDirectory() as d:
            tpm2 = Tpm2(d)

            pobjauth = pobj['objauth']
            pobj_handle = get_pobject(pobj, tpm2, hierarchyauth, d)

            if sopin != None:

                sosealctx = tpm2.load(pobj_handle, pobjauth,
                                      sealobj['sopriv'], sealobj['sopub'])

                # Unseal the wrapping key auth
                sosealauthsalt = sealobj['soauthsalt']

                sosealauth = hash_pass(sopin, salt=sosealauthsalt)

                wrappingkeyauth = tpm2.unseal(sosealctx, sosealauth['hash'])

                verify_output['pin']['so'] = {'seal-auth' : sosealauth['hash'] }

            if userpin != None:

                usersealctx = tpm2.load(pobj_handle, pobjauth,
                                        sealobj['userpriv'],
                                        sealobj['userpub'])

                # Unseal the wrapping key auth
                usersealauthsalt = sealobj['userauthsalt']

                usersealauth = hash_pass(userpin, salt=usersealauthsalt)

                wrappingkeyauth = tpm2.unseal(usersealctx,
                                              usersealauth['hash'])

                verify_output['pin']['user'] = {'seal-auth' : usersealauth['hash'] }

            verify_output['wrappingkey'] = {
                'hex' : bytes.hex(wrappingkeyauth),
            }
            if userpin != None:
                verify_output['wrappingkey']['auth'] = usersealauth['hash']
            if sopin != None:
                verify_output['wrappingkey']['soauth'] = sosealauth['hash']

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
                    tpm2.load(pobj_handle, pobjauth, priv, pub)
                    tobjauth = wrapper.unwrap(encauth).decode()

                verify_output['objects'].append({
                    'id' : tobj['id'],
                    'auth' : tobjauth,
                    'encauth' : encauth
                })

        yaml_dump = yaml.safe_dump(verify_output, default_flow_style=False)
        print(yaml_dump)

    def __call__(self, args):
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
        group_parser.add_argument(
            '--hierarchy-auth',
            help='The authorization password for the owner hierarchy when using a token with a transient primary object\n',
            default="")
    @staticmethod
    def do_token_init(db, path, args):

        userpin = args['userpin']
        sopin = args['sopin']
        label = args['label']
        pid = args['pid']
        hierarchyauth = args['hierarchy_auth']

        # Verify pid is in db
        pobject = db.getprimary(pid)
        if not pobject:
            raise RuntimeError('No primary object id: %u' % (pid))

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
            pobj_handle = get_pobject(pobject, tpm2, hierarchyauth, d)

            usersealpriv, usersealpub, _ = tpm2.create(
                pobj_handle,
                pobject['objauth'],
                usersealauth['hash'],
                seal=wrappingkey)
            sosealpriv, sosealpub, _ = tpm2.create(
                pobj_handle,
                pobject['objauth'],
                sosealauth['hash'],
                seal=wrappingkey)

            pss_sig_good = check_pss_signature(tpm2, pobj_handle, pobject['objauth'])

            # If this succeeds, we update the token table
            config = {
                'token-init': True,
                'pss-sigs-good' : pss_sig_good
            }
            if userpin == '':
                config['empty-user-pin'] = True
            tokid = db.addtoken(pobject['id'], config, label=label)

            # now we update the sealobject table with the tokid to seal objects mapping
            db.addsealobjects(tokid, usersealauth, usersealpriv, usersealpub,
                              sosealauth, sosealpriv, sosealpub)

    @staticmethod
    def do_token_noninit(db, args):

        pid = args['pid']
        hierarchyauth = args['hierarchy_auth']

        with TemporaryDirectory() as d:
            tpm2 = Tpm2(d)

            pobject = db.getprimary(pid)

            pobjauth = pobject['objauth']

            pobj_handle = get_pobject(pobject, tpm2, hierarchyauth, d)

            pss_sig_good = check_pss_signature(tpm2, pobj_handle, pobjauth)

            # If this succeeds, we update the token table
            config = {
                'token-init': False,
                'pss-sigs-good' : pss_sig_good
            }

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
            '--hierarchy-auth',
            help='The authorization password for the owner hierarchy when using a token with a transient primary object\n',
            default="")

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
            '--old', type=str, help='The old pin.\n')
        group_parser.add_argument(
            '--new', type=str, help='The new pin.\n', required=True)
        group_parser.add_argument(
            '--label',
            type=str,
            help='The label of the token.\n',
            required=True)
        group_parser.add_argument(
            '--hierarchy-auth',
            help='The authorization password for the owner hierarchy when using a token with a transient primary object\n',
            default="")

    @staticmethod
    def changepin(db, tpm2, args):

        label = args['label']

        is_so = args['user'] == 'so'
        oldpin = args['old']
        newpin = args['new']
        hierarchyauth = args['hierarchy_auth']

        token = db.gettoken(label)
        token_config = yaml.safe_load(io.StringIO(token['config']))
        if oldpin is None:
            if is_so:
                sys.exit('error: the SO PIN is missing, argument --old is required')
            # Use empty PIN if the token has an empty user PIN
            if token_config.get('empty-user-pin'):
                oldpin = ''
            else:
                sys.exit('error: the user PIN is missing, argument --old is required')

        pobjectid = token['pid']
        pobject = db.getprimary(pobjectid)
        pobjauth = pobject['objauth']

        with TemporaryDirectory() as d:

            pobj_handle = get_pobject(pobject, tpm2, hierarchyauth, d)

            sealctx, sealauth = load_sealobject(token, db, tpm2, pobj_handle, pobjauth,
                                                      oldpin, is_so)

            newsealauth = hash_pass(newpin)

            # call tpm2_changeauth and get new private portion
            newsealpriv = tpm2.changeauth(pobj_handle, sealctx, sealauth,
                                          newsealauth['hash'])

        # update 'empty-user-pin' in a safe way: clear it before setting a
        # non-empty PIN and set it after setting an empty PIN
        if not is_so and newpin != '' and token_config.get('empty-user-pin'):
            del token_config['empty-user-pin']
            db.updateconfig(token, token_config)

        # update the database
        db.updatepin(is_so, token, newsealauth, newsealpriv)

        if not is_so and newpin == '' and not token_config.get('empty-user-pin'):
            token_config['empty-user-pin'] = True
            db.updateconfig(token, token_config)

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
        group_parser.add_argument(
            '--hierarchy-auth',
            help='The authorization password for the owner hierarchy when using a token with a transient primary object\n',
            default="")

    @staticmethod
    def initpin(db, tpm2, args):

        label = args['label']

        sopin = args['sopin']
        newpin = args['userpin']

        token = db.gettoken(label)
        token_config = yaml.safe_load(io.StringIO(token['config']))

        # load and unseal the data from the SO seal object
        pobjectid = token['pid']
        pobject = db.getprimary(pobjectid)
        pobjauth = pobject['objauth']
        hierarchyauth = args['hierarchy_auth']

        with TemporaryDirectory() as d:

            pobj_handle = get_pobject(pobject, tpm2, hierarchyauth, d)

            sealctx, sealauth = load_sealobject(token, db, tpm2, pobj_handle, pobjauth,
                                                  sopin, True)
            wrappingkeyauth = tpm2.unseal(sealctx, sealauth)

            # call tpm2_create and create a new sealobject protected by the seal auth and sealing
            #    the wrapping key auth value
            newsealauth = hash_pass(newpin)

            newsealpriv, newsealpub, _ = tpm2.create(
                pobj_handle,
                pobjauth,
                newsealauth['hash'],
                seal=wrappingkeyauth)

        # update 'empty-user-pin' in a safe way
        if newpin != '' and token_config.get('empty-user-pin'):
            del token_config['empty-user-pin']
            db.updateconfig(token, token_config)

        # update the database
        db.updatepin(False, token, newsealauth, newsealpriv, newsealpub)

        if newpin == '' and not token_config.get('empty-user-pin'):
            token_config['empty-user-pin'] = True
            db.updateconfig(token, token_config)

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            with TemporaryDirectory() as d:
                tpm2 = Tpm2(d)
                InitPinCommand.initpin(db, tpm2, args)

@staticmethod
def _empty_validator(s):
    return s


def _forbid_set_empty_user_pin(_):
    raise RuntimeError("'empty-user-pin' can only be set with changepin or initpin")


@commandlet("config")
class ConfigCommand(Command):
    '''
    Manipulates and retrieves token configuration data.
    '''
    _keys = {
        'token-init' : str2bool,
        'log-level'  : _empty_validator.__func__,
        'tcti'       : _empty_validator.__func__,
        'empty-user-pin': _forbid_set_empty_user_pin,
    }

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--key', type=str, help='The key to set, valid keys are: %s.\n' % self._keys.keys())
        group_parser.add_argument(
            '--value', type=str, help='The value for the key.\n')
        group_parser.add_argument(
            '--label',
            type=str,
            help='The label of the token.\n',
            required=True)

    @classmethod
    def get_validator_for_key(cls, key):
        return cls._keys[key]

    @classmethod
    def config(cls, db, args):

        label = args['label']

        key = args['key']
        value = args['value']

        token = db.gettoken(label)

        token_config = yaml.safe_load(io.StringIO(token['config']))
        if not key and not value:
            yaml_tok_cconf = yaml.safe_dump(token_config, default_flow_style=False)
            print(yaml_tok_cconf)
            sys.exit(0)

        if not key and value:
            sys.exit("Cannot specify --value without a key")

        if key == 'log-level':
            print('WARN --key="log-level is deprecated', file=sys.stderr)

        # key has to be set here based on above logical check
        # throws an error if the key isn't known to the system
        validator = cls.get_validator_for_key(key)

        # no value, just key. Print the current value for key is set or empty if not set
        if not value:
            print("%s=%s" % (key, str(token_config[key] if key in token_config else "")))
            sys.exit(0)

        # bitbucket log-level sets
        if key == 'log-level':
            print('WARN --key="log-level is ignored', file=sys.stderr)
            return

        v = validator(value)
        token_config[key] = v

        # update the database
        db.updateconfig(token, token_config)

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            ConfigCommand.config(db, args)

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
            details = {'id': p['id']}
            details['config'] = yaml.safe_load(p['config'])
            output.append(details)

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
                'CKA_LABEL' : binascii.unhexlify(y[CKA_LABEL]).decode(),
                'CKA_CLASS' : pkcs11_cko_to_str(y[CKA_CLASS]),
            }

            if CKA_ID in y:
                d['CKA_ID'] = y[CKA_ID],

            if CKA_KEY_TYPE in y:
                d['CKA_KEY_TYPE'] = pkcs11_ckk_to_str(y[CKA_KEY_TYPE])

            output.append(d)

        if len(output):
            print(yaml.safe_dump(output, default_flow_style=False))

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            ListObjectsCommand.list(db, args)
