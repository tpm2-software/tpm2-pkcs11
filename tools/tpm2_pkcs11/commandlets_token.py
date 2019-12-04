# python stdlib dependencies
import sys

# local imports
from .command import Command
from .command import commandlet
from .db import Db
from .utils import bytes_to_file
from .utils import TemporaryDirectory
from .utils import hash_pass
from .utils import dict_from_kvp
from .utils import rand_hex_str
from .utils import AESAuthUnwrapper
from .utils import load_sealobject
from .utils import str2bool
from .tpm2 import Tpm2
from .policies import * # noqa

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

            with TemporaryDirectory() as d:
                tpm2 = Tpm2(d)
                if token['sopinnvindex']:
                    tpm2.nvindexundefine(None, token['sopinnvindex'])
                if token['userpinnvindex']:
                    tpm2.nvindexundefine(None, token['userpinnvindex'])

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

        print('Verifying label: "%s"' % label)

        pobj = db.getprimary(token['pid'])
        sealobj = db.getsealobject(token['id'])

        pobjauth = None
        wrappingkeyauth = None

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

                print("SO pin valid, seal auth: %s" % sosealauth['hash'])

            if userpin != None:

                usersealctx = tpm2.load(tr_handle, pobjauth,
                                        sealobj['userpriv'],
                                        sealobj['userpub'])

                # Unseal the wrapping key auth
                usersealauthsalt = sealobj['userauthsalt']

                usersealauth = hash_pass(userpin, salt=usersealauthsalt)

                wrappingkeyauth = tpm2.unseal(usersealctx,
                                              usersealauth['hash'])

                print("USER pin valid, seal auth: %s" % usersealauth['hash'])

            token_config = dict_from_kvp(token['config'])

            print('TOKEN CONFIG: {}'.format(token_config))

            wrapper = AESAuthUnwrapper(wrappingkeyauth)

            tobjs = db.gettertiary(token['id'])

            for tobj in tobjs:
                tpm2.load(tr_handle, pobjauth, tobj['priv'], tobj['pub'])
                tobjauth = wrapper.unwrap(tobj['objauth'])

                print("Tertiary object verified(%d), auth: %s" %
                      (tobj['id'], tobjauth))

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
        group_parser.add_argument(
            '--nopolicy',
            help='Disable adding policy NV objects for SO/ USER PIN auth model\n',
            action='store_true'
        )

    @staticmethod
    def generate_token_policies(db, tpm2, tokid, sopin, userpin):

        #
        # Create SO PIN NV object
        #
        sopinpolicy, _ = set_pinauthobject_auth_with_pinobjectauth(tpm2, False)
        sopinnvindex = tpm2.nvindexdefine(None, sopin, sopinpolicy).rstrip().split("nv-index:")
        db.update_token_sopin_nv_index(tokid, sopinnvindex[1])

        #
        # Create USER PIN NV object
        #
        user_pin_policy_truthvalue1, _ = set_pinauthobject_auth_with_pinobjectauth(tpm2, False)
        user_pin_policy_truthvalue2, _ = set_userpin_with_sopin(tpm2, sopinnvindex[1], sopin, False)
        session_context = tpm2.startauthsession(False)
        userpinpolicy, session_context = tpm2.policyor(user_pin_policy_truthvalue1, user_pin_policy_truthvalue2, session_context)
        tpm2.flushsession(session_context)
        userpinnvindex = tpm2.nvindexdefine(None, userpin, userpinpolicy).rstrip().split("nv-index:")
        db.update_token_userpin_nv_index(tokid, userpinnvindex[1])
        #
        # Assign the USERPIN object policy as userpinpolicy
        #
        db.addpolicy(USER_PIN_POLICY_TYPE, tokid, userpinpolicy)
        #
        # Save PolicySecret(=SOPIN)
        #
        db.addpolicy(SO_PIN_POLICY_SECRET_TYPE, tokid, user_pin_policy_truthvalue2)

        #
        # Create USER OBJECT policy
        #
        user_object_policy = set_user_object_policy(tpm2, userpinnvindex[1], userpin)
        #
        # Assign the USER object (tobject) policy as user_object_policy
        #
        db.addpolicy(USER_OBJECT_POLICY_TYPE , tokid, user_object_policy)

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
            tr_handle = bytes_to_file(pobject['handle'], d)

            if args['nopolicy'] == True:
                # We generate one auth for the sosealobj and the usersealobj
                sosealauth = hash_pass(sopin)
                usersealauth = hash_pass(userpin)

                # Now we generate the two seal objects, using the sealauths as their
                # auth values and sealing the wrappingkey value to it.
                # soobject will be an AES key used for decrypting tertiary object
                # auth values.


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

            else:
                config = {'token-init': True}
                tokid = db.addtoken(pobject['id'], config, label=label)
                AddTokenCommand.generate_token_policies(db, tpm2, tokid, sopin, userpin)
                # Create sealing object for wrapping auth enc key
                sealobjpolicy = db.getpolicyfile_from_tokid_and_type(tokid, SEAL_OBJECT_POLICY_TYPE)
                sealingobjpriv, sealingobjpub, _ = tpm2.create(
                   tr_handle,
                   pobject['objauth'],
                   seal=wrappingkey,
                   policy=sealobjpolicy,
                   objattrs="fixedtpm|fixedparent|adminwithpolicy")
                # Update token db with sealing object data
                db.update_token_sealobject(tokid, sealingobjpub, sealingobjpriv);

            print("Created token label: %s" % label)

    @staticmethod
    def do_token_noninit(db, args):

        pid = args['pid']

        pobject = db.getprimary(pid)

        config = [{'token-init': False}]

        tokid = db.addtoken(pobject['id'], config)

        print('Created token id: {tokid}'.format(tokid=tokid))

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

        if token['sopinnvindex'] and token['userpinnvindex']:

            nvindex = token['userpinnvindex']
            session_context = ""
            if is_so:
                nvindex = token['sopinnvindex']
                _, session_context = set_pinauthobject_auth_with_pinobjectauth(tpm2, True)
            else:
                #get-db-so-login-policy->flush (A)
                user_pin_policy_truthvalue2 = db.getpolicyfile_from_tokid_and_type(token['id'], SO_PIN_POLICY_SECRET_TYPE)
                #get-user-with-user->continue (B)
                session_context = tpm2.startauthsession(True)
                user_pin_policy_truthvalue1, session_context = set_pinauthobject_auth_with_pinobjectauth(tpm2, True)
                #policyOR (A),(B)
                _, session_context = tpm2.policyor(user_pin_policy_truthvalue1, user_pin_policy_truthvalue2, session_context)

            authstr = "session:"+str(session_context)+"+"+oldpin
            tpm2.changeauth(False, None, nvindex, authstr, newpin)
            tpm2.flushsession(session_context)

        else:

            pobjectid = token['pid']
            pobject = db.getprimary(pobjectid)
            pobjauth = pobject['objauth']

            with TemporaryDirectory() as d:

                tr_handle = bytes_to_file(pobject['handle'], d)

                sealctx, sealauth = load_sealobject(token, db, tpm2, tr_handle, pobjauth,
                                                          oldpin, is_so)

                newsealauth = hash_pass(newpin)

                # call tpm2_changeauth and get new private portion
                newsealpriv = tpm2.changeauth(True, tr_handle, sealctx, sealauth,
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

        #
        # Check if token policy is enabled by checking if NV indexes are defined
        #
        if token['sopinnvindex'] and token['userpinnvindex']:
            user_pin_policy_truthvalue1, _ = set_pinauthobject_auth_with_pinobjectauth(tpm2, False)
            session_context = tpm2.startauthsession(True)
            user_pin_policy_truthvalue2, session_context = set_userpin_with_sopin(tpm2, token['sopinnvindex'], sopin, True)
            _, session_context = tpm2.policyor(user_pin_policy_truthvalue1, user_pin_policy_truthvalue2, session_context)
            tpm2.changeauth(False, None, token['userpinnvindex'], "session:"+str(session_context), newpin)
            tpm2.flushsession(session_context)
        else:
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

@staticmethod
def _empty_validator(s):
    return s

@staticmethod
def _log_level_validator(s):

    try:
        x = int(s, 0)
    except ValueError:
        try:
            x = ['error', 'warn', 'verbose'].index(s)
        except ValueError:
            sys.exit('Expected log-level to be one of "error", "warn", or "verbose"')

    return x

@commandlet("config")
class ConfigCommand(Command):
    '''
    Manipulates and retrieves token configuration data.
    '''
    _keys = {
        'token-init' : str2bool,
        'log-level'  : _log_level_validator.__func__,
        'tcti'       : _empty_validator.__func__
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

        if not key and not value:
            print(str(token['config']))
            sys.exit(0)

        if not key and value:
            sys.exit("Cannot specify --value without a key")

        # key has to be set here based on above logical check
        # throws an error if the key isn't known to the system
        validator = cls.get_validator_for_key(key)

        config = dict_from_kvp(token['config'])

        # no value, just key. Print the current value for key is set or empty if not set
        if not value:
            print("%s=%s" % (key, str(config[key] if key in config else "")))
            sys.exit(0)

        v = validator(value)
        config[key] = v

        # update the database
        db.updateconfig(token, config)

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            ConfigCommand.config(db, args)
