# python stdlib dependencies
import sys

# local imports
from .command import Command
from .command import commandlet
from .db import Db
from .utils import TemporaryDirectory
from .utils import hash_pass
from .utils import dict_from_kvp
from .utils import rand_hex_str
from .utils import AESAuthUnwrapper
from .utils import load_sealobject
from .tpm2 import Tpm2


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

        print('Verifying label: "%s"' % label)

        pobj = db.getprimary(token['pid'])
        sealobj = db.getsealobject(token['id'])

        pobjauth = None
        wrappingkeyauth = None

        with TemporaryDirectory() as d:
            tpm2 = Tpm2(d)

            pobjauth = pobj['objauth']

            if sopin != None:

                sosealctx = tpm2.load(pobj['handle'], pobjauth,
                                      sealobj['sopriv'], sealobj['sopub'])

                # Unseal the wrapping key auth
                sosealauthsalt = sealobj['soauthsalt']

                sosealauth = hash_pass(sopin, salt=sosealauthsalt)

                wrappingkeyauth = tpm2.unseal(sosealctx, sosealauth['hash'])

                print("SO pin valid, seal auth: %s" % sosealauth['hash'])

            if userpin != None:

                usersealctx = tpm2.load(pobj['handle'], pobjauth,
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
                tpm2.load(pobj['handle'], pobjauth, tobj['priv'], tobj['pub'])
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
            usersealpriv, usersealpub, _ = tpm2.create(
                pobject['handle'],
                pobject['objauth'],
                usersealauth['hash'],
                seal=wrappingkey)
            sosealpriv, sosealpub, _ = tpm2.create(
                pobject['handle'],
                pobject['objauth'],
                sosealauth['hash'],
                seal=wrappingkey)

            # If this succeeds, we update the token table
            config = [{'token-init': True}]
            tokid = db.addtoken(pobject['id'], config, label=label)

            # now we update the sealobject table with the tokid to seal objects mapping
            db.addsealobjects(tokid, usersealauth, usersealpriv, usersealpub,
                              sosealauth, sosealpriv, sosealpub)

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

        pobjectid = token['pid']
        pobject = db.getprimary(pobjectid)
        pobjauth = pobject['objauth']

        pobj, sealctx, sealauth = load_sealobject(token, tpm2, db, pobjauth,
                                                  oldpin, is_so)

        # call tpm2_changeauth and get new private portion
        newsealauth = hash_pass(newpin)
        newsealpriv = tpm2.changeauth(pobj['handle'], sealctx, sealauth,
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

        pobj, sealctx, sealauth = load_sealobject(token, tpm2, db, pobjauth,
                                                  sopin, True)
        wrappingkeyauth = tpm2.unseal(sealctx, sealauth)

        # call tpm2_create and create a new sealobject protected by the seal auth and sealing
        #    the wrapping key auth value
        newsealauth = hash_pass(newpin)
        newsealpriv, newsealpub, _ = tpm2.create(
            pobj['handle'],
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
