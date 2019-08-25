# python stdlib dependencies
import binascii
import os
import sys
import yaml

# external modules
from cryptography.exceptions import InvalidTag

# local imports
from .command import Command
from .command import commandlet
from .db import Db
from .utils import TemporaryDirectory
from .utils import hash_pass
from .utils import dict_from_kvp
from .utils import str2bool
from .utils import check_pin
from .utils import query_yes_no
from .utils import AESAuthUnwrapper
from .utils import TPMAuthUnwrapper
from .utils import AESCipher
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
        wrappingkey = db.getwrapping(token['id'])

        pobjauth = None
        wrappingkeyauth = None

        with TemporaryDirectory() as d:
            tpm2 = Tpm2(d)

            if sopin != None:

                sopobjauth = check_pin(token, sopin, True)

                sosealctx = tpm2.load(pobj['handle'], sopobjauth,
                                      sealobj['sopriv'], sealobj['sopub'])

                # Unseal the wrapping key auth
                sosealauthiters = sealobj['soauthiters']

                sosealauthsalt = sealobj['soauthsalt']
                sosealauthsalt = binascii.unhexlify(sosealauthsalt)

                sosealauth = hash_pass(
                    sopin.encode(), salt=sosealauthsalt, iters=sosealauthiters)

                wrappingkeyauth = tpm2.unseal(sosealctx, sosealauth['hash'])
                pobjauth = sopobjauth

                print("SO pin valid!")

            if userpin != None:

                userpobjauth = check_pin(token, userpin, False)

                usersealctx = tpm2.load(pobj['handle'], userpobjauth,
                                        sealobj['userpriv'], sealobj['userpub'])

                # Unseal the wrapping key auth
                usersealauthiters = sealobj['userauthiters']

                usersealauthsalt = sealobj['userauthsalt']
                usersealauthsalt = binascii.unhexlify(usersealauthsalt)

                usersealauth = hash_pass(
                    userpin.encode(),
                    salt=usersealauthsalt,
                    iters=usersealauthiters)

                wrappingkeyauth = tpm2.unseal(usersealctx, usersealauth['hash'])
                pobjauth = userpobjauth

                print("USER pin valid!")

            token_config = dict_from_kvp(token['config'])

            print('TOKEN CONFIG: {}'.format(token_config))

            sym_support = str2bool(token_config['sym-support'])
            if sym_support:
                wrapper = TPMAuthUnwrapper(tpm2, pobj['handle'], pobjauth,
                                           wrappingkeyauth, wrappingkey['priv'],
                                           wrappingkey['pub'])
            else:
                wrapper = AESAuthUnwrapper(wrappingkeyauth)

            sobj = db.getsecondary(token['id'])

            sobjctx = tpm2.load(pobj['handle'], pobjauth, sobj['priv'],
                                sobj['pub'])

            sobjauth = wrapper.unwrap(sobj['objauth'])

            print("Secondary object verified(%d), auth: %s" %
                  (sobj['id'], sobjauth))

            tobjs = db.gettertiary(token['id'])

            for tobj in tobjs:
                tpm2.load(sobjctx, sobjauth, tobj['priv'], tobj['pub'])
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
            '--pobj-pin',
            help='The primary object password. This password is use for authentication to the primary object.\n',
            default="")
        group_parser.add_argument(
            '--label',
            help='A unique label to identify the profile in use, must be unique.\n',
            required=True)
        group_parser.add_argument(
            "--wrap",
            choices=['auto', 'software', 'tpm'],
            default='auto',
            help='Configure usage of SW based crypto for internal object protection.\n'
            +
            'This is not recommended for production environments,as the tool will'
            + 'auto-configure this option based on TPM support.')

    @staticmethod
    def verify_pobjpin(pobject, pobjpin):

        iters = pobject['pobjauthiters']
        salt = binascii.unhexlify(pobject['pobjauthsalt'])
        pobjkey = hash_pass(pobjpin.encode(), salt=salt, iters=iters)

        c = AESCipher(pobjkey['rhash'])
        try:
            return c.decrypt(pobject['pobjauth'])
        except InvalidTag:
            sys.exit('Invalid --pobj-pin, please enter the correct pin')

    @staticmethod
    def protect_pobj_auth(pobjauthhash, sopin, userpin):

        # Now we need to protect the primaryobject auth in a way where SO and USER can access the value.
        # When a "pkcs11" admin generates a token, they give the auth value to SO and USER.
        sopobjkey = hash_pass(sopin.encode())
        userpobjkey = hash_pass(userpin.encode())

        sopobjauth = AESCipher(sopobjkey['rhash']).encrypt(pobjauthhash)

        userpobjauth = AESCipher(userpobjkey['rhash']).encrypt(pobjauthhash)

        return (sopobjkey, sopobjauth, userpobjkey, userpobjauth)

    @staticmethod
    def do_token_init(db, path, args):

        pobjpin = args['pobj_pin']
        userpin = args['userpin']
        sopin = args['sopin']
        label = args['label']
        pid = args['pid']

        # Verify pid is in db
        pobject = db.getprimary(pid)

        pobjauthhash = AddTokenCommand.verify_pobjpin(pobject, pobjpin)

        with TemporaryDirectory() as d:
            tpm2 = Tpm2(d)

            #
            # Figure out if TPM supports encryptdecrypt
            # interface. If it does use a symmetric TPM
            # key to wrap object authorizations. If it
            # doesn't default to Software based crypto.
            #
            # Auto-configure only if the user didn't specify
            # explicitly what to do or specified auto.
            #
            print(
                "auto-detecting TPM encryptdecrypt interface for wrapping key usage"
            )
            commands = tpm2.getcap('commands')
            sym_support = 'encryptdecrypt'.encode() in commands

            if args['wrap'] != 'auto':
                if args['wrap'] == 'software' and sym_support:
                    print(
                        "Warning: configuring software wrapping key when TPM has support.\n"
                        "THIS IS NOT RECOMENDED")
                    sym_support = False
                elif args['wrap'] == 'tpm' and not sym_support:
                    sys.exit(
                        "TPM does not have symmetric wrapping key support and it was "
                        + "explicitly requested.")
                else:
                    sym_support = True if args['wrap'] == 'tpm' else False

            print('Using "%s" based object authorization protections' %
                  ('TPM' if sym_support else "Software"))

            # generate an auth for the wrapping object, which will be sealed
            # to that object.
            wrappingobjauth = hash_pass(os.urandom(32))

            # We generate one auth for the sosealobj and the usersealobj
            sosealauth = hash_pass(sopin.encode())
            usersealauth = hash_pass(userpin.encode())

            # Now we generate the two seal objects, using the sealauths as their
            # auth values and sealing the wrappingobjauth value to it.
            # soobject will be an AES key used for decrypting tertiary object
            # auth values.
            usersealpriv, usersealpub, _ = tpm2.create(
                pobject['handle'],
                pobjauthhash,
                usersealauth['hash'],
                seal=wrappingobjauth['hash'])
            sosealpriv, sosealpub, _ = tpm2.create(
                pobject['handle'],
                pobjauthhash,
                sosealauth['hash'],
                seal=wrappingobjauth['hash'])

            #
            # If the TPM supports encryptdecrypt we create the wrapping object in the TPM,
            # else we use the sealed auth value as the key.
            #
            # We also need to adjust the key sizes for the wrapping key and secondary object to be the maximum
            # value reported by the TPM.
            #
            fixed_properties = tpm2.getcap('properties-fixed')
            y = yaml.safe_load(fixed_properties)
            sym_size = y['TPM2_PT_CONTEXT_SYM_SIZE']['raw']

            if sym_support:
                # Now we create the wrappingbject, with algorithm aes256
                wrappingobjpriv, wrappingobjpub, _ = tpm2.create(
                    pobject['handle'],
                    pobjauthhash,
                    wrappingobjauth['hash'],
                    alg='aes{}cfb'.format(sym_size))

            sopobjkey, sopobjauth, userpobjkey, userpobjauth = AddTokenCommand.protect_pobj_auth(
                pobjauthhash, sopin, userpin)

            # Now we create the secondary object, which is just a parent dummy, wrapping it's
            # auth with the wrapping key
            sobjauth = hash_pass(os.urandom(32))['hash']

            if sym_support:
                wrapper = TPMAuthUnwrapper(
                    tpm2, pobject['handle'], pobjauthhash,
                    wrappingobjauth['hash'], wrappingobjpriv, wrappingobjpub)
            else:
                wrapper = AESAuthUnwrapper(wrappingobjauth['hash'])

            encsobjauth = wrapper.wrap(sobjauth)

            objattrs = "restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth"
            sobjpriv, sobjpub, _ = tpm2.create(
                pobject['handle'],
                pobjauthhash,
                sobjauth,
                objattrs=objattrs,
                alg='rsa2048')

            # If this succeeds, we update the token table
            config = [{'sym-support': sym_support}, {'token-init': True}]
            tokid = db.addtoken(
                pobject['id'],
                sopobjkey,
                sopobjauth,
                userpobjkey,
                userpobjauth,
                config,
                label=label)

            # now we update the sealobject table with the tokid to seal objects mapping
            db.addsealobjects(tokid, usersealauth, usersealpriv, usersealpub,
                              sosealauth, sosealpriv, sosealpub)

            # Update the wrapping object table
            if sym_support:
                tokid = db.addwrapping(tokid, wrappingobjpriv, wrappingobjpub)

            # Update the secondary object table
            tokid = db.addsecondary(tokid, encsobjauth, sobjpriv, sobjpub) # noqa

            print("Created token label: %s" % label)

    @staticmethod
    def do_token_noninit(db, args):

        pid = args['pid']
        pobjpin = args['pobj_pin']

        pobject = db.getprimary(pid)

        if len(pobjpin) > 0:
            question = 'The primary object auth value will not be protected until the token is initialized, continue?'
            choice = query_yes_no(question)
            if not choice:
                sys.exit(0)

        pobjauthhash = AddTokenCommand.verify_pobjpin(pobject, pobjpin)

        sopobjkey, sopobjauth, userpobjkey, userpobjauth = AddTokenCommand.protect_pobj_auth(
            pobjauthhash, '', '')

        config = [{'token-init': False}]

        tokid = db.addtoken(pobject['id'], sopobjkey, sopobjauth, userpobjkey,
                            userpobjauth, config)

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
        super(self.__class__, self).__call__(args)


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
        newpin = args['new'].encode()

        token = db.gettoken(label)

        pobjauth = check_pin(token, oldpin, is_so)

        pobj, sealctx, sealauth = load_sealobject(token, tpm2, db, pobjauth,
                                                  oldpin, is_so)

        #
        # Now we need to use the newpin to wrap the primaryobject auth value AND
        # call tpm2_changeauth ON the seal key and update it's tpm private portion blob
        #

        # Step 1 - Generate new wrapping key
        pobjkey = hash_pass(newpin)

        # Step 2 - Wrap pobjauth - defer db store until success
        c = AESCipher(pobjkey['rhash'])
        encpobjauth = c.encrypt(pobjauth)

        # Step 3 - call tpm2_changeauth and get new private portion
        newsealauth = hash_pass(newpin)
        newsealpriv = tpm2.changeauth(pobj['handle'], sealctx, sealauth,
                                      newsealauth['hash'])

        # Step 4 - update the database
        db.updatepin(is_so, token, pobjkey, encpobjauth, newsealauth,
                     newsealpriv)

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
        newpin = args['userpin'].encode()

        token = db.gettoken(label)

        # load and unseal the data from the SO seal object
        pobjauth = check_pin(token, sopin, True)
        pobj, sealctx, sealauth = load_sealobject(token, tpm2, db, pobjauth,
                                                  sopin, True)
        wrappingkeyauth = tpm2.unseal(sealctx, sealauth)

        #
        # Now we need to create a new pobject auth wrapping key and seal object for the user,
        # using the new pin and store
        # the wrapping key auth to the seal object. After that, update the DB
        #

        # Step 1 - Generate new pobject wrapping key
        pobjkey = hash_pass(newpin)

        # Step 2 - Wrap pobjauth - defer db store until success
        c = AESCipher(pobjkey['rhash'])
        encpobjauth = c.encrypt(pobjauth)

        # Step 3 - call tpm2_create and create a new sealobject protected by the seal auth and sealing
        #    the wrapping key auth value
        newsealauth = hash_pass(newpin)
        newsealpriv, newsealpub, _ = tpm2.create(
            pobj['handle'], pobjauth, newsealauth['hash'], seal=wrappingkeyauth)

        # Step 4 - update the database
        db.updatepin(False, token, pobjkey, encpobjauth, newsealauth,
                     newsealpriv, newsealpub)

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            with TemporaryDirectory() as d:
                tpm2 = Tpm2(d)
                InitPinCommand.initpin(db, tpm2, args)
