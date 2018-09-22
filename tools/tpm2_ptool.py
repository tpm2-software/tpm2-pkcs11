#!/usr/bin/env python

from __future__ import print_function

import argparse
import binascii
import copy
import hashlib
import hmac
import os
import random
import re
import shutil
import string
import sqlite3
import sys
import tempfile
import textwrap
import traceback
import uuid
import yaml

from base64 import b64decode
from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from subprocess import Popen, PIPE
from werkzeug.exceptions import SecurityError

DEFAULT_STORE_PATH = os.path.join(os.environ.get("HOME"), ".tpm2_pkcs11") if os.environ.get("HOME") else os.get_cwd()

def kvp_row(d):
    x = " ".join(["=".join([str(key), str(val)]) for key, val in d.items()])
    return x

def list_dict_to_kvp(l):
    x = "\n".join(kvp_row(d) for d in l)
    return x

def rand_str(num):
    return binascii.hexlify(os.urandom(32))

def hash_pass(password, iters=100000, salt=os.urandom(32)):

    phash = hashlib.pbkdf2_hmac('sha256', password, salt, iters)
    rhash = phash
    salt = binascii.hexlify(salt)
    phash = binascii.hexlify(phash)

    return { 'salt' : salt,
             'iters' : iters,
             'hash' : phash,
             'rhash' : rhash,
            }

# These CK* values come from the PKCS#11 spec
CKA_KEY_TYPE = 0x100
CKA_CLASS = 0

CKO_PUBLIC_KEY = 2
CKO_PRIVATE_KEY = 3
CKO_SECRET_KEY  = 4

CKK_RSA = 0
CKK_AES = 0x1f

CKM_RSA_PKCS_OAEP = 9
CKM_AES_CBC = 0x1082

CKA_ID = 0x102
CKA_MODULUS = 0x120
CKA_PUBLIC_EXPONENT = 0x122

class AESCipher:

    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        # Generate a random 96-bit IV.
        iv = os.urandom(12)

        # Construct an AES-GCM Cipher object with the given key and a
        # randomly generated IV.
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        iv = binascii.hexlify(iv)
        ciphertext = binascii.hexlify(ciphertext)
        tag = binascii.hexlify(encryptor.tag)
        return ':'.join((iv, tag, ciphertext))

    def decrypt(self, ciphertext):

        iv, tag, ciphertext = ciphertext.split(':')
        iv = binascii.unhexlify(iv)
        tag = binascii.unhexlify(tag)
        ciphertext = binascii.unhexlify(ciphertext)

        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

class Tpm2(object):
    def __init__(self, tmp, final):
        self._tmp = tmp;
        self._final = final

    def createprimary(self, ownerauth, objauth):
        ctx = os.path.join(self._tmp, "context.out")
        cmd = ['tpm2_createprimary',
                    '-p', 'hex:%s' % objauth,
                    '-o', ctx]

        if ownerauth and len(ownerauth) > 0:
            cmd.extend(['-P', ownerauth])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        if (p.wait()):
            raise RuntimeError("Could not execute tpm2_createprimary: %s" % stderr)
        return ctx

    @staticmethod
    def evictcontrol(ownerauth, ctx):

        cmd = ['tpm2_evictcontrol', '-c', str(ctx) ]

        if ownerauth and len(ownerauth) > 0:
            cmd.extend('-P', ownerauth)

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        y=yaml.load(stdout)
        rc = p.wait()
        handle = y['persistentHandle'] if rc == 0 else None
        if (p.wait()):
            raise RuntimeError("Could not execute tpm2_evictcontrol: %s", stderr)
        return handle

    def load(self, pctx, pauth, priv, pub):

        ctx = os.path.join(self._tmp, uuid.uuid4().hex + '.out')

        #tpm2_load -C $file_primary_key_ctx  -u $file_load_key_pub  -r $file_load_key_priv -n $file_load_key_name -o $file_load_key_ctx
        cmd = ['tpm2_load', '-C', str(pctx), '-P', 'hex:' + pauth,'-u', pub, '-r', priv, '-n', '/dev/null', '-o', ctx]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_load: %s", stderr)
        return ctx

    def unseal(self, ctx, auth):

        # tpm2_unseal -Q -c $file_unseal_key_ctx
        cmd = ['tpm2_unseal', '-c', ctx, '-p', 'hex:'+auth]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_load: %s", stderr)
        return stdout

    def _encryptdecrypt(self, ctx, auth, data, decrypt=False):

        cmd = ['tpm2_encryptdecrypt', '-c', ctx, '-p', 'hex:' + auth]

        if decrypt:
            cmd.extend(['-D'])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, env=os.environ)
        stdout, stderr = p.communicate(input=data)
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_load: %s", stderr)
        return stdout

    def encrypt(self, ctx, auth, data):
        return self._encryptdecrypt(ctx, auth, data)

    def decrypt(self, ctx, auth, data):
        return self._encryptdecrypt(ctx, auth, data, decrypt=True)

    def _move(self, path):
        b = os.path.basename(path)
        n = os.path.join(self._final, b)
        os.rename(path, n)
        return n

    def create(self, phandle, pauth, objauth, objattrs=None, seal=None, alg=None):
        # tpm2_create -Q -C context.out -g $gAlg -G $GAlg -u key.pub -r key.priv
        fd, priv = tempfile.mkstemp(prefix='', suffix='.priv', dir=self._tmp)
        fd, pub = tempfile.mkstemp(prefix='', suffix='.pub', dir=self._tmp)

        cmd = ['tpm2_create', '-C', str(phandle), '-u', pub, '-r', priv]

        if pauth and len(pauth) > 0:
            cmd.extend(['-P', 'hex:%s' % pauth])

        if objauth and len(objauth) > 0:
            cmd.extend(['-p', 'hex:%s' % objauth])

        if objattrs != None:
            cmd.extend(['-A', objattrs])

        if seal != None:
            cmd.extend(['-I', '-'])

        if alg != None:
            cmd.extend(['-G', alg])

        p = Popen(cmd,
                   stdout=PIPE, stderr=PIPE, stdin=PIPE, env=os.environ)
        stdout, stderr = p.communicate(input=seal)
        rc = p.wait()
        if (rc != 0):
            os.remove(pub)
            os.remove(priv)
            raise RuntimeError("Could not execute tpm2_create: %s" % str(stderr))

        pub = self._move(pub)
        priv = self._move(priv)
        return priv, pub, stdout

class TemporaryDirectory(object):
    """Context manager for tempfile.mkdtemp() so it's usable with "with" statement."""
    def __enter__(self):
        self.name = tempfile.mkdtemp()
        return self.name

    def __exit__(self, exc_type, exc_value, traceback):
        shutil.rmtree(self.name)

#
# With Db() as db:
# // do stuff
#
class Db(object):

    def __init__(self, dirpath):
        self._path = os.path.join(dirpath, "tpm2_pkcs11.sqlite3")

    def __enter__(self):
        self._conn = sqlite3.connect(self._path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute('PRAGMA foreign_keys = ON;')

        return self

    def gettoken(self, label):
        c = self._conn.cursor()
        c.execute("SELECT * from tokens WHERE label=?", (label,))
        x = c.fetchone()
        return x

    def getsealobject(self, tokid):
        c = self._conn.cursor()
        c.execute("SELECT * from sealobjects WHERE tokid=?", (tokid,))
        x = c.fetchone()
        return x

    def gettokens(self, pid):
        c = self._conn.cursor()
        c.execute("SELECT * from tokens WHERE pid=?", (pid,))
        x = c.fetchall()
        return x

    def rmtoken(self, label):
        # This works on the premise of a cascading delete tied by foriegn
        # key relationships.
        self._conn.execute('DELETE from tokens WHERE label=?', (label,))

    def getprimary(self, pid):
        c = self._conn.cursor()
        c.execute("SELECT * from pobjects WHERE id=?", (pid,))
        x = c.fetchone()
        return x

    def rmprimary(self, pid):
        # This works on the premise of a cascading delete tied by foriegn
        # key relationships.
        self._conn.execute('DELETE from pobjects WHERE id=?', (pid,))

    def getsecondary(self, tokid):
        c = self._conn.cursor()
        c.execute("SELECT * from sobjects WHERE id=?", (tokid, ))
        x = c.fetchone()
        return x

    def getwrapping(self, tokid):
        c = self._conn.cursor()
        c.execute("SELECT * from wrappingobjects WHERE id=?", (tokid, ))
        x = c.fetchone()
        return x

    def gettertiary(self, sid):
        c = self._conn.cursor()
        c.execute("SELECT * from tobjects WHERE sid=?", (sid, ))
        x = c.fetchall()
        return x

    def addtoken(self, pid, label, sopobjkey, sopobjauth, userpobjkey, userpobjauth):

        token = {
            # General Metadata
            'pid'        : pid,
            'label'      : label,

            'sopobjauthkeysalt'  : sopobjkey['salt'],
            'sopobjauthkeyiters' : sopobjkey['iters'],
            'sopobjauth'         : sopobjauth,

            'userpobjauthkeysalt'  : userpobjkey['salt'],
            'userpobjauthkeyiters' : userpobjkey['iters'],
            'userpobjauth'         : userpobjauth,
        }

        columns = ', '.join(token.keys())
        placeholders = ', '.join('?' * len(token))
        sql = 'INSERT INTO tokens ({}) VALUES ({})'.format(columns, placeholders)
        c = self._conn.cursor()
        c.execute(sql, token.values())

        return c.lastrowid

    def addsealobjects(self, tokid, usersealauth, usersealpriv, usersealpub, sosealauth, sosealpriv, sosealpub):

        sealobjects = {
            # General Metadata
            'tokid'         : tokid,

            'userpriv'  : usersealpriv,
            'userpub'   : usersealpub,

            'sopriv'    : sosealpriv,
            'sopub'     : sosealpub,

            'userauthsalt'  : usersealauth['salt'],
            'userauthiters' : usersealauth['iters'],

            'soauthsalt'    : sosealauth['salt'],
            'soauthiters'   : sosealauth['iters'],
        }

        columns = ', '.join(sealobjects.keys())
        placeholders = ', '.join('?' * len(sealobjects))
        sql = 'INSERT INTO sealobjects ({}) VALUES ({})'.format(columns, placeholders)
        c = self._conn.cursor()
        c.execute(sql, sealobjects.values())

        return c.lastrowid

    def addprimary(self, handle, pobjauth, pobjauthsalt, pobjauthiters, hierarchy='o'):

        # Subordiante commands will need some of this data
        # when deriving subordinate objects, so pass it back
        pobject= {
            # General Metadata
            'hierarchy'     : hierarchy,
            'handle'        : handle,
            'pobjauth'      : pobjauth,
            'pobjauthsalt'  : pobjauthsalt,
            'pobjauthiters' : pobjauthiters,
        }

        columns = ', '.join(pobject.keys())
        placeholders = ', '.join('?' * len(pobject))
        sql = 'INSERT INTO pobjects ({}) VALUES ({})'.format(columns, placeholders)
        c = self._conn.cursor()
        c.execute(sql, pobject.values())

        return c.lastrowid

    def addsecondary(self, tokid, objauth, priv, pub):

        sobject = {
            'tokid'        : tokid,
            'objauth'      : objauth,
            'pub'          : pub,
            'priv'         : priv,
        }

        columns = ', '.join(sobject.keys())
        placeholders = ', '.join('?' * len(sobject))
        sql = 'INSERT INTO sobjects ({}) VALUES ({})'.format(columns, placeholders)
        c = self._conn.cursor()
        c.execute(sql, sobject.values())
        return  c.lastrowid

    def addwrapping(self, tokid, priv, pub):

        wrapping = {
            'tokid'        : tokid,
            'pub'          : pub,
            'priv'         : priv,
        }

        columns = ', '.join(wrapping.keys())
        placeholders = ', '.join('?' * len(wrapping))
        sql = 'INSERT INTO wrappingobjects ({}) VALUES ({})'.format(columns, placeholders)
        c = self._conn.cursor()
        c.execute(sql, wrapping.values())
        return  c.lastrowid

    def addtertiary(self, sid, priv, pub, objauth, attrs, mech):
        sobject = {
            'sid'          : sid,
            'pub'          : pub,
            'priv'         : priv,
            'objauth'      : objauth,
            'attrs'        : list_dict_to_kvp(attrs),
            'mech'         : list_dict_to_kvp(mech),
        }

        columns = ', '.join(sobject.keys())
        placeholders = ', '.join('?' * len(sobject))
        sql = 'INSERT INTO tobjects ({}) VALUES ({})'.format(columns, placeholders)
        c = self._conn.cursor()
        c.execute(sql, sobject.values())
        return  c.lastrowid

    def commit(self):
        self._conn.commit()

    def __exit__(self, exc_type, exc_value, traceback):
        self._conn.commit()
        self._conn.close()

    def delete(self):
        try:
            os.remove(self._path)
        except OSError:
            pass

    # TODO collapse object tables into one, since they are common besides type.
    # move sealobject metadata into token metadata table.
    #
    # Object types:
    # soseal
    # userseal
    # wrapping
    # secondary
    # tertiary
    #
    def create(self):
        c = self._conn.cursor()
        sql = [
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS tokens(
                id INTEGER PRIMARY KEY,
                pid INTEGER NOT NULL,
                label TEST NOT NULL UNIQUE,
                userpobjauthkeysalt TEXT NOT NULL,
                userpobjauthkeyiters NUMBER NOT NULL,
                userpobjauth TEXT NOT NULL,
                sopobjauthkeysalt TEXT NOT NULL,
                sopobjauthkeyiters NUMBER NOT NULL,
                sopobjauth TEXT NOT NULL,
                FOREIGN KEY (pid) REFERENCES pobjects(id) ON DELETE CASCADE
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS sealobjects(
                id INTEGER PRIMARY KEY,
                tokid INTEGER NOT NULL,
                userpub TEXT NOT NULL,
                userpriv TEXT NOT NULL,
                userauthsalt TEXT NOT NULL,
                userauthiters NUMBER NOT NULL,
                sopub TEXT NOT NULL,
                sopriv TEXT NOT NULL,
                soauthsalt TEXT NOT NULL,
                soauthiters NUMBER NOT NULL,
                FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS wrappingobjects(
                id INTEGER PRIMARY KEY,
                tokid INTEGER NOT NULL,
                pub TEXT NOT NULL,
                priv TEXT NOT NULL,
                FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS pobjects(
                id INTEGER PRIMARY KEY,
                hierarchy TEXT NOT NULL,
                handle INTEGER NOT NULL,
                pobjauth TEXT NOT NULL,
                pobjauthsalt TEXT NOT NULL,
                pobjauthiters INTEGER NOT NULL
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS sobjects(
                id INTEGER PRIMARY KEY,
                tokid INTEGER NOT NULL,
                pub TEXT NOT NULL,
                priv TEXT NOT NULL,
                objauth TEXT NOT NULL,
                FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE
            );
        '''),
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS tobjects(
                id INTEGER PRIMARY KEY,
                sid INTEGER NOT NULL,
                pub TEXT NOT NULL,
                priv TEXT NOT NULL,
                objauth TEXT NOT NULL,
                attrs TEXT NOT NULL,
                mech TEXT NOT NULL,
                FOREIGN KEY (sid) REFERENCES sobjects(id) ON DELETE CASCADE
            );
        ''')
        ]

        for s in sql:
            c.execute(s)

class commandlet(object):
    '''Decorator class for commandlet. You can add commandlets to the tool with this decorator.'''

    _commandlets = {}

    def __init__(self, cmd):
        self._cmd = cmd

        if cmd in commandlet._commandlets:
            raise Exception('Duplicate command name' + cmd)

        commandlet._commandlets[cmd] = None

    def __call__(self, cls):
        commandlet._commandlets[self._cmd] = cls()
        return cls

    @staticmethod
    def get():
        '''Retrieves the list of registered commandlets.'''
        return commandlet._commandlets


class Command(object):
    '''Baseclass for a commandlet. Commandlets shall implement this interface.'''

    def generate_options(self, group_parser):
        '''Adds it's options to the group parser. The parser passed in is a result from
        calling add_argument_group(ArgumentGroup): https://docs.python.org/2/library/argparse.html
        Args:
            group_parser(): The parser to add options too.
        '''
        raise NotImplementedError('Implement: generate_options')

    def __call__(self, args):
        '''Called when the user selects your commandlet and passed the dictionary of arguments.
        Arguments:
            args ({str: arg}: The dictionary version of the attrs of the parser.
                The args value is obtained by:
                args = opt_parser.parse_args()
                args = vars(args)
                So to access args just do args['name']
        '''
        raise NotImplementedError('Implement: __call__')

@commandlet("init")
class InitCommand(Command):
    '''
    Initializes a tpm2-pkcs11 store
    '''
    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--pobj-pin',
            help='The authorization password for adding secondary objects under the primary object.\n',
            default="")
        group_parser.add_argument(
            '--owner-auth',
            help='The authorization password for adding a primary object to the owner hierarchy.\n',
            default="")

    def __call__(self, args):
        path = os.path.expanduser(args['path'])
        if not os.path.exists(path):
            os.mkdir(path)
        elif not os.path.isdir(path):
            sys.exit("Specified path is not a directory, got: %s" % (path))

        ownerauth = args['owner_auth']
        pobjpin = args['pobj_pin']

        # create the db
        with Db(path) as db:
            db.create()

            handle=None
            with TemporaryDirectory() as d:
                try:
                    tpm2 = Tpm2(d, path)

                    pobjkey = hash_pass(pobjpin)
                    pobjauthhash = hash_pass(rand_str(32))

                    ctx = tpm2.createprimary(ownerauth, pobjauthhash['hash'])
                    handle = Tpm2.evictcontrol(ownerauth, ctx)

                    c = AESCipher(pobjkey['rhash'])
                    pobjauth = c.encrypt(pobjauthhash['hash'])

                    pid = db.addprimary(handle, pobjauth, pobjkey['salt'], pobjkey['iters'])

                    print("Created a primary object of id: %d" % pid)

                except Exception as e:
                    if handle != None:
                        Tpm2.evictcontrol(ownerauth, handle)

                    traceback.print_exc(file=sys.stdout)
                    sys.exit(e)

@commandlet("destroy")
class DestroyCommand(Command):
    '''
    Destroys a tpm2-pkcs11 store
    '''
    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--pid',
            type=int,
            help="The primary object id to remove.\n")
        group_parser.add_argument(
            '--owner-auth',
            default="",
            help="The primary object id to remove.\n")

    def __call__(self, args):
        path = args['path']
        pid=args['pid']
        ownerauth = args['owner_auth']

        if not os.path.exists(path):
            os.mkdir(path)
        elif not os.path.isdir(path):
            sys.exit("Specified path is not a directory, got: %s" % (path))

        proceed = DestroyCommand.query_yes_no('This will delete the primary object of id "%s" and all associated data from db under "%s"' % (pid, path))
        if not proceed:
            sys.exit(0)
        # create the db
        with Db(path) as db:
            pobj = db.getprimary(pid)
            if pobj == None:
                sys.exit('Primary Object id "%s"not found' % pid)
            tokens = db.gettokens(pid)

            for token in tokens:
                RmTokenCommand.rmtokenfiles(db, token)

            db.rmprimary(pid)
            Tpm2.evictcontrol(ownerauth, pobj['handle'])

    @staticmethod
    def query_yes_no(question, default="no"):
        """Ask a yes/no question via raw_input() and return their answer.

        "question" is a string that is presented to the user.
        "default" is the presumed answer if the user just hits <Enter>.
            It must be "yes" (the default), "no" or None (meaning
            an answer is required of the user).

        The "answer" return value is True for "yes" or False for "no".
        """
        valid = {"yes": True, "y": True, "ye": True,
                 "no": False, "n": False}
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
            choice = raw_input().lower()
            if default is not None and choice == '':
                return valid[default]
            elif choice in valid:
                return valid[choice]
            else:
                sys.stdout.write("Please respond with 'yes' or 'no' "
                                 "(or 'y' or 'n').\n")

@commandlet("addtoken")
class AddTokenCommand(Command):
    '''
    Adds a token to a tpm2-pkcs11 store
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

    def __call__(self, args):

        path = args['path']
        pobjpin = args['pobj_pin']
        userpin = args['userpin']
        sopin = args['sopin']
        label = args['label']
        pid = args['pid']

        with Db(path) as db:

            tpm2 = None

            # Verify pid is in db
            pobject = db.getprimary(pid)

            iters = pobject['pobjauthiters']
            salt = binascii.unhexlify(pobject['pobjauthsalt'])
            pobjkey = hash_pass(pobjpin, salt=salt, iters=iters)

            c = AESCipher(pobjkey['rhash'])
            pobjauthhash = c.decrypt(pobject['pobjauth'])

            with TemporaryDirectory() as d:
                tpm2 = Tpm2(d, path)

                # generate an auth for the wrapping object, which will be sealed
                # to that object.
                wrappingobjauth = hash_pass(os.urandom(32))

                # We generate one auth for the sosealobj and the usersealobj
                sosealauth = hash_pass(sopin)
                usersealauth = hash_pass(userpin)

                # Now we generate the two seal objects, using the sealauths as their
                # auth values and sealing the wrappingobjauth value to it.
                # soobject will be an AES key used for decrypting tertiary object
                # auth values.
                usersealpriv, usersealpub, usersealpubdata = tpm2.create(pobject['handle'], pobjauthhash,
                                                        usersealauth['hash'], seal=wrappingobjauth['hash'])
                sosealpriv, sosealpub, sosealpubdata = tpm2.create(pobject['handle'], pobjauthhash,
                                                    sosealauth['hash'], seal=wrappingobjauth['hash'])

                # Now we create the wrappingbject, with algorithm aes256
                wrappingobjpriv, wrappingobjpub, wrappingobjpubdata = tpm2.create(pobject['handle'], pobjauthhash, wrappingobjauth['hash'], alg='aes256cfb')

                # Now we need to protect the primaryobject auth in a way where SO and USER can access the value.
                # When a "pkcs11" admin generates a token, they give the auth value to SO and USER.
                sopobjkey = hash_pass(sopin)
                userpobjkey = hash_pass(userpin)

                sopobjauth = AESCipher(sopobjkey['rhash']).encrypt(pobjauthhash)

                userpobjauth = AESCipher(userpobjkey['rhash']).encrypt(pobjauthhash)

                # Now we create the secondary object, which is just a parent dummy, wrapping it's
                # auth with the wrapping key
                wrappingctx = tpm2.load(pobject['handle'], pobjauthhash, wrappingobjpriv, wrappingobjpub)

                sobjauth = hash_pass(os.urandom(32))['hash']

                encsobjauth = tpm2.encrypt(wrappingctx, wrappingobjauth['hash'], sobjauth)
                encsobjauth = binascii.hexlify(encsobjauth)

                objattrs="restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth"
                sobjpriv, sobjpub, sobjpubdata = tpm2.create(pobject['handle'], pobjauthhash, sobjauth, objattrs=objattrs, alg='aes256')

                # If this succeeds, we update the token table
                tokid = db.addtoken(pobject['id'], label, sopobjkey, sopobjauth, userpobjkey, userpobjauth)

                # now we update the sealobject table with the tokid to seal objects mapping
                db.addsealobjects(tokid, usersealauth, usersealpriv, usersealpub, sosealauth, sosealpriv, sosealpub)

                # Update the wrapping object table
                tokid = db.addwrapping(tokid, wrappingobjpriv, wrappingobjpub)

                # Update the secondary object table
                tokid = db.addsecondary(tokid, encsobjauth, sobjpriv, sobjpub)

                db.commit()

        print("Created token: %s" % label)

@commandlet("addkey")
class AddKeyCommand(Command):
    '''
    Adds a key to a token within a tpm2-pkcs11 store.
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--label',
            help='The tokens label to add a key too.\n',
            required=True)
        group_parser.add_argument(
            '--algorithm',
            help='The type of the key.\n',
            choices=[ 'rsa1024', 'rsa2048', 'aes128', 'aes256' ],
            required=True)
        group_parser.add_argument(
            '--id',
            help='The key id. Defaults to a random 8 bytes of hex.\n',
            default=binascii.hexlify(os.urandom(8)))
        pinopts = group_parser.add_mutually_exclusive_group(required=True)
        pinopts.add_argument(
            '--sopin',
            help='The Administrator pin,'),
        pinopts.add_argument(
            '--userpin',
            help='The User pin.\n'),

    def __call__(self, args):

        path = os.path.expanduser(args['path'])

        label = args['label']

        id = args['id']

        with Db(path) as db:

            token = db.gettoken(label)

            pobj = db.getprimary(token['pid'])

            with TemporaryDirectory() as d:
                tpm2 = Tpm2(d, path)

                # Get the primary object encrypted auth value and sokey information
                # to decode it. Based on the incoming pin
                is_so = args['sopin'] != None
                if is_so:
                    pin = args['sopin']
                    pinpobjauthkeysalt = token['sopobjauthkeysalt']
                    pinpobjauthkeyiters = token['sopobjauthkeyiters']
                    pinpobjauth = token['sopobjauth']
                else:
                    pin = args['userpin']
                    pinpobjauthkeysalt = token['userpobjauthkeysalt']
                    pinpobjauthkeyiters = token['userpobjauthkeyiters']
                    pinpobjauth = token['userpobjauth']

                pinpobjauthkeysalt = binascii.unhexlify(pinpobjauthkeysalt)
                pinpobjauthkey = hash_pass(pin, iters=pinpobjauthkeyiters, salt=pinpobjauthkeysalt)

                pinpobjauth = AESCipher(pinpobjauthkey['rhash']).decrypt(pinpobjauth)

                # At this point we have recovered the ACTUAL auth value for the primary object, so now we
                # can load up the seal objects
                sealobject = db.getsealobject(token['id'])

                if is_so:
                    sealpub = sealobject['sopub']
                    sealpriv = sealobject['sopriv']
                    salt = sealobject['soauthsalt']
                    iters = sealobject['soauthiters']
                else:
                    sealpub = sealobject['userpub']
                    sealpriv = sealobject['userpriv']
                    salt = sealobject['userauthsalt']
                    iters = sealobject['userauthiters']

                salt = binascii.unhexlify(salt)
                sealauth = hash_pass(pin, iters, salt)['hash']

                # Load the so sealobject using the PARENTS AUTH (primaryobject)
                sealctx = tpm2.load(pobj['handle'], pinpobjauth, sealpriv, sealpub)

                # Now that the sealobject is loaded, we need to unseal the wrapping key
                # object auth.
                wrappingauth = tpm2.unseal(sealctx, sealauth)

                # Now that we have the unsealed wrappingauth value
                # Load the wrapping object
                wrappingobj = db.getwrapping(token['id'])
                wrappingctx = tpm2.load(pobj['handle'], pinpobjauth, wrappingobj['priv'], wrappingobj['pub'])

                # Now get the secondary object from db
                sobj = db.getsecondary(token['id'])

                # decrypt sobj auth with wrapping
                sobjauth = binascii.unhexlify(sobj['objauth'])
                sobjauth = tpm2.decrypt(wrappingctx, wrappingauth, sobjauth)

                #create an auth value for the tertiary object.
                objauth = hash_pass(rand_str(32))['hash']

                # load the secondary object
                sobjctx = tpm2.load(pobj['handle'], pinpobjauth, sobj['priv'], sobj['pub'])

                # create a tertiary object under the loaded secondary object
                # Map onto the defaults in tpm2_create and store the attributes into
                # the db.
                alg = args['algorithm']
                if alg.startswith('rsa'):
                    size = int(alg[3:],0)
                elif alg.startswith('aes'):
                    size = int(alg[3:],0)
                    # XXX: We set the mode for the tpm to NULL so we can support arbitrary mechanisms on use, but we store it
                    # as CBC for now. We may wish to make this an asterik or NULL indicating we don't filter it out...
                    # Unfortunatley AES mechs are not bitwise flags, so we can't just or them in, and 0 is a valid
                    # CKM_ value, so we can't use 0. Maybe CKM_VENDOR_DEFINED | XXX.
                else:
                    sys.exit('Unknown algorithm, got: "%s"' % alg)

                tertiarypriv, tertiarypub, tertiarypubdata = tpm2.create(sobjctx, sobjauth, objauth, alg=alg)

                # Encrypt tertiary object auth with secondary object via TPM
                encobjauth = tpm2.encrypt(wrappingctx, wrappingauth, objauth)
                encobjauth = binascii.hexlify(encobjauth)

                #
                # Cache the objects attributes from the public structure and other sources
                # and populate the db with the data. This allows use of the public data
                # without needed to load any objects which requires a pin to do.
                #
                y = yaml.load(tertiarypubdata)

                if alg.startswith('rsa'):
                    attrs = [
                        {  CKA_KEY_TYPE        : CKK_RSA         },
                        {  CKA_CLASS           : CKO_PRIVATE_KEY },
                        {  CKA_CLASS           : CKO_PUBLIC_KEY  },
                        {  CKA_ID              : id              },
                        {  CKA_MODULUS         : y['rsa']        },
                        {  CKA_PUBLIC_EXPONENT : 65537           },
                    ]

                    mech = [
                        { CKM_RSA_PKCS_OAEP : "" },
                    ]

                elif alg.startswith('aes'):
                    attrs = [
                        { CKA_CLASS    : CKO_SECRET_KEY },
                        { CKA_KEY_TYPE : CKK_AES        }
                    ]

                    mech = [
                        { CKM_AES_CBC : "" },
                    ]

                # Store to database
                tokid = db.addtertiary(sobj['id'], tertiarypriv, tertiarypub, encobjauth, attrs, mech)

                db.commit()

                print("Added key: %d" % (tokid))

@commandlet("rmtoken")
class RmTokenCommand(Command):
    '''
    Removes a token from a tpm2-pkcs11 store
    '''

    @staticmethod
    def rmtokenfiles(db, token):
        sobject = db.getsecondary(token['id'])
        priv = sobject['priv']
        pub = sobject['pub']
        os.unlink(priv)
        os.unlink(pub)

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--label',
            help='The profile label to remove.\n',
            required=True)

    def __call__(self, args):

        path = args['path']
        label = args['label']

        with Db(args['path']) as db:
            token = db.gettoken(label)
            RmTokenCommand.rmtokenfiles(db, token)
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
            help='The Administrator pin. This pin is used for object recovery.\n')
        group_parser.add_argument(
            '--userpin',
            help='The user pin. This pin is used for authentication for object use.\n')
        group_parser.add_argument(
            '--label',
            help='The label to verify.\n',
            required=True)

    @staticmethod
    def verify(db, args):

        label = args['label']

        token = db.gettoken(label)
        if token == None:
            sys.exit('No token labeled "%s"' % label)

        sopin = args['sopin']
        userpin = args['userpin']
        path = args['path']

        print('Verifying label: "%s"' % label)

        pobj = db.getprimary(token['pid'])
        sealobj = db.getsealobject(token['id'])
        wrappingkey = db.getwrapping(token['id'])

        pobjauth = None
        wrappingkeyauth = None

        with TemporaryDirectory() as d:
            tpm2 = Tpm2(d, path)

            if sopin != None:

                # load the seal object under the primary object using the AES/GCM software protected
                # primary object authorization value
                sopobjauthkeyiters = token['sopobjauthkeyiters']
                sopobjauthkeysalt = token['sopobjauthkeysalt']
                sopobjauthkeysalt = binascii.unhexlify(sopobjauthkeysalt)

                sopobjauthkey = hash_pass(sopin, salt=sopobjauthkeysalt, iters=sopobjauthkeyiters)

                sopobjauth = AESCipher(sopobjauthkey['rhash']).decrypt(token['sopobjauth'])

                sosealctx = tpm2.load(pobj['handle'], sopobjauth, sealobj['sopriv'], sealobj['sopub'])

                # Unseal the wrapping key auth
                sosealauthiters = sealobj['soauthiters']

                sosealauthsalt = sealobj['soauthsalt']
                sosealauthsalt = binascii.unhexlify(sosealauthsalt)

                sosealauth = hash_pass(sopin, salt=sosealauthsalt, iters=sosealauthiters)

                wrappingkeyauth = tpm2.unseal(sosealctx, sosealauth['hash'])
                pobjauth = sopobjauth

                print("SO pin valid!")

            if userpin != None:
                # load the seal object under the primary object using the AES/GCM software protected
                # primary object authorization value
                userpobjauthkeyiters = token['userpobjauthkeyiters']
                userpobjauthkeysalt = token['userpobjauthkeysalt']
                userpobjauthkeysalt = binascii.unhexlify(userpobjauthkeysalt)

                userpobjauthkey = hash_pass(userpin, salt=userpobjauthkeysalt, iters=userpobjauthkeyiters)

                userpobjauth = AESCipher(userpobjauthkey['rhash']).decrypt(token['userpobjauth'])

                usersealctx = tpm2.load(pobj['handle'], userpobjauth, sealobj['userpriv'], sealobj['userpub'])

                # Unseal the wrapping key auth
                usersealauthiters = sealobj['userauthiters']

                usersealauthsalt = sealobj['userauthsalt']
                usersealauthsalt = binascii.unhexlify(usersealauthsalt)

                usersealauth = hash_pass(userpin, salt=usersealauthsalt, iters=usersealauthiters)

                wrappingkeyauth = tpm2.unseal(usersealctx, usersealauth['hash'])
                pobjauth = userpobjauth

                print("USER pin valid!")


            wrappingkeyctx = tpm2.load(pobj['handle'], pobjauth, wrappingkey['priv'], wrappingkey['pub'])

            sobj = db.getsecondary(token['id'])

            sobjctx = tpm2.load(pobj['handle'], pobjauth, sobj['priv'], sobj['pub'])

            sobjauth = binascii.unhexlify(sobj['objauth'])
            sobjauth = tpm2.decrypt(wrappingkeyctx, wrappingkeyauth, sobjauth)

            print("Secondary object verified(%d), auth: %s" % (sobj['id'], sobjauth))

            tobjs = db.gettertiary(token['id'])

            for tobj in tobjs:
                tobjctx = tpm2.load(sobjctx, sobjauth, tobj['priv'], tobj['pub'])
                tobjauth = binascii.unhexlify(tobj['objauth'])
                tobjauth = tpm2._encryptdecrypt(wrappingkeyctx, wrappingkeyauth, tobjauth, decrypt=True)
                print("Tertiary object verified(%d), auth: %s" % (tobj['id'], tobjauth))

    def __call__(self, args):
        if args['userpin'] == None and args['sopin'] == None:
            sys.exit("Expected one or both of sopin or userpin")

        with Db(args['path']) as db:
            VerifyCommand.verify(db, args)

def main():
    '''The main entry point.'''

    opt_parser = argparse.ArgumentParser(
        description='A tool for manipulating the tpm2-pkcs11 database')

    subparser = opt_parser.add_subparsers(help='commands')

    commandlets = commandlet.get()

    # for each commandlet, instantiate and set up their options
    for n, c in commandlets.iteritems():
        p = subparser.add_parser(n, help=c.__doc__)
        p.set_defaults(which=n)
        # Instantiate

        opt_gen = getattr(c, 'generate_options', None)
        if callable(opt_gen):
            # get group help
            g = p.add_argument_group(n + ' options')
            # get args
            c.generate_options(g)
            g.add_argument(
            '--path',
            help='The location of the store directory.',
            default=DEFAULT_STORE_PATH)

    args = opt_parser.parse_args()

    d = vars(args)
    which = d['which']

    commandlet.get()[which](d)

if __name__ == '__main__':
    main()
