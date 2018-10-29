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
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from subprocess import Popen, PIPE

DEFAULT_STORE_PATH = os.path.join(os.environ.get("HOME"), ".tpm2_pkcs11") if os.environ.get("HOME") else os.getcwd()

def kvp_row(d):
    x = " ".join(["=".join([str(key), str(val)]) for key, val in d.items()])
    return x

def list_dict_to_kvp(l):
    x = "\n".join(kvp_row(d) for d in l)
    return x

def dict_from_kvp(kvp):
    return dict(x.split('=') for x in kvp.split('\n'))

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

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

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

CKA_LABEL = 0x3
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
            backend=default_backend()
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

class Tpm2(object):
    def __init__(self, tmp, final):
        self._tmp = tmp
        self._final = final

    def createprimary(self, ownerauth, objauth):
        ctx = os.path.join(self._tmp, "context.out")
        cmd = ['tpm2_createprimary',
                    '-p', 'hex:%s' % objauth.decode(),
                    '-o', ctx,
                    '-g', 'sha256',
                    '-G', 'rsa']

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
            cmd.extend(['-P', ownerauth])

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
        cmd = ['tpm2_load', '-C', str(pctx), '-P', 'hex:' + pauth.decode(),'-u', pub, '-r', priv, '-n', '/dev/null', '-o', ctx]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_load: %s", stderr)
        return ctx

    def unseal(self, ctx, auth):

        # tpm2_unseal -Q -c $file_unseal_key_ctx
        cmd = ['tpm2_unseal', '-c', ctx, '-p', 'hex:'+auth.decode()]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_unseal: %s", stderr)
        return stdout

    def _encryptdecrypt(self, ctx, auth, data, decrypt=False):

        cmd = ['tpm2_encryptdecrypt', '-c', ctx, '-p', 'hex:' + auth.decode()]

        if decrypt:
            cmd.extend(['-D'])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, env=os.environ)
        stdout, stderr = p.communicate(input=data)
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_encryptdecrypt: %s", stderr)
        return stdout

    def encrypt(self, ctx, auth, data):
        return self._encryptdecrypt(ctx, auth, data)

    def decrypt(self, ctx, auth, data):
        return self._encryptdecrypt(ctx, auth, data, decrypt=True)

    def _move(self, path):
        b = os.path.basename(path)
        n = os.path.join(self._final, b)
        shutil.move(path, n)
        return n

    def create(self, phandle, pauth, objauth, objattrs=None, seal=None, alg=None):
        # tpm2_create -Q -C context.out -g $gAlg -G $GAlg -u key.pub -r key.priv
        fd, priv = tempfile.mkstemp(prefix='', suffix='.priv', dir=self._tmp)
        fd, pub = tempfile.mkstemp(prefix='', suffix='.pub', dir=self._tmp)

        cmd = ['tpm2_create', '-C', str(phandle), '-u', pub, '-r', priv]

        if pauth and len(pauth) > 0:
            cmd.extend(['-P', 'hex:%s' % pauth.decode()])

        if objauth and len(objauth) > 0:
            cmd.extend(['-p', 'hex:%s' % objauth.decode()])

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

    def getcap(self, cap):

        # tpm2_getcap -Q -l $cap
        cmd = ['tpm2_getcap', '-c', cap]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_getcap: %s", stderr)
        return stdout

    def importkey(self, phandle, pauth, objauth, privkey, objattrs=None, seal=None, alg=None):

        fd, priv = tempfile.mkstemp(prefix='', suffix='.priv', dir=self._tmp)
        fd, pub = tempfile.mkstemp(prefix='', suffix='.pub', dir=self._tmp)

        if privkey and len(privkey) > 0:
            exists = os.path.isfile(privkey)
            if not exists:
                raise RuntimeError("File '%s' path is invalid or is missing", privkey)
        else:
            sys.exit("Invalid file path")

        parent_path = "file:"+ str(phandle)
        cmd = ['tpm2_import', '-V', '-C', parent_path, '-k', privkey, '-u', pub, '-r', priv]

        if pauth and len(pauth) > 0:
            cmd.extend(['-P', 'hex:%s' % pauth.decode()])

        if objauth and len(objauth) > 0:
            cmd.extend(['-p', 'hex:%s' % objauth.decode()])

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
            raise RuntimeError("Could not execute tpm2_import: %s" % str(stderr))

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
        c.execute("SELECT * from wrappingobjects WHERE tokid=?", (tokid, ))
        x = c.fetchone()
        return x

    def gettertiary(self, sid):
        c = self._conn.cursor()
        c.execute("SELECT * from tobjects WHERE sid=?", (sid, ))
        x = c.fetchall()
        return x

    def addtoken(self, pid, sopobjkey, sopobjauth, userpobjkey, userpobjauth, config, label=None):

        token = {
            # General Metadata
            'pid'        : pid,

            'sopobjauthkeysalt'  : sopobjkey['salt'],
            'sopobjauthkeyiters' : sopobjkey['iters'],
            'sopobjauth'         : sopobjauth,

            'userpobjauthkeysalt'  : userpobjkey['salt'],
            'userpobjauthkeyiters' : userpobjkey['iters'],
            'userpobjauth'         : userpobjauth,
            'config'               : list_dict_to_kvp(config)
        }

        if 'token-init=True' in token['config'] and label is None:
            raise RuntimeError('Expected label if token is to be initialized')

        if label:
             token['label'] = label

        columns = ', '.join(token.keys())
        placeholders = ', '.join('?' * len(token))
        sql = 'INSERT INTO tokens ({}) VALUES ({})'.format(columns, placeholders)
        c = self._conn.cursor()
        c.execute(sql, list(token.values()))

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
        c.execute(sql, list(sealobjects.values()))

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
        c.execute(sql, list(pobject.values()))

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
        c.execute(sql, list(sobject.values()))
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
        c.execute(sql, list(wrapping.values()))
        return  c.lastrowid

    def addtertiary(self, sid, priv, pub, objauth, attrs, mech):
        tobject = {
            'sid'          : sid,
            'pub'          : pub,
            'priv'         : priv,
            'objauth'      : objauth,
            'attrs'        : list_dict_to_kvp(attrs),
            'mech'         : list_dict_to_kvp(mech),
        }

        columns = ', '.join(tobject.keys())
        placeholders = ', '.join('?' * len(tobject))
        sql = 'INSERT INTO tobjects ({}) VALUES ({})'.format(columns, placeholders)
        c = self._conn.cursor()
        c.execute(sql, list(tobject.values()))
        return  c.lastrowid

    def updatetertiaryattrs(self, id, attrs):

        x = list_dict_to_kvp(attrs)
        sql = 'UPDATE tobjects SET attrs=? WHERE id=?'
        c = self._conn.cursor()
        c.execute(sql, (x, id))

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
                label TEXT UNIQUE,
                userpobjauthkeysalt TEXT,
                userpobjauthkeyiters NUMBER,
                userpobjauth TEXT,
                sopobjauthkeysalt TEXT,
                sopobjauthkeyiters NUMBER,
                sopobjauth TEXT,
                config TEXT NOT NULL,
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
            '''),
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
        group_parser.add_argument(
            '--primary-handle',
            nargs='?',
            type=InitCommand.str_to_int,
            action=InitCommand.make_action(primary=True),
            help='Use an existing primary key object, defaults to 0x81000001.')
        group_parser.add_argument(
            '--primary-auth',
            help='Authorization value for existing primary key object, defaults to an empty auth value.')

    @staticmethod
    def str_to_int(arg):
        return int(arg, 0)

    @staticmethod
    def make_action(**kwargs):
        class customAction(argparse.Action):
            def __call__(self, parser, args, values, option_string=None):
                args.__dict__.update(kwargs)
                setattr(args, self.dest, values)
        return customAction

    def __call__(self, args):

        use_existing_primary = 'primary' in args and args['primary']

        if not use_existing_primary and args['primary_auth'] != None:
            sys.exit('Cannot specify "--primary-auth" without "--primary-handle"')

        path = args['path']
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

                    pobjkey = hash_pass(pobjpin.encode())

                    if not use_existing_primary:
                        pobjauth = hash_pass(rand_str(32))['hash']
                        ctx = tpm2.createprimary(ownerauth, pobjauth)
                        handle = Tpm2.evictcontrol(ownerauth, ctx)
                    else:
                        # get the primary object auth value and convert it to hex
                        pobjauth = args['primary_auth'] if args['primary_auth'] != None else ""
                        pobjauth = binascii.hexlify(pobjauth.encode())

                        handle = args['primary_handle']
                        if handle == None:
                            handle = 0x81000001

                        # verify handle is persistent
                        output = tpm2.getcap('handles-persistent')
                        y = yaml.load(output)
                        if handle not in y:
                            sys.exit('Handle 0x%x is not persistent' % (handle))


                    c = AESCipher(pobjkey['rhash'])
                    pobjauth = c.encrypt(pobjauth)

                    pid = db.addprimary(handle, pobjauth, pobjkey['salt'], pobjkey['iters'])

                    action_word = "Added" if use_existing_primary else "Created"
                    print("%s a primary object of id: %d" % (action_word, pid))

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
            choices=[ 'auto', 'software', 'tpm' ],
            default='auto',
            help='Configure usage of SW based crypto for internal object protection.\n'
            + 'This is not recommended for production environments,as the tool will'
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

        tpm2 = None

        # Verify pid is in db
        pobject = db.getprimary(pid)

        pobjauthhash = AddTokenCommand.verify_pobjpin(pobject, pobjpin)

        with TemporaryDirectory() as d:
            tpm2 = Tpm2(d, path)

            #
            # Figure out if TPM supports encryptdecrypt
            # interface. If it does use a symmetric TPM
            # key to wrap object authorizations. If it
            # doesn't default to Software based crypto.
            #
            # Auto-configure only if the user didn't specify
            # explicitly what to do or specified auto.
            #
            print("auto-detecting TPM encryptdecrypt interface for wrapping key usage")
            commands = tpm2.getcap('commands')
            sym_support = 'encryptdecrypt'.encode() in commands

            if args['wrap'] != 'auto':
                if args['wrap'] == 'software' and sym_support:
                    print("Warning: confifuring software wrapping key when TPM has support.\n"
                      "THIS IS NOT RECOMENDED")
                    sym_support = False
                elif args['wrap'] == 'tpm' and not sym_support:
                    sys.exit("TPM does not have symmetric wrapping key support and it was "
                         + "explicitly requested.")
                else:
                    sym_support = True if args['wrap'] == 'tpm' else False

            print('Using "%s" based object authorization protections'
                  % ('TPM' if sym_support else "Software"))

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
            usersealpriv, usersealpub, usersealpubdata = tpm2.create(pobject['handle'], pobjauthhash,
                                                    usersealauth['hash'], seal=wrappingobjauth['hash'])
            sosealpriv, sosealpub, sosealpubdata = tpm2.create(pobject['handle'], pobjauthhash,
                                                sosealauth['hash'], seal=wrappingobjauth['hash'])

            #
            # If the TPM supports encryptdecrypt we create the wrapping object in the TPM,
            # else we use the sealed auth value as the key.
            #
            # We also need to adjust the key sizes for the wrapping key and secondary object to be the maximum
            # value reported by the TPM.
            #
            fixed_properties = tpm2.getcap('properties-fixed')
            y = yaml.load(fixed_properties)
            sym_size = y['TPM2_PT_CONTEXT_SYM_SIZE']['value']

            if sym_support:
                # Now we create the wrappingbject, with algorithm aes256
                wrappingobjpriv, wrappingobjpub, wrappingobjpubdata = tpm2.create(pobject['handle'], pobjauthhash, wrappingobjauth['hash'], alg='aes{}cfb'.format(sym_size))
                wrappingctx = tpm2.load(pobject['handle'], pobjauthhash, wrappingobjpriv, wrappingobjpub)

            sopobjkey, sopobjauth, userpobjkey, userpobjauth = AddTokenCommand.protect_pobj_auth(pobjauthhash, sopin, userpin)

            # Now we create the secondary object, which is just a parent dummy, wrapping it's
            # auth with the wrapping key
            sobjauth = hash_pass(os.urandom(32))['hash']

            if sym_support:
                encsobjauth = tpm2.encrypt(wrappingctx, wrappingobjauth['hash'], sobjauth)
                encsobjauth = binascii.hexlify(encsobjauth)
            else:
                encsobjauth = AESCipher(wrappingobjauth['rhash']).encrypt(sobjauth)

            objattrs="restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth"
            sobjpriv, sobjpub, sobjpubdata = tpm2.create(pobject['handle'], pobjauthhash, sobjauth, objattrs=objattrs, alg='rsa2048')

            # If this succeeds, we update the token table
            config = [ { 'sym-support' : sym_support}, {'token-init' : True } ]
            tokid = db.addtoken(pobject['id'], sopobjkey, sopobjauth, userpobjkey, userpobjauth, config, label=label)

            # now we update the sealobject table with the tokid to seal objects mapping
            db.addsealobjects(tokid, usersealauth, usersealpriv, usersealpub, sosealauth, sosealpriv, sosealpub)

            # Update the wrapping object table
            if sym_support:
                tokid = db.addwrapping(tokid, wrappingobjpriv, wrappingobjpub)

            # Update the secondary object table
            tokid = db.addsecondary(tokid, encsobjauth, sobjpriv, sobjpub)

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

        sopobjkey, sopobjauth, userpobjkey, userpobjauth = AddTokenCommand.protect_pobj_auth(pobjauthhash, '', '')

        config = [ {'token-init' : False } ]

        tokid = db.addtoken(pobject['id'], sopobjkey, sopobjauth, userpobjkey, userpobjauth, config)

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
            choices=[ 'auto', 'software', 'tpm' ],
            default='auto',
            help='Configure usage of SW based crypto for internal object protection.\n'
            + 'This is not recommended for production environments,as the tool will'
            + 'auto-configure this option based on TPM support.')

    def __call__(self, args):
        args['no_init'] = True
        super(self.__class__, self).__call__(args)

class NewKeyCommandBase(Command):
    '''
    creates a key to a token within a tpm2-pkcs11 store.
    '''

    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--id',
            help='The key id. Defaults to a random 8 bytes of hex.\n',
            default=binascii.hexlify(os.urandom(8)))
        pinopts = group_parser.add_mutually_exclusive_group(required=True)
        pinopts.add_argument(
            '--sopin',
            help='The Administrator pin.\n'),
        pinopts.add_argument(
            '--userpin',
            help='The User pin.\n'),

    # Implemented by derived class
    def new_key_create(self, sobjctx, sobjauth, objauth, tpm2, path, alg, privkey):
        raise NotImplementedError('Implement: new_key')

    @staticmethod
    def new_key_init(label, sopin, userpin, db, tpm2):
        token = db.gettoken(label)

        if token is None:
            sys.exit('Cannot find token by label "{}"'.format(label))

        token_config =  dict_from_kvp(token['config'])
        pobj = db.getprimary(token['pid'])

        # Get the primary object encrypted auth value and sokey information
        # to decode it. Based on the incoming pin
        is_so = sopin != None
        if is_so:
            pin = sopin
            pinpobjauthkeysalt = token['sopobjauthkeysalt']
            pinpobjauthkeyiters = token['sopobjauthkeyiters']
            pinpobjauth = token['sopobjauth']
        else:
            pin = userpin
            pinpobjauthkeysalt = token['userpobjauthkeysalt']
            pinpobjauthkeyiters = token['userpobjauthkeyiters']
            pinpobjauth = token['userpobjauth']

        pinpobjauthkeysalt = binascii.unhexlify(pinpobjauthkeysalt)
        pinpobjauthkey = hash_pass(pin.encode(), iters=pinpobjauthkeyiters, salt=pinpobjauthkeysalt)

        try:
            pinpobjauth = AESCipher(pinpobjauthkey['rhash']).decrypt(pinpobjauth)
        except InvalidTag:
            sys.exit('Invalid {} pin'.format('so' if is_so else 'user'))

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
        sealauth = hash_pass(pin.encode(), iters, salt)['hash']

        # Load the so sealobject using the PARENTS AUTH (primaryobject)
        sealctx = tpm2.load(pobj['handle'], pinpobjauth, sealpriv, sealpub)

        # Now that the sealobject is loaded, we need to unseal the wrapping key
        # object auth or the key when the TPM doesn't support encryptdecrypt

        wrappingauth = tpm2.unseal(sealctx, sealauth)

        sym_support = str2bool(token_config['sym-support'])
        if sym_support:
            # Now that we have the unsealed wrappingauth value
            # Load the wrapping object
            wrappingobj = db.getwrapping(token['id'])
            wrappingctx = tpm2.load(pobj['handle'], pinpobjauth, wrappingobj['priv'], wrappingobj['pub'])

        # Now get the secondary object from db
        sobj = db.getsecondary(token['id'])

        # decrypt sobj auth with wrapping
        sobjauth = sobj['objauth'];
        if sym_support:
            sobjauth = binascii.unhexlify(sobjauth)
            sobjauth = tpm2.decrypt(wrappingctx, wrappingauth, sobjauth)
        else:
            c = AESCipher(binascii.unhexlify(wrappingauth))
            sobjauth = c.decrypt(sobjauth)

        # load the secondary object
        sobjctx = tpm2.load(pobj['handle'], pinpobjauth, sobj['priv'], sobj['pub'])

        #create an auth value for the tertiary object.
        objauth = hash_pass(rand_str(32))['hash']

        if sym_support:
            # Encrypt tertiary object auth with secondary object via TPM
            encobjauth = tpm2.encrypt(wrappingctx, wrappingauth, objauth)
            encobjauth = binascii.hexlify(encobjauth)
        else:
            c = AESCipher(binascii.unhexlify(wrappingauth))
            encobjauth = c.encrypt(objauth)

        return (sobjctx, sobjauth, encobjauth, objauth)

    @staticmethod
    def new_key_save(alg, keylabel, id, label, tertiarypriv, tertiarypub, tertiarypubdata, encobjauth, objauth, db, tpm2):
        token = db.gettoken(label)

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

        # Add keylabel for ALL objects if set
        if keylabel is not None:
            attrs.append({CKA_LABEL : keylabel})

        # Now get the secondary object from db
        sobj = db.getsecondary(token['id'])

        # Store to database
        rowid = db.addtertiary(sobj['id'], tertiarypriv, tertiarypub, encobjauth, attrs, mech)

        # if the keylabel is not set, use the tertiary object id as the keylabel
        # Normally we would use a transaction to make this atomic, but Pythons
        # sqlite3 transaction handling is quite odd. So when the keylabel is None, just insert
        # into the db without that attribute, retrieve the primary key, and then issue an
        # update. A possible race exists if someone is looking for the key by label between
        # these operations.
        # See:
        #   - https://stackoverflow.com/questions/107005/predict-next-auto-inserted-row-id-sqlite
        if keylabel is None:
            keylabel = str(rowid)
            attrs.append({CKA_LABEL : keylabel})
            db.updatetertiaryattrs(rowid, attrs)

        db.commit()

        return keylabel

    def __call__(self, args):
        path = args['path']

        with Db(path) as db:

            with TemporaryDirectory() as d:
                tpm2 = Tpm2(d, path)

                label = args['label']
                sopin = args['sopin']
                userpin = args['userpin']
                alg = args['algorithm']
                key_label= args['key_label']
                id = args['id']

                privkey = None
                try:
                    privkey = args['privkey']
                except:
                    privkey = None
                else:
                    path = args['path']

                path = args['path']

                sobjctx, sobjauth, encobjauth, objauth = NewKeyCommandBase.new_key_init(label, sopin, userpin, db, tpm2)

                tertiarypriv, tertiarypub, tertiarypubdata = self.new_key_create(sobjctx, sobjauth, objauth, tpm2, path, alg, privkey)

                final_key_label = NewKeyCommandBase.new_key_save(alg, key_label, id, label, tertiarypriv, tertiarypub, tertiarypubdata, encobjauth, objauth, db, tpm2)

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
            help='The label of the key imported. Defaults to an integer value.\n')
        group_parser.add_argument(
            '--algorithm',
            help='The type of the key.\n',
            choices=[ 'rsa'],
            required=True)

    # Imports a new key
    def new_key_create(self, sobjctx, sobjauth, objauth, tpm2, path, alg, privkey):
        if alg !='rsa':
            sys.exit('Unknown algorithm or algorithm not supported, got "%s"' % alg)

        if privkey == None:
            sys.exit("Invalid private key path")

        tertiarypriv, tertiarypub, tertiarypubdata = tpm2.importkey(sobjctx, sobjauth, objauth, privkey=privkey, alg=alg)

        return (tertiarypriv, tertiarypub, tertiarypubdata)

    def __call__(self, args):
        keylabel = super(self.__class__, self).__call__(args)
        print('Imported key as label: "{keylabel}"'.format(keylabel=keylabel))

@commandlet("addkey")
class AddKeyCommand(NewKeyCommandBase):
    '''
    Adds a key to a token within a tpm2-pkcs11 store.
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        super(self.__class__, self).generate_options(group_parser)
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
            '--key-label',
            help='The key label to identify the key. Defaults to an integer value.\n')

    # Creates a new key
    def new_key_create(self, sobjctx, sobjauth, objauth, tpm2, path, alg, privkey):
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

        return (tertiarypriv, tertiarypub, tertiarypubdata)

    def __call__(self, args):
        keylabel = super(self.__class__, self).__call__(args)
        print('Added key as label: "{keylabel}"'.format(keylabel=keylabel))

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

                sopobjauthkey = hash_pass(sopin.encode(), salt=sopobjauthkeysalt, iters=sopobjauthkeyiters)

                sopobjauth = AESCipher(sopobjauthkey['rhash']).decrypt(token['sopobjauth'])

                sosealctx = tpm2.load(pobj['handle'], sopobjauth, sealobj['sopriv'], sealobj['sopub'])

                # Unseal the wrapping key auth
                sosealauthiters = sealobj['soauthiters']

                sosealauthsalt = sealobj['soauthsalt']
                sosealauthsalt = binascii.unhexlify(sosealauthsalt)

                sosealauth = hash_pass(sopin.encode(), salt=sosealauthsalt, iters=sosealauthiters)

                wrappingkeyauth = tpm2.unseal(sosealctx, sosealauth['hash'])
                pobjauth = sopobjauth

                print("SO pin valid!")

            if userpin != None:
                # load the seal object under the primary object using the AES/GCM software protected
                # primary object authorization value
                userpobjauthkeyiters = token['userpobjauthkeyiters']
                userpobjauthkeysalt = token['userpobjauthkeysalt']
                userpobjauthkeysalt = binascii.unhexlify(userpobjauthkeysalt)

                userpobjauthkey = hash_pass(userpin.encode(), salt=userpobjauthkeysalt, iters=userpobjauthkeyiters)

                userpobjauth = AESCipher(userpobjauthkey['rhash']).decrypt(token['userpobjauth'])

                usersealctx = tpm2.load(pobj['handle'], userpobjauth, sealobj['userpriv'], sealobj['userpub'])

                # Unseal the wrapping key auth
                usersealauthiters = sealobj['userauthiters']

                usersealauthsalt = sealobj['userauthsalt']
                usersealauthsalt = binascii.unhexlify(usersealauthsalt)

                usersealauth = hash_pass(userpin.encode(), salt=usersealauthsalt, iters=usersealauthiters)

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
    for n, c in commandlets.items():
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
            type=os.path.expanduser,
            help='The location of the store directory.',
            default=DEFAULT_STORE_PATH)

    args = opt_parser.parse_args()

    d = vars(args)
    which = d['which']

    commandlet.get()[which](d)

if __name__ == '__main__':
    main()
