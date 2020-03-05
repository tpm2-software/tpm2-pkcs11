# SPDX-License-Identifier: BSD-2-Clause
import argparse
import io
import os
import sys
import traceback
import yaml

# local imports
from .command import Command
from .command import commandlet

from .db import Db
from .utils import bytes_to_file
from .utils import TemporaryDirectory
from .utils import rand_hex_str
from .utils import query_yes_no
from .utils import str2bool

from .tpm2 import Tpm2

@commandlet("init")
class InitCommand(Command):
    '''
    Initializes a tpm2-pkcs11 store
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        group_parser.add_argument(
            '--owner-auth',
            help='The authorization password for adding a primary object to the owner hierarchy.\n',
            default="")
        group_parser.add_argument(
            '--primary-handle',
            nargs='?',
            type=InitCommand.str_to_handle,
            action=InitCommand.make_action(primary=True),
            help='Use an existing primary key object, defaults to 0x81000001.')
        group_parser.add_argument(
            '--primary-auth',
            help='Authorization value for existing primary key object, defaults to an empty auth value.'
        )

    @staticmethod
    def str_to_handle(arg):
        try:
            return int(arg, 0)
        except ValueError:
                if not os.path.exists(arg):
                    sys.exit('arg "%s" neither a handle nor esys handle file')
                else:
                    return arg


    @staticmethod
    def make_action(**kwargs):
        class customAction(argparse.Action):
            def __call__(self, parser, args, values, option_string=None):
                args.__dict__.update(kwargs)
                setattr(args, self.dest, values)

        return customAction

    def __call__(self, args):

        use_existing_primary = 'primary' in args and args['primary']

        path = args['path']
        if not os.path.isdir(path):
            sys.exit("Specified path is not a directory, got: %s" % (path))

        ownerauth = args['owner_auth']
        pobjauth = args['primary_auth']

        # create the db
        with Db(path) as db:

            shall_evict = False
            with TemporaryDirectory() as d:
                try:
                    tpm2 = Tpm2(d)

                    if not use_existing_primary:
                        pobjauth = pobjauth if pobjauth != None else rand_hex_str(
                        )
                        ctx = tpm2.createprimary(ownerauth, pobjauth)
                        tr_handle = tpm2.evictcontrol(ownerauth, ctx)
                        shall_evict = True
                    else:
                        # get the primary object auth value and convert it to hex
                        if pobjauth is None:
                            pobjauth = ""

                        handle = args['primary_handle'] if args['primary_handle'] is not None else 0x81000001

                        # If we get a raw handle, capture the ESYS_TR serialized and
                        # and verify that its persistent.
                        #
                        # TODO: with python bindings call esys_tr_from_public() over readpublic.
                        # TODO: we need a sapi handle from esys tr to look into getcap to see if
                        # its persistent.
                        if isinstance(handle, int):
                            tr_handle = tpm2.readpublic(handle)

                            # verify handle is persistent
                            output = tpm2.getcap('handles-persistent')
                            y = yaml.safe_load(output)
                            if handle not in y:
                                sys.exit('Handle 0x%x is not persistent' %
                                         (handle))
                        else:
                            tr_handle = handle


                    pid = db.addprimary(tr_handle, pobjauth)

                    d = {
                        'id' : pid,
                        'action' : "Added" if use_existing_primary else "Created"
                    }

                    print(yaml.safe_dump(d, default_flow_style=False))

                except Exception as e:
                    if shall_evict and tr_handle != None:
                        tpm2.evictcontrol(ownerauth, tr_handle)

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
            '--pid', type=int, help="The primary object id to remove.\n")
        group_parser.add_argument(
            '--owner-auth',
            default="",
            help="The primary object id to remove.\n")

    def __call__(self, args):
        path = args['path']
        pid = args['pid']
        ownerauth = args['owner_auth']

        if not os.path.exists(path):
            os.mkdir(path)
        elif not os.path.isdir(path):
            sys.exit("Specified path is not a directory, got: %s" % (path))

        proceed = query_yes_no(
            'This will delete the primary object of id "%s" and all associated data from db under "%s"'
            % (pid, path))
        if not proceed:
            sys.exit(0)
        # create the db
        with Db(path) as db:
            pobj = db.getprimary(pid)
            if pobj is None:
                sys.exit('Primary Object id "%s"not found' % pid)

            with TemporaryDirectory() as d:
                tpm2 = Tpm2(d)

                tr_file = bytes_to_file(pobj['handle'], d)

                db.rmprimary(pid)
                tpm2.evictcontrol(ownerauth, tr_file)

@commandlet("dbup")
class DbUp(Command):
    '''
    Initializes a tpm2-pkcs11 store
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        pass

    def __call__(self, args):

        path = args['path']

        # create the db
        with Db(path) as db:
            old_ver = db.version
            new_ver = db.VERSION
            y = {
                'old' : old_ver,
                'new' : new_ver,
            }

            print(yaml.safe_dump(y, default_flow_style=False))

@staticmethod
def _empty_validator(s):
    return s

@staticmethod
def _log_level_validator(s):

    if s == "":
        return s

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

    @classmethod
    def get_validator_for_key(cls, key):
        try:
            return cls._keys[key]
        except KeyError:
            sys.exit('Invalid key, got: \"{}\", expected ont of "{}"'.format(
                key, ", ".join(ConfigCommand._keys.keys())))

    @classmethod
    def config(cls, db, args):

        key = args['key']
        value = args['value']

        s = db.get_store_config()
        store_config = yaml.safe_load(io.StringIO(s)) if s is not None else {}
        if key is None and value is None:
            yaml_tok_cconf = yaml.safe_dump(store_config, default_flow_style=False)
            print(yaml_tok_cconf)
            sys.exit(0)

        if key is None and value:
            sys.exit("Cannot specify --value without --key")

        # key has to be set here based on above logical check
        # throws an error if the key isn't known to the system
        validator = cls.get_validator_for_key(key)

        # no value, just key. Print the current value for key is set or empty if not set
        if value is None:
            v = None
            if store_config:
                v = str(store_config[key] if key in store_config else "")
            print(yaml.safe_dump({key : v}, default_flow_style=False))
            sys.exit(0)

        v = validator(value)
        store_config[key] = v

        # update the database
        db.update_store_config(store_config)

    def __call__(self, args):

        path = args['path']

        with Db(path) as db:
            ConfigCommand.config(db, args)
