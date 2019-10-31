import argparse
import os
import sys
import traceback
import yaml

# local imports
from .command import Command
from .command import commandlet

from .db import Db
from .utils import TemporaryDirectory
from .utils import rand_hex_str
from .utils import query_yes_no

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
            type=InitCommand.str_to_int,
            action=InitCommand.make_action(primary=True),
            help='Use an existing primary key object, defaults to 0x81000001.')
        group_parser.add_argument(
            '--primary-auth',
            help='Authorization value for existing primary key object, defaults to an empty auth value.'
        )

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

        path = args['path']
        if not os.path.exists(path):
            os.mkdir(path)
        elif not os.path.isdir(path):
            sys.exit("Specified path is not a directory, got: %s" % (path))

        ownerauth = args['owner_auth']
        pobjauth = args['primary_auth']

        # create the db
        with Db(path) as db:
            db.create()

            handle = None
            with TemporaryDirectory() as d:
                try:
                    tpm2 = Tpm2(d)

                    if not use_existing_primary:
                        pobjauth = pobjauth if pobjauth != None else rand_hex_str(
                        )
                        ctx = tpm2.createprimary(ownerauth, pobjauth)
                        handle = Tpm2.evictcontrol(ownerauth, ctx)
                    else:
                        # get the primary object auth value and convert it to hex
                        if pobjauth is None:
                            pobjauth = ""

                        handle = args['primary_handle']
                        if handle is None:
                            handle = 0x81000001

                        # verify handle is persistent
                        output = tpm2.getcap('handles-persistent')
                        y = yaml.safe_load(output)
                        if handle not in y:
                            sys.exit('Handle 0x%x is not persistent' %
                                     (handle))

                    pid = db.addprimary(handle, pobjauth)

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

            db.rmprimary(pid)
            Tpm2.evictcontrol(ownerauth, pobj['handle'])
