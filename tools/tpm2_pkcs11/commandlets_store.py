# SPDX-License-Identifier: BSD-2-Clause
import argparse
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
from .utils import query_yes_no
from .utils import create_primary

from .tpm2 import Tpm2

@commandlet("init")
class InitCommand(Command):
    '''
    Initializes a tpm2-pkcs11 store
    '''

    # adhere to an interface
    # pylint: disable=no-self-use
    def generate_options(self, group_parser):
        mg = group_parser.add_mutually_exclusive_group()
        # Keep the old --owner-auth kicking around for backwards compat
        # but hide it in the help output.
        mg.add_argument(
            '--hierarchy-auth',
            help='The authorization password for adding a primary object to the hierarchy.\n',
            default="")
        mg.add_argument(
            '--owner-auth',
            help=argparse.SUPPRESS,
            dest='hierarchy_auth',
            default="")
        group_parser.add_argument(
            '--primary-auth',
            help='Authorization value for existing primary key object, defaults to an empty auth value.',
            default="")
        exclusive_group = group_parser.add_mutually_exclusive_group()
        exclusive_group.add_argument(
            '--primary-handle',
            nargs='?',
            type=InitCommand.str_to_handle,
            action=InitCommand.make_action(primary=True),
            help='Use an existing primary key object, defaults to 0x81000001.')
        exclusive_group.add_argument(
            '--transient-parent',
            const='tpm2-tools-default',
            nargs='?',
            choices=[ t for t in Tpm2.TEMPLATES.keys() if t is not None ],
            help='use a transient primary object of a given template.')

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

        hierarchyauth = args['hierarchy_auth']
        pobjauth = args['primary_auth']

        # create the db
        with Db(path) as db:

            transient_parent = args['transient_parent']
            shall_evict = False
            with TemporaryDirectory() as d:
                try:
                    tpm2 = Tpm2(d)

                    if not use_existing_primary:
                        pobj_ctx = create_primary(tpm2, hierarchyauth, pobjauth, transient_parent)
                        if not transient_parent:
                            pobj_ctx = tpm2.evictcontrol(hierarchyauth, pobj_ctx)
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
                            (_, pobj_ctx) = tpm2.readpublic(handle)

                            # verify handle is persistent
                            output = tpm2.getcap('handles-persistent')
                            y = yaml.safe_load(output)
                            if handle not in y:
                                sys.exit('Handle 0x%x is not persistent' %
                                         (handle))
                        else:
                            pobj_ctx = handle

                    y = {
                        'transient' : bool(transient_parent)
                    }

                    if transient_parent:
                        y['template-name'] = args['transient_parent']
                    else:
                        with open(pobj_ctx, 'rb') as f:
                            y['esys-tr'] = bytes.hex(f.read())
                    pid = db.addprimary(y, pobjauth)

                    d = {
                        'id' : pid,
                        'action' : "Added" if use_existing_primary else "Created"
                    }

                    print(yaml.safe_dump(d, default_flow_style=False))

                except Exception as e:
                    if shall_evict and pobj_ctx != None:
                        tpm2.evictcontrol(hierarchyauth, pobj_ctx)

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
            '--hierarchy-auth',
            default="",
            help="The primary object id to remove.\n")

    def __call__(self, args):
        path = args['path']
        pid = args['pid']
        hierarchyauth = args['hierarchy_auth']

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
                tpm2.evictcontrol(hierarchyauth, tr_file)

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
