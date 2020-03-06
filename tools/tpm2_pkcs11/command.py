# SPDX-License-Identifier: BSD-2-Clause
import argparse
import os


class commandlet(object):
    '''Decorator class for commandlet. You can add commandlets to the tool with this decorator.'''

    @staticmethod
    def get_default_store_path():

        # always use the env variable no matter what
        if "TPM2_PKCS11_STORE" in os.environ:
            store = os.environ.get("TPM2_PKCS11_STORE")
            try:
                os.mkdir(store, 0o770);
            except FileExistsError:
                return store
            except:
                # Keep trying
                pass
            # Exists, use it
            return store

        # is their a system store and can I access it?
        store = "/etc/tpm2_pkcs11"
        if os.path.exists(store) and os.access(store, os.W_OK):
            return store

        # look for a store in home
        if "HOME" in os.environ:
            store = os.path.join(os.environ.get("HOME"), ".tpm2_pkcs11")
            try:
                os.mkdir(store, 0o770);
            except FileExistsError:
                return store
            except:
                # Keep trying
                pass
            # Exists, use it
            return store

        # nothing else available, use cwd
        return os.getcwd()

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

    @staticmethod
    def init(description):

        opt_parser = argparse.ArgumentParser(description=description)

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
                    help='The location of the store directory. If not specified performs '
                    +'a search by looking at environment variable TPM2_PKCS11_STORE '
                    + 'and if not set then '
                    + '/etc/tpm2_pkcs11 and if not found or no write access, then '
                    + '$HOME/.tpm2_pkcs11 and if not found, then '
                    + 'defaults to using the current working directory.',
                    default=commandlet.get_default_store_path())

        args = opt_parser.parse_args()

        d = vars(args)
        if 'which' in d:
            commandlet.get()[d['which']](d)
        else:
            opt_parser.print_usage()


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
