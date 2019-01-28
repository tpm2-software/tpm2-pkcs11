import argparse
import os


class commandlet(object):
    '''Decorator class for commandlet. You can add commandlets to the tool with this decorator.'''

    DEFAULT_STORE_PATH = os.path.join(
        os.environ.get("HOME"),
        ".tpm2_pkcs11") if os.environ.get("HOME") else os.getcwd()

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
                    help='The location of the store directory.',
                    default=commandlet.DEFAULT_STORE_PATH)

        args = opt_parser.parse_args()

        d = vars(args)
        which = d['which']

        commandlet.get()[which](d)


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
