from .command import commandlet

# These imports are required to add the commandlet even though they appear unused
# Store level commands
from .commandlets_store import InitCommand  # pylint: disable=unused-import # noqa
from .commandlets_store import DestroyCommand  # pylint: disable=unused-import # noqa

# Token Level Commands
from .commandlets_token import AddTokenCommand  # pylint: disable=unused-import # noqa
from .commandlets_token import AddEmptyTokenCommand  # pylint: disable=unused-import # noqa
from .commandlets_token import RmTokenCommand  # pylint: disable=unused-import # noqa

from .commandlets_token import VerifyCommand  # pylint: disable=unused-import # noqa

from .commandlets_token import InitPinCommand  # pylint: disable=unused-import # noqa
from .commandlets_token import ChangePinCommand  # pylint: disable=unused-import # noqa

from .commandlets_keys import AddKeyCommand  # pylint: disable=unused-import # noqa
from .commandlets_keys import ImportCommand  # pylint: disable=unused-import # noqa


def main():
    '''The main entry point.'''

    commandlet.init('A tool for manipulating the tpm2-pkcs11 database')


if __name__ == '__main__':
    main()
