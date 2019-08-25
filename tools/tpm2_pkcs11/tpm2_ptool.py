from .command import commandlet

# These imports are required to add the commandlet even though they appear unused
# Store level commands
from .commandlets_store import InitCommand  # noqa # pylint: disable=unused-import
from .commandlets_store import DestroyCommand  # noqa # pylint: disable=unused-import

# Token Level Commands
from .commandlets_token import AddTokenCommand  # noqa # pylint: disable=unused-import
from .commandlets_token import AddEmptyTokenCommand  # noqa # pylint: disable=unused-import
from .commandlets_token import RmTokenCommand  # noqa # pylint: disable=unused-import

from .commandlets_token import VerifyCommand  # noqa # pylint: disable=unused-import

from .commandlets_token import InitPinCommand  # noqa # pylint: disable=unused-import
from .commandlets_token import ChangePinCommand  # noqa # pylint: disable=unused-import

from .commandlets_keys import AddKeyCommand  # noqa # pylint: disable=unused-import
from .commandlets_keys import ImportCommand  # noqa # pylint: disable=unused-import

def main():
    '''The main entry point.'''

    commandlet.init('A tool for manipulating the tpm2-pkcs11 database')


if __name__ == '__main__':
    main()
