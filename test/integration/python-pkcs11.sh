#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -exo pipefail

if [ -z "$T" ]; then
    export T="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
fi

source "$T/test/integration/scripts/helpers.sh"

setup_asan

"${PYTHON_INTERPRETER:-python3}" - <<'_SCRIPT_'
import os
import unittest

import pkcs11

class TestPKCS11(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.getenv('TPM2_PKCS11_MODULE', os.path.join(os.getcwd(), 'src/.libs/libtpm2_pkcs11.so'))
        lib = pkcs11.lib(path)
        cls._token = lib.get_token(token_label='label')

    def test_CKM_PKCS11(self):
        with self._token.open(rw=False, user_pin='myuserpin') as session:

            public = session.get_key(label='rsa0',object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY)
            private = session.get_key(label='rsa0',object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY)

            original = plaintext = b'1234567890123456'
            ciphertext = public.encrypt(plaintext, mechanism=pkcs11.mechanisms.Mechanism.RSA_PKCS)
            self.assertNotEqual(plaintext, ciphertext)

            plaintext = 'notdecrypted'
            plaintext = private.decrypt(ciphertext, mechanism=pkcs11.mechanisms.Mechanism.RSA_PKCS)
            # strip padding
            p2 = plaintext[-len(original):]
            self.assertEqual(p2, original)

if __name__ == '__main__':
    unittest.main()
_SCRIPT_

exit $?
