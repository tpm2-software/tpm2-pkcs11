# tpm2_ptool command tests

import os
import subprocess
import unittest

tpm2_ptool = os.path.realpath(os.path.join(os.path.dirname(__file__),
                                           '..', 'tpm2_ptool'))


class TestTpm2Ptool(unittest.TestCase):
    def test_usage(self):
        # usage -> rc=2
        rc = subprocess.call(['tpm2_ptool'])
        self.assertEqual(rc, 2)


if __name__ == '__main__':
    unittest.main()
