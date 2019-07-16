# SPDX-License-Identifier: MIT
# Copyright (c) 2019 Intel Corporation
# All rights reserved.
import sys
import unittest
import subprocess
from unittest.mock import patch

from tpm2_pyesys.util.simulator import SimulatorTest

from tpm2_pkcs11 import tpm2_ptool as tool
from tpm2_pkcs11.utils import TemporaryDirectory


class TestPTool(SimulatorTest, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.abrmd = subprocess.Popen(
            ["sudo", "-u", "tss", "tpm2-abrmd", "--tcti=mssim"]
        )

    @classmethod
    def tearDownClass(cls):
        for pid in [
            line.split()[1]
            for line in subprocess.check_output(["ps", "aux"]).decode().split("\n")
            if "tpm2-abrmd" in line
        ]:
            subprocess.call(["sudo", "kill", pid])
        super().tearDownClass()
        cls.abrmd.wait()

    def test_init(self):
        with TemporaryDirectory() as tempdir:
            with patch("sys.exit"), patch(
                "sys.argv",
                new=[
                    "tpm2_ptool.py",
                    "init",
                    "--pobj-pin=mypobjpin",
                    "--path=%s" % (tempdir,),
                ],
            ):
                tool.main()
