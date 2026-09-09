"""Shared test helpers."""
import os
import shutil
import tempfile
import unittest

from netsentinel.fixtures import build_all, build_proc_tree


class FixtureTestCase(unittest.TestCase):
    """Builds the standard fixture set once per test class."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="netsentinel_test_")
        cls.fixtures = build_all(cls._tmp)
        cls.proc_root = build_proc_tree(os.path.join(cls._tmp, "proc"))
        cls.clean_proc_root = build_proc_tree(
            os.path.join(cls._tmp, "proc_clean"),
            bad={"ps": "1 systemd\n523 sshd\n",
                 "sockets": "0100007F:0016 00000000:0000 0 523 0A\n",
                 "traces": "1700000100 execve /usr/bin/sshd -D\n"},
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)