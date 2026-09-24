import os
import shutil
import socket
import tempfile
import threading
import time
import dataclasses
import unittest
from unittest import mock

from postwarden.__main__ import main, socket_address
from postwarden.config import ServiceSettings

from helpers import BASE_TOML


class WaitReady(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp")
        self.sock_path = os.path.join(self.dir, "policy.sock")
        self.config = os.path.join(self.dir, "config.toml")
        with open(self.config, "w") as fh:
            fh.write(BASE_TOML)
        loader = __import__("postwarden.config", fromlist=["load_settings"]).load_settings
        patched = lambda path: dataclasses.replace(loader(path), service=ServiceSettings(socket=f"unix:{self.sock_path}"))
        patcher = mock.patch("postwarden.__main__.load_settings", patched)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def wait(self, timeout):
        return main(["--config", self.config, "wait-ready", "--timeout", str(timeout)])

    def test_succeeds_once_listener_appears(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)

        def listen_later():
            time.sleep(0.4)
            server.bind(self.sock_path)
            server.listen(1)

        threading.Thread(target=listen_later, daemon=True).start()
        self.assertEqual(self.wait(5), 0)

    def test_stale_socket_file_is_not_ready(self):
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(self.sock_path)
        stale.close()
        self.assertTrue(os.path.exists(self.sock_path))
        self.assertEqual(self.wait(0.5), 1)

    def test_missing_socket_times_out(self):
        self.assertEqual(self.wait(0.3), 1)


class SocketSpec(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(socket_address("unix:/run/x.sock"), (socket.AF_UNIX, "/run/x.sock"))
        self.assertEqual(socket_address("inet:8891"), (socket.AF_INET, ("127.0.0.1", 8891)))
        self.assertEqual(socket_address("inet:8891@192.0.2.1"), (socket.AF_INET, ("192.0.2.1", 8891)))
        self.assertEqual(socket_address("inet6:8891"), (socket.AF_INET6, ("::1", 8891)))


class Lookup(unittest.TestCase):
    LINES = [
        "2026-09-23T10:00:00 host postwarden[1]: action=reject mid=3f9c2a7b41d0 stage=rcpt rule=protected_recipient\n",
        "2026-09-23T10:00:01 host postwarden[1]: action=accept mid=3f9c2a7b41d01 stage=eom\n",
        "2026-09-23T10:00:02 host postwarden[1]: action=accept mid=aaaaaaaaaaaa stage=eom\n",
        "2026-09-23T10:00:03 host postwarden[1]: action=reject mid=3f9c2a7b41d0 stage=eom rule=authentication\n",
    ]

    def test_reference_forms_accepted(self):
        from postwarden.lookup import normalize_ref
        for text in ("3f9c2a7b41d0", "(ref 3f9c2a7b41d0)", "ref 3F9C2A7B41D0", "mid=3f9c2a7b41d0"):
            self.assertEqual(normalize_ref(text), "3f9c2a7b41d0")

    def test_malformed_reference_refused(self):
        from postwarden.lookup import LookupFailed, normalize_ref
        for text in ("", "3f9c", "3f9c2a7b41d0; rm -rf /", "zzzzzzzzzzzz"):
            with self.assertRaises(LookupFailed):
                normalize_ref(text)

    def test_matches_whole_field_only(self):
        from postwarden.lookup import matching
        found = list(matching(self.LINES, "3f9c2a7b41d0"))
        self.assertEqual(len(found), 2)
        self.assertTrue(all("mid=3f9c2a7b41d0 " in line for line in found))

    def test_searches_plain_and_compressed_files(self):
        import gzip
        tmp = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, tmp, True)
        with open(os.path.join(tmp, "mail.log"), "w") as fh:
            fh.writelines(self.LINES[:2])
        with gzip.open(os.path.join(tmp, "mail.log.2.gz"), "wt") as fh:
            fh.writelines(self.LINES[2:])
        with mock.patch("sys.stdout") as out:
            status = main(["lookup", "(ref 3f9c2a7b41d0)", "--file", os.path.join(tmp, "mail.log*")])
        self.assertEqual(status, 0)
        printed = "".join(call.args[0] for call in out.write.call_args_list)
        self.assertIn("rule=protected_recipient", printed)
        self.assertIn("rule=authentication", printed)

    def test_journal_query_uses_structured_arguments(self):
        from postwarden import lookup as mod
        fake = mock.Mock(stdout=iter(self.LINES), stderr=mock.Mock(read=lambda: ""), wait=lambda: 0)
        with mock.patch.object(mod.shutil, "which", return_value="/bin/journalctl"), \
             mock.patch.object(mod.subprocess, "Popen", return_value=fake) as popen:
            found = mod.lookup("3f9c2a7b41d0", since="-7d", files=None)
        self.assertEqual(len(found), 2)
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:1], ["journalctl"])
        self.assertIn("postwarden", argv)
        self.assertEqual(argv[-2:], ["--since", "-7d"])

    def test_not_found_exit_status(self):
        tmp = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "mail.log")
        with open(path, "w") as fh:
            fh.writelines(self.LINES)
        with mock.patch("sys.stderr"):
            self.assertEqual(main(["lookup", "bbbbbbbbbbbb", "--file", path]), 1)


class CheckConfigSummary(unittest.TestCase):
    def test_counts_addresses_and_groups_separately(self):
        from postwarden.__main__ import _protection_summary
        from postwarden.config import parse_settings
        import tomllib
        text = """
[protection.addresses."all@example.com"]
authorized_logins = ["a@example.com"]
[protection.addresses."all@*"]
authorized_logins = []
"""
        self.assertEqual(_protection_summary(parse_settings(tomllib.loads(text), source="x")),
                         "1 protected address, 1 protected group")
        self.assertEqual(_protection_summary(parse_settings({}, source="x")), "0 protected addresses")


class RunSocketOption(unittest.TestCase):
    def run_with(self, *extra):
        import sys
        import types
        captured = {}
        fake = types.ModuleType("postwarden.milter")
        fake.run_daemon = lambda settings: captured.setdefault("settings", settings) and 0
        tmp = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, tmp, True)
        config = os.path.join(tmp, "config.toml")
        with open(config, "w") as fh:
            fh.write(BASE_TOML)
        with mock.patch.dict(sys.modules, {"postwarden.milter": fake}), \
             mock.patch("postwarden.__main__._with_postfix", side_effect=lambda s, required: (s, "")), \
             mock.patch("sys.stderr"):
            status = main(["--config", config, "run", *extra])
        return status, captured.get("settings")

    def test_socket_override_reaches_the_daemon(self):
        status, settings = self.run_with("--socket", "unix:/tmp/pwload/policy.sock")
        self.assertEqual(settings.service.socket, "unix:/tmp/pwload/policy.sock")

    def test_default_socket_is_unchanged(self):
        status, settings = self.run_with()
        self.assertEqual(settings.service.socket, ServiceSettings().socket)

    def test_malformed_socket_refused(self):
        status, settings = self.run_with("--socket", "/tmp/x.sock")
        self.assertEqual(status, 1)
        self.assertIsNone(settings)
