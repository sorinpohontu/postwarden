import contextlib
import io
import os
import shutil
import socket
import tempfile
import threading
import time
import dataclasses
import unittest
from pathlib import Path
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

    def journal(self, lines=None):
        from postwarden import logsource
        fake = mock.Mock(stdout=iter(self.LINES if lines is None else lines), stderr=mock.Mock(read=lambda: ""),
                         wait=lambda: 0)
        return (mock.patch.object(logsource.shutil, "which", return_value="/bin/journalctl"),
                mock.patch.object(logsource.subprocess, "Popen", return_value=fake),
                mock.patch.object(logsource, "journal_start", return_value=None))

    def run_lookup(self, *argv, journal=True):
        patches = self.journal() if journal else ()
        with contextlib.ExitStack() as stack:
            mocks = [stack.enter_context(p) for p in patches]
            out = stack.enter_context(mock.patch("sys.stdout", new_callable=io.StringIO))
            err = stack.enter_context(mock.patch("sys.stderr", new_callable=io.StringIO))
            status = main(["lookup", *argv])
        popen = mocks[1] if mocks else None
        return status, out.getvalue(), err.getvalue(), popen

    def test_searches_plain_and_compressed_files_and_labels_them_unverified(self):
        import gzip
        tmp = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, tmp, True)
        with open(os.path.join(tmp, "mail.log"), "w") as fh:
            fh.writelines(self.LINES[:2])
        with gzip.open(os.path.join(tmp, "mail.log.2.gz"), "wt") as fh:
            fh.writelines(self.LINES[2:])
        status, out, err, _ = self.run_lookup("(ref 3f9c2a7b41d0)", "--file", os.path.join(tmp, "mail.log*"), journal=False)
        self.assertEqual(status, 0)
        self.assertIn("rule=protected_recipient", out)
        self.assertIn("rule=authentication", out)
        self.assertIn(f"source: files {tmp}/mail.log* (unverified", err)

    def test_journal_is_read_by_trusted_unit(self):
        status, out, err, popen = self.run_lookup("3f9c2a7b41d0")
        self.assertEqual((status, out.count("\n")), (0, 2))
        argv = popen.call_args.args[0]
        self.assertEqual(argv[0], "journalctl")
        self.assertIn("_SYSTEMD_UNIT=postwarden.service", argv)
        self.assertNotIn("-t", argv)
        self.assertEqual(argv[-2:], ["--since", "-7d"])
        self.assertIn("source: journal, unit postwarden.service, since -7d (verified)", err)

    def test_any_source_matches_the_tag_and_says_so(self):
        status, _, err, popen = self.run_lookup("3f9c2a7b41d0", "--any-source", "--since", "-1d")
        argv = popen.call_args.args[0]
        self.assertIn("-t", argv)
        self.assertNotIn("_SYSTEMD_UNIT=postwarden.service", argv)
        self.assertIn("(--any-source), since -1d (unverified", err)

    def test_not_found_exit_status(self):
        tmp = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "mail.log")
        with open(path, "w") as fh:
            fh.writelines(self.LINES)
        status, _, err, _ = self.run_lookup("bbbbbbbbbbbb", "--file", path, journal=False)
        self.assertEqual(status, 1)
        self.assertIn(f"source: files {path}", err)
        self.assertNotIn("journal", err)

    def test_not_found_in_journal_mentions_permissions(self):
        status, _, err, _ = self.run_lookup("bbbbbbbbbbbb")
        self.assertEqual(status, 1)
        self.assertIn("systemd-journal", err)

    def test_without_journalctl_the_mail_logs_are_named_as_a_fallback(self):
        from postwarden import logsource
        with mock.patch.object(logsource.shutil, "which", return_value=None), \
             mock.patch.object(logsource, "_file_lines", return_value=iter(self.LINES)), \
             mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(main(["lookup", "bbbbbbbbbbbb"]), 1)
        self.assertIn(f"source: files {logsource.MAIL_LOGS} (journalctl not found; unverified", err.getvalue())

    def test_coverage_line_when_since_predates_the_journal(self):
        from postwarden import logsource
        patches = self.journal()
        with patches[0], patches[1], mock.patch.object(logsource, "journal_start", return_value=time.time() - 86400), \
             mock.patch("sys.stdout", new_callable=io.StringIO), mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            main(["lookup", "3f9c2a7b41d0", "--since", "-30d"])
        self.assertIn("note: the journal starts at ", err.getvalue())
        self.assertIn("--file '/var/log/mail.log*' (unverified)", err.getvalue())


class NegativeSince(unittest.TestCase):
    def test_relative_since_is_a_value_on_every_python(self):
        from postwarden.__main__ import _join_negative_values
        self.assertEqual(_join_negative_values(["lookup", "x", "--since", "-30d", "--file", "f"]),
                         ["lookup", "x", "--since=-30d", "--file", "f"])
        self.assertEqual(_join_negative_values(["stats", "--since", "2026-09-01"]), ["stats", "--since", "2026-09-01"])
        self.assertEqual(_join_negative_values(["stats", "--since", "--json"]), ["stats", "--since", "--json"])


class LogSource(unittest.TestCase):
    NOW = 1_800_000_000.0

    def test_since_forms(self):
        from postwarden.logsource import since_timestamp
        self.assertEqual(since_timestamp("-7d", self.NOW), self.NOW - 7 * 86400)
        self.assertEqual(since_timestamp("-24h", self.NOW), self.NOW - 86400)
        self.assertEqual(since_timestamp("-30days", self.NOW), self.NOW - 30 * 86400)
        self.assertIsNotNone(since_timestamp("2026-09-01"))
        self.assertIsNone(since_timestamp("yesterday"))

    def test_no_coverage_line_inside_the_journal_or_for_files(self):
        from postwarden.logsource import Source, coverage_note
        journal = Source("journal", since="-1d")
        self.assertIsNone(coverage_note(journal, self.NOW - 2 * 86400, self.NOW))
        self.assertIsNotNone(coverage_note(journal, self.NOW - 3600, self.NOW))
        self.assertIsNone(coverage_note(Source("files", pattern="/x"), self.NOW, self.NOW))
        self.assertIsNone(coverage_note(journal, None, self.NOW))


class Overview(unittest.TestCase):
    def run_bare(self, *argv, which=None, shown=""):
        from postwarden import __main__ as cli
        result = mock.Mock(stdout=shown)
        with mock.patch("shutil.which", return_value=which), \
             mock.patch("subprocess.run", return_value=result), \
             mock.patch.object(cli.socket, "gethostname", return_value="mx1"), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            status = main(list(argv))
        return status, out.getvalue().splitlines()

    @staticmethod
    def rows(out):
        """Box rows as (label, value); a row with an empty label continues the previous one; '---' is a separator."""
        rows = []
        for line in out[1:]:
            if line.startswith("+-"):
                rows.append(("---", ""))
            elif line.startswith("| "):
                label, value = (cell.strip() for cell in line.strip("|").split("|", 1))
                rows.append((label or rows[-1][0], value))
            else:
                break
        return rows

    def write(self, directory, text):
        path = os.path.join(directory, "config.toml")
        Path(path).write_text(text)
        return path

    def test_bare_call_shows_version_config_modes_service_and_commands(self):
        from postwarden import __version__
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, BASE_TOML)
            status, out = self.run_bare("--config", path, which="/bin/systemctl",
                                        shown="ActiveState=active\nActiveEnterTimestamp=Tue 2026-09-29 11:52:15 EEST\n")
        self.assertEqual(status, 0)
        self.assertEqual(self.rows(out), [
            ("postwarden", f"{__version__} on mx1"), ("Config", path), ("---", ""),
            ("Mode", "enforce (all rules except sending limits)"),
            ("Sending limits", "observe; 100/h, 500/day per sender; local 1000/h, 5000/day"), ("Protected", "all@*"), ("Protected", "everyone@*"),
            ("Protected", "all@example.com"), ("Protected", "everyone@example.com"), ("---", ""),
            ("Service", "active since Tue 2026-09-29 11:52:15 EEST"), ("---", ""),
            ("Docs", "/etc/postwarden/docs"), ("Homepage", "https://github.com/sorinpohontu/postwarden"), ("---", "")])
        self.assertIn("commands", out)
        self.assertTrue(any(line.startswith("  stats ") for line in out))

    def test_long_protected_list_is_capped_with_a_pointer(self):
        entries = "".join(f'[protection.addresses."a{n}@example.com"]\nauthorized_logins = []\n' for n in range(7))
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, "schema_version = 1\n" + entries)
            status, out = self.run_bare("--config", path)
        protected = [value for label, value in self.rows(out) if label == "Protected"]
        self.assertEqual(protected, ["a0@example.com", "a1@example.com", "a2@example.com", "a3@example.com",
                                     f"... and 3 more: postwarden --config {path} show-config"])

    def test_limits_row_lists_only_keys_changed_from_their_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, BASE_TOML + "\n[limits]\nmax_recipients = 500\nmessage_bytes = 41943040\n"
                                                      "dns_timeout_seconds = 3\n")
            status, out = self.run_bare("--config", path)
        self.assertEqual(dict(self.rows(out))["Limits"], "max_recipients 500, dns_timeout_seconds 3")

    def test_sending_limits_show_numbers_and_multipliers_but_not_when_off(self):
        extra = ('\n[sending_limits]\nper_hour = 50\n[sending_limits.multipliers]\n'
                 '"marketing@example.com" = 10\n"example.org" = 0.5\n')
        with tempfile.TemporaryDirectory() as directory:
            rows = self.rows(self.run_bare("--config", self.write(directory, BASE_TOML + extra))[1])
            off = self.rows(self.run_bare("--config", self.write(
                directory, BASE_TOML + extra.replace("per_hour = 50", 'mode = "off"')))[1])
        self.assertEqual(dict(rows)["Sending limits"], "observe; 50/h, 500/day per sender; local 1000/h, 5000/day")
        self.assertEqual([value for label, value in rows if label == "Multipliers"],
                         ["marketing@example.com x10 (500/h, 5000/day)", "example.org x0.5 (25/h, 250/day)"])
        self.assertEqual(dict(off)["Sending limits"], "off")
        self.assertNotIn("Multipliers", dict(off))

    def test_missing_config_and_systemctl_are_lines_not_errors(self):
        status, out = self.run_bare("--config", "/nonexistent/config.toml")
        rows = dict(self.rows(out))
        self.assertEqual(status, 0)
        self.assertTrue(rows["Mode"].startswith("not read: configuration file not found"))
        self.assertEqual(rows["Service"], "unknown (systemctl not found)")


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


class InstallerArguments(unittest.TestCase):
    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("install_cli", Path(__file__).resolve().parents[2] / "scripts" / "install.py")
        self.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cli)

    def test_apply_and_dry_run_are_exclusive(self):
        for command in (["install"], ["configure-postfix", "--phase", "observe"], ["rollback", "--deployment-id", "x"]):
            with self.subTest(command=command[0]), mock.patch.object(self.cli.deployment, "inspect") as inspect, \
                 mock.patch("sys.stderr", new=io.StringIO()) as err, self.assertRaises(SystemExit) as ctx:
                self.cli.main(command + ["--apply", "--dry-run"])
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn("not allowed with argument", err.getvalue())
            inspect.assert_not_called()

    def test_config_only_for_inspect(self):
        for command in (["install"], ["configure-postfix", "--phase", "enforce"], ["rollback", "--deployment-id", "x"]):
            with self.subTest(command=command[0]), mock.patch.object(self.cli.deployment, "inspect") as inspect, \
                 self.assertRaises(SystemExit) as ctx:
                self.cli.main(["--config", "/tmp/other.toml"] + command)
            self.assertIn("--config applies to inspect only", str(ctx.exception.code))
            inspect.assert_not_called()
        report = {"candidate_version": "x", "debian": {"id": "debian", "version_id": "13", "codename": "trixie"},
                  "python": "3.13", "supported": True, "packages": {}, "installed_release": None, "unit_installed": False,
                  "daemon_active": False, "socket_present": False, "config": {"path": "/tmp/other.toml", "present": False},
                  "postfix": None, "findings": []}
        with mock.patch.object(self.cli.deployment, "inspect", return_value=report) as inspect, \
             mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(self.cli.main(["--config", "/tmp/other.toml", "inspect"]), 0)
        inspect.assert_called_once_with("/tmp/other.toml")
