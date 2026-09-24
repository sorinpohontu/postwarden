import ipaddress
import os
import re
import tempfile
import tomllib
import unittest

from postwarden.config import ConfigError, LimitSettings, describe, load_settings, parse_settings
from postwarden.replies import Reply, validate_reply

from helpers import BASE_TOML, EXAMPLE, example_settings, settings


class ExampleFile(unittest.TestCase):
    def test_example_validates_and_matches_defaults(self):
        s = example_settings()
        self.assertEqual(s.mode, "observe")
        self.assertEqual(s.protection.addresses["all@*"], frozenset())
        self.assertEqual(s.protection.addresses["all@example.com"], frozenset({"manager@example.com"}))
        self.assertEqual(s.protection.addresses["board@example.com"], frozenset({"chair@example.com"}))
        self.assertEqual(s.responses["temporary_failure"].smtp_code, 451)
        self.assertNotIn("password", str(describe(s)).lower())

    def test_commented_example_defaults_match_the_code(self):
        text = EXAMPLE.read_text()
        uncommented = re.sub(r"(?m)^# (\[[a-z_.]+\]|[a-z_]+ = .*)$", r"\1", text)
        self.assertIn("[limits]\nmessage_bytes", uncommented)
        self.assertEqual(describe(parse_settings(tomllib.loads(uncommented), source="x")), describe(parse_settings(tomllib.loads(text), source="x")))
        limits = tomllib.loads(uncommented)["limits"]
        self.assertEqual(set(limits), set(LimitSettings.__dataclass_fields__))


class Validation(unittest.TestCase):
    def errors(self, extra="", base=BASE_TOML):
        with self.assertRaises(ConfigError) as ctx:
            settings(extra, base)
        return ctx.exception.errors

    def test_unknown_keys_and_types_reported_together(self):
        errors = self.errors('\nbogus = 1\n[logging]\nlevel = 5\n[limits]\nmessage_bytes = "big"\n')
        self.assertTrue(any(e.startswith("bogus: unknown key") for e in errors))
        self.assertTrue(any(e.startswith("logging.level: must be a string") for e in errors))
        self.assertTrue(any(e.startswith("limits.message_bytes: must be an integer") for e in errors))

    def test_schema_version_optional_and_supported(self):
        self.assertEqual(settings(base="mode = 'observe'\n").schema_version, 1)
        self.assertTrue(any("unsupported version 2" in e for e in self.errors(base="schema_version = 2\n")))

    def test_mode_choice(self):
        self.assertTrue(any(e.startswith("mode: must be one of") for e in self.errors(base="schema_version = 1\nmode = 'maybe'\n")))

    def test_fixed_service_and_logging_keys_removed(self):
        errors = self.errors('\n[service]\nsocket = "unix:/tmp/x"\n[logging]\nbackend = "stderr"\nidentifier = "x"\nlevel = "debug"\n')
        self.assertIn("service: removed; the milter socket is fixed at unix:/var/spool/postfix/postwarden/policy.sock", errors)
        self.assertEqual(sum(e.startswith(("logging.backend: removed", "logging.identifier: removed")) for e in errors), 2)
        self.assertEqual(len(errors), 3)

    def test_fixed_sender_authentication_keys_removed(self):
        errors = self.errors('\n[sender_authentication]\nalignment = "strict"\n'
                             'temporary_error = "defer"\nallow_local = false\n')
        self.assertEqual(sorted(errors), [
            "sender_authentication.alignment: removed; the rule is fixed: SPF and DKIM must match the From domain exactly",
            "sender_authentication.temporary_error: removed; the rule is fixed: DNS and verifier trouble always defers"])
        self.assertFalse(settings("\n[sender_authentication]\nallow_local = false\n").sender_authentication.allow_local)

    def test_timeouts_must_be_finite(self):
        for value in ("nan", "+nan", "inf"):
            errors = self.errors(f"\n[limits]\ndns_timeout_seconds = {value}\nauthentication_deadline_seconds = {value}\n")
            self.assertIn("limits.dns_timeout_seconds: must be a finite number", errors, value)
            self.assertIn("limits.authentication_deadline_seconds: must be a finite number", errors, value)
        self.assertEqual(settings("\n[limits]\ndns_timeout_seconds = 0.5\n").limits.dns_timeout_seconds, 0.5)

    def test_port_lists_removed(self):
        errors = self.errors('\n[self_sender]\nports = [25]\n[sender_authentication]\nallow_authenticated_ports = [587]\n')
        self.assertEqual([e.split(":")[0] for e in errors], ["self_sender.ports", "sender_authentication.allow_authenticated_ports"])
        self.assertEqual(self.errors('\n[authentication]\nnull_sender = "both"\n'), ["authentication: renamed to [sender_authentication]"])

    def test_networks_are_no_longer_configured(self):
        errors = self.errors('\n[trust]\nmynetworks = ["10.0.0.0/8"]\nlocal_ingress_marker = "LOCAL_PICKUP"\n')
        self.assertEqual(errors, ["trust: removed; mynetworks and recipient_delimiter are read from Postfix at start, "
                                  "same-server clients are detected automatically and the pickup marker is fixed"])

    def test_old_protected_recipients_schema_rejected(self):
        errors = self.errors('\n[[protected_recipients]]\naddresses = ["all@example.com"]\nauthorized_sasl_logins = ["x@example.com"]\n')
        self.assertTrue(any(e.startswith("protected_recipients: removed; configure protected addresses under [protection]") for e in errors))

    def test_address_keys_are_normalized(self):
        s = settings('\n[protection.addresses."Board@B\u00fccher.Example"]\nauthorized_logins = ["x@example.org"]\n')
        self.assertIn("board@xn--bcher-kva.example", s.protection.addresses)

    def test_group_is_local_part_at_star_only(self):
        joined = "\n".join(self.errors(
            '\n[protection.addresses."ALL@*"]\nauthorized_logins = []\n'
            '[protection.addresses."all@*.example.com"]\nauthorized_logins = []\n'
            '[protection.addresses."*@example.com"]\nauthorized_logins = []\n'
            '[protection]\non_hosted_domains = ["all"]\n'))
        self.assertIn("same address as another protection.addresses entry (all@*)", joined)
        self.assertIn("'all@*.example.com': a protected group is written <local>@*, as in all@*", joined)
        self.assertIn("'*@example.com': a protected group is written <local>@*", joined)
        self.assertIn("protection.on_hosted_domains: unknown key", joined)

    def test_addresses_are_full_mailboxes_and_unique(self):
        joined = "\n".join(self.errors(
            '\n[protection.addresses."ceo@example.com"]\nauthorized_logins = ["a@example.com"]\n'
            '[protection.addresses."CEO@Example.COM"]\nauthorized_logins = ["b@example.com"]\n'
            '[protection.addresses."ceo"]\nauthorized_logins = []\n'))
        self.assertIn("same address as another protection.addresses entry (ceo@example.com)", joined)
        self.assertIn("protection.addresses.'ceo': not a mailbox", joined)

    def test_removed_keys_are_unknown(self):
        errors = self.errors('\n[protection]\nports = [587]\nrequire_tls = false\n'
                             '[protection.domains."example.com"]\nauthorized_logins = []\n'
                             '[protection.addresses."all@example.com"]\nsender_must_equal_sasl_login = false\n')
        self.assertIn("protection.ports: unknown key", errors)
        self.assertIn("protection.require_tls: unknown key", errors)
        self.assertIn("protection.domains: unknown key", errors)
        self.assertTrue(any(e.endswith("sender_must_equal_sasl_login: unknown key") for e in errors))

    def test_response_validation(self):
        errors = self.errors('\n[responses.protected_recipient]\nsmtp_code = 451\n[responses.temporary_failure]\nsmtp_code = 550\n'
                             '[responses.self_sender]\nenhanced_code = "4.7.1"\n[responses.invalid_from]\nmessage = "bad\\nline"\n'
                             '[responses.nonsense]\nsmtp_code = 550\n')
        joined = "\n".join(errors)
        self.assertIn("responses.protected_recipient.smtp_code: 451 is not one of [550, 554]", joined)
        self.assertIn("responses.temporary_failure.smtp_code: 550 is not one of [450, 451, 452]", joined)
        self.assertIn("responses.self_sender.enhanced_code: class 4 does not match 550", joined)
        self.assertIn("responses.invalid_from.message: must be nonempty printable ASCII", joined)
        self.assertIn("responses.nonsense: unknown response key", joined)

    def test_reply_length_bound(self):
        self.assertTrue(validate_reply("self_sender", Reply(550, "5.7.1", "x" * 600)))
        self.assertEqual(validate_reply("self_sender", Reply(554, "5.7.1", "Denied")), [])

    def test_customized_reply_keeps_class(self):
        s = settings('\n[responses.self_sender]\nsmtp_code = 554\nmessage = "No"\n')
        self.assertEqual(s.reply("self_sender").render(), "554 5.7.1 No")

    def test_deadline_not_below_dns_timeout(self):
        errors = self.errors('\n[limits]\ndns_timeout_seconds = 30\nauthentication_deadline_seconds = 20\n')
        self.assertTrue(any("must not be shorter than dns_timeout_seconds" in e for e in errors))


class Loading(unittest.TestCase):
    def test_missing_file_points_to_example(self):
        with self.assertRaises(ConfigError) as ctx:
            load_settings("/nonexistent/config.toml")
        self.assertIn("etc/config.example.toml", ctx.exception.errors[0])

    def test_syntax_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
            fh.write("schema_version = \n")
        try:
            with self.assertRaises(ConfigError) as ctx:
                load_settings(fh.name)
            self.assertIn("TOML syntax error", ctx.exception.errors[0])
        finally:
            os.unlink(fh.name)


if __name__ == "__main__":
    unittest.main()
