import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "stubs"))

import Milter  # noqa: E402  (stub)

from postwarden import milter  # noqa: E402
from postwarden.__main__ import main  # noqa: E402
from postwarden.policy import AuthStatus, AuthenticationInput, DkimOutcome, SpfOutcome, TrustClass  # noqa: E402
from postwarden.simulate import Facts, render, simulate, split_message  # noqa: E402

from helpers import BASE_TOML, settings  # noqa: E402

MESSAGE = b"From: Bob <bob@example.org>\nTo: carol@example.com\nSubject: hi\n\nhello\n"


def facts(**kwargs):
    base = dict(ingress="25", sender="bob@example.org", recipients=("carol@example.com",), peer="198.51.100.7")
    base.update(kwargs)
    return Facts(**base)


def rcpt_results(outcome):
    return [(text, d.action.value, d.rule, d.reason) for text, d in outcome.recipients]


class Evaluation(unittest.TestCase):
    def setUp(self):
        self.s = settings()

    def test_mixed_recipients_on_submission(self):
        outcome = simulate(self.s, facts(ingress="587", login="demo@example.com", sender="demo@example.com",
                                         recipients=("carol@example.net", "all@example.com")), MESSAGE)
        self.assertEqual(outcome.trust, TrustClass.AUTHENTICATED_SUBMISSION)
        self.assertEqual(rcpt_results(outcome), [("carol@example.net", "allow", "none", "no_rule_matched"),
                                                 ("all@example.com", "reject", "protected_recipient", "login_not_authorized")])
        self.assertEqual((outcome.final.action.value, outcome.final.rule), ("allow", "trust"))
        self.assertEqual(outcome.exit_code, 1)

    def test_forced_results_decide_authentication(self):
        cases = {("pass", "pass"): ("allow", "spf_and_dkim_aligned"), ("pass", "none"): ("reject", "dkim_absent"),
                 ("fail", "pass"): ("reject", "spf_fail"), ("none", "pass"): ("reject", "spf_none"),
                 ("pass", "temperror"): ("defer", "dkim_temperror"), ("temperror", "pass"): ("defer", "spf_temperror")}
        for (spf, dkim), expected in cases.items():
            with self.subTest(spf=spf, dkim=dkim):
                final = simulate(self.s, facts(spf=spf, dkim=dkim), MESSAGE).final
                self.assertEqual((final.action.value, final.reason), expected)

    def test_either_mode_from_a_candidate_configuration(self):
        candidate = settings('\n[sender_authentication]\nrequire = "either"\n')
        self.assertEqual(simulate(candidate, facts(spf="pass", dkim="none"), MESSAGE).final.reason, "spf_aligned")

    def test_same_sender_and_recipient_by_peer(self):
        message = b"From: carol@example.com\n\nhi\n"
        results = {}
        for name, peer in (("same host", "127.0.0.1"), ("mynetworks", "203.0.113.9"), ("external", "198.51.100.7")):
            outcome = simulate(self.s, facts(peer=peer, sender="carol@example.com", spf="pass", dkim="pass"), message)
            results[name] = (outcome.trust.value, outcome.recipients[0][1].action.value, outcome.final.action.value)
        self.assertEqual(results, {"same host": ("local_smtp", "allow", "allow"),
                                   "mynetworks": ("mynetworks", "allow", "allow"),
                                   "external": ("untrusted", "reject", "allow")})

    def test_local_pickup_applies_refusals_at_end_of_message(self):
        outcome = simulate(self.s, facts(ingress="local", peer=None, sender="www-data@example.com",
                                         recipients=("carol@example.com", "all@example.com")),
                           b"From: www-data@example.com\n\nhi\n")
        self.assertEqual(outcome.trust, TrustClass.LOCAL_PICKUP)
        self.assertEqual((outcome.final.action.value, outcome.final.rule), ("reject", "protected_recipient"))
        text = "\n".join(render(self.s, facts(ingress="local"), outcome, None))
        self.assertIn("refusals are applied at end of message", text)

    def test_without_a_message_only_the_rcpt_stage_runs(self):
        outcome = simulate(self.s, facts(), None)
        self.assertIsNone(outcome.final)
        self.assertEqual(outcome.exit_code, 3)
        self.assertIn("  not evaluated: no message file (RCPT stage only)", render(self.s, facts(), outcome, None))

    def test_sending_limit_key_multiplier_and_limits_only(self):
        s = settings('\n[sending_limits.multipliers]\n"marketing@example.com" = 10\n')
        outcome = simulate(s, facts(ingress="587", login="marketing@example.com", sender="marketing@example.com"), None)
        line = [l for l in render(s, facts(ingress="587"), outcome, None) if l.startswith("sending limits")][0]
        self.assertEqual(line, "sending limits (observe): key marketing@example.com, multiplier 10, 1000 per hour, "
                               "5000 per day; current counts are not shown")

    def test_live_dns_is_used_for_what_is_not_forced(self):
        calls = []

        def live(peer, helo, sender, message, signatures, limits, deadline=None, skip_dkim=None):
            calls.append((peer, sender, skip_dkim(SpfOutcome(AuthStatus.FAIL, None, "fail"))))
            return AuthenticationInput(SpfOutcome(AuthStatus.PASS, "example.org", "pass"),
                                       (DkimOutcome(AuthStatus.TEMPERROR, "example.org"),))
        outcome = simulate(self.s, facts(), MESSAGE, live=live)
        self.assertEqual((outcome.final.action.value, outcome.final.reason), ("defer", "dkim_temperror"))
        self.assertEqual(outcome.authentication, "spf=pass (DNS), dkim=example.org:temperror (DNS)")
        self.assertEqual(calls, [("198.51.100.7", "bob@example.org", True)])
        outcome = simulate(self.s, facts(spf="pass"), MESSAGE, live=live)
        self.assertEqual(outcome.authentication, "spf=pass (forced), dkim=example.org:temperror (DNS)")
        outcome = simulate(self.s, facts(dkim="pass"), MESSAGE, live=live)
        self.assertEqual(outcome.final.reason, "spf_and_dkim_aligned")

    def test_header_limit_defers(self):
        s = settings("\n[limits]\nmax_headers = 1\n")
        final = simulate(s, facts(spf="pass", dkim="pass"), MESSAGE).final
        self.assertEqual((final.action.value, final.reason), ("defer", "max_headers"))

    def test_folded_headers_keep_their_bytes(self):
        headers, body = split_message(b"Subject: a\r\n b\r\nFrom: x@example.org\r\n\r\nbody\r\n")
        self.assertEqual(headers, [(b"Subject", b" a\n b"), (b"From", b" x@example.org")])
        self.assertEqual(body, b"body\r\n")


class MatchesTheDaemon(unittest.TestCase):
    """simulate and the milter callbacks take the same decisions from the same facts."""

    def daemon(self, s, f, message, auth):
        milter.configure(s, mock.Mock())
        milter.authenticator = lambda *a, **k: auth
        self.addCleanup(setattr, milter, "authenticator", None)
        m = milter.PolicyMilter()
        m.macros, m.replies = {}, []
        m.negotiate([0x1ff, 0x1fffff, 0, 0])
        conn = __import__("postwarden.simulate", fromlist=["connection"]).connection(f)
        m.macros.update({"{daemon_port}": str(conn.daemon_port or 0), "{postwarden_ingress}": conn.ingress_marker,
                         "{auth_type}": conn.auth_type, "{auth_authen}": conn.auth_authen,
                         "{cipher_bits}": str(conn.cipher_bits) if conn.cipher_bits else None})
        m.connect("client", 2, (conn.peer_ip, 1))
        m.envfrom(f"<{f.sender}>")
        codes = [m.envrcpt(f"<{r}>") for r in f.recipients]
        headers, body = split_message(message)
        for name, value in headers:
            m.header(name.decode(), value.decode())
        m.eoh()
        m.body(body)
        rc = m.eom()
        m.close()
        return codes, rc

    def test_same_decisions(self):
        s = settings()
        auth = AuthenticationInput(SpfOutcome(AuthStatus.PASS, "example.org", "pass"), ())
        cases = [facts(), facts(recipients=("all@example.com", "carol@example.com")),
                 facts(ingress="587", login="demo@example.com", sender="demo@example.com",
                       recipients=("all@example.com", "x@example.net"))]
        code = {"allow": Milter.CONTINUE, "reject": Milter.REJECT, "defer": Milter.TEMPFAIL}
        for f in cases:
            with self.subTest(f=f):
                outcome = simulate(s, f, MESSAGE, live=lambda *a, **k: auth)
                codes, rc = self.daemon(s, f, MESSAGE, auth)
                self.assertEqual(codes, [code[d.action.value] for _, d in outcome.recipients])
                self.assertEqual(rc, code[outcome.final.action.value])


class Command(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.config = os.path.join(directory.name, "candidate.toml")
        with open(self.config, "w") as fh:
            fh.write(BASE_TOML)
        self.message = os.path.join(directory.name, "m.eml")
        with open(self.message, "wb") as fh:
            fh.write(MESSAGE)

    def run_cli(self, *argv):
        with mock.patch("postwarden.__main__._with_postfix", side_effect=lambda s, required: (s, "from Postfix: test")), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
             mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            try:
                status = main(["simulate", *argv])
            except SystemExit as exc:
                status = exc.code
        return status, out.getvalue(), err.getvalue()

    def test_exit_codes(self):
        base = ["--config", self.config, "--from", "bob@example.org", "--peer", "198.51.100.7", "--ingress", "25"]
        self.assertEqual(self.run_cli(self.message, *base, "--to", "carol@example.com", "--spf", "pass",
                                      "--dkim", "pass")[0], 0)
        self.assertEqual(self.run_cli(self.message, *base, "--to", "all@example.com", "--spf", "pass",
                                      "--dkim", "pass")[0], 1)
        status, out, _ = self.run_cli(*base, "--to", "carol@example.com")
        self.assertEqual(status, 3)
        self.assertIn("RCPT stage only", out)
        self.assertIn(f"configuration: {self.config} (mode enforce)", out)

    def test_usage_errors(self):
        status, _, err = self.run_cli("--config", self.config, "--ingress", "587", "--from", "a@example.com",
                                      "--to", "b@example.com")
        self.assertEqual(status, 2)
        self.assertIn("--peer is required for --ingress 587", err)
        self.assertEqual(self.run_cli("--ingress", "25", "--from", "a@example.com")[0], 2)
        status, _, err = self.run_cli("--config", self.config, "--ingress", "25", "--peer", "not-an-ip",
                                      "--from", "a@example.com", "--to", "b@example.com")
        self.assertEqual(status, 2)
        status, _, err = self.run_cli("--config", "/nonexistent.toml", "--ingress", "local", "--from", "a@example.com",
                                      "--to", "b@example.com")
        self.assertEqual(status, 2)


if __name__ == "__main__":
    unittest.main()
