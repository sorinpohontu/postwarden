import os
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "stubs"))

import Milter  # noqa: E402  (stub)

from postwarden import milter  # noqa: E402
from postwarden.logging import format_event  # noqa: E402
from postwarden.policy import AuthStatus, AuthenticationInput, DkimOutcome, SpfOutcome  # noqa: E402
from postwarden.quota import QuotaStore  # noqa: E402

from helpers import settings  # noqa: E402


class RecordingLogger:
    def __init__(self):
        self.events = []

    def event(self, level="info", **fields):
        self.events.append((level, fields))

    info = lambda self, **f: self.event("info", **f)
    warning = lambda self, **f: self.event("warning", **f)
    error = lambda self, **f: self.event("error", **f)
    debug = lambda self, **f: self.event("debug", **f)

    def actions(self):
        return [(f.get("stage"), f.get("action"), f.get("rule")) for _, f in self.events if f.get("action")]


def session(mode="enforce", extra=""):
    log = RecordingLogger()
    milter.configure(settings(f'\nmode = "{mode}"\n' + extra), log)
    m = milter.PolicyMilter()
    m.macros, m.replies = {}, []
    m.negotiate([0x1ff, 0x1fffff, 0, 0])
    return m, log


def connect(m, peer="198.51.100.7", port="25", ingress="SMTP25", login=None, cipher=None):
    m.macros.update({"{daemon_port}": port, "{postwarden_ingress}": ingress, "{auth_type}": "PLAIN" if login else None,
                     "{auth_authen}": login, "{cipher_bits}": cipher, "i": "QID1"})
    m.connect("host", 2, (peer, 12345))
    m.hello("client.example")


def message(m, sender, rcpts, headers, body=b"hello\r\n"):
    m.envfrom(sender)
    codes = [m.envrcpt(r) for r in rcpts]
    for name, value in headers:
        m.header(name, value)
    m.eoh()
    m.body(body)
    return codes, m.eom()


def auth_result(spf="pass", dkim="pass", domain="example.org"):
    status = {"pass": AuthStatus.PASS, "fail": AuthStatus.FAIL, "temp": AuthStatus.TEMPERROR}
    return lambda *a, **k: AuthenticationInput(
        SpfOutcome(status[spf], domain if spf == "pass" else None, spf),
        (DkimOutcome(status[dkim], domain),) if dkim else ())


class SmtpTransactions(unittest.TestCase):
    def tearDown(self):
        milter.authenticator = None

    def test_protected_rejected_at_rcpt_others_continue(self):
        m, log = session()
        connect(m)
        milter.authenticator = auth_result()
        codes, rc = message(m, "<bob@example.org>", ["<carol@example.com>", "<all@example.com>", "<dave@example.com>"],
                            [("From", " bob@example.org")])
        self.assertEqual(codes, [Milter.CONTINUE, Milter.REJECT, Milter.CONTINUE])
        self.assertEqual([r[:2] for r in m.replies], [("550", "5.7.1")])
        self.assertRegex(m.replies[0][2], r"^Recipient address rejected: Access denied \(ref [0-9a-f]{12}\)$")
        self.assertEqual(rc, Milter.CONTINUE)
        self.assertIn(("rcpt", "reject", "protected_recipient"), log.actions())
        self.assertIn(("eom", "accept", "authentication"), log.actions())

    def test_recipient_transport_decides_default_protection(self):
        m, log = session()
        self.addCleanup(m.close)
        connect(m, peer="203.0.113.9")
        milter.authenticator = auth_result()
        m.envfrom("<relay@example.org>")
        m.macros["{rcpt_mailer}"] = "smtp"
        remote = m.envrcpt("<all@partner.example>")
        m.macros["{rcpt_mailer}"] = "dovecot"
        local = m.envrcpt("<all@hosted.example>")
        self.assertEqual((remote, local), (Milter.CONTINUE, Milter.REJECT))
        event = [f for _, f in log.events if f.get("rule") == "protected_recipient"][0]
        self.assertEqual((event["rcpt"], event["transport"], event["reason"]), ("all@hosted.example", "dovecot", "ingress_smtp25"))

    def test_reply_reference_matches_logged_mid(self):
        for mode in ("enforce", "observe"):
            with self.subTest(mode=mode):
                m, log = session(mode=mode)
                connect(m)
                milter.authenticator = auth_result()
                message(m, "<bob@example.org>", ["<all@example.com>"], [("From", " bob@example.org")])
                event = [f for _, f in log.events if f.get("rule") == "protected_recipient"][0]
                self.assertTrue(event["reply"].endswith(f"(ref {event['mid']})"))
                if mode == "enforce":
                    self.assertTrue(m.replies[0][2].endswith(f"(ref {event['mid']})"))

    def test_spf_failure_skips_dkim_and_logs_it(self):
        m, log = session()
        connect(m)
        seen = {}

        def fake(*a, skip_dkim=None, **k):
            outcome = SpfOutcome(AuthStatus.FAIL, None, "softfail")
            seen["skip"] = skip_dkim(outcome)
            return AuthenticationInput(outcome, dkim_skipped=seen["skip"])
        milter.authenticator = fake
        _, rc = message(m, "<bob@example.org>", ["<carol@example.net>"], [("From", " bob@example.org")])
        self.assertTrue(seen["skip"])
        self.assertEqual(rc, Milter.REJECT)
        eom = [f for _, f in log.events if f.get("stage") == "eom" and f.get("action") == "reject"][0]
        self.assertEqual((eom["reason"], eom["spf"], eom["dkim"]), ("spf_softfail", "softfail", "skipped"))

    def test_either_mode_accepts_on_aligned_spf_and_skips_dkim(self):
        m, log = session(extra='\n[sender_authentication]\nrequire = "either"\n')
        connect(m)

        def fake(*a, skip_dkim=None, **k):
            outcome = SpfOutcome(AuthStatus.PASS, "example.org", "pass")
            return AuthenticationInput(outcome, dkim_skipped=skip_dkim(outcome))
        milter.authenticator = fake
        _, rc = message(m, "<bob@example.org>", ["<carol@example.net>"], [("From", " bob@example.org")])
        self.assertEqual(rc, Milter.CONTINUE)
        eom = [f for _, f in log.events if f.get("stage") == "eom" and f.get("action") == "accept"][0]
        self.assertEqual((eom["reason"], eom["spf"], eom["dkim"]), ("spf_aligned", "pass", "skipped"))
        self.assertLess(float(eom["auth_elapsed"]), float(eom["elapsed"]) + 0.001)

    def test_observe_mode_logs_but_continues(self):
        m, log = session(mode="observe")
        connect(m)
        milter.authenticator = auth_result(spf="fail")
        codes, rc = message(m, "<bob@example.org>", ["<all@example.com>"], [("From", " bob@example.org")])
        self.assertEqual(codes, [Milter.CONTINUE])
        self.assertEqual(rc, Milter.CONTINUE)
        self.assertEqual(m.replies, [])
        self.assertIn(("rcpt", "would_reject", "protected_recipient"), log.actions())
        self.assertIn(("eom", "would_reject", "authentication"), log.actions())

    def test_eom_summary_separates_sent_and_observed_refusals(self):
        for mode, refused_action, sent, observed in (("observe", "would_reject", None, 1), ("enforce", "reject", 1, None)):
            with self.subTest(mode=mode):
                m, log = session(mode=mode)
                connect(m, peer="127.0.0.1", ingress="SMTP25")
                message(m, "<bob@example.org>", ["<all@example.com>", "<carol@example.com>"], [("From", " bob@example.org")])
                self.assertIn(("rcpt", refused_action, "protected_recipient"), log.actions())
                eom = [f for _, f in log.events if f.get("stage") == "eom" and f.get("action") == "accept"][0]
                self.assertEqual((eom["rcpts"], eom.get("rejected_rcpts"), eom.get("would_rejected_rcpts")),
                                 (2, sent, observed))
                self.assertNotIn("deferred_rcpts", eom)
                self.assertNotIn("would_deferred_rcpts", eom)

    def test_eom_summary_counts_deferred_recipients_separately(self):
        m, log = session(mode="observe")
        connect(m, ingress="SOMETHING_ELSE")
        milter.authenticator = auth_result()
        message(m, "<bob@example.org>", ["<all@example.com>", "<carol@example.com>"], [("From", " bob@example.org")])
        self.assertIn(("rcpt", "would_defer", "protected_recipient"), log.actions())
        eom = [f for _, f in log.events if f.get("stage") == "eom" and f.get("action") == "accept"][0]
        self.assertEqual(eom["would_deferred_rcpts"], 1)
        self.assertNotIn("deferred_rcpts", eom)
        self.assertNotIn("would_rejected_rcpts", eom)

    def test_eom_summary_omits_refusal_counts_when_none(self):
        m, log = session()
        connect(m, peer="127.0.0.1", ingress="SMTP25")
        message(m, "<bob@example.org>", ["<carol@example.com>"], [("From", " bob@example.org")])
        eom = [f for _, f in log.events if f.get("stage") == "eom" and f.get("action") == "accept"][0]
        for key in ("rejected_rcpts", "deferred_rcpts", "would_rejected_rcpts", "would_deferred_rcpts"):
            self.assertNotIn(key, eom)

    def test_untrusted_authentication_failure_rejects_at_eom(self):
        m, log = session()
        connect(m)
        milter.authenticator = auth_result(spf="pass", dkim=None)
        _, rc = message(m, "<bob@example.org>", ["<carol@example.com>"], [("From", " Bob <bob@example.org>")])
        self.assertEqual(rc, Milter.REJECT)
        self.assertTrue(m.replies[-1][2].startswith("Message rejected: Sender domain authentication failed (SPF, DKIM) (ref "))
        self.assertEqual(m.replies[-1][1], "5.7.26")
        fields = [f for _, f in log.events if f.get("stage") == "eom"][0]
        self.assertEqual(fields["reason"], "dkim_absent")
        self.assertEqual(fields["from_domain"], "example.org")

    def test_temporary_error_tempfails(self):
        m, _ = session()
        connect(m)
        milter.authenticator = auth_result(spf="temp", dkim="pass")
        _, rc = message(m, "<bob@example.org>", ["<carol@example.com>"], [("From", " bob@example.org")])
        self.assertEqual(rc, Milter.TEMPFAIL)
        self.assertEqual(m.replies[-1][0], "451")

    def test_mynetworks_skips_authentication_and_self_sender(self):
        m, log = session()
        connect(m, peer="203.0.113.9")
        milter.authenticator = lambda *a, **k: self.fail("authentication must not run for mynetworks")
        codes, rc = message(m, "<bob@example.org>", ["<bob@example.org>"], [("From", " bob@example.org")])
        self.assertEqual(codes, [Milter.CONTINUE])
        self.assertEqual(rc, Milter.CONTINUE)

    def test_authenticated_submission_exempt_but_protected_needs_login(self):
        m, _ = session()
        connect(m, peer="198.51.100.7", port="587", ingress="SUBMISSION587", login="bob@example.org", cipher="256")
        milter.authenticator = lambda *a, **k: self.fail("authentication must not run for submission")
        codes, rc = message(m, "<bob@example.org>", ["<all@example.com>", "<carol@example.com>"], [("From", " bob@example.org")])
        self.assertEqual(codes, [Milter.REJECT, Milter.CONTINUE])
        self.assertEqual(rc, Milter.CONTINUE)

    def test_invalid_from_rejected_before_authentication(self):
        m, _ = session()
        connect(m)
        milter.authenticator = lambda *a, **k: self.fail("authentication must not run without a valid From")
        _, rc = message(m, "<bob@example.org>", ["<carol@example.com>"], [("From", " a@example.org, b@example.org")])
        self.assertEqual(rc, Milter.REJECT)
        self.assertTrue(m.replies[-1][2].startswith("Message rejected: From header does not conform to RFC 5322 (ref "))

    def test_header_self_sender_rejects_whole_message(self):
        m, _ = session()
        connect(m)
        milter.authenticator = lambda *a, **k: self.fail("rejected before authentication")
        _, rc = message(m, "<alice@example.org>", ["<carol@example.com>", "<bob@example.org>"], [("From", " bob@example.org")])
        self.assertEqual(rc, Milter.REJECT)
        self.assertTrue(m.replies[-1][2].startswith("Sender address rejected: Access denied (ref "))

    def test_state_isolated_between_transactions(self):
        m, _ = session()
        connect(m)
        milter.authenticator = auth_result()
        m.envfrom("<bob@example.org>")
        m.envrcpt("<all@example.com>")
        m.abort()
        codes, rc = message(m, "<eve@example.org>", ["<carol@example.com>"], [("From", " eve@example.org")])
        self.assertEqual(codes, [Milter.CONTINUE])
        self.assertEqual(rc, Milter.CONTINUE)
        self.assertIsNone(m.capture)
        self.assertEqual(m.state.recipients, [])

    def test_oversized_message_defers(self):
        m, _ = session(extra="\n[limits]\nmessage_bytes = 100\n")
        connect(m, peer="203.0.113.9")
        _, rc = message(m, "<bob@example.org>", ["<carol@example.com>"], [("From", " bob@example.org")], body=b"x" * 200)
        self.assertEqual(rc, Milter.TEMPFAIL)


    def test_unparseable_sender_never_gets_the_bounce_exception(self):
        m, log = session()
        connect(m)
        seen = []
        def fake(peer, helo, sender, *rest, **kw):
            seen.append(sender)
            return AuthenticationInput(SpfOutcome(AuthStatus.FAIL, None, "fail"),
                                       (DkimOutcome(AuthStatus.PASS, "example.org"),))
        milter.authenticator = fake
        _, rc = message(m, '<"a b"@example.org>', ["<carol@example.com>"], [("From", " author@example.org")])
        self.assertEqual(rc, Milter.REJECT)
        self.assertEqual(seen, ['"a b"@example.org'])
        event = [f for _, f in log.events if f.get("stage") == "eom"][0]
        self.assertEqual((event["reason"], event["sender"]), ("spf_fail", '"a b"@example.org'))

    def test_real_null_sender_still_gets_the_bounce_exception(self):
        m, log = session()
        connect(m)
        milter.authenticator = lambda *a, **k: AuthenticationInput(SpfOutcome(AuthStatus.FAIL, None, "none"),
                                                                   (DkimOutcome(AuthStatus.PASS, "example.org"),))
        _, rc = message(m, "<>", ["<carol@example.com>"], [("From", " mailer-daemon@example.org")])
        self.assertEqual(rc, Milter.CONTINUE)
        self.assertIn(("eom", "accept", "authentication"), log.actions())

    def test_unparseable_sender_cannot_reach_protected_address(self):
        m, log = session()
        connect(m, port="587", ingress="SUBMISSION587", login="manager@example.com", cipher="256")
        codes, _ = message(m, '<"a b"@example.com>', ["<all@example.com>"], [("From", " manager@example.com")])
        self.assertEqual(codes, [Milter.REJECT])
        event = [f for _, f in log.events if f.get("rule") == "protected_recipient"][0]
        self.assertEqual(event["reason"], "sender_login_mismatch")

    def test_unparseable_recipient_rejected_others_continue(self):
        m, log = session()
        connect(m)
        milter.authenticator = auth_result()
        codes, rc = message(m, "<bob@example.org>", ["<carol@example.com>", '<"x y"@example.com>'],
                            [("From", " bob@example.org")])
        self.assertEqual(codes, [Milter.CONTINUE, Milter.REJECT])
        self.assertEqual(m.replies[0][:2], ("550", "5.1.3"))
        self.assertEqual(rc, Milter.CONTINUE)
        self.assertEqual([f.get("rejected_rcpts") for _, f in log.events if f.get("action") == "accept"], [1])

    def test_open_message_cap_defers_at_mail_and_frees_slots(self):
        first, log = session(extra="\n[limits]\nmax_open_messages = 1\n")
        milter.authenticator = auth_result()
        connect(first)
        first.envfrom("<bob@example.org>")
        second = milter.PolicyMilter()
        second.macros, second.replies = {}, []
        second.negotiate([0x1ff, 0x1fffff, 0, 0])
        connect(second)
        self.assertEqual(second.envfrom("<eve@example.org>"), Milter.TEMPFAIL)
        self.assertIn(("mail", "defer", "limits"), log.actions())
        first.abort()
        self.assertEqual(second.envfrom("<eve@example.org>"), Milter.CONTINUE)
        second.close()

    def test_header_limit_defers_even_when_from_came_after_the_cutoff(self):
        for limit in ("max_headers = 1", "max_header_bytes = 20"):
            with self.subTest(limit=limit):
                m, log = session(extra=f"\n[limits]\n{limit}\n")
                connect(m)
                milter.authenticator = lambda *a, **k: self.fail("no authentication on a truncated capture")
                _, rc = message(m, "<bob@example.org>", ["<carol@example.com>"],
                                [("Subject", " a subject longer than twenty bytes"), ("From", " a@example.org")])
                self.assertEqual(rc, Milter.TEMPFAIL)
                self.assertEqual(m.replies[-1][0], "451")
                self.assertIn(("eom", "defer", "limits"), log.actions())

    def test_smtp_recipients_over_the_limit_are_deferred_without_state(self):
        m, log = session(extra="\n[limits]\nmax_recipients = 1\n")
        connect(m)
        m.envfrom("<bob@example.org>")
        codes = [m.envrcpt(f"<u{i}@example.com>") for i in range(50)]
        self.assertEqual((codes[0], set(codes[1:])), (Milter.CONTINUE, {Milter.TEMPFAIL}))
        self.assertEqual(len(m.state.recipients), 1)
        m.close()

    def test_mynetworks_authenticates_when_exemption_is_off(self):
        m, log = session(extra="\n[sender_authentication]\nallow_mynetworks = false\n")
        connect(m, peer="203.0.113.9")
        milter.authenticator = auth_result(spf="fail", dkim=None)
        _, rc = message(m, "<bob@example.org>", ["<carol@example.com>"], [("From", " bob@example.org")])
        self.assertEqual(rc, Milter.REJECT)
        self.assertIn(("eom", "reject", "authentication"), log.actions())


class LocalPickup(unittest.TestCase):
    def pickup(self, extra=""):
        m, log = session(extra=extra)
        m.macros.update({"{daemon_port}": "0", "{postwarden_ingress}": "LOCAL_PICKUP"})
        m.connect("localhost", 2, ("127.0.0.1", 0))
        return m, log

    def test_recipients_over_the_limit_keep_state_bounded(self):
        m, log = self.pickup("\n[limits]\nmax_recipients = 2\n")
        m.envfrom("root@example.com")
        codes = [m.envrcpt(f"user{i}@example.com") for i in range(1000)]
        self.assertEqual(set(codes), {Milter.CONTINUE})
        self.assertEqual((len(m.state.recipients), len(m.state.deferred_rejections), m.state.overflow_rcpts), (2, 1, 998))
        m.header("From", " root@example.com")
        self.assertEqual(m.eom(), Milter.TEMPFAIL)
        eom = [f for _, f in log.events if f.get("stage") == "eom"][0]
        self.assertEqual((eom["rcpts"], eom["deferred_rcpts"]), (1000, 998))

    def test_recipient_limit_waits_for_eom(self):
        m, log = self.pickup("\n[limits]\nmax_recipients = 1\n")
        codes, rc = message(m, "root@example.com", ["carol@example.com", "dave@example.com"], [("From", " root@example.com")])
        self.assertEqual(codes, [Milter.CONTINUE, Milter.CONTINUE])
        self.assertEqual(rc, Milter.TEMPFAIL)
        self.assertIn(("rcpt", "pending_eom", "limits"), log.actions())

    def test_unparseable_recipient_waits_for_eom(self):
        m, log = self.pickup()
        codes, rc = message(m, "root@example.com", ['"x y"@example.com'], [("From", " root@example.com")])
        self.assertEqual((codes, rc), ([Milter.CONTINUE], Milter.REJECT))

    def test_open_message_cap_waits_for_eom(self):
        m, log = self.pickup("\n[limits]\nmax_open_messages = 1\n")
        milter._open_slots.acquire()
        self.addCleanup(milter._open_slots.release)
        codes, rc = message(m, "root@example.com", ["carol@example.com"], [("From", " root@example.com")])
        self.assertEqual((codes, rc), ([Milter.CONTINUE], Milter.TEMPFAIL))
        self.assertIn(("eom", "defer", "limits"), log.actions())

    def test_local_mail_authenticates_when_exemption_is_off(self):
        m, log = self.pickup("\n[sender_authentication]\nallow_local = false\n")
        _, rc = message(m, "root@example.com", ["carol@example.com"], [("Subject", " cron")])
        self.assertEqual(rc, Milter.REJECT)
        self.assertIn(("eom", "reject", "invalid_from"), log.actions())

    def test_protected_violation_rejected_at_eom_not_rcpt(self):
        m, log = session()
        m.macros.update({"{daemon_port}": "0", "{postwarden_ingress}": "LOCAL_PICKUP", "i": "QID2"})
        m.connect("localhost", 2, ("127.0.0.1", 0))
        codes, rc = message(m, "www-data@example.com", ["carol@example.com", "all@example.com"],
                            [("From", " www-data@example.com")])
        self.assertEqual(codes, [Milter.CONTINUE, Milter.CONTINUE])
        self.assertEqual(rc, Milter.REJECT)
        self.assertIn(("rcpt", "pending_eom", "protected_recipient"), log.actions())
        self.assertIn(("eom", "reject", "protected_recipient"), log.actions())

    def test_ordinary_local_mail_without_from_is_accepted(self):
        m, _ = session()
        m.macros.update({"{daemon_port}": "0", "{postwarden_ingress}": "LOCAL_PICKUP"})
        m.connect("localhost", 2, ("127.0.0.1", 0))
        milter.authenticator = lambda *a, **k: self.fail("local mail is exempt")
        _, rc = message(m, "root@example.com", ["carol@example.com"], [("Subject", " cron")])
        self.assertEqual(rc, Milter.CONTINUE)


LIMITS = '\n[sending_limits]\nper_hour = 2\nper_day = 3\nlocal_per_hour = 3\nlocal_per_day = 5\n'


class SendingLimits(unittest.TestCase):
    def setUp(self):
        self.addCleanup(setattr, milter, "authenticator", None)
        milter.authenticator = auth_result()

    def session(self, mode="enforce", limits="enforce", extra="", capacity=100):
        log = RecordingLogger()
        cfg = settings(f'\nmode = "{mode}"\n' + LIMITS.replace("per_hour = 2", f'mode = "{limits}"\nper_hour = 2', 1) + extra)
        self.quota = QuotaStore(cfg.sending_limits, capacity=capacity)
        milter.configure(cfg, log, self.quota)
        m = milter.PolicyMilter()
        m.macros, m.replies = {}, []
        m.negotiate([0x1ff, 0x1fffff, 0, 0])
        return m, log

    def submission(self, login="demo@example.com", **kwargs):
        m, log = self.session(**kwargs)
        connect(m, port="587", ingress="SUBMISSION587", login=login, cipher="256")
        return m, log

    def pickup(self, **kwargs):
        m, log = self.session(**kwargs)
        m.macros.update({"{daemon_port}": "0", "{postwarden_ingress}": "LOCAL_PICKUP"})
        m.connect("localhost", 2, ("127.0.0.1", 0))
        return m, log

    def send(self, m, sender, count, first=0):
        return message(m, sender, [f"<r{first + n}@example.net>" for n in range(count)], [("From", f" {sender}")])

    def eom(self, log):
        return [f for _, f in log.events if f.get("stage") == "eom"][-1]

    def counts(self, key, now=None):
        return self.quota.counts(key, now or milter.time.time())

    def test_over_the_limit_defers_from_the_first_recipient_over(self):
        m, log = self.submission()
        codes, rc = self.send(m, "demo@example.com", 3)
        self.assertEqual((codes, rc), ([Milter.CONTINUE, Milter.CONTINUE, Milter.TEMPFAIL], Milter.CONTINUE))
        self.assertEqual(m.replies[0][:2], ("451", "4.7.1"))
        self.assertRegex(m.replies[0][2], r"^Sending limit exceeded - try again later \(ref [0-9a-f]{12}\)$")
        refusal = [f for _, f in log.events if f.get("rule") == "sending_limit" and f.get("action")][0]
        self.assertEqual((refusal["action"], refusal["reason"], refusal["limit_key"]), ("defer", "per_hour", "demo@example.com"))
        eom = self.eom(log)
        self.assertEqual((eom["limit_key"], eom["limit_measured"], eom["deferred_rcpts"]), ("demo@example.com", "yes", 1))
        self.assertEqual(self.counts("demo@example.com"), (2, 2))

    def test_first_refusal_per_window_is_a_warning(self):
        m, log = self.submission()
        self.send(m, "demo@example.com", 4)
        self.send(m, "demo@example.com", 1)
        warnings = [f for level, f in log.events if level == "warning"]
        self.assertEqual(len(warnings), 1)
        self.assertEqual((warnings[0]["event"], warnings[0]["reason"], warnings[0]["limit"]), ("limit_reached", "per_hour", 2))

    def test_own_observe_mode_logs_would_defer_while_other_rules_enforce(self):
        m, log = self.submission(limits="observe")
        codes, rc = self.send(m, "demo@example.com", 3)
        self.assertEqual((set(codes), rc, m.replies), ({Milter.CONTINUE}, Milter.CONTINUE, []))
        self.assertIn(("rcpt", "would_defer", "sending_limit"), log.actions())
        self.assertEqual(self.eom(log)["would_deferred_rcpts"], 1)
        self.assertEqual(self.counts("demo@example.com"), (2, 2))
        codes, _ = message(m, "<demo@example.com>", ["<all@example.com>"], [("From", " demo@example.com")])
        self.assertEqual(codes, [Milter.REJECT])

    def test_global_observe_wins_over_enforced_limits(self):
        m, log = self.submission(mode="observe", limits="enforce")
        codes, _ = self.send(m, "demo@example.com", 3)
        self.assertEqual((set(codes), m.replies), ({Milter.CONTINUE}, []))
        self.assertIn(("rcpt", "would_defer", "sending_limit"), log.actions())

    def test_off_counts_nothing_but_still_logs_the_key(self):
        m, log = self.submission(limits="off")
        self.assertIsNone(milter._quota)
        codes, _ = self.send(m, "demo@example.com", 5)
        self.assertEqual(set(codes), {Milter.CONTINUE})
        self.assertFalse([f for _, f in log.events if f.get("rule") == "sending_limit"])
        self.assertEqual((self.eom(log)["limit_key"], self.eom(log)["limit_measured"]), ("demo@example.com", "off"))

    def test_recipients_refused_by_another_rule_reserve_nothing(self):
        m, log = self.submission()
        codes, _ = message(m, "<demo@example.com>", ["<all@example.com>", "<r1@example.net>"], [("From", " demo@example.com")])
        self.assertEqual(codes, [Milter.REJECT, Milter.CONTINUE])
        self.assertEqual(self.counts("demo@example.com"), (1, 1))

    def test_message_refused_at_eom_releases_its_reservations(self):
        m, log = self.submission(extra="\n[limits]\nmessage_bytes = 10\n")
        _, rc = self.send(m, "demo@example.com", 2)
        self.assertEqual(rc, Milter.TEMPFAIL)
        self.assertEqual(self.counts("demo@example.com"), (0, 0))

    def test_abort_new_mail_and_close_release_reservations(self):
        for end in ("abort", "envfrom", "close"):
            with self.subTest(end=end):
                m, log = self.submission()
                m.envfrom("<demo@example.com>")
                m.envrcpt("<r1@example.net>")
                self.assertEqual(self.counts("demo@example.com"), (1, 1))
                getattr(m, end)(*(["<other@example.com>"] if end == "envfrom" else []))
                self.assertEqual(self.counts("demo@example.com"), (0, 0))
                m.close()

    def test_observe_mode_counts_what_enforcement_would_commit(self):
        m, log = self.submission(mode="observe", extra="\n[limits]\nmessage_bytes = 10\n")
        _, rc = self.send(m, "demo@example.com", 2)
        self.assertEqual(rc, Milter.CONTINUE)
        self.assertEqual(self.counts("demo@example.com"), (0, 0))

    def test_short_login_is_its_own_key(self):
        m, log = self.submission(login="Demo")
        self.send(m, "demo@example.com", 1)
        self.assertEqual(self.eom(log)["limit_key"], "login:demo")

    def test_local_mail_over_the_local_cap_is_held_at_eom(self):
        m, log = self.pickup()
        for n, sender in enumerate(("a@example.com", "b@example.com", "c@example.com")):
            _, rc = self.send(m, sender, 1, first=n)
            self.assertEqual(rc, Milter.CONTINUE)
        codes, rc = self.send(m, "d@example.com", 1)
        self.assertEqual((codes, rc), ([Milter.CONTINUE], Milter.TEMPFAIL))
        self.assertIn(("rcpt", "pending_eom", "sending_limit"), log.actions())
        eom = self.eom(log)
        self.assertEqual((eom["action"], eom["rule"], eom["reason"], eom["limit_key"]),
                         ("defer", "sending_limit", "local_per_hour", "d@example.com"))
        self.assertEqual(self.quota.local_counts(milter.time.time()), (3, 3))

    def test_local_mail_held_for_one_recipient_releases_the_others(self):
        m, log = self.pickup()
        _, rc = self.send(m, "a@example.com", 3)
        self.assertEqual(rc, Milter.TEMPFAIL)
        self.assertEqual((self.counts("a@example.com"), self.quota.local_counts(milter.time.time())), ((0, 0), (0, 0)))

    def test_an_observed_limit_never_hides_an_enforced_deferral(self):
        m, log = self.pickup(limits="observe", extra="\n[limits]\nmax_recipients = 3\n")
        _, rc = self.send(m, "a@example.com", 4)
        self.assertEqual(rc, Milter.TEMPFAIL)
        eom = self.eom(log)
        self.assertEqual((eom["action"], eom["rule"], eom["reason"]), ("defer", "limits", "max_recipients"))

    def test_relays_count_by_client_address_and_untrusted_mail_is_not_limited(self):
        m, log = self.session()
        connect(m, peer="203.0.113.9")
        self.send(m, "app@example.org", 1)
        self.assertEqual(self.eom(log)["limit_key"], "203.0.113.9")
        m, log = self.session()
        connect(m, peer="198.51.100.7")
        codes, _ = self.send(m, "bob@example.org", 5)
        self.assertEqual(set(codes), {Milter.CONTINUE})
        self.assertNotIn("limit_key", self.eom(log))

    def test_full_key_store_defers_new_keys_in_enforce(self):
        m, log = self.submission(capacity=1)
        self.send(m, "demo@example.com", 1)
        m.macros["{auth_authen}"] = "other@example.com"
        codes, _ = self.send(m, "other@example.com", 1)
        self.assertEqual(codes, [Milter.TEMPFAIL])
        self.assertEqual([f["event"] for level, f in log.events if level == "warning"], ["key_store_full"])

    def test_full_key_store_in_observe_leaves_the_new_key_unmeasured(self):
        m, log = self.submission(limits="observe", capacity=1)
        self.send(m, "demo@example.com", 1)
        m.macros["{auth_authen}"] = "other@example.com"
        codes, _ = self.send(m, "other@example.com", 1)
        self.assertEqual(codes, [Milter.CONTINUE])
        self.assertIn(("rcpt", "would_defer", "sending_limit"), log.actions())
        self.assertEqual(self.eom(log)["limit_measured"], "no")


class Lifecycle(unittest.TestCase):
    def run_daemon(self, extra="", during=None):
        log = RecordingLogger()
        log.lifecycle = lambda **f: log.event("lifecycle", **f)
        cfg = settings('\nmode = "enforce"\n[logging]\nlevel = "warning"\n' + extra)
        previous = os.umask(0o022)
        self.addCleanup(os.umask, previous)
        with unittest.mock.patch.object(milter, "EventLogger", return_value=log), \
             unittest.mock.patch.object(milter.Milter, "runmilter", side_effect=lambda *a: during and during()), \
             unittest.mock.patch.object(milter.limitstate, "STATE_FILE", self.path):
            milter.run_daemon(cfg)
        return log

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = os.path.join(directory.name, "limits.json")

    def events(self, log, name):
        return [f for _, f in log.events if f.get("event") == name]

    def test_start_line_reports_mode_and_logging_level(self):
        log = self.run_daemon()
        start = self.events(log, "start")[0]
        self.assertEqual((start["mode"], start["sending_limits"], start["logging_level"]), ("enforce", "observe", "warning"))
        self.assertEqual([f.get("event") for level, f in log.events], ["start", "limit_state_empty", "stop"])
        self.assertEqual((start["limit_state"], self.events(log, "limit_state_empty")[0]["reason"]), ("missing", "missing"))

    def test_windows_survive_a_restart(self):
        def traffic():
            m = milter.PolicyMilter()
            m.macros, m.replies = {}, []
            connect(m, port="587", ingress="SUBMISSION587", login="demo@example.com", cipher="256")
            milter.authenticator = auth_result()
            message(m, "<demo@example.com>", ["<r1@example.net>", "<r2@example.net>"], [("From", " demo@example.com")])
        self.addCleanup(setattr, milter, "authenticator", None)
        stop = self.events(self.run_daemon(during=traffic), "stop")[0]
        self.assertEqual(stop["limit_state"], "saved")
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        log = self.run_daemon()
        start = self.events(log, "start")[0]
        self.assertEqual((start["limit_state"], start["limit_keys"], start["limit_state_age"]), ("loaded", 1, 0))
        self.assertEqual(milter._quota.counts("demo@example.com", milter.time.time()), (2, 2))

    def test_limits_off_neither_loads_nor_saves(self):
        log = self.run_daemon('\n[sending_limits]\nmode = "off"\n')
        self.assertEqual(self.events(log, "start")[0]["limit_state"], "off")
        self.assertEqual([f.get("event") for level, f in log.events], ["start", "stop"])
        self.assertFalse(os.path.exists(self.path))


class LogFormatting(unittest.TestCase):
    def test_fields_are_escaped_and_bounded(self):
        line = format_event({"rule": "x", "detail": 'a b="c"\n', "none": None, "long": "y" * 300,
                             "path": "a\\b", "empty": ""})
        self.assertEqual(line, 'rule=x detail="a b=\\"c\\"\\x0a" long=' + "y" * 256 + '... path="a\\\\b" empty=""')

    def test_reply_is_quoted_and_readable(self):
        line = format_event({"action": "reject", "reply": "550 5.7.1 Recipient address rejected: Access denied (ref 0123456789ab)",
                             "mid": "0123456789ab"})
        self.assertEqual(line, 'action=reject reply="550 5.7.1 Recipient address rejected: Access denied (ref 0123456789ab)" '
                               'mid=0123456789ab')


if __name__ == "__main__":
    unittest.main()
