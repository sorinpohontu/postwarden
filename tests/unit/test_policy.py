import unittest

from postwarden.addresses import parse_mailbox
from postwarden.policy import (Action, AuthStatus, AuthenticationInput, ConnectionFacts, DkimOutcome,
                                   SpfOutcome, TransactionState, TrustClass, classify_trust, combine,
                                   evaluate_authentication, evaluate_recipient, evaluate_self_sender_header,
                                   evaluate_visible_from, spf_decides)

from helpers import pickup, settings, smtp25, submission

M = parse_mailbox
ALL = M("all@example.com")
BOB = M("bob@example.org")


def rcpt(s, facts, sender, recipient, trust=None, transport=None):
    trust = trust or classify_trust(s, facts)
    state = TransactionState(sender=M(sender) if sender else None, null_sender=sender is None)
    return evaluate_recipient(s, facts, trust, state, M(recipient), transport), state


class Trust(unittest.TestCase):
    def setUp(self):
        self.s = settings()

    def test_classes(self):
        self.assertIs(classify_trust(self.s, pickup()), TrustClass.LOCAL_PICKUP)
        self.assertIs(classify_trust(self.s, smtp25("127.0.0.1")), TrustClass.LOCAL_SMTP)
        self.assertIs(classify_trust(self.s, smtp25("::ffff:127.0.0.1")), TrustClass.LOCAL_SMTP)
        self.assertIs(classify_trust(self.s, smtp25("203.0.113.9")), TrustClass.MYNETWORKS)
        self.assertIs(classify_trust(self.s, smtp25("2001:db8:1::5")), TrustClass.MYNETWORKS)
        self.assertIs(classify_trust(self.s, smtp25("198.51.100.7")), TrustClass.UNTRUSTED)
        self.assertIs(classify_trust(self.s, submission()), TrustClass.AUTHENTICATED_SUBMISSION)
        self.assertIs(classify_trust(self.s, submission(login=None)), TrustClass.UNTRUSTED)

    def test_same_host_is_detected_without_configuration(self):
        self.assertIs(classify_trust(self.s, smtp25("192.0.2.25", daemon_addr="192.0.2.25")), TrustClass.LOCAL_SMTP)
        self.assertIs(classify_trust(self.s, smtp25("2001:db8:9::25", daemon_addr="2001:db8:9::25")), TrustClass.LOCAL_SMTP)
        self.assertIs(classify_trust(self.s, smtp25("::ffff:192.0.2.25", daemon_addr="192.0.2.25")), TrustClass.LOCAL_SMTP)
        self.assertIs(classify_trust(self.s, smtp25("127.0.0.2", daemon_addr=None)), TrustClass.LOCAL_SMTP)
        self.assertIs(classify_trust(self.s, smtp25("192.0.2.26", daemon_addr="192.0.2.25")), TrustClass.UNTRUSTED)
        self.assertIs(classify_trust(self.s, smtp25("198.51.100.7", daemon_addr=None)), TrustClass.UNTRUSTED)

    def test_same_host_on_submission_is_not_local_smtp(self):
        facts = ConnectionFacts(peer_ip="127.0.0.1", daemon_port=587, ingress_marker="SUBMISSION587", daemon_addr="127.0.0.1")
        self.assertIs(classify_trust(self.s, facts), TrustClass.MYNETWORKS)

    def test_loopback_without_marker_is_not_local_pickup(self):
        facts = ConnectionFacts(peer_ip="127.0.0.1", daemon_port=0, ingress_marker=None)
        self.assertIs(classify_trust(self.s, facts), TrustClass.UNTRUSTED)

    def test_wrong_port_for_submission_marker_is_untrusted(self):
        facts = ConnectionFacts(peer_ip="198.51.100.7", daemon_port=25, ingress_marker="SUBMISSION587",
                                auth_type="PLAIN", auth_authen="manager@example.com", cipher_bits=256)
        self.assertIs(classify_trust(self.s, facts), TrustClass.UNTRUSTED)


class ProtectedRecipient(unittest.TestCase):
    def setUp(self):
        self.s = settings()

    def assertReject(self, decision, reason):
        self.assertIs(decision.action, Action.REJECT, decision)
        self.assertEqual(decision.rule, "protected_recipient")
        self.assertEqual(decision.reason, reason)
        self.assertEqual(decision.reply.render(), "550 5.7.1 Recipient address rejected: Access denied")

    def test_authorized_on_587_and_465(self):
        for port in (587, 465):
            d, _ = rcpt(self.s, submission(port), "manager@example.com", "all@example.com")
            self.assertIs(d.action, Action.ALLOW, port)

    def test_port_25_rejected_even_from_trusted_networks(self):
        for peer in ("198.51.100.7", "203.0.113.9", "127.0.0.1"):
            d, _ = rcpt(self.s, smtp25(peer), "manager@example.com", "all@example.com")
            self.assertReject(d, "ingress_smtp25")

    def test_local_pickup_rejected(self):
        d, _ = rcpt(self.s, pickup(), "manager@example.com", "all@example.com")
        self.assertReject(d, "ingress_local_pickup")

    def test_wrong_absent_login_and_sender(self):
        self.assertReject(rcpt(self.s, submission(login="bob@example.com"), "bob@example.com", "all@example.com")[0], "login_not_authorized")
        self.assertReject(rcpt(self.s, submission(login=None), "manager@example.com", "all@example.com")[0], "not_authenticated")
        self.assertReject(rcpt(self.s, submission(), "bob@example.com", "all@example.com")[0], "sender_login_mismatch")
        self.assertReject(rcpt(self.s, submission(), None, "all@example.com")[0], "sender_login_mismatch")

    def test_login_equality_is_byte_exact_but_lookup_is_not(self):
        self.assertReject(rcpt(self.s, submission(), "Manager@example.com", "all@example.com")[0], "sender_login_mismatch")
        d, _ = rcpt(self.s, submission(login="Ceo@example.com"), "Ceo@example.com", "ALL@Example.COM")
        self.assertIs(d.action, Action.ALLOW)

    def test_plus_extension_and_alias_entries(self):
        self.assertReject(rcpt(self.s, smtp25(), "x@example.org", "all+news@example.com")[0], "ingress_smtp25")
        self.assertReject(rcpt(self.s, smtp25(), "x@example.org", "everyone@example.com")[0], "ingress_smtp25")
        d, _ = rcpt(settings(recipient_delimiter=""), smtp25(), "x@example.org", "all+news@example.com")
        self.assertIs(d.action, Action.ALLOW)

    def test_submission_marker_must_match_its_port(self):
        for marker, port in (("SUBMISSION587", 465), ("SUBMISSION465", 587), ("SUBMISSION587", 25)):
            facts = ConnectionFacts(peer_ip="198.51.100.7", daemon_port=port, ingress_marker=marker,
                                    auth_type="PLAIN", auth_authen="manager@example.com", cipher_bits=256)
            self.assertIs(classify_trust(self.s, facts), TrustClass.UNTRUSTED, (marker, port))
            self.assertReject(rcpt(self.s, facts, "manager@example.com", "all@example.com")[0], "port_not_allowed")

    def test_tls_required(self):
        self.assertReject(rcpt(self.s, submission(tls=False), "manager@example.com", "all@example.com")[0], "tls_required")

    def test_local_domain_without_table_is_closed(self):
        for sender in ("manager@example.com", "anyone@hosted.example"):
            d, _ = rcpt(self.s, submission(login=sender), sender, "all@hosted.example", transport="dovecot")
            self.assertReject(d, "no_authorized_logins")
        self.assertReject(rcpt(self.s, pickup(), "www@hosted.example", "all@hosted.example")[0], "ingress_local_pickup")
        d, _ = rcpt(self.s, submission(login="bob@hosted.example"), "bob@hosted.example", "bob@hosted.example", transport="dovecot")
        self.assertIs(d.action, Action.ALLOW)

    def test_missing_transport_counts_as_local(self):
        d, _ = rcpt(self.s, submission(), "manager@example.com", "all@hosted.example", transport=None)
        self.assertReject(d, "no_authorized_logins")

    def test_remote_domain_without_table_is_not_protected(self):
        for transport in ("smtp", "relay"):
            d, _ = rcpt(self.s, submission(), "manager@example.com", "all@partner.example", transport=transport)
            self.assertIs(d.action, Action.ALLOW, transport)
            self.assertEqual(d.rule, "none")
        custom = settings('\n[protection]\nremote_transports = ["smtp"]\n')
        d, _ = rcpt(custom, submission(), "manager@example.com", "all@partner.example", transport="relay")
        self.assertReject(d, "no_authorized_logins")

    def test_listed_address_applies_whatever_the_transport(self):
        d, _ = rcpt(self.s, smtp25("203.0.113.9"), "x@example.org", "all@example.com", transport="smtp")
        self.assertReject(d, "ingress_smtp25")

    def test_listed_address_needs_no_group(self):
        s = settings('\n[protection.addresses."board@partner.example"]\nauthorized_logins = ["manager@example.com"]\n',
                     base="schema_version = 1\n")
        self.assertIs(rcpt(s, smtp25(), "x@example.org", "all@hosted.example", transport="dovecot")[0].action, Action.ALLOW)
        self.assertReject(rcpt(s, smtp25("203.0.113.9"), "x@example.org", "board@partner.example", transport="smtp")[0],
                          "ingress_smtp25")

    def test_group_logins_apply_to_every_hosted_domain(self):
        s = settings('\n[protection.addresses."all@*"]\nauthorized_logins = ["postmaster@example.com"]\n')
        d, _ = rcpt(s, submission(login="postmaster@example.com"), "postmaster@example.com", "all@hosted.example",
                    transport="dovecot")
        self.assertIs(d.action, Action.ALLOW)
        self.assertReject(rcpt(s, submission(login="postmaster@example.com"), "postmaster@example.com",
                               "all@example.com")[0], "login_not_authorized")

    def test_address_has_its_own_logins(self):
        s = settings('\n[protection.addresses."ceo@example.com"]\nauthorized_logins = ["assistant@example.com"]\n'
                     '[protection.addresses."vault@example.com"]\nauthorized_logins = []\n')
        d, _ = rcpt(s, submission(login="assistant@example.com"), "assistant@example.com", "ceo+x@example.com")
        self.assertIs(d.action, Action.ALLOW)
        self.assertReject(rcpt(s, submission(), "manager@example.com", "CEO@example.com")[0], "login_not_authorized")
        self.assertReject(rcpt(s, submission(login="assistant@example.com"), "assistant@example.com", "all@example.com")[0],
                          "login_not_authorized")
        self.assertReject(rcpt(s, submission(), "manager@example.com", "vault@example.com")[0], "no_authorized_logins")

    def test_unclassified_ingress_defers(self):
        facts = ConnectionFacts(peer_ip="198.51.100.7", daemon_port=587, ingress_marker="UNCLASSIFIED",
                                auth_type="PLAIN", auth_authen="manager@example.com", cipher_bits=256)
        d, _ = rcpt(self.s, facts, "manager@example.com", "all@example.com")
        self.assertIs(d.action, Action.DEFER)
        self.assertEqual(d.reply.smtp_code, 451)

    def test_ordinary_recipients_unaffected_and_order_independent(self):
        state = TransactionState(sender=M("bob@example.org"))
        facts = smtp25()
        first = evaluate_recipient(self.s, facts, TrustClass.UNTRUSTED, state, M("carol@example.com"))
        second = evaluate_recipient(self.s, facts, TrustClass.UNTRUSTED, state, ALL)
        third = evaluate_recipient(self.s, facts, TrustClass.UNTRUSTED, state, M("dave@example.com"))
        self.assertEqual([d.action for d in (first, second, third)], [Action.ALLOW, Action.REJECT, Action.ALLOW])
        self.assertEqual([str(r) for r in state.accepted_recipients()], ["carol@example.com", "dave@example.com"])


class SelfSender(unittest.TestCase):
    def setUp(self):
        self.s = settings()

    def test_envelope_match_rejected_on_25_only(self):
        d, _ = rcpt(self.s, smtp25(), "bob@example.org", "Bob@Example.org")
        self.assertIs(d.action, Action.REJECT)
        self.assertEqual(d.rule, "self_sender")
        d, _ = rcpt(self.s, submission(login="bob@example.org"), "bob@example.org", "bob@example.org")
        self.assertIs(d.action, Action.ALLOW)

    def test_mynetworks_ipv4_ipv6_and_pickup_exempt(self):
        for facts in (smtp25("203.0.113.9"), smtp25("2001:db8:1::5"), smtp25("127.0.0.1"), pickup()):
            d, _ = rcpt(self.s, facts, "bob@example.org", "bob@example.org")
            self.assertIs(d.action, Action.ALLOW, facts)

    def test_disabled_and_allowlist(self):
        d, _ = rcpt(settings('\n[self_sender]\nenabled = false\n'), smtp25(), "bob@example.org", "bob@example.org")
        self.assertIs(d.action, Action.ALLOW)
        d, _ = rcpt(settings('\n[self_sender]\nallow_senders = ["bob@example.org"]\n'), smtp25(), "bob@example.org", "bob@example.org")
        self.assertIs(d.action, Action.ALLOW)

    def test_null_sender_and_nonmatching(self):
        self.assertIs(rcpt(self.s, smtp25(), None, "bob@example.org")[0].action, Action.ALLOW)
        self.assertIs(rcpt(self.s, smtp25(), "alice@example.org", "bob@example.org")[0].action, Action.ALLOW)

    def test_header_from_matches_recipient(self):
        recipients = [M("carol@example.org"), M("bob@example.org")]
        d = evaluate_self_sender_header(self.s, smtp25(), TrustClass.UNTRUSTED, M("BOB@example.org"), recipients)
        self.assertIs(d.action, Action.REJECT)
        self.assertEqual(d.reason, "header_from_matches_recipient")
        self.assertIsNone(evaluate_self_sender_header(self.s, smtp25(), TrustClass.UNTRUSTED, M("eve@example.org"), recipients))
        self.assertIsNone(evaluate_self_sender_header(self.s, smtp25("203.0.113.9"), TrustClass.MYNETWORKS, M("bob@example.org"), recipients))

    def test_allowed_envelope_does_not_hide_prohibited_header(self):
        s = settings('\n[self_sender]\nallow_senders = ["alice@example.org"]\n')
        d, state = rcpt(s, smtp25(), "alice@example.org", "alice@example.org")
        self.assertIs(d.action, Action.ALLOW)
        d = evaluate_self_sender_header(s, smtp25(), TrustClass.UNTRUSTED, M("bob@example.org"),
                                        state.accepted_recipients() + [M("bob@example.org")])
        self.assertIs(d.action, Action.REJECT)

    def test_protected_rejection_not_cancelled_by_self_sender_allowlist(self):
        s = settings('\n[self_sender]\nallow_senders = ["all@example.com"]\n')
        d, _ = rcpt(s, smtp25("203.0.113.9"), "all@example.com", "all@example.com")
        self.assertIs(d.action, Action.REJECT)
        self.assertEqual(d.rule, "protected_recipient")


class VisibleFrom(unittest.TestCase):
    def test_untrusted_requires_single_valid_from(self):
        s = settings()
        for values in ([], ["a@example.com", "b@example.com"], ["a@example.com, b@example.com"], ["nonsense"]):
            mailbox, d = evaluate_visible_from(s, TrustClass.UNTRUSTED, values)
            self.assertIsNone(mailbox)
            self.assertIs(d.action, Action.REJECT)
            self.assertEqual(d.rule, "invalid_from")
        mailbox, d = evaluate_visible_from(s, TrustClass.UNTRUSTED, ["Jane <jane@Example.com>"])
        self.assertEqual(mailbox, M("jane@example.com"))
        self.assertIsNone(d)

    def test_trusted_mail_tolerates_missing_from(self):
        mailbox, d = evaluate_visible_from(settings(), TrustClass.LOCAL_PICKUP, [])
        self.assertIsNone(mailbox)
        self.assertIsNone(d)


def spf(status, domain="example.net", result=""):
    return SpfOutcome(status, domain, result)


def dkim(status, domain="example.net", partial=False):
    return DkimOutcome(status, domain, partial)


class SpfDecides(unittest.TestCase):
    def test_definitive_spf_failure_settles_without_dkim(self):
        s = settings()
        P, F, T = AuthStatus.PASS, AuthStatus.FAIL, AuthStatus.TEMPERROR
        self.assertTrue(spf_decides(s, "example.net", spf(F, None, "softfail")))
        self.assertTrue(spf_decides(s, "example.net", spf(F, None, "none")))
        self.assertTrue(spf_decides(s, "example.net", spf(P, "other.example", "pass")))
        self.assertFalse(spf_decides(s, "example.net", spf(P, "example.net", "pass")))
        self.assertFalse(spf_decides(s, "example.net", spf(T, None, "temperror")))

    def test_null_sender_keeps_dkim_unless_strict(self):
        F = AuthStatus.FAIL
        self.assertFalse(spf_decides(settings(), "example.net", spf(F, None, "fail"), null_sender=True))
        strict = settings('\n[sender_authentication]\nnull_sender = "both"\n')
        self.assertTrue(spf_decides(strict, "example.net", spf(F, None, "fail"), null_sender=True))

    def test_either_mode_skips_dkim_only_after_an_aligned_spf_pass(self):
        either = settings('\n[sender_authentication]\nrequire = "either"\n')
        P, F, T = AuthStatus.PASS, AuthStatus.FAIL, AuthStatus.TEMPERROR
        self.assertTrue(spf_decides(either, "example.net", spf(P, "example.net", "pass")))
        self.assertTrue(spf_decides(either, "example.net", spf(P, "example.net", "pass"), null_sender=True))
        for outcome in (spf(F, None, "softfail"), spf(P, "other.example", "pass"), spf(T, None, "temperror")):
            self.assertFalse(spf_decides(either, "example.net", outcome), outcome)

    def test_skipped_dkim_still_rejects_with_the_spf_reason(self):
        decision = evaluate_authentication(settings(), TrustClass.UNTRUSTED, "example.net",
                                           AuthenticationInput(spf(AuthStatus.FAIL, None, "softfail"), dkim_skipped=True))
        self.assertEqual((decision.action, decision.reason), (Action.REJECT, "spf_softfail"))


class Authentication(unittest.TestCase):
    def setUp(self):
        self.s = settings()

    def run_case(self, spf_o, dkim_os, trust=TrustClass.UNTRUSTED, incomplete=False):
        return evaluate_authentication(self.s, trust, "example.net", AuthenticationInput(spf_o, tuple(dkim_os), incomplete))

    def test_matrix(self):
        P, F, T = AuthStatus.PASS, AuthStatus.FAIL, AuthStatus.TEMPERROR
        cases = [
            (spf(P), [dkim(P)], Action.ALLOW, "spf_and_dkim_aligned"),
            (spf(F, result="softfail"), [dkim(P)], Action.REJECT, "spf_softfail"),
            (spf(F, result="none"), [dkim(P)], Action.REJECT, "spf_none"),
            (spf(P, domain="bounce.example.net"), [dkim(P)], Action.REJECT, "spf_unaligned"),
            (spf(P), [], Action.REJECT, "dkim_absent"),
            (spf(P), [dkim(F)], Action.REJECT, "dkim_no_aligned_pass"),
            (spf(P), [dkim(P, domain="other.example")], Action.REJECT, "dkim_no_aligned_pass"),
            (spf(P), [dkim(P, partial=True)], Action.REJECT, "dkim_no_aligned_pass"),
            (spf(P), [dkim(F), dkim(P)], Action.ALLOW, "spf_and_dkim_aligned"),
            (spf(T), [dkim(P)], Action.DEFER, "spf_temperror"),
            (spf(T), [dkim(T)], Action.DEFER, "spf_temperror"),
            (spf(P), [dkim(T)], Action.DEFER, "dkim_temperror"),
            (spf(P), [dkim(F), dkim(T)], Action.DEFER, "dkim_temperror"),
            (spf(F, result="fail"), [dkim(T)], Action.REJECT, "spf_fail"),
            (spf(T), [dkim(F)], Action.REJECT, "dkim_no_aligned_pass"),
            (spf(T), [], Action.REJECT, "dkim_absent"),
        ]
        for spf_o, dkim_os, action, reason in cases:
            with self.subTest(spf=spf_o, dkim=dkim_os):
                d = self.run_case(spf_o, dkim_os)
                self.assertIs(d.action, action)
                self.assertEqual(d.reason, reason)
                self.assertEqual(d.rule, "authentication")
                if action is Action.REJECT:
                    self.assertEqual(d.reply.smtp_code, 550)
                elif action is Action.DEFER:
                    self.assertEqual(d.reply.smtp_code, 451)

    def test_null_sender_relies_on_aligned_dkim_by_default(self):
        P, F, T = AuthStatus.PASS, AuthStatus.FAIL, AuthStatus.TEMPERROR
        run = lambda s_, d_, **kw: evaluate_authentication(kw.get("settings", self.s), TrustClass.UNTRUSTED, "example.net",
                                                          AuthenticationInput(s_, tuple(d_)), null_sender=True)
        self.assertEqual(run(spf(F, result="none"), [dkim(P)]).reason, "null_sender_dkim_aligned")
        self.assertIs(run(spf(F, result="none"), [dkim(P, domain="other.example")]).action, Action.REJECT)
        self.assertIs(run(spf(P), []).action, Action.REJECT)
        self.assertIs(run(spf(F), [dkim(T)]).action, Action.DEFER)
        strict = settings('\n[sender_authentication]\nnull_sender = "both"\n')
        self.assertEqual(run(spf(F, result="none"), [dkim(P)], settings=strict).reason, "spf_none")
        self.assertEqual(self.run_case(spf(F, result="none"), [dkim(P)]).reason, "spf_none")

    def test_exemptions_do_not_check_authentication(self):
        for trust in (TrustClass.LOCAL_PICKUP, TrustClass.LOCAL_SMTP, TrustClass.AUTHENTICATED_SUBMISSION, TrustClass.MYNETWORKS):
            d = self.run_case(spf(AuthStatus.FAIL), [], trust=trust)
            self.assertIs(d.action, Action.ALLOW, trust)

    def test_incomplete_evaluation_defers_instead_of_failing(self):
        d = self.run_case(spf(AuthStatus.PASS), [dkim(AuthStatus.FAIL)], incomplete=True)
        self.assertIs(d.action, Action.DEFER)
        self.assertEqual(d.reason, "evaluation_incomplete")


class EitherMechanism(unittest.TestCase):
    def setUp(self):
        self.s = settings('\n[sender_authentication]\nrequire = "either"\n')

    def run_case(self, spf_o, dkim_os, incomplete=False, null_sender=False):
        return evaluate_authentication(self.s, TrustClass.UNTRUSTED, "example.net",
                                       AuthenticationInput(spf_o, tuple(dkim_os), incomplete), null_sender)

    def test_matrix(self):
        P, F, T = AuthStatus.PASS, AuthStatus.FAIL, AuthStatus.TEMPERROR
        cases = [
            (spf(P), [dkim(P)], Action.ALLOW, "spf_aligned"),
            (spf(P), [], Action.ALLOW, "spf_aligned"),
            (spf(P), [dkim(F)], Action.ALLOW, "spf_aligned"),
            (spf(P), [dkim(T)], Action.ALLOW, "spf_aligned"),
            (spf(F, result="softfail"), [dkim(P)], Action.ALLOW, "dkim_aligned"),
            (spf(P, domain="bounce.example.net"), [dkim(P)], Action.ALLOW, "dkim_aligned"),
            (spf(T), [dkim(P)], Action.ALLOW, "dkim_aligned"),
            (spf(F, result="fail"), [dkim(F)], Action.REJECT, "no_aligned_pass"),
            (spf(F, result="none"), [], Action.REJECT, "no_aligned_pass"),
            (spf(P, domain="bounce.example.net"), [dkim(P, domain="other.example")], Action.REJECT, "no_aligned_pass"),
            (spf(F, result="fail"), [dkim(P, partial=True)], Action.REJECT, "no_aligned_pass"),
            (spf(T), [dkim(F)], Action.DEFER, "spf_temperror"),
            (spf(T), [], Action.DEFER, "spf_temperror"),
            (spf(F, result="softfail"), [dkim(T)], Action.DEFER, "dkim_temperror"),
        ]
        for spf_o, dkim_os, action, reason in cases:
            with self.subTest(spf=spf_o, dkim=dkim_os):
                d = self.run_case(spf_o, dkim_os)
                self.assertEqual((d.action, d.reason), (action, reason))
                if action is Action.REJECT:
                    self.assertEqual(d.reply.smtp_code, 550)
                elif action is Action.DEFER:
                    self.assertEqual(d.reply.smtp_code, 451)

    def test_aligned_pass_settles_incomplete_evaluation(self):
        P, F = AuthStatus.PASS, AuthStatus.FAIL
        self.assertEqual(self.run_case(spf(F), [dkim(P)], incomplete=True).reason, "dkim_aligned")
        self.assertEqual(self.run_case(spf(P), [], incomplete=True).reason, "spf_aligned")
        d = self.run_case(spf(F), [dkim(F)], incomplete=True)
        self.assertEqual((d.action, d.reason), (Action.DEFER, "evaluation_incomplete"))

    def test_null_sender_follows_the_same_rule(self):
        P, F = AuthStatus.PASS, AuthStatus.FAIL
        self.assertEqual(self.run_case(spf(P), [], null_sender=True).reason, "spf_aligned")
        self.assertEqual(self.run_case(spf(F, result="none"), [dkim(P)], null_sender=True).reason, "dkim_aligned")

    def test_exemptions_still_apply(self):
        d = evaluate_authentication(self.s, TrustClass.MYNETWORKS, "example.net",
                                    AuthenticationInput(spf(AuthStatus.FAIL), ()))
        self.assertIs(d.action, Action.ALLOW)


class Combination(unittest.TestCase):
    def test_reject_beats_defer_beats_allow(self):
        from postwarden.policy import Decision
        allow = Decision.allow("a", "x")
        defer = Decision(Action.DEFER, "b", "y")
        reject = Decision(Action.REJECT, "c", "z")
        self.assertIs(combine([allow, defer, reject]).action, Action.REJECT)
        self.assertIs(combine([allow, defer]).action, Action.DEFER)
        self.assertIs(combine([None, allow]).action, Action.ALLOW)
        self.assertEqual(combine([None]).reason, "no_rule_matched")


if __name__ == "__main__":
    unittest.main()
