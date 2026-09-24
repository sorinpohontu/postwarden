"""Adapter control flow (deadline, incompleteness, error mapping) with a fake verifier.

The real spf/dkim/dns modules are used when installed (Debian); stand-ins only where they are missing.
Either way these prove how results are classified, not cryptographic or DNS behaviour."""
import sys
import time
import types
import unittest
import unittest.mock


def _install_stubs():
    dns = types.ModuleType("dns")
    exception = types.ModuleType("dns.exception")
    resolver = types.ModuleType("dns.resolver")
    exception.Timeout = type("Timeout", (Exception,), {})
    for name in ("NXDOMAIN", "NoAnswer", "NoNameservers"):
        setattr(resolver, name, type(name, (Exception,), {}))
    resolver.Resolver = type("Resolver", (), {"resolve": lambda self, *a, **k: []})
    dns.exception, dns.resolver = exception, resolver
    dkim = types.ModuleType("dkim")
    util = types.ModuleType("dkim.util")
    util.parse_tag_value = lambda value: dict(p.strip().split(b"=", 1) for p in value.split(b";") if b"=" in p)
    dkim.util = util
    dkim.DKIMException = type("DKIMException", (Exception,), {})
    spf = types.ModuleType("spf")
    for name, module in {"dns": dns, "dns.exception": exception, "dns.resolver": resolver,
                         "dkim": dkim, "dkim.util": util, "spf": spf}.items():
        sys.modules[name] = module


try:
    import dkim  # noqa: F401
    import dns.resolver  # noqa: F401
    import spf  # noqa: F401
except ImportError:
    _install_stubs()

from postwarden import authentication  # noqa: E402
from postwarden.config import LimitSettings  # noqa: E402
from postwarden.policy import AuthStatus, AuthenticationInput, SpfOutcome, TrustClass, evaluate_authentication  # noqa: E402

from helpers import settings  # noqa: E402


class FakeDKIM:
    behaviours: list = []

    def __init__(self, message, timeout=None):
        pass

    def verify(self, idx=0, dnsfunc=None):
        behaviour = FakeDKIM.behaviours[idx]
        if isinstance(behaviour, Exception):
            raise behaviour
        if callable(behaviour):
            return behaviour()
        return behaviour


def sig(domain, partial=False):
    return b"v=1; d=" + domain.encode() + (b"; l=10" if partial else b"") + b"; b=x"


class DkimAdapter(unittest.TestCase):
    def setUp(self):
        saved = getattr(authentication.dkim, "DKIM", None)
        authentication.dkim.DKIM = FakeDKIM
        self.addCleanup(setattr, authentication.dkim, "DKIM", saved)

    def verify(self, behaviours, sigs, deadline_in=5.0, **limits):
        FakeDKIM.behaviours = behaviours
        return authentication.dkim_verify(b"msg", sigs, LimitSettings(**limits), time.monotonic() + deadline_in)

    def test_late_result_is_discarded(self):
        slow = lambda: (time.sleep(0.05), True)[1]
        outcomes, incomplete = self.verify([slow], [sig("example.org")], deadline_in=0.01)
        self.assertEqual((outcomes, incomplete), ((), True))

    def test_late_failure_is_discarded_too(self):
        def slow_failure():
            time.sleep(0.05)
            raise authentication.dkim.DKIMException("body hash mismatch")
        outcomes, incomplete = self.verify([slow_failure], [sig("example.org")], deadline_in=0.01)
        self.assertEqual((outcomes, incomplete), ((), True))
        decision = evaluate_authentication(settings(), TrustClass.UNTRUSTED, "example.org",
                                           AuthenticationInput(SpfOutcome(AuthStatus.FAIL, "example.org", "softfail"),
                                                               outcomes, incomplete))
        self.assertEqual(decision.reason, "evaluation_incomplete")

    def test_unrelated_pass_does_not_hide_truncation(self):
        outcomes, incomplete = self.verify([True, True], [sig("unrelated.example"), sig("example.org")], max_signatures=1)
        self.assertTrue(incomplete)
        decision = evaluate_authentication(settings(), TrustClass.UNTRUSTED, "example.org",
                                           AuthenticationInput(SpfOutcome(AuthStatus.PASS, "example.org", "pass"),
                                                               outcomes, incomplete))
        self.assertEqual(decision.reason, "evaluation_incomplete")

    def test_partial_body_pass_does_not_hide_truncation(self):
        outcomes, incomplete = self.verify([True, True], [sig("example.org", partial=True), sig("example.org")],
                                           max_signatures=1)
        decision = evaluate_authentication(settings(), TrustClass.UNTRUSTED, "example.org",
                                           AuthenticationInput(SpfOutcome(AuthStatus.PASS, "example.org", "pass"),
                                                               outcomes, incomplete))
        self.assertEqual(decision.reason, "evaluation_incomplete")

    def test_eligible_pass_settles_despite_truncation(self):
        outcomes, incomplete = self.verify([True, True], [sig("example.org"), sig("other.example")], max_signatures=1)
        decision = evaluate_authentication(settings(), TrustClass.UNTRUSTED, "example.org",
                                           AuthenticationInput(SpfOutcome(AuthStatus.PASS, "example.org", "pass"),
                                                               outcomes, incomplete))
        self.assertEqual(decision.reason, "spf_and_dkim_aligned")

    def test_unexpected_verifier_error_is_temporary(self):
        outcomes, _ = self.verify([RuntimeError("boom")], [sig("example.org")])
        self.assertEqual((outcomes[0].status, outcomes[0].detail), (AuthStatus.TEMPERROR, "error:RuntimeError"))
        decision = evaluate_authentication(settings(), TrustClass.UNTRUSTED, "example.org",
                                           AuthenticationInput(SpfOutcome(AuthStatus.PASS, "example.org", "pass"), outcomes))
        self.assertEqual(decision.reason, "dkim_temperror")

    def test_invalid_signature_is_a_failure(self):
        outcomes, _ = self.verify([authentication.dkim.DKIMException("bad")], [sig("example.org")])
        self.assertIs(outcomes[0].status, AuthStatus.FAIL)


class SkipDkim(unittest.TestCase):
    def test_dkim_not_verified_when_spf_decides(self):
        saved = getattr(authentication.dkim, "DKIM", None)
        authentication.dkim.DKIM = lambda *a, **k: self.fail("DKIM must not be verified")
        self.addCleanup(setattr, authentication.dkim, "DKIM", saved)
        failed = SpfOutcome(AuthStatus.FAIL, None, "softfail")
        with unittest.mock.patch.object(authentication, "spf_check", return_value=failed):
            result = authentication.authenticate("192.0.2.1", "h.example", "a@example.org", b"msg", [sig("example.org")],
                                                 LimitSettings(), skip_dkim=lambda outcome: outcome.status is AuthStatus.FAIL)
        self.assertEqual((result.spf, result.dkim, result.dkim_skipped), (failed, (), True))


class SpfAdapter(unittest.TestCase):
    def test_expired_deadline_is_temporary(self):
        outcome = authentication.spf_check("192.0.2.1", "h.example", "a@example.org", LimitSettings(), time.monotonic() - 1)
        self.assertIs(outcome.status, AuthStatus.TEMPERROR)

    def test_result_after_deadline_is_temporary(self):
        class Query:
            def __init__(self, **kw):
                pass

            def check(self):
                time.sleep(0.05)
                return "pass", 250, ""
        saved = getattr(authentication.spf, "query", None)
        authentication.spf.query = Query
        self.addCleanup(setattr, authentication.spf, "query", saved)
        outcome = authentication.spf_check("192.0.2.1", "h.example", "a@example.org", LimitSettings(), time.monotonic() + 0.01)
        self.assertIs(outcome.status, AuthStatus.TEMPERROR)
