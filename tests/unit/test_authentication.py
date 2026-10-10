"""Adapter control flow (deadline, incompleteness, error mapping) with a fake verifier.

The real spf/dkim/dns modules are used when installed (Debian); stand-ins only where they are missing.
Either way these prove how results are classified, not cryptographic or DNS behaviour."""
import io
import json
import sys
import tempfile
import threading
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


NO_KEY = object()


class FakeDKIM:
    """Like dkimpy: a missing or unusable key returns False before `pk` is set; a body hash mismatch raises."""
    behaviours: list = []

    def __init__(self, message, timeout=None):
        pass

    def verify(self, idx=0, dnsfunc=None):
        behaviour = FakeDKIM.behaviours[idx]
        if isinstance(behaviour, Exception):
            raise behaviour
        result = behaviour() if callable(behaviour) else behaviour
        if result is NO_KEY:
            return False
        self.pk = object()
        return result


class FakeSource:
    """The parts of MessageCapture the adapter reads; counts how often the whole message is loaded."""

    def __init__(self, fd=None, header=b"From: a@example.org\r\n\r\n", body_bytes=3):
        self.fd, self.header, self.body_bytes, self.loads = fd, header, body_bytes, 0

    def body_fd(self):
        return self.fd

    def header_block(self):
        return self.header

    def message_bytes(self):
        self.loads += 1
        return self.header + b"msg"


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
        outcomes, incomplete = self.verify([slow, True], [sig("example.org"), sig("example.net")], deadline_in=0.01)
        self.assertEqual(([(o.domain, o.word) for o in outcomes], incomplete),
                         ([("example.org", "neutral"), ("example.net", "neutral")], "deadline"))

    def test_late_failure_is_discarded_too(self):
        def slow_failure():
            time.sleep(0.05)
            raise authentication.dkim.DKIMException("body hash mismatch")
        outcomes, incomplete = self.verify([slow_failure], [sig("example.org")], deadline_in=0.01)
        self.assertEqual(([o.word for o in outcomes], incomplete), (["neutral"], "deadline"))
        softfail = SpfOutcome(AuthStatus.FAIL, "example.org", "softfail")
        for require, reason in (("either", "evaluation_incomplete"), ("both", "spf_softfail")):
            decision = evaluate_authentication(settings(f'[sender_authentication]\nrequire = "{require}"\n'),
                                               TrustClass.UNTRUSTED, "example.org",
                                               AuthenticationInput(softfail, outcomes, incomplete))
            self.assertEqual(decision.reason, reason, require)

    def test_unrelated_pass_does_not_hide_truncation(self):
        outcomes, incomplete = self.verify([True, True], [sig("unrelated.example"), sig("example.org")], max_signatures=1)
        self.assertEqual(([o.word for o in outcomes], incomplete), (["pass", "neutral"], "limit"))
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

    def test_result_words(self):
        cases = {"body hash mismatch": (authentication.dkim.DKIMException("body hash mismatch (got x, expected y)"), "fail"),
                 "header signature mismatch": (False, "fail"),
                 "missing or malformed key": (NO_KEY, "permerror"),
                 "malformed signature": (authentication.dkim.DKIMException("missing b="), "permerror"),
                 "pass": (True, "pass")}
        outcomes, _ = self.verify([b for b, _ in cases.values()] + [True],
                                  [sig("example.org")] * len(cases) + [sig("example.org", partial=True)])
        self.assertEqual([o.word for o in outcomes], [w for _, w in cases.values()] + ["policy"])
        self.assertEqual({o.status for o in outcomes[:4]}, {AuthStatus.FAIL})


class SkipDkim(unittest.TestCase):
    def test_dkim_not_verified_when_spf_decides(self):
        saved = getattr(authentication.dkim, "DKIM", None)
        authentication.dkim.DKIM = lambda *a, **k: self.fail("DKIM must not be verified")
        self.addCleanup(setattr, authentication.dkim, "DKIM", saved)
        failed = SpfOutcome(AuthStatus.FAIL, None, "softfail")
        with unittest.mock.patch.object(authentication, "spf_check", return_value=failed):
            result = authentication.authenticate("192.0.2.1", "h.example", "a@example.org",
                                                 FakeSource(), [sig("example.org")],
                                                 LimitSettings(), skip_dkim=lambda outcome: outcome.status is AuthStatus.FAIL)
        self.assertEqual((result.spf, result.dkim, result.dkim_skipped), (failed, (), True))


class Diagnostics(unittest.TestCase):
    """dkim_diagnostics adds DKIM work only after an SPF pass, and never changes a verdict."""

    def setUp(self):
        saved = getattr(authentication.dkim, "DKIM", None)
        authentication.dkim.DKIM = FakeDKIM
        self.addCleanup(setattr, authentication.dkim, "DKIM", saved)

    def run_check(self, spf_outcome, behaviours, sigs, diagnostics, require="both", null_sender=False, max_signatures=10,
                  deadline_in=20.0):
        from postwarden.policy import skip_dkim
        s = settings(f'[sender_authentication]\nrequire = "{require}"\ndkim_diagnostics = {str(diagnostics).lower()}\n'
                     f"[limits]\nmax_signatures = {max_signatures}\n")
        calls = []
        FakeDKIM.behaviours = [(lambda b=b: calls.append(1) or (b() if callable(b) else b)) if not isinstance(b, Exception)
                               else b for b in behaviours]
        with unittest.mock.patch.object(authentication, "spf_check", return_value=spf_outcome):
            auth = authentication.authenticate("192.0.2.1", "h.example", None if null_sender else "a@example.org",
                                               FakeSource(), sigs, s.limits, deadline=time.monotonic() + deadline_in,
                                               skip_dkim=lambda o: skip_dkim(s, "example.org", o, null_sender))
        decision = evaluate_authentication(s, TrustClass.UNTRUSTED, "example.org", auth, null_sender=null_sender)
        return auth, (decision.action, decision.reason), len(calls)

    def test_verifier_runs_after_an_spf_pass_only(self):
        aligned = SpfOutcome(AuthStatus.PASS, "example.org", "pass")
        unaligned = SpfOutcome(AuthStatus.PASS, "other.example", "pass")
        failed = SpfOutcome(AuthStatus.FAIL, None, "fail")
        cases = [(aligned, "either", False, 0, 1), (unaligned, "both", False, 0, 1), (failed, "both", False, 0, 0),
                 (failed, "either", False, 1, 1), (failed, "both", True, 1, 1)]
        for spf_outcome, require, null_sender, calls_off, calls_on in cases:
            with self.subTest(spf=spf_outcome.result, require=require, null_sender=null_sender):
                _, verdict_off, off = self.run_check(spf_outcome, [False], [sig("example.org")], False, require, null_sender)
                _, verdict_on, on = self.run_check(spf_outcome, [False], [sig("example.org")], True, require, null_sender)
                self.assertEqual((off, on, verdict_on), (calls_off, calls_on, verdict_off))

    def test_unsigned_mail_needs_no_lookup(self):
        auth, _, calls = self.run_check(SpfOutcome(AuthStatus.PASS, "example.org", "pass"), [], [], True, "either")
        self.assertEqual((auth.dkim, auth.dkim_skipped, calls), ((), False, 0))

    def test_verdicts_match_with_diagnostics_on_and_off(self):
        spf_outcomes = [SpfOutcome(AuthStatus.PASS, "example.org", "pass"), SpfOutcome(AuthStatus.PASS, "other.example", "pass"),
                        SpfOutcome(AuthStatus.FAIL, None, "softfail"), SpfOutcome(AuthStatus.TEMPERROR, None, "temperror")]
        dkim_sets = {"none": ([], []), "aligned pass": ([True], [sig("example.org")]),
                     "unaligned pass": ([True], [sig("other.example")]), "fail": ([False], [sig("example.org")]),
                     "permerror": ([authentication.dkim.DKIMException("missing b=")], [sig("example.org")]),
                     "no key": ([NO_KEY], [sig("example.org")]),
                     "body hash": ([authentication.dkim.DKIMException("body hash mismatch")], [sig("example.org")]),
                     "temperror": ([authentication.DnsTemporaryError("timeout")], [sig("example.org")]),
                     "partial": ([True], [sig("example.org", partial=True)]),
                     "over the limit": ([False, True], [sig("other.example"), sig("example.org")]),
                     "late": ([lambda: (time.sleep(0.03), True)[1]], [sig("example.org")])}
        for require in ("both", "either"):
            for null_sender in (False, True):
                for spf_outcome in spf_outcomes:
                    for name, (behaviours, sigs) in dkim_sets.items():
                        limits = {"max_signatures": 1} if name == "over the limit" else {}
                        deadline = {"deadline_in": 0.01} if name == "late" else {}
                        with self.subTest(require=require, null_sender=null_sender, spf=spf_outcome, dkim=name):
                            _, off, _ = self.run_check(spf_outcome, behaviours, sigs, False, require, null_sender,
                                                       **limits, **deadline)
                            _, on, _ = self.run_check(spf_outcome, behaviours, sigs, True, require, null_sender,
                                                      **limits, **deadline)
                            self.assertEqual(on, off)


class Workers(unittest.TestCase):
    """A body spooled to disk is verified in a child process under a memory limit; smaller ones in this process."""

    def setUp(self):
        saved = getattr(authentication.dkim, "DKIM", None)
        authentication.dkim.DKIM = FakeDKIM
        self.addCleanup(setattr, authentication.dkim, "DKIM", saved)
        FakeDKIM.behaviours = [True]
        body = tempfile.TemporaryFile()
        body.write(b"0123456789" * 1000)
        body.flush()
        self.addCleanup(body.close)
        self.body = body

    def worker(self, code):
        command = [sys.executable, "-c", "import json, os, sys, time\nrequest = json.loads(sys.stdin.read())\n" + code]
        patcher = unittest.mock.patch.object(authentication, "WORKER_COMMAND", command)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_check(self, source, workers, require="both", deadline_in=5.0):
        s = settings(f'[sender_authentication]\nrequire = "{require}"\n')
        aligned = SpfOutcome(AuthStatus.PASS, "example.org", "pass")
        with unittest.mock.patch.object(authentication, "spf_check", return_value=aligned):
            auth = authentication.authenticate("192.0.2.1", "h.example", "a@example.org", source, [sig("example.org")],
                                               s.limits, deadline=time.monotonic() + deadline_in, workers=workers)
        return auth, evaluate_authentication(s, TrustClass.UNTRUSTED, "example.org", auth).reason

    def test_small_message_is_verified_in_process(self):
        self.worker("raise SystemExit('no worker for a small message')")
        source = FakeSource()
        auth, reason = self.run_check(source, threading.BoundedSemaphore(1))
        self.assertEqual(([o.word for o in auth.dkim], reason, source.loads), (["pass"], "spf_and_dkim_aligned", 1))

    def test_large_message_is_verified_by_a_worker_reading_the_spool(self):
        self.worker("body = os.pread(request['fd'], request['body_bytes'], 0)\n"
                    "print(json.dumps({'outcomes': [['pass', 'example.org', False, str(len(body)), '']], 'incomplete': None}))")
        source = FakeSource(fd=self.body.fileno(), body_bytes=10000)
        auth, reason = self.run_check(source, threading.BoundedSemaphore(1))
        self.assertEqual(([(o.word, o.detail) for o in auth.dkim], reason, source.loads),
                         ([("pass", "10000")], "spf_and_dkim_aligned", 0))

    def test_worker_over_its_memory_limit(self):
        self.worker("print(json.dumps({'memory': True}))")
        auth, reason = self.run_check(FakeSource(fd=self.body.fileno(), body_bytes=10000), threading.BoundedSemaphore(1))
        self.assertEqual(([o.word for o in auth.dkim], auth.incomplete, reason), (["neutral"], "memory", "evaluation_incomplete"))
        auth, reason = self.run_check(FakeSource(fd=self.body.fileno(), body_bytes=10000), threading.BoundedSemaphore(1),
                                      require="either")
        self.assertEqual((auth.incomplete, reason), ("memory", "spf_aligned"))

    def test_worker_is_killed_at_the_deadline(self):
        self.worker("time.sleep(10)")
        started = time.monotonic()
        auth, reason = self.run_check(FakeSource(fd=self.body.fileno(), body_bytes=10000), threading.BoundedSemaphore(1),
                                      deadline_in=0.5)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual((auth.incomplete, reason), ("deadline", "evaluation_incomplete"))

    def test_failed_worker_is_a_temporary_error(self):
        self.worker("sys.exit(3)")
        auth, reason = self.run_check(FakeSource(fd=self.body.fileno(), body_bytes=10000), threading.BoundedSemaphore(1))
        self.assertEqual(([(o.status, o.detail) for o in auth.dkim], reason),
                         ([(AuthStatus.TEMPERROR, "error:worker exit 3")], "dkim_temperror"))

    def test_no_free_worker_within_the_deadline(self):
        self.worker("raise SystemExit('started without a free worker')")
        busy = threading.BoundedSemaphore(1)
        busy.acquire()
        auth, reason = self.run_check(FakeSource(fd=self.body.fileno(), body_bytes=10000), busy, deadline_in=0.2)
        self.assertEqual(([o.word for o in auth.dkim], auth.incomplete, reason), (["neutral"], "deadline", "evaluation_incomplete"))

    def test_memory_error_in_process(self):
        FakeDKIM.behaviours = [MemoryError()]
        auth, reason = self.run_check(FakeSource(), threading.BoundedSemaphore(1))
        self.assertEqual((auth.incomplete, reason), ("memory", "evaluation_incomplete"))


class WorkerProcess(unittest.TestCase):
    """postwarden.dkimworker as the child runs it, with the fake verifier."""

    def setUp(self):
        saved = getattr(authentication.dkim, "DKIM", None)
        authentication.dkim.DKIM = FakeDKIM
        self.addCleanup(setattr, authentication.dkim, "DKIM", saved)

    def run_worker(self, behaviours):
        from postwarden import dkimworker
        FakeDKIM.behaviours = behaviours
        body = tempfile.TemporaryFile()
        self.addCleanup(body.close)
        body.write(b"hello\r\n")
        body.flush()
        request = {"memory": 1 << 30, "fd": body.fileno(), "body_bytes": 7, "header": "RnJvbTogYUBleGFtcGxlLm9yZw0KDQo=",
                   "deadline_in": 5, "dns_timeout_seconds": 1, "max_signatures": 10,
                   "signatures": [__import__("base64").b64encode(sig("example.org")).decode()]}
        stdin = io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))
        with unittest.mock.patch.object(dkimworker.resource, "setrlimit") as setrlimit, \
                unittest.mock.patch.object(sys, "stdin", stdin), unittest.mock.patch.object(sys, "stdout", io.StringIO()) as out:
            self.assertEqual(dkimworker.main(), 0)
        setrlimit.assert_called_once_with(dkimworker.resource.RLIMIT_AS, (1 << 30, 1 << 30))
        return json.loads(out.getvalue())

    def test_outcomes_are_returned(self):
        self.assertEqual(self.run_worker([True]), {"outcomes": [["pass", "example.org", False, "", ""]], "incomplete": None})

    def test_memory_error_is_reported(self):
        self.assertEqual(self.run_worker([MemoryError()]), {"memory": True})


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
