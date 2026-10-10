"""SPF and DKIM adapters over the Debian-packaged pyspf, dkimpy and dnspython. Imported only by the daemon."""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import threading
import time
from typing import Callable

import dns.exception
import dns.resolver
import dkim
import dkim.util
import spf

from .config import LimitSettings
from .message import MessageCapture
from .policy import AuthStatus, AuthenticationInput, DkimOutcome, SpfOutcome

SPF_PASS = "pass"
SPF_TEMP = "temperror"
WORKER_COMMAND = [sys.executable, "-P", "-m", "postwarden.dkimworker"]


class DnsTemporaryError(Exception):
    """DNS timeout or server failure: the answer is unknown, not negative."""


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def spf_check(peer_ip: str, helo: str, sender: str | None, limits: LimitSettings, deadline: float) -> SpfOutcome:
    """Evaluate the actual peer IP and envelope sender; the HELO identity covers a null reverse path."""
    identity_domain = None
    budget = _remaining(deadline)
    if budget <= 0:
        return SpfOutcome(AuthStatus.TEMPERROR, None, SPF_TEMP)
    try:
        query = spf.query(i=peer_ip, s=sender or "", h=helo or "", timeout=min(limits.dns_timeout_seconds, budget),
                          querytime=budget)
        result, _code, _explanation = query.check()
    except Exception:
        return SpfOutcome(AuthStatus.TEMPERROR, None, SPF_TEMP)
    if time.monotonic() > deadline:
        return SpfOutcome(AuthStatus.TEMPERROR, None, SPF_TEMP)
    if result == SPF_PASS:
        identity_domain = _spf_identity_domain(sender, helo)
        return SpfOutcome(AuthStatus.PASS, identity_domain, result)
    if result == SPF_TEMP:
        return SpfOutcome(AuthStatus.TEMPERROR, None, result)
    return SpfOutcome(AuthStatus.FAIL, None, result)


def _spf_identity_domain(sender: str | None, helo: str) -> str | None:
    from .addresses import AddressError, normalize_domain
    domain = sender.rpartition("@")[2] if sender and "@" in sender else helo
    try:
        return normalize_domain(domain)
    except AddressError:
        return None


def make_dnsfunc(timeout: float, deadline: float):
    resolver = dns.resolver.Resolver()

    def get_txt(name, timeout=timeout):
        if isinstance(name, bytes):
            name = name.decode("ascii", "replace")
        budget = min(timeout, _remaining(deadline))
        if budget <= 0:
            raise DnsTemporaryError("authentication deadline reached")
        resolver.lifetime = resolver.timeout = budget
        try:
            answer = resolver.resolve(name, "TXT", search=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise DnsTemporaryError(str(exc)) from exc
        for record in answer:
            return b"".join(record.strings)
        return None

    return get_txt


def _signature_tags(value: bytes) -> dict:
    try:
        return dkim.util.parse_tag_value(value.replace(b"\r\n", b"").replace(b"\n", b""))
    except Exception:
        return {}


def _signature_domain(tags: dict) -> str | None:
    from .addresses import AddressError, normalize_domain
    try:
        return normalize_domain(tags[b"d"].decode("ascii", "replace")) if tags.get(b"d") else None
    except AddressError:
        return None


def _unevaluated(raw: bytes) -> DkimOutcome:
    tags = _signature_tags(raw)
    return DkimOutcome(AuthStatus.FAIL, _signature_domain(tags), b"l" in tags, result="neutral")


def dkim_verify(message: bytes, signature_headers: list[bytes], limits: LimitSettings,
                deadline: float) -> tuple[tuple[DkimOutcome, ...], str | None]:
    """Verify signatures within the work limit and deadline. Returns one outcome per signature and why evaluation
    was cut short (limit, deadline or None); signatures not evaluated, and a result that arrives after the
    deadline, are neutral."""
    dnsfunc = make_dnsfunc(limits.dns_timeout_seconds, deadline)
    outcomes: list[DkimOutcome] = []
    incomplete = None
    for index, raw in enumerate(signature_headers):
        tags = _signature_tags(raw)
        domain, partial = _signature_domain(tags), b"l" in tags
        if incomplete is None and index >= limits.max_signatures:
            incomplete = "limit"
        elif incomplete is None and time.monotonic() >= deadline:
            incomplete = "deadline"
        if incomplete is not None:
            outcomes.append(_unevaluated(raw))
            continue
        verifier = dkim.DKIM(message, timeout=limits.dns_timeout_seconds)
        try:
            ok = verifier.verify(idx=index, dnsfunc=dnsfunc)
            if ok:
                outcome = DkimOutcome(AuthStatus.PASS, domain, partial)
            elif getattr(verifier, "pk", None) is None:
                outcome = DkimOutcome(AuthStatus.FAIL, domain, partial, "key", result="permerror")
            else:
                outcome = DkimOutcome(AuthStatus.FAIL, domain, partial)
        except DnsTemporaryError as exc:
            outcome = DkimOutcome(AuthStatus.TEMPERROR, domain, partial, f"dns:{exc}")
        except dkim.DKIMException as exc:
            word = "" if str(exc).startswith("body hash mismatch") else "permerror"
            outcome = DkimOutcome(AuthStatus.FAIL, domain, partial, type(exc).__name__, result=word)
        except MemoryError:
            raise
        except Exception as exc:
            outcome = DkimOutcome(AuthStatus.TEMPERROR, domain, partial, f"error:{type(exc).__name__}")
        if time.monotonic() > deadline:
            incomplete = "deadline"
            outcome = DkimOutcome(AuthStatus.FAIL, domain, partial, result="neutral")
        outcomes.append(outcome)
    return tuple(outcomes), incomplete


def verify_in_worker(header: bytes, body_fd: int, body_bytes: int, signature_headers: list[bytes],
                     limits: LimitSettings, deadline: float) -> tuple[tuple[DkimOutcome, ...], str | None]:
    """Run dkim_verify in a child process under limits.dkim_worker_memory; the child reads the body from body_fd."""
    unevaluated = tuple(_unevaluated(raw) for raw in signature_headers)
    request = json.dumps({"memory": limits.dkim_worker_memory, "fd": body_fd, "body_bytes": body_bytes,
                          "header": base64.b64encode(header).decode(), "deadline_in": _remaining(deadline),
                          "dns_timeout_seconds": limits.dns_timeout_seconds, "max_signatures": limits.max_signatures,
                          "signatures": [base64.b64encode(raw).decode() for raw in signature_headers]}).encode()
    try:
        child = subprocess.run(WORKER_COMMAND, input=request, capture_output=True, pass_fds=(body_fd,), cwd="/",
                               timeout=max(_remaining(deadline), 0.001), check=False)
    except subprocess.TimeoutExpired:
        return unevaluated, "deadline"
    try:
        reply = json.loads(child.stdout)
    except ValueError:
        detail = f"error:worker exit {child.returncode}"
        return tuple(DkimOutcome(AuthStatus.TEMPERROR, o.domain, o.partial_body, detail) for o in unevaluated), None
    if reply.get("memory"):
        return unevaluated, "memory"
    outcomes = tuple(DkimOutcome(AuthStatus(status), domain, partial, detail, result)
                     for status, domain, partial, detail, result in reply["outcomes"])
    return outcomes, reply["incomplete"]


def authenticate(peer_ip: str, helo: str, sender: str | None, source: MessageCapture,
                 signature_headers: list[bytes], limits: LimitSettings, deadline: float | None = None,
                 skip_dkim: Callable[[SpfOutcome], bool] | None = None,
                 workers: threading.Semaphore | None = None) -> AuthenticationInput:
    """The message is read only when DKIM runs. With `workers`, a body spooled to disk is verified in a child
    process holding one of them; otherwise in this process."""
    deadline = deadline if deadline is not None else time.monotonic() + limits.authentication_deadline_seconds
    spf_outcome = spf_check(peer_ip, helo, sender, limits, deadline)
    if skip_dkim is not None and skip_dkim(spf_outcome):
        return AuthenticationInput(spf_outcome, dkim_skipped=True)
    if not signature_headers:
        return AuthenticationInput(spf_outcome)
    body_fd = source.body_fd() if workers is not None else None
    if body_fd is None:
        try:
            dkim_outcomes, incomplete = dkim_verify(source.message_bytes(), signature_headers, limits, deadline)
        except MemoryError:
            dkim_outcomes, incomplete = tuple(_unevaluated(raw) for raw in signature_headers), "memory"
        return AuthenticationInput(spf_outcome, dkim_outcomes, incomplete)
    if not workers.acquire(timeout=_remaining(deadline)):
        return AuthenticationInput(spf_outcome, tuple(_unevaluated(raw) for raw in signature_headers), "deadline")
    try:
        dkim_outcomes, incomplete = verify_in_worker(source.header_block(), body_fd, source.body_bytes,
                                                     signature_headers, limits, deadline)
    finally:
        workers.release()
    return AuthenticationInput(spf_outcome, dkim_outcomes, incomplete)
