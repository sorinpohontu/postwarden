"""SPF and DKIM adapters over the Debian-packaged pyspf, dkimpy and dnspython. Imported only by the daemon."""
from __future__ import annotations

import time
from typing import Callable

import dns.exception
import dns.resolver
import dkim
import dkim.util
import spf

from .config import LimitSettings
from .policy import AuthStatus, AuthenticationInput, DkimOutcome, SpfOutcome

SPF_PASS = "pass"
SPF_TEMP = "temperror"


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


def dkim_verify(message: bytes, signature_headers: list[bytes], limits: LimitSettings,
                deadline: float) -> tuple[tuple[DkimOutcome, ...], bool]:
    """Verify signatures within the work limit and deadline. Returns outcomes and whether evaluation was cut short;
    a result that arrives after the deadline is discarded."""
    from .addresses import AddressError, normalize_domain
    dnsfunc = make_dnsfunc(limits.dns_timeout_seconds, deadline)
    outcomes: list[DkimOutcome] = []
    incomplete = False
    for index, raw in enumerate(signature_headers):
        if index >= limits.max_signatures or time.monotonic() >= deadline:
            incomplete = True
            break
        tags = _signature_tags(raw)
        domain = None
        try:
            domain = normalize_domain(tags.get(b"d", b"").decode("ascii", "replace")) if tags.get(b"d") else None
        except AddressError:
            domain = None
        partial = b"l" in tags
        verifier = dkim.DKIM(message, timeout=limits.dns_timeout_seconds)
        try:
            ok = verifier.verify(idx=index, dnsfunc=dnsfunc)
            outcome = DkimOutcome(AuthStatus.PASS if ok else AuthStatus.FAIL, domain, partial)
        except DnsTemporaryError as exc:
            outcome = DkimOutcome(AuthStatus.TEMPERROR, domain, partial, f"dns:{exc}")
        except dkim.DKIMException as exc:
            outcome = DkimOutcome(AuthStatus.FAIL, domain, partial, type(exc).__name__)
        except Exception as exc:
            outcome = DkimOutcome(AuthStatus.TEMPERROR, domain, partial, f"error:{type(exc).__name__}")
        if time.monotonic() > deadline:
            incomplete = True
            break
        outcomes.append(outcome)
    return tuple(outcomes), incomplete


def authenticate(peer_ip: str, helo: str, sender: str | None, message: bytes,
                 signature_headers: list[bytes], limits: LimitSettings, deadline: float | None = None,
                 skip_dkim: Callable[[SpfOutcome], bool] | None = None) -> AuthenticationInput:
    deadline = deadline if deadline is not None else time.monotonic() + limits.authentication_deadline_seconds
    spf_outcome = spf_check(peer_ip, helo, sender, limits, deadline)
    if skip_dkim is not None and skip_dkim(spf_outcome):
        return AuthenticationInput(spf_outcome, dkim_skipped=True)
    dkim_outcomes, incomplete = dkim_verify(message, signature_headers, limits, deadline)
    return AuthenticationInput(spf_outcome, dkim_outcomes, incomplete)
