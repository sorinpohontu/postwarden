"""Evaluate given connection facts and an optional message against a configuration, with the daemon's own policy
functions. Nothing is sent, delivered, counted or changed."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable

from .addresses import AddressError, Mailbox, parse_envelope
from .config import Settings
from .message import MessageCapture
from .policy import (Action, AuthStatus, AuthenticationInput, ConnectionFacts, Decision, DkimOutcome, RecipientState,
                     SpfOutcome, TransactionState, TrustClass, classify_trust, combine, evaluate_authentication,
                     evaluate_message, evaluate_recipient, spf_decides)
from .quota import LimitKey, limit_key

INGRESS = {"25": ("SMTP25", 25), "587": ("SUBMISSION587", 587), "465": ("SUBMISSION465", 465),
           "local": ("LOCAL_PICKUP", None)}
FORCED = ("pass", "fail", "none", "temperror")
ALLOWED, REFUSED, PARTIAL = 0, 1, 3


@dataclass(frozen=True, slots=True)
class Facts:
    ingress: str
    sender: str
    recipients: tuple[str, ...]
    login: str | None = None
    peer: str | None = None
    helo: str = ""
    tls: bool = True
    spf: str | None = None
    dkim: str | None = None
    transport: str | None = None


@dataclass(slots=True)
class Outcome:
    trust: TrustClass
    limit: LimitKey | None
    recipients: list[tuple[str, Decision]] = field(default_factory=list)
    final: Decision | None = None
    from_domain: str | None = None
    authentication: str | None = None

    @property
    def exit_code(self) -> int:
        refused = any(d.action is not Action.ALLOW for _, d in self.recipients)
        if refused or (self.final is not None and self.final.action is not Action.ALLOW):
            return REFUSED
        return ALLOWED if self.final is not None else PARTIAL


def connection(facts: Facts) -> ConnectionFacts:
    marker, port = INGRESS[facts.ingress]
    submission = facts.ingress in ("587", "465")
    return ConnectionFacts(peer_ip=facts.peer or "127.0.0.1", daemon_port=port, ingress_marker=marker,
                           auth_type="PLAIN" if facts.login else None, auth_authen=facts.login,
                           cipher_bits=256 if submission and facts.tls else None)


def split_message(raw: bytes) -> tuple[list[tuple[bytes, bytes]], bytes]:
    """Header fields as Postfix passes them to a milter (name, value with its leading space and folding) and the
    body with CRLF line ends."""
    if b"\r\n" not in raw:
        raw = raw.replace(b"\n", b"\r\n")
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        head, body = raw, b""
    headers: list[tuple[bytes, bytes]] = []
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and headers:
            name, value = headers[-1]
            headers[-1] = (name, value + b"\n" + line)
        elif b":" in line:
            name, _, value = line.partition(b":")
            headers.append((name, value))
    return headers, body


def forced_authentication(spf: str, dkim: str, from_domain: str) -> AuthenticationInput:
    spf_outcome = {"pass": SpfOutcome(AuthStatus.PASS, from_domain, "pass"),
                   "fail": SpfOutcome(AuthStatus.FAIL, None, "fail"),
                   "none": SpfOutcome(AuthStatus.FAIL, None, "none"),
                   "temperror": SpfOutcome(AuthStatus.TEMPERROR, None, "temperror")}[spf]
    dkim_outcomes = {"pass": (DkimOutcome(AuthStatus.PASS, from_domain),),
                     "fail": (DkimOutcome(AuthStatus.FAIL, from_domain),),
                     "none": (),
                     "temperror": (DkimOutcome(AuthStatus.TEMPERROR, from_domain),)}[dkim]
    return AuthenticationInput(spf_outcome, dkim_outcomes)


def simulate(settings: Settings, facts: Facts, message: bytes | None,
             live: Callable[..., AuthenticationInput] | None = None) -> Outcome:
    conn = connection(facts)
    trust = classify_trust(settings, conn)
    raw_sender = facts.sender.strip().removeprefix("<").removesuffix(">")
    try:
        sender = parse_envelope(facts.sender)
        null_sender = sender is None
    except AddressError:
        sender, null_sender = None, False
    state = TransactionState(sender=sender, null_sender=null_sender, raw_sender=None if null_sender else raw_sender)
    outcome = Outcome(trust, limit_key(settings.sending_limits, trust.value, login=facts.login, sender=sender,
                                       null_sender=null_sender, raw_sender=raw_sender, peer_ip=conn.peer_ip))
    for text in facts.recipients:
        decision = _recipient(settings, conn, trust, state, text, facts.transport)
        outcome.recipients.append((text, decision))
        if decision.action is not Action.ALLOW and trust is TrustClass.LOCAL_PICKUP:
            state.deferred_rejections.append(decision)
    if message is None:
        return outcome

    capture = MessageCapture(settings.limits)
    try:
        headers, body = split_message(message)
        for name, value in headers:
            capture.add_header(name, value)
        capture.add_body(body)
        complete = capture.over_limit not in ("max_headers", "max_header_bytes")
        from_values = ([v.decode("utf-8", "surrogateescape") for v in capture.header_values(b"From")]
                       if complete else None)

        def authenticate(header_from: Mailbox) -> Decision:
            auth = _authentication(settings, facts, conn, state, capture, header_from, live)
            outcome.authentication = _describe(auth, facts)
            return evaluate_authentication(settings, trust, header_from.domain, auth, null_sender=state.null_sender)

        decisions, header_from = evaluate_message(settings, conn, trust, state, from_values, capture.over_limit,
                                                  authenticate)
    finally:
        capture.close()
    outcome.from_domain = header_from.domain if header_from else None
    outcome.final = combine(decisions)
    return outcome


def _recipient(settings: Settings, conn: ConnectionFacts, trust: TrustClass, state: TransactionState, text: str,
               transport: str | None) -> Decision:
    if len(state.recipients) >= settings.limits.max_recipients:
        state.overflow_rcpts += 1
        return Decision(Action.DEFER, "limits", "max_recipients", settings.reply("temporary_failure"))
    try:
        recipient = parse_envelope(text)
        if recipient is None:
            raise AddressError("empty recipient")
    except AddressError:
        decision = Decision(Action.REJECT, "invalid_recipient", "recipient_unparseable", settings.reply("invalid_recipient"))
        state.recipients.append(RecipientState(None, decision))
        return decision
    return evaluate_recipient(settings, conn, trust, state, recipient, transport)


def _authentication(settings: Settings, facts: Facts, conn: ConnectionFacts, state: TransactionState,
                    capture: MessageCapture, header_from: Mailbox,
                    live: Callable[..., AuthenticationInput] | None) -> AuthenticationInput:
    if facts.spf and facts.dkim:
        return forced_authentication(facts.spf, facts.dkim, header_from.domain)
    if live is None:
        from .authentication import authenticate as live
    forced_spf = forced_authentication(facts.spf, "none", header_from.domain).spf if facts.spf else None
    deadline = time.monotonic() + settings.limits.authentication_deadline_seconds

    def skip_dkim(spf_outcome: SpfOutcome) -> bool:
        return facts.dkim is None and spf_decides(settings, header_from.domain, spf_outcome, state.null_sender)

    result = live(conn.peer_ip or "", facts.helo, state.raw_sender, capture.message_bytes(),
                  capture.header_values(b"DKIM-Signature"), settings.limits, deadline=deadline,
                  skip_dkim=lambda spf_outcome: skip_dkim(forced_spf or spf_outcome))
    spf_outcome = forced_spf or result.spf
    if facts.dkim:
        return AuthenticationInput(spf_outcome, forced_authentication("none", facts.dkim, header_from.domain).dkim)
    return AuthenticationInput(spf_outcome, result.dkim, result.incomplete, result.dkim_skipped)


def _describe(auth: AuthenticationInput, facts: Facts) -> str:
    spf = f"spf={auth.spf.result or auth.spf.status.value}" + (" (forced)" if facts.spf else " (DNS)")
    if auth.dkim_skipped:
        dkim = "dkim=skipped (SPF decides)"
    else:
        dkim = "dkim=" + (",".join(f"{o.domain or '-'}:{o.status.value}" for o in auth.dkim) or "none")
        dkim += " (forced)" if facts.dkim else " (DNS)"
    return f"{spf}, {dkim}"


def _reply(decision: Decision) -> str:
    return decision.reply.render() if decision.reply is not None else ""


def render(settings: Settings, facts: Facts, outcome: Outcome, message_name: str | None) -> list[str]:
    conn = connection(facts)
    login = f", login {facts.login}" if facts.login else ""
    tls = "" if facts.ingress not in ("587", "465") else (", TLS" if facts.tls else ", no TLS")
    out = [f"connection: ingress {facts.ingress}, peer {conn.peer_ip}{login}{tls} -> trust {outcome.trust.value}"]
    if settings.mode != "enforce":
        out.append("note: observe mode: postwarden would only log the refusals below and let the mail through")
    if outcome.limit is None:
        out.append("sending limits: none (outside mail is not limited)")
    else:
        key = outcome.limit
        out.append(f"sending limits ({settings.sending_limits.mode}): key {key.text}, multiplier {key.multiplier:g}, "
                   f"{key.per_hour} per hour, {key.per_day} per day; current counts are not shown")
    if facts.transport is None:
        out.append("transport: not given; every recipient counts as locally delivered (--transport NAME)")
    pickup = outcome.trust is TrustClass.LOCAL_PICKUP
    out += ["", "RCPT" + (" (local sendmail: refusals are applied at end of message)" if pickup else "")]
    width = max(len(text) for text, _ in outcome.recipients)
    for text, decision in outcome.recipients:
        detail = "" if decision.action is Action.ALLOW else f"  {decision.rule} {decision.reason}  {_reply(decision)}"
        out.append(f"  {text.ljust(width)}  {decision.action.value}{detail}")
    out += ["", "End of message"]
    if outcome.final is None:
        out.append("  not evaluated: no message file (RCPT stage only)")
    else:
        final = outcome.final
        out.append(f"  {final.action.value}  {final.rule} {final.reason}  {_reply(final)}".rstrip())
        if message_name:
            out.append(f"  message: {message_name}; From domain: {outcome.from_domain or 'none'}")
        if outcome.authentication:
            out.append(f"  {outcome.authentication}")
    return out


def valid_peer(text: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(re.sub(r"^IPv6:", "", text))
    except ValueError:
        return False
    return True
