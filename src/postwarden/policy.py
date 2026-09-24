"""Pure policy evaluation. No I/O, no milter or DNS imports; every input arrives as data."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum

from .addresses import AddressError, Mailbox, parse_from_header
from .config import Settings
from .replies import Reply


class Ingress(Enum):
    SMTP25 = "SMTP25"
    SUBMISSION587 = "SUBMISSION587"
    SUBMISSION465 = "SUBMISSION465"
    LOCAL_PICKUP = "LOCAL_PICKUP"
    UNCLASSIFIED = "UNCLASSIFIED"

    @property
    def is_submission(self) -> bool:
        return self in (Ingress.SUBMISSION587, Ingress.SUBMISSION465)

    def matches_port(self, port: int | None) -> bool:
        return port == {"SMTP25": 25, "SUBMISSION587": 587, "SUBMISSION465": 465}.get(self.value)


class TrustClass(Enum):
    LOCAL_PICKUP = "local_pickup"
    LOCAL_SMTP = "local_smtp"
    AUTHENTICATED_SUBMISSION = "authenticated_submission"
    MYNETWORKS = "mynetworks"
    UNTRUSTED = "untrusted"


class Action(Enum):
    ALLOW = "allow"
    REJECT = "reject"
    DEFER = "defer"


@dataclass(frozen=True, slots=True)
class Decision:
    action: Action
    rule: str
    reason: str
    reply: Reply | None = None

    @staticmethod
    def allow(rule: str, reason: str) -> "Decision":
        return Decision(Action.ALLOW, rule, reason)


@dataclass(frozen=True, slots=True)
class ConnectionFacts:
    """Postfix-supplied metadata for one connection/transaction. Header content never enters here."""
    peer_ip: str | None
    daemon_port: int | None
    ingress_marker: str | None
    daemon_addr: str | None = None
    auth_type: str | None = None
    auth_authen: str | None = None
    cipher_bits: int | None = None

    @property
    def ingress(self) -> Ingress:
        try:
            return Ingress(self.ingress_marker or "")
        except ValueError:
            return Ingress.UNCLASSIFIED

    @property
    def authenticated(self) -> bool:
        return bool(self.auth_authen) and bool(self.auth_type)

    @property
    def tls(self) -> bool:
        return bool(self.cipher_bits)


def _in_networks(peer_ip: str | None, networks) -> bool:
    if not peer_ip or not networks:
        return False
    try:
        address = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        candidates = (address, address.ipv4_mapped)
    else:
        candidates = (address,)
    return any(c.version == n.version and c in n for c in candidates for n in networks)


def _same_host(peer_ip: str | None, daemon_addr: str | None) -> bool:
    """Loopback, or a client using the server address it connected to: only this host can do that."""
    peer = _address(peer_ip)
    if peer is None:
        return False
    return peer.is_loopback or peer == _address(daemon_addr)


def _address(text: str | None):
    try:
        address = ipaddress.ip_address((text or "").removeprefix("IPv6:"))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def classify_trust(settings: Settings, facts: ConnectionFacts) -> TrustClass:
    """Ingress marker and peer address decide; nothing derived from message headers or reverse DNS."""
    ingress = facts.ingress
    if ingress is Ingress.LOCAL_PICKUP:
        return TrustClass.LOCAL_PICKUP
    if ingress.is_submission and facts.authenticated and ingress.matches_port(facts.daemon_port):
        return TrustClass.AUTHENTICATED_SUBMISSION
    if ingress is Ingress.SMTP25 and _same_host(facts.peer_ip, facts.daemon_addr):
        return TrustClass.LOCAL_SMTP
    if ingress in (Ingress.SMTP25, Ingress.SUBMISSION587, Ingress.SUBMISSION465) and _in_networks(facts.peer_ip, settings.trust.mynetworks):
        return TrustClass.MYNETWORKS
    return TrustClass.UNTRUSTED


def evaluate_protected_recipient(settings: Settings, facts: ConnectionFacts, sender: Mailbox | None,
                                 recipient: Mailbox, transport: str | None = None) -> Decision | None:
    """None when the recipient is not protected; otherwise the definitive decision for this recipient."""
    protected, logins = settings.protection.lookup(
        recipient.without_extension(settings.trust.recipient_delimiter), transport)
    if not protected:
        return None
    rule = "protected_recipient"
    reply = settings.reply(rule)
    ingress = facts.ingress
    if ingress is Ingress.UNCLASSIFIED:
        return Decision(Action.DEFER, rule, "ingress_unclassified", settings.reply("temporary_failure"))
    if not ingress.is_submission:
        return Decision(Action.REJECT, rule, f"ingress_{ingress.value.lower()}", reply)
    if not ingress.matches_port(facts.daemon_port):
        return Decision(Action.REJECT, rule, "port_not_allowed", reply)
    if not facts.tls:
        return Decision(Action.REJECT, rule, "tls_required", reply)
    if not facts.authenticated:
        return Decision(Action.REJECT, rule, "not_authenticated", reply)
    if not logins:
        return Decision(Action.REJECT, rule, "no_authorized_logins", reply)
    if facts.auth_authen not in logins:
        return Decision(Action.REJECT, rule, "login_not_authorized", reply)
    if sender is None or sender.exact_key != facts.auth_authen:
        return Decision(Action.REJECT, rule, "sender_login_mismatch", reply)
    return Decision.allow(rule, "authorized")


def _self_sender_applies(settings: Settings, facts: ConnectionFacts, trust: TrustClass) -> bool:
    ss = settings.self_sender
    if not ss.enabled or trust is TrustClass.LOCAL_PICKUP:
        return False
    if facts.daemon_port != 25:
        return False
    if ss.allow_mynetworks and trust in (TrustClass.MYNETWORKS, TrustClass.LOCAL_SMTP):
        return False
    return True


def evaluate_self_sender_envelope(settings: Settings, facts: ConnectionFacts, trust: TrustClass,
                                  sender: Mailbox | None, recipient: Mailbox) -> Decision | None:
    if sender is None or not _self_sender_applies(settings, facts, trust):
        return None
    if settings.self_sender.identity == "header_from":
        return None
    if sender.lookup_key != recipient.lookup_key:
        return None
    if sender.lookup_key in settings.self_sender.allow_senders:
        return Decision.allow("self_sender", "envelope_allowlisted")
    return Decision(Action.REJECT, "self_sender", "envelope_matches_recipient", settings.reply("self_sender"))


def evaluate_self_sender_header(settings: Settings, facts: ConnectionFacts, trust: TrustClass,
                                header_from: Mailbox, recipients: list[Mailbox]) -> Decision | None:
    if not _self_sender_applies(settings, facts, trust) or settings.self_sender.identity == "envelope":
        return None
    keys = {r.lookup_key for r in recipients}
    if header_from.lookup_key not in keys:
        return None
    if header_from.lookup_key in settings.self_sender.allow_senders:
        return Decision.allow("self_sender", "header_allowlisted")
    return Decision(Action.REJECT, "self_sender", "header_from_matches_recipient", settings.reply("self_sender"))


def requires_authentication(settings: Settings, trust: TrustClass) -> bool:
    """Whether SPF/DKIM must prove the sender domain for this trust class."""
    sa = settings.sender_authentication
    if trust in (TrustClass.LOCAL_PICKUP, TrustClass.LOCAL_SMTP):
        return not sa.allow_local
    if trust is TrustClass.MYNETWORKS:
        return not sa.allow_mynetworks
    return trust is TrustClass.UNTRUSTED


def evaluate_visible_from(settings: Settings, trust: TrustClass, from_values: list[str]) -> tuple[Mailbox | None, Decision | None]:
    """Mail that must authenticate needs exactly one valid From mailbox; exempt mail tolerates a missing From."""
    try:
        return parse_from_header(from_values), None
    except AddressError as exc:
        if not requires_authentication(settings, trust):
            return None, None
        return None, Decision(Action.REJECT, "invalid_from", str(exc), settings.reply("invalid_from"))


class AuthStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    TEMPERROR = "temperror"


@dataclass(frozen=True, slots=True)
class SpfOutcome:
    status: AuthStatus
    domain: str | None
    result: str = ""


@dataclass(frozen=True, slots=True)
class DkimOutcome:
    status: AuthStatus
    domain: str | None
    partial_body: bool = False
    detail: str = ""


@dataclass(frozen=True, slots=True)
class AuthenticationInput:
    spf: SpfOutcome
    dkim: tuple[DkimOutcome, ...] = ()
    incomplete: bool = False
    dkim_skipped: bool = False


def spf_decides(settings: Settings, from_domain: str, spf: SpfOutcome, null_sender: bool = False) -> bool:
    """True when the SPF result alone settles the outcome, so DKIM need not be verified:
    a definitive failure when both are required, an aligned pass when either suffices."""
    aligned_pass = spf.status is AuthStatus.PASS and spf.domain == from_domain
    if settings.sender_authentication.require == "either":
        return aligned_pass
    if null_sender and settings.sender_authentication.null_sender == "dkim_aligned":
        return False
    return spf.status is AuthStatus.FAIL or (spf.status is AuthStatus.PASS and not aligned_pass)


def evaluate_authentication(settings: Settings, trust: TrustClass, from_domain: str,
                            auth: AuthenticationInput, null_sender: bool = False) -> Decision:
    """Both mechanisms must pass with exact From-domain alignment; temporary errors defer, never rescue.

    Null-sender mail (bounces) may instead rely on an aligned DKIM pass alone."""
    rule = "authentication"
    if not requires_authentication(settings, trust):
        return Decision.allow(rule, f"exempt_{trust.value}")

    spf_pass = auth.spf.status is AuthStatus.PASS and auth.spf.domain == from_domain
    spf_temp = auth.spf.status is AuthStatus.TEMPERROR
    dkim_pass = any(s.status is AuthStatus.PASS and s.domain == from_domain and not s.partial_body for s in auth.dkim)
    dkim_temp = any(s.status is AuthStatus.TEMPERROR for s in auth.dkim)
    if settings.sender_authentication.require == "either":
        if spf_pass:
            return Decision.allow(rule, "spf_aligned")
        if dkim_pass:
            return Decision.allow(rule, "dkim_aligned")
        if spf_temp or dkim_temp or auth.incomplete:
            reason = "evaluation_incomplete" if auth.incomplete else "spf_temperror" if spf_temp else "dkim_temperror"
            return Decision(Action.DEFER, rule, reason, settings.reply("temporary_failure"))
        return Decision(Action.REJECT, rule, "no_aligned_pass", settings.reply("authentication_failed"))
    if auth.incomplete and not dkim_pass:
        return Decision(Action.DEFER, rule, "evaluation_incomplete", settings.reply("temporary_failure"))

    if null_sender and settings.sender_authentication.null_sender == "dkim_aligned":
        if dkim_pass:
            return Decision.allow(rule, "null_sender_dkim_aligned")
        if dkim_temp:
            return Decision(Action.DEFER, rule, "dkim_temperror", settings.reply("temporary_failure"))
        reason = "dkim_absent" if not auth.dkim else "dkim_no_aligned_pass"
        return Decision(Action.REJECT, rule, reason, settings.reply("authentication_failed"))

    if auth.spf.status is AuthStatus.FAIL or (auth.spf.status is AuthStatus.PASS and not spf_pass):
        reason = "spf_" + (auth.spf.result or "fail") if auth.spf.status is AuthStatus.FAIL else "spf_unaligned"
        return Decision(Action.REJECT, rule, reason, settings.reply("authentication_failed"))
    if not dkim_pass and not dkim_temp:
        reason = "dkim_absent" if not auth.dkim else "dkim_no_aligned_pass"
        return Decision(Action.REJECT, rule, reason, settings.reply("authentication_failed"))
    if spf_temp or not dkim_pass:
        return Decision(Action.DEFER, rule, "spf_temperror" if spf_temp else "dkim_temperror",
                        settings.reply("temporary_failure"))
    return Decision.allow(rule, "spf_and_dkim_aligned")


@dataclass(slots=True)
class RecipientState:
    original: Mailbox | None
    decision: Decision | None


@dataclass(slots=True)
class TransactionState:
    """Per-message accumulation shared by the callback layer; reset on MAIL, abort and end of message.

    `sender` is None both for the null reverse path and for an unparseable sender; only `null_sender`
    marks a real `MAIL FROM:<>`. `raw_sender` is what SPF evaluates."""
    sender: Mailbox | None = None
    null_sender: bool = False
    raw_sender: str | None = None
    recipients: list[RecipientState] = field(default_factory=list)
    overflow_rcpts: int = 0
    deferred_rejections: list[Decision] = field(default_factory=list)

    def accepted_recipients(self) -> list[Mailbox]:
        return [r.original for r in self.recipients
                if r.original is not None and (r.decision is None or r.decision.action is Action.ALLOW)]


def evaluate_recipient(settings: Settings, facts: ConnectionFacts, trust: TrustClass,
                       state: TransactionState, recipient: Mailbox, transport: str | None = None) -> Decision:
    """RCPT-stage composition: protected first, then self-sender; an allowance never cancels a rejection."""
    decisions = [
        evaluate_protected_recipient(settings, facts, state.sender, recipient, transport),
        evaluate_self_sender_envelope(settings, facts, trust, state.sender, recipient),
    ]
    final = combine(decisions)
    state.recipients.append(RecipientState(recipient, final))
    return final


def combine(decisions: list[Decision | None]) -> Decision:
    """Rejection outranks deferral outranks allowance."""
    present = [d for d in decisions if d is not None]
    for action in (Action.REJECT, Action.DEFER):
        for d in present:
            if d.action is action:
                return d
    return present[0] if present else Decision.allow("none", "no_rule_matched")
