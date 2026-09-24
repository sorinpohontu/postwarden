"""PyMilter callbacks: translate Postfix metadata into policy inputs and decisions into SMTP replies."""
from __future__ import annotations

import os
import threading
import time
import uuid

import Milter

from .addresses import AddressError, Mailbox, parse_envelope
from .config import Settings
from .logging import EventLogger
from .message import MessageCapture
from .policy import (Action, ConnectionFacts, Decision, RecipientState, TransactionState, TrustClass,
                     classify_trust, combine, evaluate_authentication, evaluate_recipient,
                     evaluate_self_sender_header, evaluate_visible_from, requires_authentication,
                     spf_decides)

P_HDR_LEADSPC = getattr(Milter, "P_HDR_LEADSPC", 0x100000)
SPOOL_DIR = "/var/lib/postwarden"

_settings: Settings
_log: EventLogger
_verify_slots: threading.BoundedSemaphore
_open_slots: threading.BoundedSemaphore
authenticator = None


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


class PolicyMilter(Milter.Base):
    def __init__(self):
        self.cid = uuid.uuid4().hex[:12]
        self.peer_ip: str | None = None
        self.helo: str = ""
        self.leadspc = False
        self.facts = ConnectionFacts(None, None, None)
        self.trust = TrustClass.UNTRUSTED
        self.state = TransactionState()
        self.capture: MessageCapture | None = None
        self.mid: str | None = None
        self.started = 0.0
        self.holds_slot = False

    # -- helpers -------------------------------------------------------------

    def _reset_message(self) -> None:
        if self.capture is not None:
            self.capture.close()
        self.capture = None
        if self.holds_slot:
            _open_slots.release()
            self.holds_slot = False
        self.state = TransactionState()
        self.mid = None

    def _sender_field(self) -> str:
        return "<>" if self.state.null_sender else (self.state.raw_sender or "")

    def _refuse_recipient(self, decision: Decision, recipient: Mailbox | None, recorded: bool = False, **fields) -> int:
        """Apply a recipient decision; non-SMTP callbacks cannot refuse at RCPT, so pickup waits for EOM."""
        if not recorded:
            self.state.recipients.append(RecipientState(recipient, decision))
        if decision.action is not Action.ALLOW and self.trust is TrustClass.LOCAL_PICKUP:
            self.state.deferred_rejections.append(decision)
            _log.info(action="pending_eom", stage="rcpt", rule=decision.rule, reason=decision.reason,
                      **fields, **self._base_fields())
            return Milter.CONTINUE
        return self._apply(decision, "rcpt", sender=self._sender_field(), **fields)

    def _base_fields(self) -> dict:
        return {
            "cid": self.cid, "mid": self.mid, "queue_id": self.getsymval("i"),
            "ingress": self.facts.ingress.value, "trust": self.trust.value,
            "peer": self.peer_ip, "port": self.facts.daemon_port,
            "sasl": self.facts.auth_authen if self.facts.authenticated else None,
        }

    def _apply(self, decision: Decision, stage: str, **extra) -> int:
        """Log the decision and turn it into a milter action according to mode."""
        fields = self._base_fields()
        fields.update(stage=stage, rule=decision.rule, reason=decision.reason, **extra)
        if decision.action is Action.ALLOW:
            _log.debug(action="allow", **fields)
            return Milter.CONTINUE
        reply = (decision.reply or _settings.reply("temporary_failure")).with_reference(self.mid)
        if _settings.mode != "enforce":
            _log.info(action=f"would_{decision.action.value}", reply=reply.render(), **fields)
            return Milter.CONTINUE
        _log.info(action=decision.action.value, reply=reply.render(), **fields)
        self.setreply(str(reply.smtp_code), reply.enhanced_code, reply.message)
        return Milter.REJECT if decision.action is Action.REJECT else Milter.TEMPFAIL

    def _refresh_facts(self) -> None:
        self.facts = ConnectionFacts(
            peer_ip=self.peer_ip,
            daemon_port=_int(self.getsymval("{daemon_port}")),
            daemon_addr=self.getsymval("{daemon_addr}") or None,
            ingress_marker=self.getsymval("{postwarden_ingress}"),
            auth_type=self.getsymval("{auth_type}") or None,
            auth_authen=self.getsymval("{auth_authen}") or None,
            cipher_bits=_int(self.getsymval("{cipher_bits}")),
        )
        self.trust = classify_trust(_settings, self.facts)

    # -- callbacks -----------------------------------------------------------

    def negotiate(self, opts):
        offered = opts[1]
        rc = super().negotiate(opts)
        self.leadspc = bool(offered & P_HDR_LEADSPC)
        if self.leadspc:
            opts[1] |= P_HDR_LEADSPC
        return rc

    def connect(self, hostname, family, hostaddr):
        self.peer_ip = hostaddr[0] if hostaddr else None
        self._refresh_facts()
        _log.debug(stage="connect", **self._base_fields())
        return Milter.CONTINUE

    def hello(self, hostname):
        self.helo = hostname or ""
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *args):
        self._reset_message()
        self.mid = uuid.uuid4().hex[:12]
        self.started = time.monotonic()
        self._refresh_facts()
        raw = (mailfrom or "").strip().removeprefix("<").removesuffix(">")
        try:
            sender = parse_envelope(mailfrom)
            null_sender = sender is None
        except AddressError as exc:
            _log.warning(stage="mail", event="sender_unparseable", detail=str(exc), **self._base_fields())
            sender, null_sender = None, False
        self.state = TransactionState(sender=sender, null_sender=null_sender, raw_sender=None if null_sender else raw)
        if not _open_slots.acquire(blocking=False):
            decision = Decision(Action.DEFER, "limits", "max_open_messages", _settings.reply("temporary_failure"))
            if self.trust is TrustClass.LOCAL_PICKUP:
                self.state.deferred_rejections.append(decision)
                return Milter.CONTINUE
            return self._apply(decision, "mail", sender=self._sender_field())
        self.holds_slot = True
        self.capture = MessageCapture(_settings.limits, SPOOL_DIR if os.path.isdir(SPOOL_DIR) else None, self.leadspc)
        return Milter.CONTINUE

    def envrcpt(self, to, *args):
        if len(self.state.recipients) >= _settings.limits.max_recipients:
            decision = Decision(Action.DEFER, "limits", "max_recipients", _settings.reply("temporary_failure"))
            self.state.overflow_rcpts += 1
            if self.trust is TrustClass.LOCAL_PICKUP:
                if self.state.overflow_rcpts == 1:
                    self.state.deferred_rejections.append(decision)
                    _log.info(action="pending_eom", stage="rcpt", rule=decision.rule, reason=decision.reason,
                              **self._base_fields())
                return Milter.CONTINUE
            return self._apply(decision, "rcpt", rcpt=str(to))
        try:
            recipient = parse_envelope(to)
            if recipient is None:
                raise AddressError("empty recipient")
        except AddressError as exc:
            decision = Decision(Action.REJECT, "invalid_recipient", "recipient_unparseable",
                                _settings.reply("invalid_recipient"))
            return self._refuse_recipient(decision, None, detail=str(exc))
        transport = self.getsymval("{rcpt_mailer}") or None
        decision = evaluate_recipient(_settings, self.facts, self.trust, self.state, recipient, transport)
        return self._refuse_recipient(decision, recipient, recorded=True, rcpt=str(recipient), transport=transport)

    def header(self, name, hval):
        if self.capture is not None:
            self.capture.add_header(_bytes(name), _bytes(hval))
        return Milter.CONTINUE

    def eoh(self):
        return Milter.CONTINUE

    def body(self, chunk):
        if self.capture is not None:
            self.capture.add_body(chunk)
        return Milter.CONTINUE

    def eom(self):
        try:
            return self._eom()
        finally:
            self._reset_message()

    def _eom(self) -> int:
        capture = self.capture
        if capture is None:
            if not self.state.deferred_rejections:
                return Milter.CONTINUE
            return self._apply(combine(list(self.state.deferred_rejections)), "eom", sender=self._sender_field())
        fields = dict(sender=self._sender_field(), rcpts=len(self.state.recipients) + self.state.overflow_rcpts)
        for action, key in ((Action.REJECT, "rejected_rcpts"), (Action.DEFER, "deferred_rcpts")):
            count = sum(1 for r in self.state.recipients if r.decision is not None and r.decision.action is action)
            count += self.state.overflow_rcpts if action is Action.DEFER else 0
            if count:
                fields[key] = count
        decisions: list[Decision | None] = list(self.state.deferred_rejections)

        headers_complete = capture.over_limit not in ("max_headers", "max_header_bytes")
        header_from = None
        if headers_complete:
            from_values = [v.decode("utf-8", "surrogateescape") for v in capture.header_values(b"From")]
            header_from, from_decision = evaluate_visible_from(_settings, self.trust, from_values)
            decisions.append(from_decision)
        if header_from is not None:
            decisions.append(evaluate_self_sender_header(_settings, self.facts, self.trust, header_from,
                                                         self.state.accepted_recipients()))
            fields["from_domain"] = header_from.domain

        if capture.over_limit:
            decisions.append(Decision(Action.DEFER, "limits", capture.over_limit, _settings.reply("temporary_failure")))
        elif (requires_authentication(_settings, self.trust) and header_from is not None
              and not any(d is not None and d.action is Action.REJECT for d in decisions)):
            decisions.append(self._authenticate(capture, header_from, fields))

        if not any(d is not None for d in decisions):
            decisions.append(Decision.allow("trust", f"exempt_{self.trust.value}"))
        final = combine(decisions)
        fields["elapsed"] = f"{time.monotonic() - self.started:.3f}"
        rc = self._apply(final, "eom", **fields)
        if final.action is Action.ALLOW:
            _log.info(action="accept", stage="eom", rule=final.rule, reason=final.reason, **self._base_fields(), **fields)
        return rc

    def _authenticate(self, capture: MessageCapture, header_from: Mailbox, fields: dict) -> Decision:
        global authenticator
        if authenticator is None:
            from .authentication import authenticate as authenticator
        started = time.monotonic()
        deadline = started + _settings.limits.authentication_deadline_seconds
        if not _verify_slots.acquire(timeout=_settings.limits.authentication_deadline_seconds):
            fields["auth_elapsed"] = f"{time.monotonic() - started:.3f}"
            return Decision(Action.DEFER, "limits", "max_concurrent_messages", _settings.reply("temporary_failure"))
        try:
            message = capture.message_bytes()
            result = authenticator(self.peer_ip or "", self.helo, self.state.raw_sender,
                                   message, capture.header_values(b"DKIM-Signature"), _settings.limits, deadline=deadline,
                                   skip_dkim=lambda spf: spf_decides(_settings, header_from.domain, spf,
                                                                     self.state.null_sender))
        finally:
            _verify_slots.release()
            fields["auth_elapsed"] = f"{time.monotonic() - started:.3f}"
        fields["spf"] = result.spf.result or result.spf.status.value
        fields["spf_domain"] = result.spf.domain
        fields["dkim"] = "skipped" if result.dkim_skipped else (
            ",".join(f"{o.domain or '-'}:{o.status.value}" for o in result.dkim) or "none")
        return evaluate_authentication(_settings, self.trust, header_from.domain, result,
                                       null_sender=self.state.null_sender)

    def abort(self):
        if self.mid:
            _log.debug(stage="abort", **self._base_fields())
        self._reset_message()
        return Milter.CONTINUE

    def close(self):
        self._reset_message()
        return Milter.CONTINUE


def _bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", "surrogateescape")


def configure(settings: Settings, logger: EventLogger | None = None) -> None:
    global _settings, _log, _verify_slots, _open_slots
    _settings = settings
    _log = logger or EventLogger(settings.logging)
    _verify_slots = threading.BoundedSemaphore(settings.limits.max_concurrent_messages)
    _open_slots = threading.BoundedSemaphore(settings.limits.max_open_messages)


def run_daemon(settings: Settings) -> int:
    configure(settings)
    socket = settings.service.socket
    if socket.startswith("unix:"):
        path = socket[5:]
        if os.path.exists(path):
            os.unlink(path)
    os.umask(0o007)
    Milter.factory = PolicyMilter
    Milter.set_flags(0)
    Milter.set_exception_policy(Milter.TEMPFAIL)
    addresses, groups = settings.protection.counts()
    _log.lifecycle(event="start", mode=settings.mode, socket=socket, config=settings.source,
                   protected_addresses=addresses, protected_groups=groups, mynetworks=len(settings.trust.mynetworks),
                   recipient_delimiter=settings.trust.recipient_delimiter)
    try:
        Milter.runmilter(settings.logging.identifier, socket, int(settings.limits.authentication_deadline_seconds) + 40)
    finally:
        _log.lifecycle(event="stop")
    return 0
