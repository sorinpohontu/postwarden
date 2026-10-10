"""PyMilter callbacks: translate Postfix metadata into policy inputs and decisions into SMTP replies."""
from __future__ import annotations

import contextlib
import os
import threading
import time
import uuid

import Milter

from .addresses import AddressError, Mailbox, parse_envelope
from .config import Settings
from . import limitstate
from .logging import EventLogger
from .message import MessageCapture
from .policy import (Action, ConnectionFacts, Decision, TransactionState, TrustClass, classify_trust, dkim_fields,
                     effective, enforced, evaluate_authentication, evaluate_message, evaluate_recipient, mode_of,
                     needs_message, skip_dkim)
from .quota import KEY_STORE_FULL, LimitKey, QuotaStore, Reservation, limit_key

P_HDR_LEADSPC = getattr(Milter, "P_HDR_LEADSPC", 0x100000)
SPOOL_DIR = "/var/lib/postwarden"

_settings: Settings
_log: EventLogger
_verify_slots: threading.BoundedSemaphore | None
_dkim_workers: threading.BoundedSemaphore
_open_slots: threading.BoundedSemaphore | None
_quota: QuotaStore | None = None
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
        self.limit_key: LimitKey | None = None
        self.reservation: Reservation | None = None

    # -- helpers -------------------------------------------------------------

    def _reset_message(self) -> None:
        if self.capture is not None:
            self.capture.close()
        self.capture = None
        if self.holds_slot:
            _open_slots.release()
            self.holds_slot = False
        if self.reservation is not None and _quota is not None:
            _quota.release(self.reservation)
        self.reservation = None
        self.limit_key = None
        self.state = TransactionState()
        self.mid = None

    def _sender_field(self) -> str:
        return "<>" if self.state.null_sender else (self.state.raw_sender or "")

    def _refuse_recipient(self, decision: Decision, **fields) -> int:
        """Apply a recipient decision; non-SMTP callbacks cannot refuse at RCPT, so pickup waits for EOM."""
        if decision.action is not Action.ALLOW and self.trust is TrustClass.LOCAL_PICKUP:
            if decision.reason == "max_recipients" and decision in self.state.deferred_rejections:
                return Milter.CONTINUE
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
        mode = mode_of(_settings, decision)
        if mode == "off":
            return Milter.CONTINUE
        reply = (decision.reply or _settings.reply("temporary_failure")).with_reference(self.mid)
        if mode != "enforce":
            _log.info(action=f"would_{decision.action.value}", reply=reply.render(), **fields)
            return Milter.CONTINUE
        _log.info(action=decision.action.value, reply=reply.render(), **fields)
        self.setreply(str(reply.smtp_code), reply.enhanced_code, reply.message)
        return Milter.REJECT if decision.action is Action.REJECT else Milter.TEMPFAIL

    def _limit_fields(self) -> dict:
        if self.limit_key is None:
            return {}
        if _quota is None:
            measured = "off"
        else:
            measured = "yes" if self.reservation is None or self.reservation.measured else "no"
        return {"limit_key": self.limit_key.text, "limit_measured": measured}

    def _reserve(self, decision: Decision) -> Decision:
        """Take one sending-limit reservation for a recipient Postfix accepts; an enforced refusal takes none."""
        if self.reservation is None or _quota is None or enforced(_settings, decision):
            return decision
        verdict = _quota.reserve(self.reservation, time.time(), observe=not _limits_enforced())
        if verdict is None:
            return decision
        key = self.limit_key
        if verdict.first:
            if verdict.reason == KEY_STORE_FULL:
                _log.warning(event="key_store_full", rule="sending_limit", keys=_quota.capacity,
                             limit_key=key.text, **self._base_fields())
            else:
                limit = {"per_hour": key.per_hour, "per_day": key.per_day,
                         "local_per_hour": _settings.sending_limits.local_per_hour,
                         "local_per_day": _settings.sending_limits.local_per_day}[verdict.reason]
                _log.warning(event="limit_reached", rule="sending_limit", reason=verdict.reason, limit=limit,
                             limit_key=key.text, **self._base_fields())
        return effective(_settings, [decision, Decision(Action.DEFER, "sending_limit", verdict.reason,
                                                        _settings.reply("sending_limit"))])

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
        self.limit_key = limit_key(_settings.sending_limits, self.trust.value, login=self.facts.auth_authen,
                                   sender=sender, null_sender=null_sender, raw_sender=raw, peer_ip=self.peer_ip)
        if self.limit_key is not None and _quota is not None:
            self.reservation = _quota.begin(self.limit_key)
        if _open_slots is not None and not _open_slots.acquire(blocking=False):
            decision = Decision(Action.DEFER, "limits", "max_open_messages", _settings.reply("temporary_failure"),
                                needs_message(_settings, self.facts, self.trust))
            if self.trust is TrustClass.LOCAL_PICKUP or not enforced(_settings, decision):
                self.state.deferred_rejections.append(decision)
            if self.trust is TrustClass.LOCAL_PICKUP:
                return Milter.CONTINUE
            return self._apply(decision, "mail", sender=self._sender_field(), **self._limit_fields())
        self.holds_slot = _open_slots is not None
        self.capture = MessageCapture(_settings.limits, SPOOL_DIR if os.path.isdir(SPOOL_DIR) else None, self.leadspc)
        return Milter.CONTINUE

    def envrcpt(self, to, *args):
        transport = self.getsymval("{rcpt_mailer}") or None
        recipient, decision = evaluate_recipient(_settings, self.facts, self.trust, self.state, to, transport)
        if recipient is None:
            return self._refuse_recipient(decision, rcpt=str(to))
        limited = self._reserve(decision)
        if limited is not decision:
            self.state.recipients[-1].decision = limited
            return self._refuse_recipient(limited, rcpt=str(recipient), transport=transport,
                                          limit_key=self.limit_key.text)
        return self._refuse_recipient(decision, rcpt=str(recipient), transport=transport)

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
        overflow = self.state.refused_overflow()
        fields = dict(sender=self._sender_field(), rcpts=len(self.state.recipients) + len(overflow))
        fields.update(self._limit_fields())
        refused = [r.decision for r in self.state.recipients if r.decision is not None
                   and r.decision.action is not Action.ALLOW and mode_of(_settings, r.decision) != "off"] + overflow
        for action, key in ((Action.REJECT, "rejected_rcpts"), (Action.DEFER, "deferred_rcpts")):
            sent = sum(1 for d in refused if d.action is action and enforced(_settings, d))
            hypothetical = sum(1 for d in refused if d.action is action and not enforced(_settings, d))
            if sent:
                fields[key] = sent
            if hypothetical:
                fields[f"would_{key}"] = hypothetical
        if capture is None:
            final = effective(_settings, list(self.state.deferred_rejections))
        else:
            headers_complete = capture.over_limit not in ("max_headers", "max_header_bytes")
            from_values = ([v.decode("utf-8", "surrogateescape") for v in capture.header_values(b"From")]
                           if headers_complete else None)
            decisions, header_from = evaluate_message(_settings, self.facts, self.trust, self.state, from_values,
                                                      capture.over_limit,
                                                      lambda sender_from: self._authenticate(capture, sender_from,
                                                                                             fields))
            if header_from is not None:
                fields["from_domain"] = header_from.domain
            final = effective(_settings, decisions)
        fields["elapsed"] = f"{time.monotonic() - self.started:.3f}"
        rc = self._apply(final, "eom", **fields)
        if self.reservation is not None and not enforced(_settings, final):
            _quota.commit(self.reservation, time.time())
        if final.action is Action.ALLOW:
            _log.info(action="accept", stage="eom", rule=final.rule, reason=final.reason, **self._base_fields(), **fields)
        return rc

    def _authenticate(self, capture: MessageCapture, header_from: Mailbox, fields: dict) -> Decision:
        global authenticator
        if authenticator is None:
            from .authentication import authenticate as authenticator
        started = time.monotonic()
        deadline = started + _settings.limits.authentication_deadline_seconds
        waited = _settings.limits.authentication_deadline_seconds
        if _verify_slots is not None and not _verify_slots.acquire(timeout=waited):
            fields["auth_elapsed"] = f"{time.monotonic() - started:.3f}"
            return Decision(Action.DEFER, "limits", "max_concurrent_messages", _settings.reply("temporary_failure"),
                            _settings.sender_authentication.mode == "enforce")
        try:
            result = authenticator(self.peer_ip or "", self.helo, self.state.raw_sender,
                                   capture, capture.header_values(b"DKIM-Signature"), _settings.limits,
                                   deadline=deadline,
                                   skip_dkim=lambda spf: skip_dkim(_settings, header_from.domain, spf,
                                                                   self.state.null_sender),
                                   workers=_dkim_workers)
        finally:
            if _verify_slots is not None:
                _verify_slots.release()
            fields["auth_elapsed"] = f"{time.monotonic() - started:.3f}"
        fields["spf"] = result.spf.result or result.spf.status.value
        fields["spf_domain"] = result.spf.domain
        fields.update(dkim_fields(_settings, result))
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


def _limits_enforced() -> bool:
    return _settings.sending_limits.mode == "enforce"


def _bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", "surrogateescape")


def configure(settings: Settings, logger: EventLogger | None = None, quota: QuotaStore | None = None) -> None:
    global _settings, _log, _verify_slots, _dkim_workers, _open_slots, _quota
    _settings = settings
    if settings.sending_limits.mode == "off":
        _quota = None
    else:
        _quota = quota if quota is not None else QuotaStore(settings.sending_limits)
    _log = logger or EventLogger(settings.logging)
    bounded = settings.limits.bounded
    _verify_slots = threading.BoundedSemaphore(settings.limits.max_concurrent_messages) if bounded else None
    _dkim_workers = threading.BoundedSemaphore(settings.limits.dkim_workers)
    _open_slots = threading.BoundedSemaphore(settings.limits.max_open_messages) if bounded else None


def _stage_loaded(loaded: str, digest: str) -> None:
    pending = loaded + ".pending"
    with contextlib.suppress(FileNotFoundError):
        os.unlink(loaded)
    tmp = f"{pending}.{os.getpid()}"
    with open(tmp, "w") as fh:
        fh.write(digest + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, pending)


def run_daemon(settings: Settings, loaded: str | None = None) -> int:
    """loaded: where `wait-ready` publishes the hash of the configuration this daemon runs, once it accepts."""
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
    state = limitstate.LoadResult("off") if _quota is None else limitstate.load(_quota, limitstate.STATE_FILE)
    _log.lifecycle(event="start", **{f"{section}_mode": mode for section, mode in settings.section_modes().items()},
                   failure_action=settings.failure_action(),
                   dkim_diagnostics="on" if settings.sender_authentication.dkim_diagnostics else "off",
                   logging_level=settings.logging.level, socket=socket, config=settings.source,
                   protected_addresses=addresses, protected_groups=groups, mynetworks=len(settings.trust.mynetworks),
                   recipient_delimiter=settings.trust.recipient_delimiter,
                   limit_state=state.status, limit_keys=state.keys if _quota is not None else None,
                   limit_state_age=state.age)
    saver = None
    if _quota is not None:
        if state.status != "loaded":
            _log.warning(event="limit_state_empty", reason=state.status, detail=state.detail, path=limitstate.STATE_FILE)
        last_saved = time.time() - state.age if state.age is not None else None
        saver = limitstate.Saver(_quota, _save_failed, limitstate.STATE_FILE, last_saved=last_saved)
        saver.start()
    if loaded is not None:
        _stage_loaded(loaded, settings.sha256)
    try:
        Milter.runmilter(settings.logging.identifier, socket, int(settings.limits.authentication_deadline_seconds) + 40)
    finally:
        saved = None if saver is None else ("saved" if saver.stop() else "failed")
        _log.lifecycle(event="stop", limit_state=saved)
    return 0


def _save_failed(detail: str, age: int | None) -> None:
    _log.warning(event="limit_state_save_failed", detail=detail, snapshot_age=age, path=limitstate.STATE_FILE)
