"""TOML schema, validation and the immutable Settings tree. No runtime adapters are imported here."""
from __future__ import annotations

import ipaddress
import math
import tomllib
from dataclasses import dataclass, field, fields
from typing import Any

from . import DEFAULT_CONFIG_PATH
from .addresses import AddressError, Mailbox, parse_mailbox
from .replies import DEFAULT_REPLIES, Reply, validate_reply

SUPPORTED_SCHEMA_VERSIONS = (1,)
MODES = ("observe", "enforce")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ConfigError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass(frozen=True, slots=True)
class ServiceSettings:
    socket: str = "unix:/var/spool/postfix/postwarden/policy.sock"


@dataclass(frozen=True, slots=True)
class LoggingSettings:
    backend: str = "syslog"
    facility: str = "mail"
    identifier: str = "postwarden"
    level: str = "info"


@dataclass(frozen=True, slots=True)
class TrustSettings:
    mynetworks: tuple[Network, ...] = ()
    recipient_delimiter: str = ""


@dataclass(frozen=True, slots=True)
class SelfSenderSettings:
    enabled: bool = True
    identity: str = "envelope_or_header_from"
    allow_mynetworks: bool = True
    allow_senders: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class SenderAuthenticationSettings:
    require: str = "both"
    allow_local: bool = True
    allow_mynetworks: bool = True
    null_sender: str = "dkim_aligned"


@dataclass(frozen=True, slots=True)
class ProtectionSettings:
    remote_transports: frozenset[str] = frozenset({"smtp", "relay"})
    addresses: dict[str, frozenset[str]] = field(default_factory=dict)

    def lookup(self, recipient: Mailbox, transport: str | None) -> tuple[bool, frozenset[str]]:
        """(protected, authorized logins) for a recipient already stripped of its extension."""
        if recipient.lookup_key in self.addresses:
            return True, self.addresses[recipient.lookup_key]
        group = f"{recipient.local.lower()}@*"
        if group in self.addresses and transport not in self.remote_transports:
            return True, self.addresses[group]
        return False, frozenset()


@dataclass(frozen=True, slots=True)
class LimitSettings:
    message_bytes: int = 41943040
    max_signatures: int = 10
    max_headers: int = 1000
    max_header_bytes: int = 65536
    max_recipients: int = 1000
    dns_timeout_seconds: float = 5.0
    authentication_deadline_seconds: float = 20.0
    max_concurrent_messages: int = 32
    max_open_messages: int = 100


@dataclass(frozen=True, slots=True)
class Settings:
    schema_version: int = 1
    mode: str = "observe"
    service: ServiceSettings = ServiceSettings()
    logging: LoggingSettings = LoggingSettings()
    trust: TrustSettings = TrustSettings()
    self_sender: SelfSenderSettings = SelfSenderSettings()
    sender_authentication: SenderAuthenticationSettings = SenderAuthenticationSettings()
    protection: ProtectionSettings = ProtectionSettings()
    limits: LimitSettings = LimitSettings()
    responses: dict[str, Reply] = field(default_factory=lambda: dict(DEFAULT_REPLIES))
    source: str = ""

    def reply(self, name: str) -> Reply:
        return self.responses[name]


class _Validator:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, path: str, message: str) -> None:
        self.errors.append(f"{path}: {message}")

    def table(self, data: Any, path: str, allowed: dict[str, type | tuple[type, ...]]) -> dict[str, Any]:
        if not isinstance(data, dict):
            self.error(path, "must be a table")
            return {}
        for key in data:
            if key not in allowed:
                self.error(f"{path}.{key}" if path else key, "unknown key")
        clean: dict[str, Any] = {}
        for key, expected in allowed.items():
            if key not in data:
                continue
            value = data[key]
            if isinstance(value, bool) and expected is not bool and bool not in (expected if isinstance(expected, tuple) else (expected,)):
                self.error(f"{path}.{key}" if path else key, f"must be {self._name(expected)}")
                continue
            if not isinstance(value, expected):
                self.error(f"{path}.{key}" if path else key, f"must be {self._name(expected)}")
                continue
            clean[key] = value
        return clean

    @staticmethod
    def _name(expected: type | tuple[type, ...]) -> str:
        names = {int: "an integer", float: "a number", str: "a string", bool: "a boolean",
                 list: "an array", dict: "a table"}
        if isinstance(expected, tuple):
            return " or ".join(names.get(t, t.__name__) for t in expected)
        return names.get(expected, expected.__name__)

    def choice(self, value: str | None, path: str, choices: tuple[str, ...]) -> None:
        if value is not None and value not in choices:
            self.error(path, f"must be one of {', '.join(choices)}")

    def mailboxes(self, values: list | None, path: str) -> tuple[Mailbox, ...]:
        if values is None:
            return ()
        result = []
        for index, item in enumerate(values):
            if not isinstance(item, str):
                self.error(f"{path}[{index}]", "must be a string")
                continue
            try:
                result.append(parse_mailbox(item))
            except AddressError as exc:
                self.error(f"{path}[{index}]", str(exc))
        return result and tuple(result) or ()

    def strings(self, values: list | None, path: str) -> tuple[str, ...]:
        if values is None:
            return ()
        result = []
        for index, item in enumerate(values):
            if not isinstance(item, str) or not item.strip():
                self.error(f"{path}[{index}]", "must be a nonempty string")
                continue
            result.append(item.strip())
        return tuple(result)

    def positive(self, value: Any, path: str, default: float, *, integer: bool) -> Any:
        if value is None:
            return default
        if not math.isfinite(value):
            self.error(path, "must be a finite number")
            return default
        if value <= 0:
            self.error(path, "must be greater than zero")
            return default
        return int(value) if integer else float(value)


def parse_settings(data: dict[str, Any], source: str = "") -> Settings:
    """Validate a decoded TOML document and build Settings; raises ConfigError with every problem found."""
    v = _Validator()
    top = v.table(data, "", {
        "schema_version": int, "mode": str, "service": dict, "logging": dict, "trust": dict,
        "self_sender": dict, "authentication": dict, "sender_authentication": dict, "protection": dict, "protected_recipients": list,
        "limits": dict, "responses": dict,
    })

    schema_version = top.get("schema_version", 1)
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        v.error("schema_version", f"unsupported version {schema_version}; supported: {SUPPORTED_SCHEMA_VERSIONS}")
    mode = top.get("mode", "observe")
    v.choice(mode, "mode", MODES)

    if "service" in top:
        v.error("service", f"removed; the milter socket is fixed at {ServiceSettings().socket}")
    service = ServiceSettings()

    logging_data = top.get("logging", {})
    if isinstance(logging_data, dict):
        logging_data = dict(logging_data)
        for key in ("backend", "facility", "identifier"):
            if logging_data.pop(key, None) is not None:
                v.error(f"logging.{key}", "removed; postwarden logs to syslog (mail facility, tag postwarden); "
                                          "use `postwarden run --stderr` for foreground debugging")
    logging_t = v.table(logging_data, "logging", {"level": str})
    v.choice(logging_t.get("level"), "logging.level", ("debug", "info", "warning", "error"))
    logging_s = LoggingSettings(level=logging_t.get("level", LoggingSettings().level))

    if "trust" in top:
        v.error("trust", "removed; mynetworks and recipient_delimiter are read from Postfix at start, "
                         "same-server clients are detected automatically and the pickup marker is fixed")
    trust = TrustSettings()

    if "authentication" in top:
        v.error("authentication", "renamed to [sender_authentication]")
    for section, key in (("self_sender", "ports"), ("sender_authentication", "allow_authenticated_ports")):
        if isinstance(top.get(section), dict) and key in top[section]:
            top[section] = {k: val for k, val in top[section].items() if k != key}
            v.error(f"{section}.{key}", "removed; ports follow the Postfix services: self-sender checks apply "
                                        "to port 25, authenticated submission is 587 and 465")
    ss_t = v.table(top.get("self_sender", {}), "self_sender", {
        "enabled": bool, "identity": str, "allow_mynetworks": bool, "allow_senders": list})
    v.choice(ss_t.get("identity"), "self_sender.identity", ("envelope_or_header_from", "envelope", "header_from"))
    self_sender = SelfSenderSettings(
        enabled=ss_t.get("enabled", True),
        identity=ss_t.get("identity", SelfSenderSettings().identity),
        allow_mynetworks=ss_t.get("allow_mynetworks", True),
        allow_senders=frozenset(m.lookup_key for m in v.mailboxes(ss_t.get("allow_senders"), "self_sender.allow_senders")),
    )

    raw_auth = top.get("sender_authentication", {})
    if isinstance(raw_auth, dict):
        fixed = {"alignment": "SPF and DKIM must match the From domain exactly",
                 "temporary_error": "DNS and verifier trouble always defers"}
        for key in [k for k in raw_auth if k in fixed]:
            v.error(f"sender_authentication.{key}", f"removed; the rule is fixed: {fixed[key]}")
        raw_auth = {k: val for k, val in raw_auth.items() if k not in fixed}
    auth_t = v.table(raw_auth, "sender_authentication", {
        "require": str, "allow_local": bool, "allow_mynetworks": bool, "null_sender": str})
    v.choice(auth_t.get("require"), "sender_authentication.require", ("both", "either"))
    v.choice(auth_t.get("null_sender"), "sender_authentication.null_sender", ("dkim_aligned", "both"))
    sender_authentication = SenderAuthenticationSettings(
        require=auth_t.get("require", "both"),
        allow_local=auth_t.get("allow_local", True),
        allow_mynetworks=auth_t.get("allow_mynetworks", True),
        null_sender=auth_t.get("null_sender", "dkim_aligned"),
    )

    if "protected_recipients" in top:
        v.error("protected_recipients", "removed; configure protected addresses under [protection] (see docs/Configuration.md)")
    prot_t = v.table(top.get("protection", {}), "protection", {
        "remote_transports": list, "addresses": dict})
    addresses: dict[str, frozenset[str]] = {}
    for name, item in prot_t.get("addresses", {}).items():
        path = f"protection.addresses.{name!r}"
        try:
            if name.endswith("@*"):
                address = parse_mailbox(name[:-1] + "hosted.invalid")
                key = f"{address.local.lower()}@*"
            elif "*" in name:
                raise AddressError("a protected group is written <local>@*, as in all@*; no other * form is supported")
            else:
                address = parse_mailbox(name)
                key = address.lookup_key
        except AddressError as exc:
            v.error(path, str(exc))
            continue
        if key in addresses:
            v.error(path, f"same address as another protection.addresses entry ({key})")
            continue
        entry = v.table(item, path, {"authorized_logins": list})
        addresses[key] = frozenset(v.strings(entry.get("authorized_logins"), f"{path}.authorized_logins"))
    transports = v.strings(prot_t.get("remote_transports"), "protection.remote_transports")
    protection = ProtectionSettings(
        remote_transports=frozenset(transports) if "remote_transports" in prot_t else ProtectionSettings().remote_transports,
        addresses=addresses,
    )

    limits_t = v.table(top.get("limits", {}), "limits", {
        "message_bytes": int, "max_signatures": int, "max_headers": int, "max_header_bytes": int,
        "max_recipients": int, "dns_timeout_seconds": (int, float),
        "authentication_deadline_seconds": (int, float), "max_concurrent_messages": int,
        "max_open_messages": int})
    d = LimitSettings()
    limits = LimitSettings(
        message_bytes=v.positive(limits_t.get("message_bytes"), "limits.message_bytes", d.message_bytes, integer=True),
        max_signatures=v.positive(limits_t.get("max_signatures"), "limits.max_signatures", d.max_signatures, integer=True),
        max_headers=v.positive(limits_t.get("max_headers"), "limits.max_headers", d.max_headers, integer=True),
        max_header_bytes=v.positive(limits_t.get("max_header_bytes"), "limits.max_header_bytes", d.max_header_bytes, integer=True),
        max_recipients=v.positive(limits_t.get("max_recipients"), "limits.max_recipients", d.max_recipients, integer=True),
        dns_timeout_seconds=v.positive(limits_t.get("dns_timeout_seconds"), "limits.dns_timeout_seconds", d.dns_timeout_seconds, integer=False),
        authentication_deadline_seconds=v.positive(limits_t.get("authentication_deadline_seconds"), "limits.authentication_deadline_seconds", d.authentication_deadline_seconds, integer=False),
        max_concurrent_messages=v.positive(limits_t.get("max_concurrent_messages"), "limits.max_concurrent_messages", d.max_concurrent_messages, integer=True),
        max_open_messages=v.positive(limits_t.get("max_open_messages"), "limits.max_open_messages", d.max_open_messages, integer=True),
    )
    if limits.authentication_deadline_seconds < limits.dns_timeout_seconds:
        v.error("limits.authentication_deadline_seconds", "must not be shorter than dns_timeout_seconds")

    responses = dict(DEFAULT_REPLIES)
    responses_data = top.get("responses", {})
    if isinstance(responses_data, dict):
        for name, item in responses_data.items():
            path = f"responses.{name}"
            if name not in DEFAULT_REPLIES:
                v.error(path, "unknown response key")
                continue
            entry = v.table(item, path, {"smtp_code": int, "enhanced_code": str, "message": str})
            base = DEFAULT_REPLIES[name]
            reply = Reply(entry.get("smtp_code", base.smtp_code), entry.get("enhanced_code", base.enhanced_code),
                          entry.get("message", base.message))
            v.errors.extend(validate_reply(name, reply))
            responses[name] = reply

    if v.errors:
        raise ConfigError(v.errors)
    return Settings(
        schema_version=schema_version, mode=mode, service=service, logging=logging_s, trust=trust,
        self_sender=self_sender, sender_authentication=sender_authentication, protection=protection,
        limits=limits, responses=responses, source=source,
    )


def load_settings(path: str = DEFAULT_CONFIG_PATH) -> Settings:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError:
        raise ConfigError([f"{path}: configuration file not found; copy etc/config.example.toml to {DEFAULT_CONFIG_PATH} and edit it"]) from None
    except PermissionError:
        raise ConfigError([f"{path}: permission denied"]) from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError([f"{path}: TOML syntax error: {exc}"]) from None
    return parse_settings(data, source=path)


def describe(settings: Settings) -> dict[str, Any]:
    """Effective configuration as plain data for display; contains no secrets by construction."""
    return {
        "source": settings.source,
        "schema_version": settings.schema_version,
        "mode": settings.mode,
        "socket": settings.service.socket,
        "logging": {"level": settings.logging.level},
        "from_postfix": {
            "mynetworks": [str(n) for n in settings.trust.mynetworks],
            "recipient_delimiter": settings.trust.recipient_delimiter,
        },
        "self_sender": {
            "enabled": settings.self_sender.enabled,
            "identity": settings.self_sender.identity,
            "allow_mynetworks": settings.self_sender.allow_mynetworks,
            "allow_senders": sorted(settings.self_sender.allow_senders),
        },
        "sender_authentication": {f.name: getattr(settings.sender_authentication, f.name)
                                  for f in fields(SenderAuthenticationSettings)},
        "protection": {
            "remote_transports": sorted(settings.protection.remote_transports),
            "addresses": {name: {"authorized_logins": sorted(logins)}
                          for name, logins in sorted(settings.protection.addresses.items())},
        },
        "limits": {f.name: getattr(settings.limits, f.name) for f in fields(LimitSettings)},
        "responses": {name: {"smtp_code": r.smtp_code, "enhanced_code": r.enhanced_code, "message": r.message}
                      for name, r in settings.responses.items()},
    }
