"""TOML schema, validation and the immutable Settings tree. No runtime adapters are imported here."""
from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import math
import tomllib
from dataclasses import dataclass, field, fields
from typing import Any

from . import DEFAULT_CONFIG_PATH, LOADED_CONFIG
from .addresses import AddressError, Mailbox, parse_mailbox
from .replies import DEFAULT_REPLIES, Reply, validate_reply

SUPPORTED_SCHEMA_VERSIONS = (1,)
MODES = ("observe", "enforce", "off")
FAILURE_ACTIONS = ("auto", "accept", "tempfail")
SECTIONS = ("protection", "self_sender", "sender_authentication", "limits", "sending_limits")
RULE_SECTIONS = {
    "protected_recipient": "protection", "invalid_recipient": "protection", "self_sender": "self_sender",
    "authentication": "sender_authentication", "limits": "limits", "sending_limit": "sending_limits",
}
NULL_SENDER_KEY = "<>"
LOGIN_PREFIX = "login:"

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ConfigError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass(frozen=True, slots=True)
class PostfixSettings:
    failure_action: str = "auto"


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
    mode: str = "observe"
    identity: str = "envelope_or_header_from"
    allow_mynetworks: bool = True
    allow_senders: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class SenderAuthenticationSettings:
    mode: str = "observe"
    require: str = "both"
    allow_local: bool = True
    allow_mynetworks: bool = True
    null_sender: str = "dkim_aligned"
    dkim_diagnostics: bool = False


@dataclass(frozen=True, slots=True)
class ProtectionSettings:
    mode: str = "enforce"
    remote_transports: frozenset[str] = frozenset({"smtp", "relay"})
    addresses: dict[str, frozenset[str]] = field(default_factory=dict)

    def counts(self) -> tuple[int, int]:
        """(protected addresses, protected groups)."""
        groups = sum(1 for key in self.addresses if key.endswith("@*"))
        return len(self.addresses) - groups, groups

    def lookup(self, recipient: Mailbox, transport: str | None) -> tuple[bool, frozenset[str]]:
        """(protected, authorized logins) for a recipient already stripped of its extension."""
        if recipient.lookup_key in self.addresses:
            return True, self.addresses[recipient.lookup_key]
        group = f"{recipient.local.lower()}@*"
        if group in self.addresses and transport not in self.remote_transports:
            return True, self.addresses[group]
        return False, frozenset()


MIN_WORKER_MEMORY = 268435456


@dataclass(frozen=True, slots=True)
class LimitSettings:
    mode: str = "observe"
    message_bytes: int = 41943040
    max_signatures: int = 10
    max_headers: int = 1000
    max_header_bytes: int = 65536
    max_recipients: int = 1000
    dns_timeout_seconds: float = 5.0
    authentication_deadline_seconds: float = 20.0
    max_concurrent_messages: int = 32
    dkim_workers: int = 2
    dkim_worker_memory: int = 1073741824
    max_open_messages: int = 100

    @property
    def bounded(self) -> bool:
        """With mode "off" there is no cap on size, headers, recipients or messages open and checked at once."""
        return self.mode != "off"


@dataclass(frozen=True, slots=True)
class SendingLimitSettings:
    mode: str = "observe"
    per_hour: int = 100
    per_day: int = 500
    local_per_hour: int = 1000
    local_per_day: int = 5000
    accounts: dict[str, float] = field(default_factory=dict)
    logins: dict[str, float] = field(default_factory=dict)
    domains: dict[str, float] = field(default_factory=dict)
    networks: tuple[tuple[Network, float], ...] = ()
    null_sender: float | None = None

    def scaled(self, multiplier: float) -> tuple[int, int]:
        """(per_hour, per_day) for a multiplier: rounded down, at least 1."""
        return max(1, math.floor(self.per_hour * multiplier)), max(1, math.floor(self.per_day * multiplier))

    def multiplier_for(self, *, account: str | None = None, login: str | None = None, domain: str | None = None,
                       null_sender: bool = False, relay: str | None = None) -> float:
        """The most specific multiplier for a limit key; 1 when nothing matches."""
        if relay is not None:
            address = ipaddress.ip_address(relay)
            matches = [(net.prefixlen, m) for net, m in self.networks if address.version == net.version and address in net]
            return max(matches)[1] if matches else 1.0
        if null_sender:
            return self.null_sender if self.null_sender is not None else 1.0
        if account is not None and account in self.accounts:
            return self.accounts[account]
        if login is not None and login.casefold() in self.logins:
            return self.logins[login.casefold()]
        if domain is not None and domain in self.domains:
            return self.domains[domain]
        return 1.0

    def entries(self) -> list[tuple[str, float]]:
        """Every configured multiplier as written in the configuration, normalized."""
        listed = [(key, m) for key, m in self.accounts.items()]
        listed += [(f"{LOGIN_PREFIX}{key}", m) for key, m in self.logins.items()]
        listed += [(key, m) for key, m in self.domains.items()]
        listed += [(_network_text(net), m) for net, m in self.networks]
        if self.null_sender is not None:
            listed.append((NULL_SENDER_KEY, self.null_sender))
        return listed


@dataclass(frozen=True, slots=True)
class Settings:
    schema_version: int = 1
    postfix: PostfixSettings = PostfixSettings()
    service: ServiceSettings = ServiceSettings()
    logging: LoggingSettings = LoggingSettings()
    trust: TrustSettings = TrustSettings()
    self_sender: SelfSenderSettings = SelfSenderSettings()
    sender_authentication: SenderAuthenticationSettings = SenderAuthenticationSettings()
    protection: ProtectionSettings = ProtectionSettings()
    limits: LimitSettings = LimitSettings()
    sending_limits: SendingLimitSettings = SendingLimitSettings()
    responses: dict[str, Reply] = field(default_factory=lambda: dict(DEFAULT_REPLIES))
    source: str = ""
    sha256: str = ""

    def reply(self, name: str) -> Reply:
        return self.responses[name]

    def section_modes(self) -> dict[str, str]:
        return {section: getattr(self, section).mode for section in SECTIONS}

    def rule_mode(self, rule: str) -> str:
        """The mode governing a log rule; invalid_from takes the stronger of its two sections."""
        if rule == "invalid_from":
            modes = {self.self_sender.mode, self.sender_authentication.mode}
            return next(mode for mode in ("enforce", "observe", "off") if mode in modes)
        return getattr(self, RULE_SECTIONS[rule]).mode

    def failure_action(self) -> str:
        """Postfix's milter default_action: the configured one, or for auto tempfail while any section enforces."""
        if self.postfix.failure_action != "auto":
            return self.postfix.failure_action
        enforcing = [s for s, mode in self.section_modes().items() if mode == "enforce"
                     and (s != "protection" or self.protection.addresses)]
        return "tempfail" if enforcing else "accept"


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
        "schema_version": int, "postfix": dict, "logging": dict, "self_sender": dict, "sender_authentication": dict,
        "protection": dict, "limits": dict, "sending_limits": dict, "responses": dict,
    })

    schema_version = top.get("schema_version", 1)
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        v.error("schema_version", f"unsupported version {schema_version}; supported: {SUPPORTED_SCHEMA_VERSIONS}")
    postfix_t = v.table(top.get("postfix", {}), "postfix", {"failure_action": str})
    v.choice(postfix_t.get("failure_action"), "postfix.failure_action", FAILURE_ACTIONS)
    postfix = PostfixSettings(failure_action=postfix_t.get("failure_action", PostfixSettings().failure_action))

    service = ServiceSettings()

    logging_t = v.table(top.get("logging", {}), "logging", {"level": str})
    v.choice(logging_t.get("level"), "logging.level", ("debug", "info", "warning", "error"))
    logging_s = LoggingSettings(level=logging_t.get("level", LoggingSettings().level))

    trust = TrustSettings()

    ss_t = v.table(top.get("self_sender", {}), "self_sender", {
        "mode": str, "identity": str, "allow_mynetworks": bool, "allow_senders": list})
    v.choice(ss_t.get("mode"), "self_sender.mode", MODES)
    v.choice(ss_t.get("identity"), "self_sender.identity", ("envelope_or_header_from", "envelope", "header_from"))
    self_sender = SelfSenderSettings(
        mode=ss_t.get("mode", SelfSenderSettings().mode),
        identity=ss_t.get("identity", SelfSenderSettings().identity),
        allow_mynetworks=ss_t.get("allow_mynetworks", True),
        allow_senders=frozenset(m.lookup_key for m in v.mailboxes(ss_t.get("allow_senders"), "self_sender.allow_senders")),
    )

    auth_t = v.table(top.get("sender_authentication", {}), "sender_authentication", {
        "mode": str, "require": str, "allow_local": bool, "allow_mynetworks": bool, "null_sender": str,
        "dkim_diagnostics": bool})
    v.choice(auth_t.get("mode"), "sender_authentication.mode", MODES)
    v.choice(auth_t.get("require"), "sender_authentication.require", ("both", "either"))
    v.choice(auth_t.get("null_sender"), "sender_authentication.null_sender", ("dkim_aligned", "both"))
    sender_authentication = SenderAuthenticationSettings(
        mode=auth_t.get("mode", SenderAuthenticationSettings().mode),
        require=auth_t.get("require", "both"),
        allow_local=auth_t.get("allow_local", True),
        allow_mynetworks=auth_t.get("allow_mynetworks", True),
        null_sender=auth_t.get("null_sender", "dkim_aligned"),
        dkim_diagnostics=auth_t.get("dkim_diagnostics", False),
    )

    prot_t = v.table(top.get("protection", {}), "protection", {
        "mode": str, "remote_transports": list, "addresses": dict})
    v.choice(prot_t.get("mode"), "protection.mode", MODES)
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
        mode=prot_t.get("mode", ProtectionSettings().mode),
        remote_transports=frozenset(transports) if "remote_transports" in prot_t else ProtectionSettings().remote_transports,
        addresses=addresses,
    )

    limits_t = v.table(top.get("limits", {}), "limits", {
        "mode": str, "message_bytes": int, "max_signatures": int, "max_headers": int, "max_header_bytes": int,
        "max_recipients": int, "dns_timeout_seconds": (int, float),
        "authentication_deadline_seconds": (int, float), "max_concurrent_messages": int,
        "dkim_workers": int, "dkim_worker_memory": int, "max_open_messages": int})
    v.choice(limits_t.get("mode"), "limits.mode", MODES)
    d = LimitSettings()
    limits = LimitSettings(
        mode=limits_t.get("mode", d.mode),
        message_bytes=v.positive(limits_t.get("message_bytes"), "limits.message_bytes", d.message_bytes, integer=True),
        max_signatures=v.positive(limits_t.get("max_signatures"), "limits.max_signatures", d.max_signatures, integer=True),
        max_headers=v.positive(limits_t.get("max_headers"), "limits.max_headers", d.max_headers, integer=True),
        max_header_bytes=v.positive(limits_t.get("max_header_bytes"), "limits.max_header_bytes", d.max_header_bytes, integer=True),
        max_recipients=v.positive(limits_t.get("max_recipients"), "limits.max_recipients", d.max_recipients, integer=True),
        dns_timeout_seconds=v.positive(limits_t.get("dns_timeout_seconds"), "limits.dns_timeout_seconds", d.dns_timeout_seconds, integer=False),
        authentication_deadline_seconds=v.positive(limits_t.get("authentication_deadline_seconds"), "limits.authentication_deadline_seconds", d.authentication_deadline_seconds, integer=False),
        max_concurrent_messages=v.positive(limits_t.get("max_concurrent_messages"), "limits.max_concurrent_messages", d.max_concurrent_messages, integer=True),
        dkim_workers=v.positive(limits_t.get("dkim_workers"), "limits.dkim_workers", d.dkim_workers, integer=True),
        dkim_worker_memory=v.positive(limits_t.get("dkim_worker_memory"), "limits.dkim_worker_memory", d.dkim_worker_memory, integer=True),
        max_open_messages=v.positive(limits_t.get("max_open_messages"), "limits.max_open_messages", d.max_open_messages, integer=True),
    )
    if limits.authentication_deadline_seconds < limits.dns_timeout_seconds:
        v.error("limits.authentication_deadline_seconds", "must not be shorter than dns_timeout_seconds")
    if limits.dkim_worker_memory < MIN_WORKER_MEMORY:
        v.error("limits.dkim_worker_memory", f"must be at least {MIN_WORKER_MEMORY} (256 MiB): the worker needs room for Python and dkimpy")

    sending_limits = _sending_limits(v, top.get("sending_limits", {}))

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

    if protection.mode == "off" and protection.addresses:
        v.error("protection.mode", "off is refused while protected addresses are listed; "
                                   "use observe, or remove the addresses")
    if postfix.failure_action == "accept" and protection.mode == "enforce" and protection.addresses:
        v.error("postfix.failure_action", "accept is refused while protected addresses are enforced: "
                                          "they would be open whenever postwarden is down")

    if v.errors:
        raise ConfigError(v.errors)
    return Settings(
        schema_version=schema_version, postfix=postfix, service=service, logging=logging_s, trust=trust,
        self_sender=self_sender, sender_authentication=sender_authentication, protection=protection,
        limits=limits, sending_limits=sending_limits, responses=responses, source=source,
    )


def _sending_limits(v: _Validator, data: Any) -> SendingLimitSettings:
    t = v.table(data, "sending_limits", {
        "mode": str, "per_hour": int, "per_day": int, "local_per_hour": int, "local_per_day": int,
        "multipliers": dict})
    v.choice(t.get("mode"), "sending_limits.mode", MODES)
    d = SendingLimitSettings()
    numbers = {name: v.positive(t.get(name), f"sending_limits.{name}", getattr(d, name), integer=True)
               for name in ("per_hour", "per_day", "local_per_hour", "local_per_day")}
    for hour, day in (("per_hour", "per_day"), ("local_per_hour", "local_per_day")):
        if numbers[day] < numbers[hour]:
            v.error(f"sending_limits.{day}", f"must not be lower than {hour}")
    accounts: dict[str, float] = {}
    logins: dict[str, float] = {}
    domains: dict[str, float] = {}
    networks: dict[Network, float] = {}
    null_sender: float | None = None
    raw = t.get("multipliers", {})
    for name, value in raw.items():
        path = f"sending_limits.multipliers.{name!r}"
        if isinstance(value, dict):
            v.error(path, "must be a number; write keys that contain dots in quotes, as in \"example.com\" = 2")
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            v.error(path, "must be a number")
            continue
        factor = v.positive(value, path, None, integer=False)
        if factor is None:
            continue
        kind, key = _multiplier_key(v, name, path)
        if kind is None:
            continue
        table = {"account": accounts, "login": logins, "domain": domains, "network": networks}.get(kind)
        if kind == "null_sender":
            if null_sender is not None:
                v.error(path, "duplicate multiplier")
                continue
            null_sender = factor
        elif key in table:
            shown = f"{LOGIN_PREFIX}{key}" if kind == "login" else _network_text(key) if kind == "network" else key
            v.error(path, f"same key as another multiplier ({shown})")
        else:
            table[key] = factor
    return SendingLimitSettings(
        mode=t.get("mode", d.mode), **numbers, accounts=accounts, logins=logins, domains=domains,
        networks=tuple(networks.items()), null_sender=null_sender,
    )


def _network_text(network: Network) -> str:
    return str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _multiplier_key(v: _Validator, name: str, path: str) -> tuple[str | None, Any]:
    """Classify a multiplier key: null sender, short login, relay network, account or domain."""
    if name == NULL_SENDER_KEY:
        return "null_sender", None
    if name.startswith(LOGIN_PREFIX):
        login = name[len(LOGIN_PREFIX):]
        if not login or "@" in login or any(ch.isspace() for ch in login):
            v.error(path, f"{LOGIN_PREFIX}NAME takes a login without @ and without spaces; "
                          "write an address as the address itself")
            return None, None
        return "login", login.casefold()
    if "/" in name or ":" in name or _is_ip(name):
        try:
            return "network", ipaddress.ip_network(name, strict=True)
        except ValueError as exc:
            v.error(path, f"not a valid IP address or network: {exc}")
            return None, None
    try:
        if "@" in name:
            return "account", parse_mailbox(name).lookup_key
        domain = parse_mailbox(f"postmaster@{name}").domain
    except AddressError as exc:
        v.error(path, str(exc))
        return None, None
    if "." not in domain:
        v.error(path, f"not a domain, address, network, {LOGIN_PREFIX}NAME or {NULL_SENDER_KEY}; "
                      f"a login without a domain is written {LOGIN_PREFIX}{name}")
        return None, None
    return "domain", domain


def load_settings(path: str = DEFAULT_CONFIG_PATH) -> Settings:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        data = tomllib.loads(raw.decode("utf-8"))
    except FileNotFoundError:
        raise ConfigError([f"{path}: configuration file not found; copy etc/config.example.toml to {DEFAULT_CONFIG_PATH} and edit it"]) from None
    except PermissionError:
        raise ConfigError([f"{path}: permission denied"]) from None
    except UnicodeDecodeError:
        raise ConfigError([f"{path}: not UTF-8 text"]) from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError([f"{path}: TOML syntax error: {exc}"]) from None
    return dataclasses.replace(parse_settings(data, source=path), sha256=hashlib.sha256(raw).hexdigest())


def loaded_sha256(path: str = LOADED_CONFIG) -> str | None:
    """SHA-256 of the configuration the running daemon loaded, once it accepts connections; None when unknown."""
    try:
        with open(path) as fh:
            value = fh.read().strip()
    except OSError:
        return None
    return value if len(value) == 64 else None


def describe(settings: Settings) -> dict[str, Any]:
    """Effective configuration as plain data for display; contains no secrets by construction."""
    return {
        "source": settings.source,
        "schema_version": settings.schema_version,
        "postfix": {"failure_action": settings.postfix.failure_action, "effective": settings.failure_action()},
        "socket": settings.service.socket,
        "logging": {"level": settings.logging.level},
        "from_postfix": {
            "mynetworks": [str(n) for n in settings.trust.mynetworks],
            "recipient_delimiter": settings.trust.recipient_delimiter,
        },
        "self_sender": {
            "mode": settings.self_sender.mode,
            "identity": settings.self_sender.identity,
            "allow_mynetworks": settings.self_sender.allow_mynetworks,
            "allow_senders": sorted(settings.self_sender.allow_senders),
        },
        "sender_authentication": {f.name: getattr(settings.sender_authentication, f.name)
                                  for f in fields(SenderAuthenticationSettings)},
        "protection": {
            "mode": settings.protection.mode,
            "remote_transports": sorted(settings.protection.remote_transports),
            "addresses": {name: {"authorized_logins": sorted(logins)}
                          for name, logins in sorted(settings.protection.addresses.items())},
        },
        "limits": {f.name: getattr(settings.limits, f.name) for f in fields(LimitSettings)},
        "sending_limits": _describe_sending_limits(settings.sending_limits),
        "responses": {name: {"smtp_code": r.smtp_code, "enhanced_code": r.enhanced_code, "message": r.message}
                      for name, r in settings.responses.items()},
    }


def _describe_sending_limits(limits: SendingLimitSettings) -> dict[str, Any]:
    described: dict[str, Any] = {
        "mode": limits.mode, "per_hour": limits.per_hour, "per_day": limits.per_day,
        "local_per_hour": limits.local_per_hour, "local_per_day": limits.local_per_day,
    }
    multipliers = {}
    for key, factor in limits.entries():
        per_hour, per_day = limits.scaled(factor)
        multipliers[key] = f"x{factor:g}: {per_hour} per hour, {per_day} per day"
    if multipliers:
        described["multipliers"] = multipliers
    return described
