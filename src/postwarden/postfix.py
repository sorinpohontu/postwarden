"""Values postwarden takes from the running Postfix configuration instead of its own file."""
from __future__ import annotations

import dataclasses
import ipaddress
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import Network, SendingLimitSettings, Settings


class PostfixError(Exception):
    pass


def parse_network(text: str) -> Network:
    if text.startswith("[") and "]" in text:
        text = text[1:].replace("]", "", 1)
    return ipaddress.ip_network(text, strict=False)


def parse_mynetworks(value: str, read_file: Callable[[str], str] = lambda p: Path(p).read_text()) -> tuple[Network, ...]:
    """Literal addresses/CIDRs, pattern files and cidr: tables; anything else cannot be mirrored."""
    networks: list[Network] = []
    unsupported: list[str] = []
    for item in re.split(r"[,\s]+", value.strip()):
        if not item:
            continue
        if item.startswith("!"):
            unsupported.append(f"{item} (negation)")
            continue
        if item.startswith("cidr:") or item.startswith("/"):
            path = item.removeprefix("cidr:")
            try:
                lines = read_file(path).splitlines()
            except OSError as exc:
                unsupported.append(f"{item} ({exc.strerror or exc})")
                continue
            for line in lines:
                entry = line.split("#", 1)[0].split()
                if not entry:
                    continue
                try:
                    networks.append(parse_network(entry[0]))
                except ValueError:
                    unsupported.append(f"{entry[0]} in {path}")
            continue
        try:
            networks.append(parse_network(item))
        except ValueError:
            unsupported.append(item)
    if unsupported:
        raise PostfixError("Postfix mynetworks contains entries postwarden cannot read: " + ", ".join(unsupported)
                           + "; use literal addresses, CIDR networks, pattern files or cidr: tables")
    return tuple(networks)


def read_postfix() -> tuple[tuple[Network, ...], str]:
    """mynetworks and recipient_delimiter, as the running Postfix configuration resolves them."""
    try:
        result = subprocess.run(["postconf", "-xh", "mynetworks", "recipient_delimiter"],
                                check=True, text=True, capture_output=True, timeout=30)
    except FileNotFoundError:
        raise PostfixError("postconf not found: Postfix must be installed to read mynetworks") from None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PostfixError(f"postconf -xh mynetworks recipient_delimiter failed: {getattr(exc, 'stderr', '') or exc}") from None
    mynetworks, _, delimiter = result.stdout.rstrip("\n").partition("\n")
    return parse_mynetworks(mynetworks), delimiter.strip()


def delimiter_conflicts(settings: Settings, delimiter: str) -> list[str]:
    """Protected addresses that include a delimiter tag and therefore could never match a recipient."""
    return [key for key in settings.protection.addresses
            if any(key.rsplit("@", 1)[0].find(c) > 0 for c in delimiter)]


def with_postfix(settings: Settings, mynetworks: tuple[Network, ...] | None = None,
                 recipient_delimiter: str | None = None) -> Settings:
    if mynetworks is None or recipient_delimiter is None:
        read_networks, read_delimiter = read_postfix()
        mynetworks = read_networks if mynetworks is None else mynetworks
        recipient_delimiter = read_delimiter if recipient_delimiter is None else recipient_delimiter
    conflicts = delimiter_conflicts(settings, recipient_delimiter)
    if conflicts:
        raise PostfixError(f"protection.addresses {', '.join(conflicts)}: contains the Postfix recipient_delimiter "
                           f"{recipient_delimiter!r}; list the base address")
    return dataclasses.replace(settings, trust=dataclasses.replace(
        settings.trust, mynetworks=mynetworks, recipient_delimiter=recipient_delimiter))


RATE_PARAMS = ("smtpd_client_recipient_rate_limit", "smtpd_client_message_rate_limit")
SUBMISSION_SERVICES = ("submission/inet", "submissions/inet", "smtps/inet")
SMTP_SERVICES = ("smtp/inet", "smtpd/pass") + SUBMISSION_SERVICES
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


@dataclass(frozen=True, slots=True)
class RateLimits:
    """Postfix's per-client anvil limits: main.cf values and the effective values of each SMTP service."""
    time_unit: int
    exceptions: str
    main: dict[str, int]
    services: dict[str, dict[str, int]]


def parse_duration(text: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([smhdw]?)\s*", text)
    if not match:
        raise PostfixError(f"anvil_rate_time_unit {text!r} is not a Postfix time value")
    return int(match.group(1)) * _UNITS[match.group(2) or "s"]


def parse_rate_limits(main_values: dict[str, str], service_overrides: str, services: list[str]) -> RateLimits:
    """Effective per-service values from `postconf -xh` values and `postconf -Px` output."""
    def number(name: str, text: str) -> int:
        if not text.strip().isdigit():
            raise PostfixError(f"{name} {text!r} is not a number")
        return int(text)

    main = {name: number(name, main_values.get(name, "0") or "0") for name in RATE_PARAMS}
    overrides: dict[str, dict[str, int]] = {}
    for line in service_overrides.splitlines():
        key, _, value = line.partition(" = ")
        service, _, param = key.strip().rpartition("/")
        if param in RATE_PARAMS:
            overrides.setdefault(service, {})[param] = number(key.strip(), value.strip())
    effective = {service: {**main, **overrides.get(service, {})} for service in SMTP_SERVICES if service in services}
    return RateLimits(parse_duration(main_values.get("anvil_rate_time_unit") or "60s"),
                      main_values.get("smtpd_client_event_limit_exceptions", ""), main, effective)


def read_rate_limits() -> RateLimits:
    names = ("anvil_rate_time_unit", "smtpd_client_event_limit_exceptions") + RATE_PARAMS
    try:
        values = subprocess.run(["postconf", "-xh", *names], check=True, text=True, capture_output=True, timeout=30)
        overrides = subprocess.run(["postconf", "-Px"], check=True, text=True, capture_output=True, timeout=30)
        master = subprocess.run(["postconf", "-M"], check=True, text=True, capture_output=True, timeout=30)
    except FileNotFoundError:
        raise PostfixError("postconf not found") from None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PostfixError(f"postconf failed: {getattr(exc, 'stderr', '') or exc}") from None
    services = ["/".join(line.split()[:2]) for line in master.stdout.splitlines() if len(line.split()) >= 8]
    return parse_rate_limits(dict(zip(names, values.stdout.rstrip("\n").split("\n"))), overrides.stdout, services)


def describe_rate_limits(limits: RateLimits) -> str:
    def values(params: dict[str, int]) -> str:
        return ", ".join(f"{name.removeprefix('smtpd_client_')} {value or 'off'}" for name, value in params.items())
    parts = [f"main.cf: {values(limits.main)} per {limits.time_unit}s, "
             f"exceptions {limits.exceptions or 'none'}"]
    parts += [f"{service}: {values(params)}" for service, params in limits.services.items() if params != limits.main]
    return "; ".join(parts)


def rate_limit_warnings(limits: RateLimits, sending: SendingLimitSettings) -> list[str]:
    """Submission services whose per-client recipient rate cannot reach the highest per-login hourly limit."""
    if sending.mode == "off":
        return []
    factors = [1.0, *sending.accounts.values(), *sending.logins.values(), *sending.domains.values()]
    highest = sending.scaled(max(factors))[0]
    warnings = []
    for service in SUBMISSION_SERVICES:
        rate = limits.services.get(service, {}).get("smtpd_client_recipient_rate_limit", 0)
        if rate and rate * 3600 / limits.time_unit < highest:
            hourly = int(rate * 3600 / limits.time_unit)
            warnings.append(f"{service}: Postfix smtpd_client_recipient_rate_limit {rate} per {limits.time_unit}s "
                            f"(about {hourly} per hour per client address) is below the highest sending limit, "
                            f"{highest} per hour; a login sending from one address is stopped by Postfix first")
    return warnings
