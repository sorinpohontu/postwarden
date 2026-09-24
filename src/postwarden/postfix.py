"""Values postwarden takes from the running Postfix configuration instead of its own file."""
from __future__ import annotations

import dataclasses
import ipaddress
import re
import subprocess
from pathlib import Path
from typing import Callable

from .config import Network, Settings


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
