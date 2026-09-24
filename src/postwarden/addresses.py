"""Mailbox parsing and identity comparison."""
from __future__ import annotations

import encodings.idna
from dataclasses import dataclass
from email import headerregistry
from email.headerregistry import HeaderRegistry


class AddressError(ValueError):
    """The value is not a single valid mailbox."""


def normalize_domain(domain: str) -> str:
    domain = domain.strip().rstrip(".")
    if not domain:
        raise AddressError("empty domain")
    if domain.isascii():
        return domain.lower()
    try:
        labels = [encodings.idna.ToASCII(label).decode("ascii") for label in domain.split(".")]
    except UnicodeError as exc:
        raise AddressError(f"invalid internationalized domain {domain!r}: {exc}") from None
    return ".".join(labels).lower()


@dataclass(frozen=True, slots=True)
class Mailbox:
    local: str
    domain: str

    def __str__(self) -> str:
        return f"{self.local}@{self.domain}"

    @property
    def lookup_key(self) -> str:
        return f"{self.local.lower()}@{self.domain}"

    @property
    def exact_key(self) -> str:
        return f"{self.local}@{self.domain}"

    def without_extension(self, delimiters: str) -> "Mailbox":
        if not delimiters:
            return self
        cut = min((i for i in (self.local.find(c) for c in delimiters) if i > 0), default=-1)
        if cut < 0:
            return self
        return Mailbox(self.local[:cut], self.domain)


def parse_mailbox(text: str) -> Mailbox:
    """Parse `local@domain`, optionally in angle brackets. Rejects display names and groups."""
    value = text.strip()
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    if not value:
        raise AddressError("empty address")
    if any(ord(c) < 32 or c == "\x7f" for c in value):
        raise AddressError("control character in address")
    local, sep, domain = value.rpartition("@")
    if not sep or not local or not domain:
        raise AddressError(f"not a mailbox: {text!r}")
    if local.startswith('"') and local.endswith('"') and len(local) >= 2:
        local = local[1:-1]
    if "@" in local or any(c in local for c in " <>,;:"):
        raise AddressError(f"invalid local part in {text!r}")
    if domain.startswith("[") or " " in domain or not all(domain.split(".")):
        raise AddressError(f"invalid domain in {text!r}")
    return Mailbox(local, normalize_domain(domain))


def parse_envelope(text: str) -> Mailbox | None:
    """Envelope address as Postfix supplies it; `<>` and empty mean the null reverse path."""
    value = text.strip()
    if value in ("", "<>"):
        return None
    return parse_mailbox(value)


_registry = HeaderRegistry()


def parse_from_header(values: list[str]) -> Mailbox:
    """Exactly one From field with exactly one mailbox, otherwise AddressError."""
    if len(values) == 0:
        raise AddressError("missing From header")
    if len(values) > 1:
        raise AddressError("duplicate From header")
    raw = values[0].replace("\r\n", "").replace("\n", "")
    try:
        header = _registry("From", raw)
    except Exception as exc:
        raise AddressError(f"unparseable From header: {exc}") from None
    if not isinstance(header, headerregistry.AddressHeader):
        raise AddressError("unparseable From header")
    if header.defects:
        raise AddressError("malformed From header: " + "; ".join(str(d) for d in header.defects))
    if len(header.addresses) != 1:
        raise AddressError(f"From header must contain one mailbox, found {len(header.addresses)}")
    address = header.addresses[0]
    if not address.username or not address.domain:
        raise AddressError("From header mailbox lacks local part or domain")
    if "\x00" in raw:
        raise AddressError("control character in From header")
    return Mailbox(address.username, normalize_domain(address.domain))


def parse_from_header_bytes(values: list[bytes]) -> Mailbox:
    decoded = []
    for value in values:
        try:
            decoded.append(value.decode("utf-8"))
        except UnicodeDecodeError:
            decoded.append(value.decode("latin-1"))
    return parse_from_header(decoded)


__all__ = [
    "AddressError", "Mailbox", "normalize_domain", "parse_mailbox", "parse_envelope",
    "parse_from_header", "parse_from_header_bytes",
]
