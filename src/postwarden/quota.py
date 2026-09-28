"""Sending-limit windows: limit keys, reservations and rolling counts. Pure; the caller supplies the clock."""
from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field

from .addresses import AddressError, Mailbox, parse_mailbox
from .config import LOGIN_PREFIX, NULL_SENDER_KEY, SendingLimitSettings

HOUR = 3600
DAY = 86400
HOUR_BUCKET = 60
DAY_BUCKET = 900
KEY_CAPACITY = 20000
FULL_WARNING_INTERVAL = 60
SWEEP_INTERVAL = 60

PER_HOUR = "per_hour"
PER_DAY = "per_day"
LOCAL_PER_HOUR = "local_per_hour"
LOCAL_PER_DAY = "local_per_day"
KEY_STORE_FULL = "key_store_full"


@dataclass(frozen=True, slots=True)
class LimitKey:
    """What one message counts against, and its effective limits."""
    text: str
    per_hour: int
    per_day: int
    multiplier: float
    local: bool


def _relay_text(peer_ip: str) -> str:
    address = ipaddress.ip_address(peer_ip.removeprefix("IPv6:"))
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def limit_key(limits: SendingLimitSettings, trust: str, *, login: str | None = None, sender: Mailbox | None = None,
              null_sender: bool = False, raw_sender: str | None = None, peer_ip: str | None = None) -> LimitKey | None:
    """The limit key for a trust class name, or None when the mail is not limited."""
    local = trust in ("local_pickup", "local_smtp")
    if trust == "authenticated_submission" and login:
        domain = sender.domain if sender is not None else None
        if "@" in login:
            try:
                account = parse_mailbox(login)
                text, account_domain = account.lookup_key, account.domain
            except AddressError:
                text = login.strip().casefold()
                account_domain = text.rpartition("@")[2]
            multiplier = limits.multiplier_for(account=text, domain=account_domain)
        else:
            name = login.strip().casefold()
            text = f"{LOGIN_PREFIX}{name}"
            multiplier = limits.multiplier_for(login=name, domain=domain)
    elif local:
        if null_sender:
            text = NULL_SENDER_KEY
            multiplier = limits.multiplier_for(null_sender=True)
        elif sender is not None:
            text = sender.lookup_key
            multiplier = limits.multiplier_for(account=text, domain=sender.domain)
        else:
            text = (raw_sender or "").strip().casefold()
            multiplier = 1.0
    elif trust == "mynetworks" and peer_ip:
        try:
            text = _relay_text(peer_ip)
        except ValueError:
            return None
        multiplier = limits.multiplier_for(relay=text)
    else:
        return None
    per_hour, per_day = limits.scaled(multiplier)
    return LimitKey(text, per_hour, per_day, multiplier, local)


@dataclass(slots=True)
class _Window:
    hour: dict[int, int] = field(default_factory=dict)
    day: dict[int, int] = field(default_factory=dict)
    reserved: int = 0
    notified: dict[str, float] = field(default_factory=dict)

    def expire(self, now: float) -> None:
        for bucket in [b for b in self.hour if b + HOUR_BUCKET <= now - HOUR]:
            del self.hour[bucket]
        for bucket in [b for b in self.day if b + DAY_BUCKET <= now - DAY]:
            del self.day[bucket]

    def counts(self, now: float) -> tuple[int, int]:
        self.expire(now)
        return sum(self.hour.values()) + self.reserved, sum(self.day.values()) + self.reserved

    def add(self, now: float, count: int) -> None:
        minute = int(now // HOUR_BUCKET) * HOUR_BUCKET
        slot = int(now // DAY_BUCKET) * DAY_BUCKET
        self.hour[minute] = self.hour.get(minute, 0) + count
        self.day[slot] = self.day.get(slot, 0) + count

    def idle(self, now: float) -> bool:
        self.expire(now)
        return not self.reserved and not self.hour and not self.day

    def first_refusal(self, reason: str, now: float) -> bool:
        window = DAY if reason in (PER_DAY, LOCAL_PER_DAY) else HOUR
        if self.notified.get(reason, float("-inf")) > now - window:
            return False
        self.notified[reason] = now
        return True


@dataclass(frozen=True, slots=True)
class Verdict:
    """A refused reservation: `reason` is one of the reason constants; `first` marks the first per key and window."""
    reason: str
    first: bool = False


@dataclass(slots=True)
class Reservation:
    """One message's reservations. Commit at final acceptance, release on every other exit."""
    key: LimitKey
    keyed: int = 0
    local: int = 0
    measured: bool = True
    closed: bool = False


class QuotaStore:
    """Rolling windows per limit key plus the local cap. Thread-safe; every method takes the current time."""

    def __init__(self, limits: SendingLimitSettings, capacity: int = KEY_CAPACITY) -> None:
        self.limits = limits
        self.capacity = capacity
        self._keys: dict[str, _Window] = {}
        self._local = _Window()
        self._lock = threading.Lock()
        self._last_sweep = float("-inf")
        self._last_full_warning = float("-inf")

    def begin(self, key: LimitKey) -> Reservation:
        return Reservation(key)

    def reserve(self, reservation: Reservation, now: float, *, observe: bool) -> Verdict | None:
        """Reserve one recipient on the key and, for local mail, the local cap; both or neither.

        A full key store refuses a new key. In observe mode that key stays unmeasured and the local cap still counts.
        """
        key = reservation.key
        with self._lock:
            window = self._window(key.text, now)
            if window is None and not observe:
                return Verdict(KEY_STORE_FULL, self._full_warning_due(now))
            if window is None:
                reservation.measured = False
            else:
                hour, day = window.counts(now)
                if hour >= key.per_hour:
                    return Verdict(PER_HOUR, window.first_refusal(PER_HOUR, now))
                if day >= key.per_day:
                    return Verdict(PER_DAY, window.first_refusal(PER_DAY, now))
            if key.local:
                hour, day = self._local.counts(now)
                if hour >= self.limits.local_per_hour:
                    return Verdict(LOCAL_PER_HOUR, self._local.first_refusal(LOCAL_PER_HOUR, now))
                if day >= self.limits.local_per_day:
                    return Verdict(LOCAL_PER_DAY, self._local.first_refusal(LOCAL_PER_DAY, now))
                self._local.reserved += 1
                reservation.local += 1
            if window is None:
                return Verdict(KEY_STORE_FULL, self._full_warning_due(now))
            window.reserved += 1
            reservation.keyed += 1
            return None

    def commit(self, reservation: Reservation, now: float) -> None:
        with self._lock:
            if reservation.closed:
                return
            reservation.closed = True
            window = self._keys.get(reservation.key.text)
            if reservation.keyed and window is not None:
                window.reserved -= reservation.keyed
                window.add(now, reservation.keyed)
            if reservation.local:
                self._local.reserved -= reservation.local
                self._local.add(now, reservation.local)

    def release(self, reservation: Reservation) -> None:
        with self._lock:
            if reservation.closed:
                return
            reservation.closed = True
            window = self._keys.get(reservation.key.text)
            if reservation.keyed and window is not None:
                window.reserved -= reservation.keyed
            if reservation.local:
                self._local.reserved -= reservation.local

    def counts(self, text: str, now: float) -> tuple[int, int]:
        """Committed plus reserved recipients of a key in the rolling hour and day."""
        with self._lock:
            window = self._keys.get(text)
            return window.counts(now) if window is not None else (0, 0)

    def local_counts(self, now: float) -> tuple[int, int]:
        with self._lock:
            return self._local.counts(now)

    def __len__(self) -> int:
        with self._lock:
            return len(self._keys)

    def _window(self, text: str, now: float) -> _Window | None:
        window = self._keys.get(text)
        if window is not None:
            return window
        if len(self._keys) >= self.capacity:
            self._sweep(now)
            if len(self._keys) >= self.capacity:
                return None
        window = self._keys[text] = _Window()
        return window

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < SWEEP_INTERVAL:
            return
        self._last_sweep = now
        for text in [t for t, w in self._keys.items() if w.idle(now)]:
            del self._keys[text]

    def _full_warning_due(self, now: float) -> bool:
        if now - self._last_full_warning < FULL_WARNING_INTERVAL:
            return False
        self._last_full_warning = now
        return True
