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

STATE_VERSION = 1
MAX_KEY_TEXT = 1024
MAX_BUCKET_COUNT = 10**9
CLOCK_SKEW = 300


class StateError(ValueError):
    """A window snapshot that cannot be restored; the store starts empty."""


@dataclass(frozen=True, slots=True)
class LimitKey:
    """What one message counts against, and its effective limits."""
    text: str
    per_hour: int
    per_day: int
    multiplier: float
    local: bool


def _buckets(window: _Window) -> dict:
    return {"hour": sorted([b, c] for b, c in window.hour.items()),
            "day": sorted([b, c] for b, c in window.day.items())}


def _window_from(value, now: float) -> _Window:
    if not isinstance(value, dict) or set(value) != {"hour", "day"}:
        raise StateError("unexpected window structure")
    window = _Window()
    for name, size, span in (("hour", HOUR_BUCKET, HOUR), ("day", DAY_BUCKET, DAY)):
        entries = value[name]
        if not isinstance(entries, list) or len(entries) > span // size + 1:
            raise StateError(f"invalid {name} buckets")
        target = getattr(window, name)
        for entry in entries:
            if (not isinstance(entry, list) or len(entry) != 2
                    or not all(isinstance(v, int) and not isinstance(v, bool) for v in entry)):
                raise StateError(f"invalid {name} bucket")
            start, count = entry
            if start % size or not 0 < count <= MAX_BUCKET_COUNT or start in target:
                raise StateError(f"invalid {name} bucket")
            if start <= now:
                target[start] = count
    window.expire(now)
    return window


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

    def key_count(self) -> int:
        with self._lock:
            return len(self._keys)

    def export(self, now: float) -> dict:
        """Committed counts only; in-flight reservations are not part of a snapshot."""
        with self._lock:
            keys = {}
            for text, window in self._keys.items():
                window.expire(now)
                if window.hour or window.day:
                    keys[text] = _buckets(window)
            self._local.expire(now)
            return {"version": STATE_VERSION, "saved": int(now), "local": _buckets(self._local), "keys": keys}

    def restore(self, data, now: float) -> int:
        """Replace all windows with a snapshot; raises StateError and changes nothing when any part is invalid."""
        if not isinstance(data, dict) or set(data) != {"version", "saved", "local", "keys"}:
            raise StateError("unexpected structure")
        if data["version"] != STATE_VERSION or isinstance(data["version"], bool):
            raise StateError(f"unsupported version {data['version']!r}")
        saved = data["saved"]
        if not isinstance(saved, int) or isinstance(saved, bool) or saved > now + CLOCK_SKEW:
            raise StateError("invalid or future save time")
        keys = data["keys"]
        if not isinstance(keys, dict):
            raise StateError("keys is not a table")
        if len(keys) > self.capacity:
            raise StateError(f"{len(keys)} keys, more than {self.capacity}")
        restored = {}
        for text, value in keys.items():
            if not text or len(text) > MAX_KEY_TEXT:
                raise StateError("invalid key")
            window = _window_from(value, now)
            if window.hour or window.day:
                restored[text] = window
        local = _window_from(data["local"], now)
        with self._lock:
            reserved = {t: w.reserved for t, w in self._keys.items() if w.reserved}
            for text, count in reserved.items():
                restored.setdefault(text, _Window()).reserved = count
            local.reserved = self._local.reserved
            self._keys, self._local = restored, local
        return len(restored)

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
