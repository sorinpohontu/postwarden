"""Sending-limit window snapshots on disk: strict load, atomic save, periodic saver."""
from __future__ import annotations

import json
import os
import stat
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .quota import QuotaStore, StateError

STATE_FILE = "/var/lib/postwarden/limits.json"
MAX_STATE_BYTES = 64 * 1024 * 1024
SAVE_INTERVAL = 60


@dataclass(frozen=True, slots=True)
class LoadResult:
    status: str
    keys: int = 0
    age: int | None = None
    detail: str | None = None


def load(store: QuotaStore, path: str = STATE_FILE, now: float | None = None) -> LoadResult:
    """Restore the store from a snapshot. Any problem leaves the windows empty and says why."""
    now = time.time() if now is None else now
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return LoadResult("missing")
    except OSError as exc:
        return LoadResult("invalid", detail=f"unreadable: {exc.strerror}")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return LoadResult("invalid", detail="not a regular file")
        if info.st_size > MAX_STATE_BYTES:
            return LoadResult("invalid", detail=f"oversized: {info.st_size} bytes")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(MAX_STATE_BYTES + 1)
    except OSError as exc:
        return LoadResult("invalid", detail=f"unreadable: {exc.strerror}")
    finally:
        os.close(fd)
    if len(raw) > MAX_STATE_BYTES:
        return LoadResult("invalid", detail="oversized")
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
        keys = store.restore(data, now)
    except (UnicodeDecodeError, ValueError) as exc:
        detail = str(exc) if isinstance(exc, StateError) else "not valid JSON"
        return LoadResult("invalid", detail=detail)
    return LoadResult("loaded", keys=keys, age=max(0, int(now - data["saved"])))


def _reject_constant(name: str):
    raise ValueError(f"invalid number {name}")


def save(store: QuotaStore, path: str = STATE_FILE, now: float | None = None) -> float:
    """Write a snapshot: temporary file, fsync, rename, directory fsync. Returns the snapshot time."""
    now = time.time() if now is None else now
    payload = json.dumps(store.export(now), separators=(",", ":")).encode("ascii")
    directory = os.path.dirname(path) or "."
    temporary = os.path.join(directory, "." + os.path.basename(path) + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return now


class Saver:
    """Saves the store every interval until stopped; a failure is reported and retried at the next interval."""

    def __init__(self, store: QuotaStore, on_failure: Callable[[str, int | None], None], path: str = STATE_FILE,
                 interval: float = SAVE_INTERVAL, last_saved: float | None = None) -> None:
        self.store = store
        self.path = path
        self.interval = interval
        self.on_failure = on_failure
        self.last_saved = last_saved
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="limit-state", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def save_now(self) -> bool:
        try:
            self.last_saved = save(self.store, self.path)
            return True
        except (OSError, ValueError) as exc:
            detail = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
            self.on_failure(detail, self.snapshot_age())
            return False

    def snapshot_age(self) -> int | None:
        return None if self.last_saved is None else max(0, int(time.time() - self.last_saved))

    def stop(self) -> bool:
        """Stop the timer and save once more."""
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join()
        return self.save_now()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.save_now()
