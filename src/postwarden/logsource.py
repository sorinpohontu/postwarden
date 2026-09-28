"""Where `lookup` and `stats` read postwarden's log lines, and how far that source can be trusted."""
from __future__ import annotations

import datetime
import glob
import gzip
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Iterator

UNIT = "postwarden.service"
TAG = "postwarden"
MAIL_LOGS = "/var/log/mail.log*"


class SourceError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Source:
    kind: str
    since: str | None = None
    pattern: str | None = None
    fallback: bool = False

    @property
    def verified(self) -> bool:
        return self.kind == "journal"

    def describe(self) -> str:
        if self.kind == "journal":
            return f"journal, unit {UNIT}, since {self.since} (verified)"
        if self.kind == "journal_tag":
            return f"journal, tag {TAG} (--any-source), since {self.since} (unverified: any local user can write this tag)"
        reason = "journalctl not found; " if self.fallback else ""
        return f"files {self.pattern} ({reason}unverified: any local user can write postwarden lines to syslog)"

    def journal_args(self) -> list[str]:
        match = [f"_SYSTEMD_UNIT={UNIT}"] if self.kind == "journal" else ["-t", TAG]
        return ["journalctl", "--no-pager", "-q", "-o", "short-iso", *match, "--since", self.since or ""]


def select(*, since: str, files: str | None, any_source: bool = False) -> Source:
    if files is not None:
        return Source("files", pattern=files)
    if not shutil.which("journalctl"):
        return Source("files", pattern=MAIL_LOGS, fallback=True)
    return Source("journal_tag" if any_source else "journal", since=since)


def lines(source: Source) -> Iterator[str]:
    if source.kind == "files":
        yield from _file_lines(source.pattern or MAIL_LOGS)
        return
    proc = subprocess.Popen(source.journal_args(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, errors="replace")
    assert proc.stdout is not None
    yield from proc.stdout
    stderr = proc.stderr.read() if proc.stderr else ""
    if proc.wait() != 0:
        raise SourceError(f"journalctl failed: {stderr.strip() or proc.returncode}")


def _file_lines(pattern: str) -> Iterator[str]:
    paths = sorted(glob.glob(pattern), reverse=True)
    if not paths:
        raise SourceError(f"no log files match {pattern}")
    for path in paths:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", errors="replace") as fh:
            yield from (line for line in fh if TAG in line)


_RELATIVE = re.compile(r"-(\d+)\s*(s|sec|m|min|h|d|w|days?|hours?|weeks?)")
_SECONDS = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hour": 3600, "hours": 3600,
            "d": 86400, "day": 86400, "days": 86400, "w": 604800, "week": 604800, "weeks": 604800}


def since_timestamp(since: str, now: float | None = None) -> float | None:
    """The start of a `--since` value in the forms postwarden documents; None for anything else."""
    now = time.time() if now is None else now
    text = since.strip()
    match = _RELATIVE.fullmatch(text)
    if match:
        return now - int(match.group(1)) * _SECONDS[match.group(2)]
    try:
        moment = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment.timestamp() if moment.tzinfo else moment.astimezone().timestamp()


def journal_start() -> float | None:
    """Time of the oldest entry in the journal, or None when it cannot be read."""
    try:
        proc = subprocess.Popen(["journalctl", "--no-pager", "-q", "-o", "short-unix"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    except OSError:
        return None
    try:
        first = proc.stdout.readline() if proc.stdout else ""
    finally:
        proc.kill()
        proc.wait()
    try:
        return float(first.split()[0])
    except (IndexError, ValueError):
        return None


def coverage_note(source: Source, start: float | None, now: float | None = None) -> str | None:
    """One line when `--since` reaches before the journal's oldest entry; the source is never switched."""
    if source.kind == "files" or start is None:
        return None
    requested = since_timestamp(source.since or "", now)
    if requested is None or requested >= start:
        return None
    began = datetime.datetime.fromtimestamp(start).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    return (f"the journal starts at {began}, after --since {source.since}; older lines may be in syslog files: "
            f"--file '{MAIL_LOGS}' (unverified)")
