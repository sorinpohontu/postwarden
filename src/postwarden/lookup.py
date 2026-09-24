"""Find the log lines for a reply reference (the `mid` field)."""
from __future__ import annotations

import glob
import gzip
import re
import shutil
import subprocess
from typing import Iterable, Iterator

MAIL_LOGS = "/var/log/mail.log*"
_REF = re.compile(r"[0-9a-f]{12}")


class LookupFailed(Exception):
    pass


def normalize_ref(text: str) -> str:
    ref = text.strip().strip("()").strip()
    if ref.lower().startswith("ref"):
        ref = ref[3:].strip()
    if ref.startswith("mid="):
        ref = ref[4:]
    ref = ref.lower()
    if not _REF.fullmatch(ref):
        raise LookupFailed(f"{text!r} is not a reference: expected the 12 hex digits after 'ref' in the reply")
    return ref


def matching(lines: Iterable[str], ref: str) -> Iterator[str]:
    token = re.compile(rf"(?:^|\s)mid={ref}(?:\s|$)")
    return (line.rstrip("\n") for line in lines if token.search(line))


def journal_lines(since: str) -> Iterator[str]:
    proc = subprocess.Popen(["journalctl", "--no-pager", "-o", "short-iso", "-t", "postwarden", "--since", since],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    assert proc.stdout is not None
    yield from proc.stdout
    stderr = proc.stderr.read() if proc.stderr else ""
    if proc.wait() != 0:
        raise LookupFailed(f"journalctl failed: {stderr.strip() or proc.returncode}")


def file_lines(pattern: str) -> Iterator[str]:
    paths = sorted(glob.glob(pattern), reverse=True)
    if not paths:
        raise LookupFailed(f"no log files match {pattern}")
    for path in paths:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", errors="replace") as fh:
            yield from (line for line in fh if "postwarden" in line)


def lookup(ref: str, *, since: str, files: str | None) -> list[str]:
    if files is None and shutil.which("journalctl"):
        return list(matching(journal_lines(since), ref))
    return list(matching(file_lines(files or MAIL_LOGS), ref))
