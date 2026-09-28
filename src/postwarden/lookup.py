"""Find the log lines for a reply reference (the `mid` field)."""
from __future__ import annotations

import re
from typing import Iterable, Iterator

from .logsource import Source, SourceError, lines

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


def lookup(ref: str, source: Source) -> list[str]:
    try:
        return list(matching(lines(source), ref))
    except SourceError as exc:
        raise LookupFailed(str(exc)) from None
