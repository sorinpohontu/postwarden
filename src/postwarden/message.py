"""Byte-preserving message capture with size budgets. Bytes are never re-serialized through a MIME parser."""
from __future__ import annotations

import tempfile

from .config import LimitSettings

SPOOL_MEMORY_LIMIT = 1024 * 1024


class MessageCapture:
    def __init__(self, limits: LimitSettings, spool_dir: str | None = None, leading_space: bool = True):
        self.limits = limits
        self.leading_space = leading_space
        self.headers: list[tuple[bytes, bytes]] = []
        self.header_bytes = 0
        self.body_bytes = 0
        self.over_limit: str | None = None
        self._body = tempfile.SpooledTemporaryFile(max_size=SPOOL_MEMORY_LIMIT, dir=spool_dir, prefix="pm-")

    def add_header(self, name: bytes, value: bytes) -> None:
        if self.over_limit:
            return
        size = len(name) + len(value) + 3
        if len(self.headers) + 1 > self.limits.max_headers:
            self.over_limit = "max_headers"
        elif self.header_bytes + size > self.limits.max_header_bytes:
            self.over_limit = "max_header_bytes"
        else:
            self.headers.append((name, value))
            self.header_bytes += size

    def add_body(self, chunk: bytes) -> None:
        if self.over_limit:
            return
        if self.body_bytes + len(chunk) + self.header_bytes > self.limits.message_bytes:
            self.over_limit = "message_bytes"
            return
        self._body.write(chunk)
        self.body_bytes += len(chunk)

    def header_values(self, name: bytes) -> list[bytes]:
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    def message_bytes(self) -> bytes:
        separator = b":" if self.leading_space else b": "
        parts = []
        for name, value in self.headers:
            value = value.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            parts.append(name + separator + value + b"\r\n")
        parts.append(b"\r\n")
        self._body.seek(0)
        parts.append(self._body.read())
        return b"".join(parts)

    def close(self) -> None:
        try:
            self._body.close()
        except Exception:
            pass
