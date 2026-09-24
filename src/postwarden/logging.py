"""Structured, bounded event logging to syslog (mail facility) or stderr."""
from __future__ import annotations

import logging
import logging.handlers
import sys

from .config import LoggingSettings

MAX_FIELD = 256
_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}


def _escape(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if len(text) > MAX_FIELD:
        text = text[:MAX_FIELD] + "..."
    if text and not any(ch in ' ="\\' or ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return text
    out = []
    for ch in text:
        if ord(ch) < 32 or ord(ch) == 127:
            out.append("\\x%02x" % ord(ch))
        elif ch in ('"', "\\"):
            out.append("\\" + ch)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def format_event(fields: dict) -> str:
    return " ".join(f"{key}={_escape(value)}" for key, value in fields.items() if value is not None)


class EventLogger:
    def __init__(self, settings: LoggingSettings):
        self.settings = settings
        self._log = logging.getLogger(settings.identifier)
        self._log.propagate = False
        self._log.handlers.clear()
        if settings.backend == "syslog":
            facility = logging.handlers.SysLogHandler.facility_names[settings.facility]
            handler = logging.handlers.SysLogHandler(address="/dev/log", facility=facility)
            handler.setFormatter(logging.Formatter(f"{settings.identifier}[%(process)d]: %(message)s"))
        else:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter(f"{settings.identifier}: %(message)s"))
        self._log.addHandler(handler)
        self._log.setLevel(_LEVELS[settings.level])

    def event(self, level: str = "info", **fields) -> None:
        self._log.log(_LEVELS[level], format_event(fields))

    def lifecycle(self, **fields) -> None:
        """Info-priority record emitted whatever logging.level is set to."""
        self._log.handle(self._log.makeRecord(self._log.name, logging.INFO, __file__, 0, format_event(fields), None, None))

    def info(self, **fields) -> None:
        self.event("info", **fields)

    def warning(self, **fields) -> None:
        self.event("warning", **fields)

    def error(self, **fields) -> None:
        self.event("error", **fields)

    def debug(self, **fields) -> None:
        self.event("debug", **fields)
