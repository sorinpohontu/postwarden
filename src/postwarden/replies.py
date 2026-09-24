"""Validated per-rule SMTP replies. Reply wording is configurable; the decision class is not."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class ReplyClass(Enum):
    REJECT = "reject"
    DEFER = "defer"


REJECT_CODES = frozenset({550, 554})
DEFER_CODES = frozenset({450, 451, 452})
MAX_REPLY_BYTES = 510
REFERENCE_SUFFIX_BYTES = len(" (ref 0123456789ab)")
_ENHANCED = re.compile(r"^([245])\.(\d{1,3})\.(\d{1,3})$")


@dataclass(frozen=True, slots=True)
class Reply:
    smtp_code: int
    enhanced_code: str
    message: str

    @property
    def reply_class(self) -> ReplyClass:
        return ReplyClass.REJECT if self.smtp_code in REJECT_CODES else ReplyClass.DEFER

    def with_reference(self, reference: str | None) -> "Reply":
        return Reply(self.smtp_code, self.enhanced_code, f"{self.message} (ref {reference})") if reference else self

    def render(self) -> str:
        return f"{self.smtp_code} {self.enhanced_code} {self.message}"


DEFAULT_REPLIES: dict[str, Reply] = {
    "protected_recipient": Reply(550, "5.7.1", "Recipient address rejected: Access denied"),
    "self_sender": Reply(550, "5.7.1", "Sender address rejected: Access denied"),
    "authentication_failed": Reply(550, "5.7.26", "Message rejected: Sender domain authentication failed (SPF, DKIM)"),
    "invalid_from": Reply(550, "5.7.1", "Message rejected: From header does not conform to RFC 5322"),
    "invalid_recipient": Reply(550, "5.1.3", "Recipient address rejected: Bad address syntax"),
    "temporary_failure": Reply(451, "4.7.1", "Service unavailable - try again later"),
}

REPLY_CLASSES: dict[str, ReplyClass] = {
    name: reply.reply_class for name, reply in DEFAULT_REPLIES.items()
}


def validate_reply(name: str, reply: Reply) -> list[str]:
    errors: list[str] = []
    expected = REPLY_CLASSES.get(name)
    if expected is None:
        return [f"responses.{name}: unknown response key"]
    allowed = REJECT_CODES if expected is ReplyClass.REJECT else DEFER_CODES
    if reply.smtp_code not in allowed:
        errors.append(f"responses.{name}.smtp_code: {reply.smtp_code} is not one of {sorted(allowed)}")
    match = _ENHANCED.match(reply.enhanced_code)
    if not match:
        errors.append(f"responses.{name}.enhanced_code: {reply.enhanced_code!r} is not class.subject.detail")
    elif int(match.group(1)) != reply.smtp_code // 100:
        errors.append(f"responses.{name}.enhanced_code: class {match.group(1)} does not match {reply.smtp_code}")
    message = reply.message
    if not message or not message.isascii() or not message.isprintable():
        errors.append(f"responses.{name}.message: must be nonempty printable ASCII without control characters")
    if len(reply.render().encode("ascii", "replace")) + REFERENCE_SUFFIX_BYTES > MAX_REPLY_BYTES:
        errors.append(f"responses.{name}.message: complete reply (with its reference) exceeds {MAX_REPLY_BYTES} bytes")
    return errors
