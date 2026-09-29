"""Totals and sender ranking counted from postwarden's own log lines. Pure: lines in, report out."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable

from .config import LOGIN_PREFIX, NULL_SENDER_KEY, SendingLimitSettings
from .textbox import box, header

_PREFIX = re.compile(r"\bpostwarden(?:\[\d+\])?: ")
_FIELD = re.compile(r'([a-z_]+)=("(?:[^"\\]|\\.)*"|\S*)')
_ESCAPE = re.compile(r"\\(x[0-9a-f]{2}|.)")
_LEVELS = ("debug", "info", "warning", "error")
DELIVERED_ACTIONS = ("accept", "would_reject", "would_defer")


def _unescape(value: str) -> str:
    if not value.startswith('"'):
        return value
    return _ESCAPE.sub(lambda m: chr(int(m.group(1)[1:], 16)) if m.group(1).startswith("x") and len(m.group(1)) == 3
                       else m.group(1), value[1:-1])


def parse_line(line: str) -> tuple[str, dict[str, str]] | None:
    """(timestamp text, fields) of a postwarden event line; None for anything else."""
    match = _PREFIX.search(line)
    if not match:
        return None
    fields = {key: _unescape(value) for key, value in _FIELD.findall(line[match.end():].rstrip("\n"))}
    if "action" not in fields and "event" not in fields:
        return None
    head = line[:match.start()].split()
    stamp = " ".join(head[:3]) if head and head[0].isalpha() else (head[0] if head else "")
    return stamp, fields


def _int(fields: dict, name: str) -> int:
    try:
        return max(0, int(fields.get(name, "0")))
    except ValueError:
        return 0


@dataclass(slots=True)
class Counts:
    messages: int = 0
    delivered: int = 0
    allowed: int = 0
    unmeasured: int = 0
    limit_deferred: int = 0
    limit_would_defer: int = 0

    def add(self, other: "Counts") -> None:
        for name in self.__slots__:
            setattr(self, name, getattr(self, name) + getattr(other, name))

    def as_dict(self) -> dict:
        return {name: getattr(self, name) for name in self.__slots__}


@dataclass(slots=True)
class Tally:
    lines: int = 0
    totals: Counts = field(default_factory=Counts)
    refusals: dict[tuple[str, str, str, str], int] = field(default_factory=dict)
    senders: dict[str, dict[str | None, Counts]] = field(default_factory=dict)
    starts: list[tuple[str, str]] = field(default_factory=list)
    limits_off: bool = False
    first: str | None = None
    last: str | None = None

    def sender(self, key: str, domain: str | None) -> Counts:
        return self.senders.setdefault(key, {}).setdefault(domain, Counts())


def _sender_domain(fields: dict) -> str | None:
    sender = fields.get("sender", "")
    return sender.rpartition("@")[2].lower() or None if "@" in sender else None


def tally(lines: Iterable[str]) -> Tally:
    result = Tally()
    seen: set[tuple[str, ...]] = set()
    for line in lines:
        parsed = parse_line(line)
        if parsed is None:
            continue
        stamp, fields = parsed
        result.lines += 1
        result.first = result.first or stamp
        result.last = stamp
        if fields.get("event") == "start":
            result.starts.append((stamp, fields.get("logging_level", "")))
            continue
        action, stage = fields.get("action"), fields.get("stage")
        key = fields.get("limit_key")
        domain = _sender_domain(fields) if key and key.startswith(LOGIN_PREFIX) else None
        if action in ("reject", "defer", "would_reject", "would_defer"):
            scope = "recipient" if stage == "rcpt" else "message"
            ident = (action, fields.get("rule", "-"), fields.get("reason", "-"), scope)
            once = (fields.get("mid", ""), *ident) if scope == "message" and fields.get("mid") else None
            repeated = once in seen
            if once:
                seen.add(once)
            if not repeated:
                result.refusals[ident] = result.refusals.get(ident, 0) + 1
            if not repeated and key and fields.get("rule") == "sending_limit" and fields.get("reason") != "key_store_full":
                counts = result.sender(key, domain)
                if action == "defer":
                    counts.limit_deferred += 1
                elif action == "would_defer":
                    counts.limit_would_defer += 1
        if stage != "eom" or action not in DELIVERED_ACTIONS or "rcpts" not in fields:
            continue
        delivered = max(0, _int(fields, "rcpts") - _int(fields, "rejected_rcpts") - _int(fields, "deferred_rcpts"))
        observed = _int(fields, "would_rejected_rcpts") + _int(fields, "would_deferred_rcpts")
        message = Counts(messages=1, delivered=delivered,
                         allowed=0 if action != "accept" else max(0, delivered - observed))
        if fields.get("limit_measured") == "no":
            message.unmeasured = delivered
        if fields.get("limit_measured") == "off":
            result.limits_off = True
        result.totals.add(message)
        if key:
            result.sender(key, domain).add(message)
    return result


def completeness(result: Tally) -> list[str]:
    """Reasons the period may miss lines; empty only when every start line in it logged at info or below."""
    if not result.starts:
        return ["no daemon start line in the period: the logging level of the earliest lines is unknown"]
    notes = []
    unknown = [stamp for stamp, level in result.starts if not level]
    if len(unknown) == 1:
        notes.append(f"start at {unknown[0]} did not log its logging level: decisions may be missing after it")
    elif unknown:
        notes.append(f"{len(unknown)} starts between {unknown[0]} and {unknown[-1]} did not log their logging level: "
                     "decisions may be missing after them")
    for stamp, level in result.starts:
        if level and level not in _LEVELS[:2]:
            notes.append(f"logging level {level} from {stamp}: decisions below it were not logged")
    return notes


def _limits_for(limits: SendingLimitSettings, key: str, domain: str | None) -> tuple[int, int]:
    if key == NULL_SENDER_KEY:
        return limits.scaled(limits.multiplier_for(null_sender=True))
    if key.startswith(LOGIN_PREFIX):
        return limits.scaled(limits.multiplier_for(login=key[len(LOGIN_PREFIX):], domain=domain))
    if "@" in key:
        return limits.scaled(limits.multiplier_for(account=key, domain=key.rpartition("@")[2]))
    try:
        ipaddress.ip_address(key)
    except ValueError:
        return limits.scaled(1.0)
    return limits.scaled(limits.multiplier_for(relay=key))


def ranking(result: Tally, limits: SendingLimitSettings, top: int) -> list[dict]:
    rows = []
    for key, by_domain in result.senders.items():
        total = Counts()
        for counts in by_domain.values():
            total.add(counts)
        row = {"limit_key": key, **total.as_dict()}
        own_multiplier = key.startswith(LOGIN_PREFIX) and key[len(LOGIN_PREFIX):] in limits.logins
        if key.startswith(LOGIN_PREFIX) and not own_multiplier:
            row["per_hour"] = row["per_day"] = None
            row["by_sender_domain"] = []
            for domain, counts in sorted(by_domain.items(), key=lambda item: (-item[1].delivered, item[0] or "")):
                per_hour, per_day = _limits_for(limits, key, domain)
                row["by_sender_domain"].append({"sender_domain": domain, **counts.as_dict(),
                                                "per_hour": per_hour, "per_day": per_day})
            if len({(d["per_hour"], d["per_day"]) for d in row["by_sender_domain"]}) == 1:
                row["per_hour"], row["per_day"] = (row["by_sender_domain"][0]["per_hour"],
                                                   row["by_sender_domain"][0]["per_day"])
        else:
            row["per_hour"], row["per_day"] = _limits_for(limits, key, None)
        rows.append(row)
    rows.sort(key=lambda r: (-r["delivered"], -r["messages"], r["limit_key"]))
    return rows[:top]


def report(result: Tally, limits: SendingLimitSettings, *, source: dict, config: str, top: int,
           notes: list[str]) -> dict:
    """The `--json` document; its field names are a documented interface."""
    def refusal_rows(observed: bool) -> list[dict]:
        rows = [{"action": action, "rule": rule, "reason": reason, "scope": scope, "count": count}
                for (action, rule, reason, scope), count in result.refusals.items()
                if action.startswith("would_") == observed]
        return sorted(rows, key=lambda r: (-r["count"], r["rule"], r["reason"], r["scope"], r["action"]))

    gaps = completeness(result)
    if result.limits_off:
        notes = notes + ["sending limits were off for some or all of the period (limit_measured=off)"]
    totals = result.totals.as_dict()
    return {
        "source": source,
        "config": config,
        "complete": not gaps,
        "notes": gaps + notes,
        "lines": result.lines,
        "totals": {name: totals[name] for name in ("messages", "delivered", "allowed", "unmeasured")},
        "refusals": refusal_rows(False),
        "observed": refusal_rows(True),
        "senders": ranking(result, limits, top),
        "senders_total": len(result.senders),
    }


def _limit(per_hour: int | None, per_day: int | None) -> str | None:
    return None if per_hour is None else f"{per_hour}/{per_day}"


def render(data: dict, period: tuple[str | None, str | None] = (None, None)) -> list[str]:
    source, t = data["source"], data["totals"]
    first, last = period
    span = "no postwarden lines" if first is None else f"{first} to {last}"
    out = header(data.get("version", "-"), data.get("host", "-"), data["config"],
                 [[["Source", source["description"]], ["Period", span],
                   ["Complete", "yes" if data["complete"] else "no, see the notes below"]]])
    out += [f"note: {note}" for note in data["notes"]]
    show_allowed = t["allowed"] != t["delivered"]
    totals = [["messages accepted", t["messages"]], ["recipients delivered", t["delivered"]]]
    if show_allowed:
        totals.append(["recipients allowed", t["allowed"]])
    if t["unmeasured"]:
        totals.append(["not measured", t["unmeasured"]])
    out += ["", "Totals"] + box(["measure", "count"], totals)

    headers = ["action", "rule", "reason", "per", "count"]
    out += ["", "Refusals sent"]
    rows = [[r["action"], r["rule"], r["reason"], r["scope"], r["count"]] for r in data["refusals"]]
    out += box(headers, rows) if rows else ["none"]
    if data["observed"]:
        rows = [[r["action"], r["rule"], r["reason"], r["scope"], r["count"]] for r in data["observed"]]
        out += ["", "Observe mode: refusals not sent"] + box(headers, rows)

    out += ["", f"Senders by recipients delivered (top {len(data['senders'])} of {data['senders_total']})"]
    entries = []
    for s in data["senders"]:
        entries.append((s["limit_key"], s))
        entries += [(f"  from {d['sender_domain'] or '<unknown>'}", d) for d in s.get("by_sender_domain", [])]
    optional = [("allowed", "allowed", show_allowed)]
    optional += [(name, key, any(e[key] for _, e in entries)) for name, key in
                 (("unmeasured", "unmeasured"), ("limit deferred", "limit_deferred"),
                  ("would defer", "limit_would_defer"))]
    shown = [(name, key) for name, key, visible in optional if visible]
    headers = ["limit key", "messages", "delivered"] + [name for name, _ in shown] + ["limit h/d"]
    rows = [[label, e["messages"], e["delivered"], *(e[key] for _, key in shown), _limit(e["per_hour"], e["per_day"])]
            for label, e in entries]
    out += box(headers, rows) if rows else ["none"]

    out += ["", "Counts are totals for the period; delivered means handed on to Postfix."]
    if not show_allowed:
        out.append("Recipients allowed equal delivered: no observe-mode refusals.")
    out.append("Columns that are 0 for every sender are left out.")
    out.append("Measures: Statistics in /etc/postwarden/docs/Operations.md; --json for every field.")
    return out
