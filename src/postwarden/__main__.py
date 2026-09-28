"""Command-line entry point. Configuration commands import no milter, SPF or DKIM libraries."""
from __future__ import annotations

import argparse
import dataclasses
import json
import socket
import sys
import time

from . import DEFAULT_CONFIG_PATH, __version__
from .config import ConfigError, Settings, describe, load_settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="postwarden", description="Postfix policy milter")
    parser.add_argument("--version", action="version", version=f"postwarden {__version__}")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                        help=f"configuration file (default: {DEFAULT_CONFIG_PATH})")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-config", help="validate the configuration file and report every problem")
    show = sub.add_parser("show-config", help="print the effective configuration")
    show.add_argument("--json", action="store_true", help="machine-readable output")
    run = sub.add_parser("run", help="run the milter daemon in the foreground")
    run.add_argument("--stderr", action="store_true", help="log to standard error instead of syslog (debugging)")
    run.add_argument("--socket", help="listen on this socket instead of the fixed one, e.g. unix:/tmp/pwtest/policy.sock "
                                      "(a second instance for load tests; Postfix keeps using the normal one)")
    find = sub.add_parser("lookup", help="show the log lines for a reply reference such as (ref 3f9c2a7b41d0)")
    find.add_argument("ref", help="the reference from the SMTP reply or bounce")
    find.add_argument("--since", default="-7d", help="how far back journalctl searches (default: -7d)")
    find.add_argument("--file", help="search these syslog files instead of the journal (glob, e.g. '/var/log/mail.log*'); "
                                     "their lines cannot be verified")
    find.add_argument("--any-source", action="store_true",
                      help="match the postwarden tag instead of the postwarden.service unit, for a daemon started by hand")
    stats = sub.add_parser("stats", help="totals, refusals and top senders counted from the log")
    stats.add_argument("--since", help="how far back the journal is read (default: -24h); not with --file")
    stats.add_argument("--file", help="read these syslog files instead of the journal (glob); whole-file totals, "
                                      "unverified")
    stats.add_argument("--any-source", action="store_true",
                       help="match the postwarden tag instead of the postwarden.service unit")
    stats.add_argument("--top", type=int, default=20, help="senders to list (default: 20)")
    stats.add_argument("--json", action="store_true", help="machine-readable output")
    stats.add_argument("--config", default=argparse.SUPPRESS,
                       help="configuration whose sending limits are shown next to each sender")
    sim = sub.add_parser("simulate", help="show what postwarden would decide for given connection facts and message; "
                                          "nothing is sent")
    sim.add_argument("message", nargs="?", help="message file (.eml); without it only the RCPT stage is evaluated")
    sim.add_argument("--ingress", required=True, choices=("25", "587", "465", "local"),
                     help="port the message arrives on, or local for sendmail")
    sim.add_argument("--from", dest="sender", required=True, metavar="SENDER", help="envelope sender; <> for a bounce")
    sim.add_argument("--to", dest="recipients", action="append", required=True, metavar="RCPT",
                     help="envelope recipient (repeat for more)")
    sim.add_argument("--login", help="SASL login (587/465)")
    sim.add_argument("--peer", help="client IP address; required for 25, 587 and 465 (local: 127.0.0.1)")
    sim.add_argument("--helo", default="", help="HELO name (SPF for bounces)")
    sim.add_argument("--no-tls", action="store_true", help="the submission connection is not encrypted")
    sim.add_argument("--spf", choices=("pass", "fail", "none", "temperror"),
                     help="use this SPF result for the From domain instead of DNS")
    sim.add_argument("--dkim", choices=("pass", "fail", "none", "temperror"),
                     help="use this DKIM result for the From domain instead of DNS")
    sim.add_argument("--transport", help="Postfix transport of the recipients (default: locally delivered)")
    sim.add_argument("--config", default=argparse.SUPPRESS, help="configuration file to evaluate, e.g. a candidate")
    wait = sub.add_parser("wait-ready", help="wait until the configured milter socket accepts connections")
    wait.add_argument("--timeout", type=float, default=15.0, help="seconds to wait (default: 15)")
    return parser


def _with_postfix(settings: Settings, *, required: bool) -> tuple[Settings | None, str]:
    from .postfix import PostfixError, with_postfix
    try:
        resolved = with_postfix(settings)
    except PostfixError as exc:
        if not required and str(exc).startswith("postconf not found"):
            return settings, "Postfix settings not read: postconf not found"
        return None, str(exc)
    count = len(resolved.trust.mynetworks)
    return resolved, (f"from Postfix: {count} mynetworks {'entry' if count == 1 else 'entries'}, "
                      f"recipient_delimiter {resolved.trust.recipient_delimiter!r}")


def _protection_summary(settings: Settings) -> str:
    addresses, groups = settings.protection.counts()
    parts = [f"{addresses} protected address{'' if addresses == 1 else 'es'}"]
    if groups:
        parts.append(f"{groups} protected group{'' if groups == 1 else 's'}")
    return ", ".join(parts)


def cmd_check_config(args: argparse.Namespace) -> int:
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"{args.config}: {len(exc.errors)} problem(s)", file=sys.stderr)
        for error in exc.errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    resolved, note = _with_postfix(settings, required=False)
    if resolved is None:
        print(f"{args.config}: {note}", file=sys.stderr)
        return 1
    print(f"{args.config}: OK (schema {settings.schema_version}, mode {settings.mode}, "
          f"sending limits {settings.sending_limits.mode}, "
          f"{_protection_summary(settings)}; {note})")
    if note.startswith("from Postfix"):
        from .postfix import PostfixError, describe_rate_limits, rate_limit_warnings, read_rate_limits
        try:
            limits = read_rate_limits()
        except PostfixError as exc:
            print(f"Postfix rate limits not read: {exc}")
            return 0
        print(f"Postfix rate limits: {describe_rate_limits(limits)}")
        for warning in rate_limit_warnings(limits, settings.sending_limits):
            print(f"warning: {warning}")
    return 0


def _render(value, indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{key}:")
                lines.extend(_render(item, indent + 1))
            else:
                lines.append(f"{pad}{key}: {json.dumps(item)}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                lines.append(f"{pad}-")
                lines.extend(_render(item, indent + 1))
            else:
                lines.append(f"{pad}- {json.dumps(item)}")
    return lines


def cmd_show_config(args: argparse.Namespace) -> int:
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        for error in exc.errors:
            print(error, file=sys.stderr)
        return 1
    resolved, note = _with_postfix(settings, required=False)
    if resolved is None:
        print(note, file=sys.stderr)
        return 1
    data = describe(resolved)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print("\n".join(_render(data)))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        for error in exc.errors:
            print(error, file=sys.stderr)
        return 1
    resolved, note = _with_postfix(settings, required=True)
    if resolved is None:
        print(note, file=sys.stderr)
        return 1
    if args.stderr:
        resolved = dataclasses.replace(resolved, logging=dataclasses.replace(resolved.logging, backend="stderr"))
    if args.socket:
        if not args.socket.startswith(("unix:", "inet:", "inet6:")):
            print(f"--socket {args.socket}: expected unix:PATH, inet:PORT@HOST or inet6:PORT@HOST", file=sys.stderr)
            return 1
        resolved = dataclasses.replace(resolved, service=dataclasses.replace(resolved.service, socket=args.socket))
    from .milter import run_daemon
    return run_daemon(resolved)


def cmd_lookup(args: argparse.Namespace) -> int:
    from .logsource import coverage_note, journal_start, select
    from .lookup import LookupFailed, lookup, normalize_ref
    try:
        ref = normalize_ref(args.ref)
    except LookupFailed as exc:
        print(exc, file=sys.stderr)
        return 2
    source = select(since=args.since, files=args.file, any_source=args.any_source)
    print(f"source: {source.describe()}", file=sys.stderr)
    note = coverage_note(source, journal_start()) if source.kind != "files" else None
    if note:
        print(f"note: {note}", file=sys.stderr)
    try:
        found = lookup(ref, source)
    except (LookupFailed, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    if not found:
        hint = "; reading the journal may need root or the adm or systemd-journal group" if source.kind != "files" else ""
        print(f"no postwarden log line with mid={ref}{hint}", file=sys.stderr)
        return 1
    print("\n".join(found))
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    from .logsource import SourceError, coverage_note, journal_start, lines, select
    from .stats import render, report, tally
    if args.top < 1:
        print("--top must be at least 1", file=sys.stderr)
        return 2
    source = select(since=args.since or "-24h", files=args.file, any_source=args.any_source)
    if source.kind == "files" and args.since:
        print(f"--since applies to the journal only; {source.describe()} gives whole-file totals", file=sys.stderr)
        return 2
    notes = []
    try:
        limits = load_settings(args.config).sending_limits
    except ConfigError as exc:
        print(f"{args.config}: {len(exc.errors)} problem(s); fix it or pass --config", file=sys.stderr)
        for error in exc.errors:
            print(f"  {error}", file=sys.stderr)
        return 2
    if source.kind == "files":
        notes.append("whole-file totals: --since does not apply to files")
    else:
        note = coverage_note(source, journal_start())
        if note:
            notes.append(note)
    try:
        result = tally(lines(source))
    except (SourceError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    data = report(result, limits, top=args.top, config=args.config, notes=notes,
                  source={"kind": source.kind, "description": source.describe(), "verified": source.verified,
                          "since": source.since, "pattern": source.pattern})
    print(json.dumps(data, indent=2) if args.json else "\n".join(render(data)))
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    from .simulate import Facts, render, simulate, valid_peer
    if args.ingress != "local" and not args.peer:
        print(f"--peer is required for --ingress {args.ingress}: it decides mynetworks and same-host trust",
              file=sys.stderr)
        return 2
    if args.peer and not valid_peer(args.peer):
        print(f"--peer {args.peer}: not an IP address", file=sys.stderr)
        return 2
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"{args.config}: {len(exc.errors)} problem(s)", file=sys.stderr)
        for error in exc.errors:
            print(f"  {error}", file=sys.stderr)
        return 2
    resolved, note = _with_postfix(settings, required=False)
    if resolved is None:
        print(f"{args.config}: {note}", file=sys.stderr)
        return 2
    message = None
    if args.message:
        try:
            with open(args.message, "rb") as fh:
                message = fh.read(resolved.limits.message_bytes + 1)
        except OSError as exc:
            print(f"{args.message}: {exc.strerror or exc}", file=sys.stderr)
            return 2
    facts = Facts(ingress=args.ingress, sender=args.sender, recipients=tuple(args.recipients), login=args.login,
                  peer=args.peer, helo=args.helo, tls=not args.no_tls, spf=args.spf, dkim=args.dkim,
                  transport=args.transport)
    try:
        outcome = simulate(resolved, facts, message)
    except ImportError as exc:
        print(f"SPF/DKIM from DNS needs the Debian packages python3-spf, python3-dkim and python3-dnspython ({exc}); "
              "or give --spf and --dkim", file=sys.stderr)
        return 2
    print("\n".join(render(resolved, facts, outcome, args.message)))
    if note.startswith("Postfix settings not read"):
        print(f"note: {note}; mynetworks and recipient_delimiter are empty", file=sys.stderr)
    return outcome.exit_code


def socket_address(spec: str) -> tuple[int, object]:
    """Translate a libmilter socket spec (unix:PATH, inet:PORT[@HOST], inet6:PORT[@HOST]) into a connect target."""
    kind, _, rest = spec.partition(":")
    if kind == "unix":
        return socket.AF_UNIX, rest
    port, _, host = rest.partition("@")
    if kind == "inet6":
        return socket.AF_INET6, (host or "::1", int(port))
    return socket.AF_INET, (host or "127.0.0.1", int(port))


def cmd_wait_ready(args: argparse.Namespace) -> int:
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        for error in exc.errors:
            print(error, file=sys.stderr)
        return 1
    family, address = socket_address(settings.service.socket)
    deadline = time.monotonic() + args.timeout
    while True:
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            try:
                probe.connect(address)
                return 0
            except OSError:
                pass
        if time.monotonic() >= deadline:
            print(f"{settings.service.socket}: not accepting connections after {args.timeout:g}s", file=sys.stderr)
            return 1
        time.sleep(0.2)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = {"check-config": cmd_check_config, "show-config": cmd_show_config, "run": cmd_run,
               "lookup": cmd_lookup, "stats": cmd_stats, "simulate": cmd_simulate,
               "wait-ready": cmd_wait_ready}[args.command]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
