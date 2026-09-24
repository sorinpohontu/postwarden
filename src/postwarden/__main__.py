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
    find.add_argument("--file", help="search these syslog files instead of the journal (glob, e.g. '/var/log/mail.log*')")
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
    groups = sum(1 for key in settings.protection.addresses if key.endswith("@*"))
    addresses = len(settings.protection.addresses) - groups
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
          f"{_protection_summary(settings)}; {note})")
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
    from .lookup import LookupFailed, lookup, normalize_ref
    try:
        ref = normalize_ref(args.ref)
        lines = lookup(ref, since=args.since, files=args.file)
    except (LookupFailed, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    if not lines:
        print(f"no postwarden log line with mid={ref} (searched {args.file or 'the journal since ' + args.since}; "
              "reading the journal may need root or the adm group)", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0


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
               "lookup": cmd_lookup, "wait-ready": cmd_wait_ready}[args.command]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
