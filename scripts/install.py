#!/usr/bin/python3
"""Installer for postwarden. Without --apply every command is read-only."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

CANDIDATE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CANDIDATE / "src"))

from postwarden import DEFAULT_CONFIG_PATH, __version__  # noqa: E402
from postwarden import deployment  # noqa: E402


def log(message: str) -> None:
    print(message, flush=True)


def require_root(args: argparse.Namespace) -> None:
    if getattr(args, "apply", False) and os.geteuid() != 0:
        sys.exit("--apply requires root")


def cmd_inspect(args: argparse.Namespace) -> int:
    report = deployment.inspect(args.config)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0
    print(f"candidate: postwarden {report['candidate_version']} from {CANDIDATE}")
    print(f"debian: {report['debian']['id']} {report['debian']['version_id']} ({report['debian']['codename']}), python {report['python']}, supported={report['supported']}")
    for name, version in report["packages"].items():
        print(f"package {name}: {version or 'not installed'}")
    print(f"installed release: {report['installed_release'] or 'none'}; unit={report['unit_installed']} active={report['daemon_active']} socket={report['socket_present']}")
    if report.get("root_unmanaged"):
        print(f"  not part of the release (install --apply moves them to the backup directory): {', '.join(report['root_unmanaged'])}")
    config = report["config"]
    print(f"config {config['path']}: " + ("missing" if not config["present"] else ("valid, mode=" + config["mode"] if config["valid"] else "INVALID")))
    if report["postfix"]:
        pf = report["postfix"]
        print(f"postfix {pf['version']}: queue={pf['queue_directory']} delimiter={pf['recipient_delimiter']!r} attached={pf['attached']}")
        print(f"  smtpd_milters = {pf['smtpd_milters']}")
        print(f"  services: " + ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in pf["services"].items()))
        if pf["content_filters"]:
            print(f"  content filters: {pf['content_filters']}")
    for finding in report["findings"]:
        print(f"! {finding}")
    return 1 if report["findings"] else 0


def cmd_install(args: argparse.Namespace) -> int:
    require_root(args)
    report = deployment.inspect(args.config)
    blocking = [f for f in report["findings"] if f.startswith(("unsupported", "configuration missing", "configuration invalid"))]
    if blocking and not (args.import_config and any(f.startswith("configuration") for f in blocking) and len(blocking) == 1):
        for finding in blocking:
            log("! " + finding)
        return 1
    config_import = Path(args.import_config).resolve() if args.import_config else None
    if config_import is not None:
        from postwarden.config import ConfigError, load_settings
        try:
            load_settings(str(config_import))
        except ConfigError as exc:
            for error in exc.errors:
                log("! " + error)
            return 1
    try:
        backup = deployment.install(CANDIDATE, report, args.apply, log, config_import)
    except deployment.DeploymentError as exc:
        log(f"! {exc}")
        return 1
    if not args.apply:
        log("dry run: nothing changed (use --apply)")
    elif backup:
        log(f"install complete; deployment id {backup}")
    return 0


def cmd_configure_postfix(args: argparse.Namespace) -> int:
    require_root(args)
    report = deployment.inspect(args.config)
    try:
        backup = deployment.configure_postfix(args.phase, report, args.apply, log, args.remove_legacy, args.keep_legacy)
    except deployment.DeploymentError as exc:
        log(f"! {exc}")
        return 1
    if not args.apply:
        log("dry run: nothing changed (use --apply)")
    elif backup:
        log(f"configure-postfix {args.phase} complete; deployment id {backup}")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    require_root(args)
    try:
        deployment.rollback(args.deployment_id, args.apply, log, force=args.force)
    except deployment.DeploymentError as exc:
        log(f"! {exc}")
        return 1
    if not args.apply:
        log("dry run: nothing changed (use --apply)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"postwarden installer {__version__}")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"active configuration (default {DEFAULT_CONFIG_PATH})")
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("inspect", help="report host state without changing anything (default)")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("install", help="install packages, release, user, unit and start the daemon")
    p.add_argument("--apply", action="store_true", help="perform the changes; otherwise dry-run")
    p.add_argument("--dry-run", action="store_true", help="(default) show the plan only")
    p.add_argument("--import-config", metavar="FILE", help=f"copy FILE to {DEFAULT_CONFIG_PATH} before validation")
    p = sub.add_parser("configure-postfix", help="attach the daemon to Postfix for the given phase")
    p.add_argument("--phase", choices=deployment.PHASES, required=True)
    p.add_argument("--apply", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--remove-legacy", action="store_true",
                   help="enforce phase only: drop pipe content filters and the policyd-spf call")
    p.add_argument("--keep-legacy", action="store_true",
                   help="enforce while SMTP content filters remain (reinjected mail to protected recipients bounces)")
    p = sub.add_parser("rollback", help="restore the files recorded for a deployment id")
    p.add_argument("--deployment-id", required=True)
    p.add_argument("--apply", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true", help="overwrite files changed since the deployment")
    args = parser.parse_args(argv)
    if args.command is None:
        args.command, args.json = "inspect", False
    return {"inspect": cmd_inspect, "install": cmd_install, "configure-postfix": cmd_configure_postfix,
            "rollback": cmd_rollback}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
