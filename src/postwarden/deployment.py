"""Inspect, stage, apply and roll back the installation. Only `apply` functions mutate the host."""
from __future__ import annotations

import contextlib
import fcntl
import fnmatch
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import DEFAULT_CONFIG_PATH, __version__
from .config import ConfigError, load_settings

ROOT = Path("/etc/postwarden")
NOT_INSTALLED = ("__pycache__", "*.pyc", "logs", "gate-env.sh", "build-release.py", "Testing.md", "Releasing.md")
APP_FILES = ("src", "bin", "scripts", "packaging", "etc", "docs", "README.md", "CHANGELOG.md", "LICENSE", "pyproject.toml",
             "MANIFEST.sha256")
LAUNCHER = Path("/usr/local/sbin/postwarden")
UNIT = Path("/etc/systemd/system/postwarden.service")
SOCKET_DIR = Path("/var/spool/postfix/postwarden")
STATE_DIR = Path("/var/lib/postwarden")
BACKUPS = Path("/var/backups/postwarden")
LOCK = Path("/run/lock/postwarden-install.lock")
SERVICE_USER = "postwarden"
RUNTIME_PACKAGES = ("python3", "python3-milter", "python3-spf", "python3-dkim", "python3-dnspython")
POSTFIX_DIR = Path("/etc/postfix")
CUSTOM_MILTER = "unix:postwarden/policy.sock"
MILTER_PARAM = "postwarden_milter"
MILTER_REF = "$" + MILTER_PARAM
REQUIRED_MACROS = {
    "milter_connect_macros": ("{daemon_addr}", "{daemon_port}", "{client_port}", "{postwarden_ingress}"),
    "milter_mail_macros": ("{daemon_port}", "{auth_type}", "{auth_authen}", "{cipher_bits}", "{tls_version}",
                           "{postwarden_ingress}"),
    "milter_rcpt_macros": ("{rcpt_mailer}",),
}
LOCAL_CLEANUP = "postwarden-cleanup"
INGRESS = {"smtpd/pass": "SMTP25", "smtp/inet": "SMTP25", "submission/inet": "SUBMISSION587",
           "submissions/inet": "SUBMISSION465", "smtps/inet": "SUBMISSION465"}
PHASES = ("observe", "enforce")
CHAIN_FINDING = "postwarden missing from milter chain: "
MACRO_FINDING = "Postfix does not send macros postwarden needs: "


class DeploymentError(Exception):
    pass


def run(args: list[str], check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, check=check, text=True, capture_output=True, input=input_text)
    except FileNotFoundError:
        if check:
            raise DeploymentError(f"required command not found: {args[0]}") from None
        return subprocess.CompletedProcess(args, 127, "", f"{args[0]}: not found")
    except subprocess.CalledProcessError as exc:
        raise DeploymentError(f"{' '.join(args)} failed ({exc.returncode}): {exc.stderr.strip() or exc.stdout.strip()}") from None


def sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


# -- inspection ---------------------------------------------------------------


def os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    with contextlib.suppress(OSError):
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                data[key] = value.strip().strip('"')
    return data


def package_versions(names: tuple[str, ...]) -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for name in names:
        result = run(["dpkg-query", "-W", "-f=${Version} ${Status}", name], check=False)
        if result.returncode == 0 and "install ok installed" in result.stdout:
            versions[name] = result.stdout.split()[0]
        else:
            versions[name] = None
    return versions


def postconf(name: str, config_dir: Path | None = None, expand: bool = False) -> str:
    args = ["postconf"] + (["-c", str(config_dir)] if config_dir else []) + (["-xh"] if expand else ["-h"]) + [name]
    return run(args).stdout.strip()


def service_param(service: str, param: str, config_dir: Path | None = None, expand: bool = False) -> str | None:
    """A master.cf `-o` override, or None when the service inherits main.cf."""
    key = f"{service}/{param}"
    args = ["postconf"] + (["-c", str(config_dir)] if config_dir else []) + (["-Px"] if expand else ["-P"]) + [key]
    for line in run(args, check=False).stdout.splitlines():
        name, sep, value = line.partition(" = ")
        if name.strip() == key:
            return value.strip()
        if line.strip() == f"{key} =":
            return ""
    return None


def split_list(value: str) -> list[str]:
    """Postfix list elements separated by commas/whitespace outside { } groups."""
    items, current, depth = [], "", 0
    for char in value:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        if depth == 0 and (char == "," or char.isspace()):
            if current.strip():
                items.append(current.strip())
            current = ""
        else:
            current += char
    if current.strip():
        items.append(current.strip())
    return items


def _is_postwarden(item: str) -> bool:
    return CUSTOM_MILTER in item or item in (MILTER_REF, "${" + MILTER_PARAM + "}", "$(" + MILTER_PARAM + ")")


def with_postwarden(value: str, separator: str = ", ") -> str:
    """postwarden first, every other milter kept in order."""
    return separator.join([MILTER_REF] + [item for item in split_list(value) if not _is_postwarden(item)])


def with_ingress_marker(value: str, marker: str) -> str:
    """Set only postwarden_ingress in a milter_macro_defaults value; other milters' defaults are kept."""
    others = [item for item in split_list(value) if not item.startswith("postwarden_ingress=")]
    return ",".join([f"postwarden_ingress={marker}"] + others)


def chain_gaps(config_dir: Path | None = None) -> list[str]:
    """Ingress paths whose effective milter chain lacks postwarden."""
    gaps = []
    if CUSTOM_MILTER not in postconf("smtpd_milters", config_dir, expand=True):
        gaps.append("smtpd_milters")
    if CUSTOM_MILTER not in postconf("non_smtpd_milters", config_dir, expand=True):
        gaps.append("non_smtpd_milters")
    services = master_services(config_dir)
    for service in INGRESS:
        if service in services and services[service].split()[7] == "smtpd":
            override = service_param(service, "smtpd_milters", config_dir, expand=True)
            if override is not None and CUSTOM_MILTER not in override:
                gaps.append(f"{service} smtpd_milters override")
    return gaps


def service_overrides(config_dir: Path | None = None) -> dict[str, str]:
    """Every master.cf `-o` override, keyed service/type/parameter."""
    args = ["postconf"] + (["-c", str(config_dir)] if config_dir else []) + ["-P"]
    overrides = {}
    for line in run(args, check=False).stdout.splitlines():
        name, _, value = line.partition("=")
        overrides[name.strip()] = value.strip()
    return overrides


def macro_overrides(config_dir: Path | None = None) -> dict[str, tuple[str, str]]:
    """Macro lists set per service: service/type/parameter -> (parameter, value)."""
    found = {}
    for key, value in service_overrides(config_dir).items():
        param = key.rpartition("/")[2]
        if param in REQUIRED_MACROS:
            found[key] = (param, value)
    return found


def missing_macros(value: str, required: tuple[str, ...]) -> list[str]:
    present = split_list(value)
    return [m for m in required if m not in present]


def macro_gaps(config_dir: Path | None = None) -> list[str]:
    """Macros postwarden reads that Postfix does not send at the stage where they are read, globally or per service."""
    gaps = [f"{name} lacks {' '.join(missing)}" for name, required in REQUIRED_MACROS.items()
            if (missing := missing_macros(postconf(name, config_dir), required))]
    gaps += [f"{key} lacks {' '.join(missing)}" for key, (param, value) in macro_overrides(config_dir).items()
             if (missing := missing_macros(value, REQUIRED_MACROS[param]))]
    return gaps


def postfix_references(config_dir: Path | None = None) -> list[str]:
    """main.cf parameters and master.cf service overrides whose effective value uses the postwarden socket."""
    base = ["postconf"] + (["-c", str(config_dir)] if config_dir else [])
    found = []
    for flag in ("-nx", "-Px"):
        for line in run(base + [flag]).stdout.splitlines():
            name, _, value = line.partition(" = ")
            if CUSTOM_MILTER in value and name.strip() != MILTER_PARAM:
                found.append(name.strip())
    return found


def master_services(config_dir: Path | None = None) -> dict[str, str]:
    args = ["postconf"] + (["-c", str(config_dir)] if config_dir else []) + ["-M"]
    services: dict[str, str] = {}
    for line in run(args).stdout.splitlines():
        parts = line.split()
        if len(parts) >= 8:
            services[f"{parts[0]}/{parts[1]}"] = line
    return services


def service_active(unit: str) -> bool:
    return run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0


def inspect(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    """Read-only view of the host; safe to run before runtime packages exist."""
    release = os_release()
    report: dict = {
        "candidate_version": __version__,
        "debian": {"id": release.get("ID"), "version_id": release.get("VERSION_ID"), "codename": release.get("VERSION_CODENAME")},
        "python": sys.version.split()[0],
        "packages": package_versions(RUNTIME_PACKAGES + ("postfix", "opendkim", "postfix-policyd-spf-python")),
        "supported": release.get("ID") == "debian" and release.get("VERSION_ID") in ("12", "13"),
    }
    with contextlib.suppress(KeyError):
        report["service_user"] = pwd.getpwnam(SERVICE_USER).pw_uid
    report["installed_release"] = _installed_version()
    report["unit_installed"] = UNIT.exists()
    report["daemon_active"] = service_active("postwarden.service")
    report["socket_dir"] = str(SOCKET_DIR) if SOCKET_DIR.is_dir() else None
    report["socket_present"] = (SOCKET_DIR / "policy.sock").exists()
    report["root_foreign_owned"] = [str(p) for p in foreign_owned(ROOT)]
    report["root_writable"] = [str(p) for p in writable_by_others(ROOT)]
    report["root_unmanaged"] = [p.name for p in unmanaged_entries(ROOT)]
    report["managed_symlinks"] = [str(p) for p in managed_files() if p.is_symlink()]

    config: dict = {"path": config_path, "present": Path(config_path).exists()}
    if config["present"]:
        try:
            settings = load_settings(config_path)
            addresses, groups = settings.protection.counts()
            config.update(valid=True, mode=settings.mode, protected_addresses=addresses, protected_groups=groups,
                          remote_transports=sorted(settings.protection.remote_transports))
        except ConfigError as exc:
            config.update(valid=False, errors=exc.errors)
    report["config"] = config

    if shutil.which("postconf"):
        services = master_services()
        postfix = {
            "version": postconf("mail_version"),
            "queue_directory": postconf("queue_directory"),
            "recipient_delimiter": postconf("recipient_delimiter"),
            "mynetworks": postconf("mynetworks"),
            "postfix_settings_error": _postfix_settings_error(config_path),
            "relaying_transports": sorted({postconf(name).split(":", 1)[0] for name in ("default_transport", "relay_transport")} - {""}),
            "milter_protocol": postconf("milter_protocol"),
            "smtpd_milters": postconf("smtpd_milters"),
            "non_smtpd_milters": postconf("non_smtpd_milters"),
            "milter_default_action": postconf("milter_default_action"),
            "services": {name: (name in services) for name in list(INGRESS) + ["pickup/unix", f"{LOCAL_CLEANUP}/unix", "policyd-spf/unix"]},
            "content_filters": {name: _service_option(services.get(name, ""), "content_filter") for name in INGRESS if name in services},
            "attached": CUSTOM_MILTER in postconf("smtpd_milters", expand=True),
            "chain_gaps": chain_gaps(),
            "macro_gaps": macro_gaps(),
            "main_cf_sha256": sha256(POSTFIX_DIR / "main.cf"),
            "master_cf_sha256": sha256(POSTFIX_DIR / "master.cf"),
        }
        report["postfix"] = postfix
        report["findings"] = _findings(report)
    else:
        report["postfix"] = None
        report["findings"] = ["postconf not found: Postfix is not installed"]
    return report


def unmanaged_entries(root: Path) -> list[Path]:
    """Top-level entries of the installation root that are neither release content nor the configuration."""
    if not root.is_dir():
        return []
    keep = set(APP_FILES) | {Path(DEFAULT_CONFIG_PATH).name}
    return sorted(p for p in root.iterdir() if p.name not in keep)


def foreign_owned(root: Path) -> list[Path]:
    """Paths in the installation root (itself included) not owned by root; any such owner could replace the code."""
    if not root.is_dir():
        return []
    paths = [root] + sorted(root.rglob("*"))
    return [p for p in paths if p.lstat().st_uid != 0]


def writable_by_others(root: Path) -> list[Path]:
    """Paths in the installation root (itself included) that group or others can write; they could replace the code."""
    if not root.is_dir():
        return []
    paths = [root] + sorted(root.rglob("*"))
    return [p for p in paths if not p.is_symlink() and p.lstat().st_mode & 0o022]


def normalize_modes(root: Path) -> None:
    """Release modes under the installation root: directories and executables 0755, other files 0644; config.toml untouched."""
    os.chmod(root, 0o755)
    for path in root.rglob("*"):
        if path.is_symlink() or path.name == "config.toml":
            continue
        if path.is_dir() or path.parent.name in ("bin", "scripts") or path.suffix == ".sh":
            os.chmod(path, 0o755)
        else:
            os.chmod(path, 0o644)


def tree_digest(root: Path, metadata: bool = False) -> str:
    """Content digest of the application tree; with metadata, also each file's mode and ownership."""
    digest = hashlib.sha256()
    for name in APP_FILES:
        source = root / name
        if not source.exists():
            continue
        files = [source] if source.is_file() else sorted(p for p in source.rglob("*") if p.is_file())
        for path in files:
            rel = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(part, pattern) for part in rel.split("/") for pattern in NOT_INSTALLED):
                continue
            digest.update(rel.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
            if metadata:
                st = path.stat()
                digest.update(f"{st.st_mode & 0o7777}:{st.st_uid}:{st.st_gid}".encode())
    return digest.hexdigest()


def _installed_version() -> str | None:
    init = ROOT / "src" / "postwarden" / "__init__.py"
    if not init.exists():
        return None
    match = re.search(r'__version__\s*=\s*"([^"]+)"', init.read_text())
    return match.group(1) if match else "unknown"


def _service_option(line: str, option: str) -> str | None:
    match = re.search(rf"-o\s+{re.escape(option)}=(\S*)", line)
    return match.group(1) if match else None


def _findings(report: dict) -> list[str]:
    findings = []
    if not report["supported"]:
        findings.append("unsupported distribution: Debian 12 or 13 required")
    missing = [name for name in RUNTIME_PACKAGES if report["packages"].get(name) is None]
    if missing:
        findings.append("runtime packages to install: " + " ".join(missing))
    foreign = report.get("root_foreign_owned") or []
    if foreign:
        findings.append(f"{len(foreign)} path(s) in {ROOT} not owned by root (first: {foreign[0]}); run install --apply")
    writable = report.get("root_writable") or []
    if writable:
        findings.append(f"{len(writable)} path(s) in {ROOT} writable by group or others (first: {writable[0]}); "
                        "run install --apply")
    if report.get("managed_symlinks"):
        findings.append(", ".join(report["managed_symlinks"]) + " is a symlink; postwarden manages regular files only")
    config = report["config"]
    postfix = report["postfix"]
    if not config["present"]:
        findings.append(f"configuration missing: create {config['path']} from etc/config.example.toml")
    elif not config["valid"]:
        findings.append("configuration invalid: " + "; ".join(config["errors"]))
    elif postfix:
        missing_transports = sorted(set(postfix["relaying_transports"]) - set(config["remote_transports"]))
        if missing_transports:
            findings.append("protection.remote_transports lacks Postfix default_transport/relay_transport "
                            f"{', '.join(missing_transports)}: all@ at other domains would be refused")
    if postfix and postfix.get("attached") and postfix.get("chain_gaps"):
        findings.append(CHAIN_FINDING + ", ".join(postfix["chain_gaps"]) + "; run configure-postfix to repair")
    if postfix and postfix.get("attached") and postfix.get("macro_gaps"):
        findings.append(MACRO_FINDING + "; ".join(postfix["macro_gaps"])
                        + "; run configure-postfix to repair")
    if postfix and postfix.get("postfix_settings_error"):
        findings.append(postfix["postfix_settings_error"] + "; postwarden will not start")
    if postfix:
        if not any(postfix["services"].get(name) for name in ("smtpd/pass", "smtp/inet")):
            findings.append("no smtpd/pass or smtp/inet service found in master.cf")
        if not postfix["services"].get("pickup/unix"):
            findings.append("no pickup service found in master.cf")
    return findings


def _postfix_settings_error(config_path: str) -> str | None:
    from .postfix import PostfixError, read_postfix, with_postfix
    try:
        try:
            with_postfix(load_settings(config_path))
        except ConfigError:
            read_postfix()
    except PostfixError as exc:
        return str(exc)
    return None


# -- steps --------------------------------------------------------------------


@dataclass
class Step:
    description: str
    apply: Callable[[], None]
    needed: bool = True


@dataclass
class Plan:
    steps: list[Step] = field(default_factory=list)

    def add(self, description: str, apply: Callable[[], None], needed: bool = True) -> None:
        self.steps.append(Step(description, apply, needed))

    def describe(self) -> list[str]:
        return [("* " if s.needed else "= ") + s.description for s in self.steps]

    def execute(self, log: Callable[[str], None]) -> None:
        for step in self.steps:
            if step.needed:
                log("applying: " + step.description)
                step.apply()


@contextlib.contextmanager
def deployment_lock():
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK, "w") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise DeploymentError("another installer run holds the deployment lock") from None
        yield


def new_backup(kind: str) -> Path:
    deployment_id = time.strftime("%Y%m%dT%H%M%S") + f"-{kind}"
    path = BACKUPS / deployment_id
    path.mkdir(parents=True, exist_ok=False)
    os.chmod(BACKUPS, 0o700)
    os.chmod(path, 0o700)
    return path


def managed_files() -> list[Path]:
    return [POSTFIX_DIR / "main.cf", POSTFIX_DIR / "master.cf", Path(DEFAULT_CONFIG_PATH), LAUNCHER, UNIT]


def refuse_symlinks() -> None:
    """postwarden changes and restores regular files only."""
    links = [str(p) for p in managed_files() if p.is_symlink()]
    if links:
        raise DeploymentError(", ".join(links) + " is a symlink; postwarden manages regular files only. "
                              "Replace the link with the file, then re-run")


def snapshot(paths: list[Path]) -> dict[str, dict | None]:
    return {str(p): file_state(p) for p in paths}


def refuse_changes(recorded: dict[str, dict | None], what: str) -> None:
    """Stop when a file changed between planning and the mutation that depends on it."""
    changed = [name for name, state in recorded.items() if file_state(Path(name)) != state]
    if changed:
        raise DeploymentError(", ".join(changed) + f" changed since {what}; re-run")


def backup_file(source: Path, backup: Path) -> None:
    if source.is_symlink():
        raise DeploymentError(f"{source} is a symlink; postwarden manages regular files only")
    if source.exists():
        shutil.copy2(source, backup / source.name)


def write_manifest(backup: Path, data: dict) -> None:
    (backup / "manifest.json").write_text(json.dumps(data, indent=2, default=str))


def file_state(path: Path) -> dict | None:
    if not path.exists():
        return None
    st = path.stat()
    return {"sha256": sha256(path), "mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid}


def record_after(backup: Path, paths: list[Path], application: bool = False) -> None:
    """Post-deployment identities that rollback compares against."""
    manifest = json.loads((backup / "manifest.json").read_text())
    manifest["after"] = {str(p): file_state(p) for p in paths}
    if application:
        manifest["after"]["application"] = tree_digest(ROOT, metadata=True)
    write_manifest(backup, manifest)


def atomic_copy(source: Path, target: Path, mode: int, owner: tuple[str | int, str | int] | None = None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    os.close(fd)
    shutil.copyfile(source, tmp)
    os.chmod(tmp, mode)
    if owner:
        shutil.chown(tmp, *owner)
    os.replace(tmp, target)


# -- application installation --------------------------------------------------


def _has_state(path: Path, user: str, group: str, mode: int, directory: bool) -> bool:
    try:
        st = path.lstat()
        uid, gid = pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
    except (FileNotFoundError, KeyError):
        return False
    kind_ok = path.is_dir() if directory else path.is_file()
    return kind_ok and not path.is_symlink() and (st.st_uid, st.st_gid, st.st_mode & 0o7777) == (uid, gid, mode)


def plan_install(candidate: Path, report: dict, config_import: Path | None = None) -> Plan:
    plan = Plan()
    version = __version__
    in_place = candidate.resolve() == ROOT.resolve()
    missing = [name for name in RUNTIME_PACKAGES if report["packages"].get(name) is None]
    plan.add(f"apt-get install {' '.join(missing) if missing else '(nothing missing)'}",
             lambda: run(["apt-get", "install", "-y", "--no-install-recommends", *missing]), needed=bool(missing))

    def create_user():
        run(["groupadd", "--system", SERVICE_USER], check=False)
        try:
            pwd.getpwnam(SERVICE_USER)
        except KeyError:
            run(["useradd", "--system", "--gid", SERVICE_USER, "--groups", "postfix", "--home-dir", str(STATE_DIR),
                 "--shell", "/usr/sbin/nologin", "--no-create-home", SERVICE_USER])
        if "postfix" not in [g.gr_name for g in grp.getgrall() if SERVICE_USER in g.gr_mem]:
            run(["usermod", "-a", "-G", "postfix", SERVICE_USER])
    plan.add(f"create system user {SERVICE_USER} (groups {SERVICE_USER}, postfix)", create_user,
             needed="service_user" not in report)

    def directories():
        ROOT.mkdir(mode=0o755, exist_ok=True)
        SOCKET_DIR.mkdir(exist_ok=True)
        shutil.chown(SOCKET_DIR, SERVICE_USER, "postfix")
        os.chmod(SOCKET_DIR, 0o2750)
        STATE_DIR.mkdir(exist_ok=True)
        shutil.chown(STATE_DIR, SERVICE_USER, SERVICE_USER)
        os.chmod(STATE_DIR, 0o700)
    dirs_ready = (ROOT.is_dir() and _has_state(SOCKET_DIR, SERVICE_USER, "postfix", 0o2750, True)
                  and _has_state(STATE_DIR, SERVICE_USER, SERVICE_USER, 0o700, True))
    plan.add(f"create {ROOT}, {SOCKET_DIR} ({SERVICE_USER}:postfix 2750), {STATE_DIR} (0700)", directories,
             needed=not dirs_ready)

    unmanaged = [] if in_place else unmanaged_entries(ROOT)
    foreign = foreign_owned(ROOT)
    writable = writable_by_others(ROOT)

    def secure_root():
        if unmanaged:
            parking = BACKUPS / (time.strftime("%Y%m%dT%H%M%S") + "-unmanaged")
            parking.mkdir(parents=True, exist_ok=False)
            os.chmod(BACKUPS, 0o700)
            os.chmod(parking, 0o700)
            for path in unmanaged:
                shutil.move(str(path), str(parking / path.name))
        os.chown(ROOT, 0, 0)
        config = Path(DEFAULT_CONFIG_PATH)
        for path in ROOT.rglob("*"):
            if path == config:
                shutil.chown(path, "root", SERVICE_USER)
            else:
                os.lchown(path, 0, 0)
        normalize_modes(ROOT)
        if config.is_file() and not config.is_symlink():
            os.chmod(config, 0o640)
    names = ", ".join(p.name for p in unmanaged)
    plan.add(f"secure {ROOT}: root ownership, no group/other write" + (f"; move unmanaged entries to {BACKUPS}/<time>-unmanaged: {names}" if unmanaged else ""),
             secure_root, needed=bool(unmanaged or foreign or writable))

    def copy_app():
        for name in APP_FILES:
            source, target = candidate / name, ROOT / name
            if not source.exists():
                if target.is_file() and name == "MANIFEST.sha256":
                    target.unlink()
                continue
            if source.is_dir():
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(source, target, ignore=shutil.ignore_patterns(*NOT_INSTALLED))
            else:
                shutil.copy2(source, target)
        normalize_modes(ROOT)
    same = in_place or ((ROOT / "src").exists() and tree_digest(candidate) == tree_digest(ROOT))
    plan.add(f"copy application {version} into {ROOT}" + (" (already in place)" if in_place else ""), copy_app, needed=not same)

    def config_import_step():
        from .postfix import PostfixError, with_postfix
        try:
            with_postfix(load_settings(str(config_import)))
        except (ConfigError, PostfixError) as exc:
            raise DeploymentError(f"{config_import} is not valid, live configuration left unchanged: {exc}") from None
        atomic_copy(config_import, Path(DEFAULT_CONFIG_PATH), 0o640, ("root", SERVICE_USER))
    config_changed = config_import is not None and sha256(config_import) != sha256(Path(DEFAULT_CONFIG_PATH))
    if config_import is not None:
        plan.add(f"validate and import {config_import} as {DEFAULT_CONFIG_PATH}", config_import_step, needed=config_changed)

    def validate():
        from .postfix import PostfixError, with_postfix
        try:
            settings = with_postfix(load_settings(DEFAULT_CONFIG_PATH))
        except PostfixError as exc:
            raise DeploymentError(str(exc)) from None
        target = Path(DEFAULT_CONFIG_PATH)
        shutil.chown(target, "root", SERVICE_USER)
        os.chmod(target, 0o640)
        return settings
    config_ready = config_import is None and _has_state(Path(DEFAULT_CONFIG_PATH), "root", SERVICE_USER, 0o640, False)
    plan.add(f"validate {DEFAULT_CONFIG_PATH} and set root:{SERVICE_USER} 0640", validate, needed=not config_ready)

    plan.add(f"install launcher {LAUNCHER}", lambda: atomic_copy(candidate / "bin" / "postwarden", LAUNCHER, 0o755),
             needed=sha256(candidate / "bin" / "postwarden") != sha256(LAUNCHER))
    unit_source = candidate / "packaging" / "systemd" / "postwarden.service"
    unit_changed = sha256(unit_source) != sha256(UNIT)
    plan.add(f"install systemd unit {UNIT}", lambda: (atomic_copy(unit_source, UNIT, 0o644), run(["systemctl", "daemon-reload"])),
             needed=unit_changed)

    def start():
        run(["systemctl", "enable", "postwarden.service"])
        run(["systemctl", "restart", "postwarden.service"])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if service_active("postwarden.service") and (SOCKET_DIR / "policy.sock").exists():
                return
            time.sleep(0.5)
        status = run(["systemctl", "status", "postwarden.service", "--no-pager"], check=False).stdout
        raise DeploymentError("daemon did not become ready:\n" + status)
    restart_needed = (not same or unit_changed or config_changed or not report.get("daemon_active")
                      or not report.get("socket_present"))
    plan.add("enable and (re)start postwarden.service, wait for the socket", start, needed=restart_needed)
    return plan


def install(candidate: Path, report: dict, apply: bool, log: Callable[[str], None],
            config_import: Path | None = None) -> str | None:
    refuse_symlinks()
    planned = snapshot([Path(DEFAULT_CONFIG_PATH), UNIT, LAUNCHER] + ([config_import] if config_import else []))
    planned_tree = tree_digest(ROOT, metadata=True) if (ROOT / "src").exists() else None
    plan = plan_install(candidate, report, config_import)
    for line in plan.describe():
        log(line)
    if not apply:
        return None
    if not any(step.needed for step in plan.steps):
        log("nothing to change; no deployment recorded")
        return None
    with deployment_lock():
        refuse_symlinks()
        refuse_changes(planned, "the plan was made")
        if planned_tree is not None and tree_digest(ROOT, metadata=True) != planned_tree:
            raise DeploymentError(f"{ROOT} changed since the plan was made; re-run")
        backup = new_backup("install")
        for path in (Path(DEFAULT_CONFIG_PATH), UNIT, LAUNCHER):
            backup_file(path, backup)
        if report.get("installed_release") and candidate.resolve() != ROOT.resolve():
            shutil.make_archive(str(backup / "application"), "gztar", root_dir=ROOT, base_dir=".",
                                verbose=False)
        write_manifest(backup, {"kind": "install", "version": __version__, "previous_release": report.get("installed_release"),
                                "candidate": str(candidate), "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                "before": {str(p): file_state(p) for p in (Path(DEFAULT_CONFIG_PATH), UNIT, LAUNCHER)}})
        try:
            plan.execute(log)
        except Exception as exc:
            log(f"installation failed: {exc}; backup kept at {backup}; "
                f"to restore: install.py rollback --deployment-id {backup.name} --force --apply")
            raise
        record_after(backup, [Path(DEFAULT_CONFIG_PATH), UNIT, LAUNCHER], application=True)
        return backup.name


# -- postfix integration ----------------------------------------------------------


def without_policy_call(restrictions: str, service_name: str) -> str:
    """Drop `check_policy_service <endpoint>` pairs whose endpoint names service_name; returns the input unchanged when absent."""
    if "{" in restrictions:
        if service_name in restrictions:
            raise DeploymentError("smtpd_recipient_restrictions uses { } grouping; remove the policy call manually")
        return restrictions
    pattern = r"(?<![^\s,])check_policy_service[\s,]+[^\s,]*" + re.escape(service_name) + r"[^\s,]*[\s,]*"
    cleaned = re.sub(pattern, "", restrictions)
    return restrictions if cleaned == restrictions else cleaned.rstrip(" \t\n,")


def _already_set(op: list[str], staging: Path, services: dict[str, str]) -> bool:
    """True when a postconf -e/-P operation would write the value that is already there; rewriting master.cf moves comments."""
    flag, spec = op
    if flag == "-e":
        name, value = spec.split("=", 1)
        return postconf(name, staging) == value
    if flag == "-P":
        key, value = spec.split("=", 1)
        service, _, param = key.rpartition("/")
        line = services.get(service)
        return line is not None and _service_option(line, param) == value
    return False


def render_postfix(phase: str, staging: Path, remove_legacy: bool) -> list[str]:
    """Apply the integration to a staged copy of /etc/postfix and return the postconf operations performed."""
    if phase not in PHASES:
        raise DeploymentError(f"unknown phase {phase}")
    failure = "accept" if phase == "observe" else "tempfail"
    ops: list[list[str]] = []
    ops.append(["-e", "milter_protocol=6"])
    ops.append(["-e", f"{MILTER_PARAM}={{ {CUSTOM_MILTER}, default_action={failure}, content_timeout=60s }}"])
    ops.append(["-e", "smtpd_milters=" + with_postwarden(postconf("smtpd_milters", staging))])
    local_chain = split_list(postconf("non_smtpd_milters", staging))
    if not any(item in ("$smtpd_milters", "${smtpd_milters}", "$(smtpd_milters)") for item in local_chain):
        ops.append(["-e", "non_smtpd_milters=" + with_postwarden(postconf("non_smtpd_milters", staging))])
    global_defaults = with_ingress_marker(postconf("milter_macro_defaults", staging), "UNCLASSIFIED")
    ops.append(["-e", "milter_macro_defaults=" + global_defaults])
    for name, extra in REQUIRED_MACROS.items():
        current = split_list(postconf(name, staging))
        merged = current + [m for m in extra if m not in current]
        ops.append(["-e", f"{name}={' '.join(merged)}"])
    for key, (param, value) in macro_overrides(staging).items():
        if missing := missing_macros(value, REQUIRED_MACROS[param]):
            ops.append(["-P", f"{key}=" + ",".join(split_list(value) + missing)])
    services = master_services(staging)

    def service_defaults(service: str, marker: str) -> str:
        own = service_param(service, "milter_macro_defaults", staging)
        return f"{service}/milter_macro_defaults=" + with_ingress_marker(global_defaults if own is None else own, marker)

    for service, marker in INGRESS.items():
        if service in services and services[service].split()[7] == "smtpd":
            ops.append(["-P", service_defaults(service, marker)])
            override = service_param(service, "smtpd_milters", staging)
            if override is not None:
                if any(" " in item for item in split_list(override)):
                    raise DeploymentError(f"{service} sets smtpd_milters with a braced entry; move it to a main.cf "
                                          "parameter and refer to it with $name, then re-run")
                ops.append(["-P", f"{service}/smtpd_milters=" + with_postwarden(override, ",")])
    if f"{LOCAL_CLEANUP}/unix" not in services:
        ops.append(["-M", f"{LOCAL_CLEANUP}/unix={LOCAL_CLEANUP} unix n - y - 0 cleanup"])
        ops.append(["-P", f"{LOCAL_CLEANUP}/unix/milter_macro_defaults=" + with_ingress_marker(global_defaults, "LOCAL_PICKUP")])
    else:
        ops.append(["-P", service_defaults(f"{LOCAL_CLEANUP}/unix", "LOCAL_PICKUP")])
    ops.append(["-P", f"pickup/unix/cleanup_service_name={LOCAL_CLEANUP}"])
    if phase == "enforce" and remove_legacy:
        for service in INGRESS:
            if service in services and _service_option(services[service], "content_filter"):
                ops.append(["-PX", f"{service}/content_filter"])
                if _service_option(services[service], "receive_override_options"):
                    ops.append(["-PX", f"{service}/receive_override_options"])
        restrictions = postconf("smtpd_recipient_restrictions", staging)
        cleaned = without_policy_call(restrictions, "policyd-spf")
        if cleaned != restrictions:
            ops.append(["-e", f"smtpd_recipient_restrictions={cleaned}"])
    performed = []
    for op in ops:
        if _already_set(op, staging, services):
            continue
        run(["postconf", "-c", str(staging), *op])
        performed.append("postconf " + " ".join(op))
    gaps = chain_gaps(staging) + macro_gaps(staging)
    if gaps:
        raise DeploymentError("postwarden would still be missing from: " + ", ".join(gaps))
    return performed


def stage_postfix(phase: str, remove_legacy: bool) -> tuple[Path, list[str], str]:
    staging = Path(tempfile.mkdtemp(prefix="postwarden-stage."))
    for name in ("main.cf", "master.cf"):
        shutil.copy2(POSTFIX_DIR / name, staging / name)
    for name in ("dynamicmaps.cf", "postfix-files"):
        if (POSTFIX_DIR / name).exists():
            shutil.copy2(POSTFIX_DIR / name, staging / name)
    if (POSTFIX_DIR / "postfix-files.d").is_dir():
        shutil.copytree(POSTFIX_DIR / "postfix-files.d", staging / "postfix-files.d")
    if (POSTFIX_DIR / "dynamicmaps.cf.d").is_dir():
        shutil.copytree(POSTFIX_DIR / "dynamicmaps.cf.d", staging / "dynamicmaps.cf.d")
    ops = render_postfix(phase, staging, remove_legacy)
    diff = ""
    for name in ("main.cf", "master.cf"):
        result = run(["diff", "-u", "--label", f"a/{name}", "--label", f"b/{name}", str(POSTFIX_DIR / name), str(staging / name)], check=False)
        diff += result.stdout
    return staging, ops, diff


def set_config_mode(path: Path, mode: str) -> bool:
    """Set the top-level `mode` key, in any TOML spelling, adding it when absent; the result must parse to `mode`."""
    text = path.read_text()
    header = re.search(r"^[ \t]*\[", text, flags=re.M)
    top, rest = (text[:header.start()], text[header.start():]) if header else (text, "")
    key = r"""^([ \t]*(?:mode|"mode"|'mode')[ \t]*=[ \t]*)(?:"[^"\n]*"|'[^'\n]*')"""
    new_top, count = re.subn(key, rf'\g<1>"{mode}"', top, count=1, flags=re.M)
    if count == 0:
        new_top = f'mode = "{mode}"\n' + top
    new_text = new_top + rest
    if new_text == text:
        return False
    try:
        if tomllib.loads(new_text).get("mode") != mode:
            raise DeploymentError(f"{path}: could not set mode = \"{mode}\"; edit the file by hand")
    except tomllib.TOMLDecodeError as exc:
        raise DeploymentError(f"{path}: {exc}") from None
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".config.toml.")
    with os.fdopen(fd, "w") as fh:
        fh.write(new_text)
    shutil.copymode(path, tmp)
    shutil.chown(tmp, "root", SERVICE_USER)
    os.replace(tmp, path)
    return True


def enforcement_blockers(phase: str, report: dict, remove_legacy: bool, keep_legacy: bool) -> list[str]:
    """SMTP services whose content_filter would reinject mail through pickup, where protected recipients are refused."""
    if phase != "enforce" or remove_legacy or keep_legacy:
        return []
    return sorted(name for name, target in report["postfix"]["content_filters"].items() if target)


def configure_postfix(phase: str, report: dict, apply: bool, log: Callable[[str], None], remove_legacy: bool = False,
                      keep_legacy: bool = False) -> str | None:
    if remove_legacy and keep_legacy:
        raise DeploymentError("--remove-legacy and --keep-legacy are mutually exclusive")
    blockers = enforcement_blockers(phase, report, remove_legacy, keep_legacy)
    if blockers:
        raise DeploymentError(
            "content_filter still set on " + ", ".join(blockers) + ": mail reinjected by the filter reaches the milter "
            "as local pickup, where protected recipients are always refused, so authorized group mail would bounce. "
            "Use --remove-legacy (cutover), or --keep-legacy to accept that for testing")
    if not report.get("daemon_active") or not report.get("socket_present"):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not (service_active("postwarden.service") and (SOCKET_DIR / "policy.sock").exists()):
            time.sleep(0.5)
        if not (service_active("postwarden.service") and (SOCKET_DIR / "policy.sock").exists()):
            raise DeploymentError("daemon is not running with its socket present; run install --apply first")
        report["daemon_active"] = report["socket_present"] = True
    config = report["config"]
    if not config.get("valid"):
        raise DeploymentError("configuration is invalid; fix it before attaching to Postfix")
    blocking = [f for f in report["findings"] if not f.startswith((CHAIN_FINDING, MACRO_FINDING))]
    if blocking:
        raise DeploymentError("unresolved findings from inspect:\n  " + "\n  ".join(blocking))
    refuse_symlinks()
    planned = snapshot([Path(DEFAULT_CONFIG_PATH)])
    staging, ops, diff = stage_postfix(phase, remove_legacy)
    try:
        log(f"daemon mode: {config['mode']} -> {phase}")
        for op in ops:
            log(op)
        log(diff if diff else "(no Postfix changes)")
        if "master.cf" in diff:
            log("note: postconf rewrites master.cf in its own layout; comment lines may move (see the diff above)")
        if not apply:
            return None
        if not diff and config["mode"] == phase:
            log("nothing to change; no deployment recorded")
            return None
        with deployment_lock():
            if sha256(POSTFIX_DIR / "main.cf") != report["postfix"]["main_cf_sha256"] or \
               sha256(POSTFIX_DIR / "master.cf") != report["postfix"]["master_cf_sha256"]:
                raise DeploymentError("main.cf/master.cf changed since inspection; re-run")
            refuse_symlinks()
            refuse_changes(planned, "inspection")
            backup = new_backup(f"postfix-{phase}")
            managed = [POSTFIX_DIR / "main.cf", POSTFIX_DIR / "master.cf", Path(DEFAULT_CONFIG_PATH)]
            for path in managed:
                backup_file(path, backup)
            write_manifest(backup, {"kind": f"postfix-{phase}", "ops": ops, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                    "previous_mode": config["mode"], "before": {str(p): file_state(p) for p in managed}})
            run(["postfix", "-c", str(staging), "check"])
            progress: set[str] = set()
            try:
                if set_config_mode(Path(DEFAULT_CONFIG_PATH), phase):
                    progress.add("config")
                    log(f"set mode = \"{phase}\" in {DEFAULT_CONFIG_PATH}; restarting daemon")
                    run(["systemctl", "restart", "postwarden.service"])
                    time.sleep(1)
                    if not service_active("postwarden.service"):
                        raise DeploymentError("daemon failed to restart with the new mode")
                if diff:
                    progress.add("postfix")
                    for name in ("main.cf", "master.cf"):
                        atomic_copy(staging / name, POSTFIX_DIR / name, 0o644)
                    run(["postfix", "check"])
                    run(["postfix", "reload"])
                    log(f"Postfix reloaded; backup {backup.name}")
                else:
                    log(f"Postfix unchanged, not reloaded; backup {backup.name}")
            except Exception as exc:
                log(f"! activation failed: {exc}; restoring the previous state from {backup.name}")
                try:
                    restore_activation(backup, progress, log)
                except Exception as recovery:
                    raise DeploymentError(f"activation failed ({exc}) and recovery failed ({recovery}); "
                                          f"restore by hand from {backup}") from None
                raise DeploymentError(f"activation failed and the previous state was restored: {exc}") from None
            record_after(backup, managed)
            return backup.name
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def restore_activation(backup: Path, progress: set[str], log: Callable[[str], None]) -> None:
    """Undo a partly applied configure-postfix: Postfix files first, then the daemon mode."""
    if "postfix" in progress:
        for name in ("main.cf", "master.cf"):
            atomic_copy(backup / name, POSTFIX_DIR / name, 0o644)
        run(["postfix", "check"])
        run(["postfix", "reload"])
        log("restored main.cf/master.cf and reloaded Postfix")
    if "config" in progress:
        atomic_copy(backup / "config.toml", Path(DEFAULT_CONFIG_PATH), 0o640, ("root", SERVICE_USER))
        run(["systemctl", "restart", "postwarden.service"])
        log("restored the previous mode and restarted postwarden")


# -- rollback -----------------------------------------------------------------------


def rollback_divergence(manifest: dict, targets: list[Path], application: bool) -> list[str]:
    """Files whose content, mode or ownership changed since the deployment wrote them."""
    after = manifest.get("after")
    if after is None:
        return ["(this deployment has no post-deployment record)"]
    changed = [str(t) for t in targets if after.get(str(t)) != file_state(t)]
    if application and after.get("application") != tree_digest(ROOT, metadata=True):
        changed.append(str(ROOT))
    return changed


def rollback(deployment_id: str, apply: bool, log: Callable[[str], None], force: bool = False) -> None:
    backup = BACKUPS / deployment_id
    if not (backup / "manifest.json").exists():
        raise DeploymentError(f"no deployment {deployment_id} under {BACKUPS}")
    manifest = json.loads((backup / "manifest.json").read_text())
    before = manifest.get("before", {})
    restores: list[tuple[Path, Path]] = []
    removals: list[Path] = []
    for name, target in (("main.cf", POSTFIX_DIR / "main.cf"), ("master.cf", POSTFIX_DIR / "master.cf"),
                         ("config.toml", Path(DEFAULT_CONFIG_PATH)), ("postwarden.service", UNIT), ("postwarden", LAUNCHER)):
        if (backup / name).exists():
            restores.append((backup / name, target))
        elif manifest["kind"] == "install" and target in (UNIT, LAUNCHER) and str(target) in before \
                and before[str(target)] is None and target.exists():
            removals.append(target)
    archive = backup / "application.tar.gz"
    for source, target in restores:
        log(f"restore {target} from {source}")
    for target in removals:
        log(f"remove {target} (absent before this first installation)")
    if archive.exists():
        log(f"restore application tree {ROOT} from {archive}")
    if removals:
        log("stop and disable postwarden.service; keep " + f"{ROOT} (application and config.toml), user {SERVICE_USER}, "
            f"{SOCKET_DIR}, {STATE_DIR} and {BACKUPS}")
    targets = [t for _, t in restores] + removals

    def check() -> None:
        refuse_symlinks()
        if removals and shutil.which("postconf") and (used := postfix_references()):
            raise DeploymentError("Postfix still uses postwarden in " + ", ".join(used)
                                  + "; roll back the configure-postfix deployment first")
        diverged = rollback_divergence(manifest, targets, archive.exists())
        if diverged:
            log("changed since the deployment: " + ", ".join(diverged))
            if not force:
                raise DeploymentError("files changed after the deployment; review them, then re-run with --force to overwrite")

    check()
    if not apply:
        return
    default_modes = {str(LAUNCHER): (0o755, 0, 0), str(DEFAULT_CONFIG_PATH): (0o640, 0, None)}
    with deployment_lock():
        check()
        if removals:
            run(["systemctl", "disable", "--now", "postwarden.service"], check=False)
        for source, target in restores:
            recorded = before.get(str(target)) or {}
            default_mode, default_uid, default_gid = default_modes.get(str(target), (0o644, 0, 0))
            mode = recorded.get("mode", default_mode)
            gid = recorded.get("gid", default_gid if default_gid is not None else grp.getgrnam(SERVICE_USER).gr_gid)
            atomic_copy(source, target, mode, (recorded.get("uid", default_uid), gid))
        for target in removals:
            target.unlink()
        if archive.exists():
            for name in APP_FILES:
                target = ROOT / name
                if target.is_dir():
                    shutil.rmtree(target)
                elif target.exists():
                    target.unlink()
            shutil.unpack_archive(str(archive), str(ROOT))
        if manifest["kind"].startswith("postfix"):
            run(["postfix", "check"])
            run(["postfix", "reload"])
        run(["systemctl", "daemon-reload"])
        if UNIT.exists():
            run(["systemctl", "restart", "postwarden.service"])
        log("rollback applied")
