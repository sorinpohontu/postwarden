#!/usr/bin/python3
"""Build postwarden-<version>.tar.gz containing only the distributable files, plus a checksum.

The archive is reproducible: file order, ownership, modes and timestamps are fixed, and the
timestamp comes from SOURCE_DATE_EPOCH or, if unset, the HEAD commit time."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from postwarden import __version__  # noqa: E402

INCLUDE = [
    "src", "bin", "packaging", "etc",
    "scripts/install.py",
    "docs/README.md", "docs/Installation.md", "docs/Configuration.md", "docs/Operations.md",
    "docs/Migration.md",
    "README.md", "CHANGELOG.md", "LICENSE", "pyproject.toml",
]
EXCLUDE_NAMES = {"__pycache__", ".DS_Store", "logs", "gate-env.sh"}


def wanted(path: Path) -> bool:
    return not any(part in EXCLUDE_NAMES or part.startswith("._") or part.endswith(".pyc") for part in path.parts)


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True).stdout.strip()


def source_date_epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH") or git("log", "-1", "--format=%ct")
    return int(value) if value.isdigit() else 0


def entry(name: str, size: int, mode: int, mtime: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = size, mode, mtime
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    return info


LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")


def broken_links(names: set[str]) -> list[str]:
    """Relative Markdown links in the archive that point outside it."""
    broken = []
    for name in sorted(n for n in names if n.endswith(".md")):
        for target in LINK.findall((REPO / name).read_text()):
            if "://" in target or target.startswith("mailto:"):
                continue
            resolved = os.path.normpath(os.path.join(os.path.dirname(name), target)).rstrip("/")
            if resolved not in names and not any(n.startswith(resolved + "/") for n in names):
                broken.append(f"{name} -> {target}")
    return broken


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(REPO / "dist"))
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    revision = git("rev-parse", "--short", "HEAD") or "unknown"
    if git("status", "--porcelain", "--", *INCLUDE):
        revision += "-dirty"
        print("warning: distributable files differ from HEAD; the archive is not a build of a commit", file=sys.stderr)
    mtime = source_date_epoch()
    selected = {p.relative_to(REPO).as_posix()
                for item in INCLUDE if (REPO / item).exists()
                for p in ([REPO / item] if (REPO / item).is_file() else (REPO / item).rglob("*"))
                if p.is_file() and wanted(p.relative_to(REPO))}
    broken = broken_links(selected)
    if broken:
        print("error: links to files outside the archive:\n  " + "\n  ".join(broken), file=sys.stderr)
        return 1
    archive = out / f"postwarden-{__version__}.tar.gz"
    manifest = io.StringIO()
    with open(archive, "wb") as raw, \
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=mtime, compresslevel=9) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for item in INCLUDE:
            source = REPO / item
            if not source.exists():
                print(f"warning: {item} missing", file=sys.stderr)
                continue
            files = [source] if source.is_file() else sorted(p for p in source.rglob("*") if p.is_file())
            for path in files:
                rel = path.relative_to(REPO)
                if not wanted(rel):
                    continue
                data = path.read_bytes()
                mode = 0o755 if (path.parent.name in ("bin", "scripts") or path.suffix == ".sh") else 0o644
                tar.addfile(entry(rel.as_posix(), len(data), mode, mtime), io.BytesIO(data))
                manifest.write(f"{hashlib.sha256(data).hexdigest()}  {rel.as_posix()}\n")
        manifest.write(f"# postwarden {__version__} revision {revision}\n")
        data = manifest.getvalue().encode()
        tar.addfile(entry("MANIFEST.sha256", len(data), 0o644, mtime), io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (out / (archive.name + ".sha256")).write_text(f"{digest}  {archive.name}\n")
    print(f"{archive}\nsha256 {digest}\nrevision {revision}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
