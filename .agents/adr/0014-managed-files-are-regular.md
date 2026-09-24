# ADR-0014: Managed files must be regular files

- Status: Accepted
- Date: 2026-09-23

## Context

Backups stored a symlinked managed file as `<name>.symlink`, which neither
rollback nor activation recovery could restore, and applying a staged file
replaced the live symlink with a regular file (follow-up review 2026-09-23,
R21).

## Decision

- `main.cf`, `master.cf`, `config.toml`, the launcher and the unit must be
  regular files. `inspect` reports a symlink; `install`, `configure-postfix`
  and `rollback` stop before changing anything.
- Backups store regular files only.

## Consequences

- One restore path, fully tested; no silently skipped files.
- Sites that symlink these files from configuration management must replace
  the link with the file, or manage those files by hand.
- Option not taken: recording link targets and restoring link and target.
