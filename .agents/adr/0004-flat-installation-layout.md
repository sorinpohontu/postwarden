# ADR-0004: Install the application directly in /etc/postwarden

- Status: Accepted
- Date: 2026-09-22

## Context

The original design proposed `/etc/postwarden/releases/<version>/`, a `current` symlink
and a `staging/` area so releases could be switched atomically and rolled back
by re-pointing the symlink. The project targets a small number of servers
managed by hand and, later, by Ansible; the extra indirection complicated the
installer, the launcher and the operator instructions.

## Decision

`/etc/postwarden/` holds the unpacked application (`src/`, `bin/`,
`scripts/`, `packaging/`, `etc/`, `docs/`) together with the single active
`config.toml`. The launcher runs `/etc/postwarden/src`. Upgrades unpack a
new candidate over the same directory; before that, the installer stores the
previous tree in the deployment backup so `rollback` can restore it.

## Consequences

- One directory to inspect, back up and document; the installer runs from the
  directory it installs.
- No atomic release switch: an upgrade is "backup, overwrite, restart", and code
  rollback restores files from `/var/backups/postwarden/<id>/`.
- Release archives must never contain `config.toml` or other host state.
- Option not taken: versioned releases with a `current` symlink.
