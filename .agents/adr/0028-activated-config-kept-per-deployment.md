# ADR-0028: Each deployment keeps the configuration it activated

- Status: Accepted; predecessor selection superseded by ADR-0030
- Date: 2026-10-08

## Context

From 1.2 operators and templates edit `config.toml` before running
`configure-postfix --apply` (ADR-0025). The apply backup is taken after that
edit, so it holds the new configuration, not the one the running daemon
loaded. The loaded-config hash detects the change but cannot restore the old
bytes (plan review F5).

## Decision

- Each successful `--apply` stores a copy of the configuration it activated in
  its deployment backup directory, with the existing permissions, lock and
  concurrent-edit checks.
- Failed activation and rollback restore the configuration from the previous
  successful deployment's copy, together with Postfix files, and restart the
  daemon. A first apply has no previous copy and rolls back as a first install
  does (ADR-0015).
- The daemon hashes the exact bytes it parsed and publishes the hash
  atomically once it accepts connections; a missing or unreadable hash counts
  as "differs" and causes a restart.
- Order of activation: when the failure action becomes stricter (`accept` to
  `tempfail`), Postfix is updated before the daemon restarts; when it becomes
  looser, the daemon restarts first. Newly enforced rules are never open
  during the switch.

## Consequences

- Rollback works for hand edits and templates without an extra operator step.
- A hand edit followed only by `systemctl restart` is not a deployment and has
  no copy; the next `--apply` records it.
- Not taken: one separate active-copy file (a second place with its own
  permissions and locking); an operator `--snapshot` step (a template run that
  skips it has no rollback).
