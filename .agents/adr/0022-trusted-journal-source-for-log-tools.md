# ADR-0022: `lookup` and `stats` read postwarden's journal entries by trusted unit

- Status: Accepted
- Date: 2026-09-25

## Context

`postwarden lookup` reads the journal with `journalctl -t postwarden`, which
matches the syslog identifier. Any local user, including a customer's PHP
script, can write lines with that identifier (`logger -t postwarden ...`), so
forged lines can appear in `lookup` output and would inflate `stats` (ADR-0020).
The journal also records trusted fields set by journald itself, such as
`_SYSTEMD_UNIT`, which a client cannot choose. Syslog files written by rsyslog
carry no such field.

## Decision

- From 1.1, `lookup` and `stats` read journal entries whose `_SYSTEMD_UNIT` is
  `postwarden.service`.
- `--any-source` falls back to the syslog identifier, for a daemon started by
  hand in the foreground (tests, debugging).
- With `--file`, results come from syslog files and the output says that their
  source cannot be verified.

## Consequences

- Forged lines no longer show up in `lookup` or count in `stats` when the
  journal is the source.
- Syslog files stay forgeable; operators who rely on `--file` get a notice
  instead of a guarantee.
- A daemon not run by `postwarden.service` is invisible to both commands
  unless `--any-source` is given.
- Not taken: trusted-only with no fallback; keeping the identifier match.
