# ADR-0021: `lookup` and `stats` read postwarden's journal entries by trusted unit

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
- When `journalctl` is missing, the automatic fallback to
  `/var/log/mail.log*` is labelled the same way; it is never silent.
- Every `lookup` and `stats` output names its source (trusted journal,
  journal by tag with `--any-source`, or files) and its verification status.
- The journal stays the default even where `/var/log/mail.log` exists: it is
  the unforgeable source, and it is indexed. When `--since` reaches before the
  journal's oldest entry (a volatile or size-capped journal), `lookup` and
  `stats` say so in one line, with the journal's start time and a pointer to
  `--file '/var/log/mail.log*'` as an unverified source. They never switch
  source by themselves.

## Consequences

- Forged lines no longer show up in `lookup` or count in `stats` when the
  journal is the source.
- Syslog files stay forgeable; operators who rely on `--file` get a notice
  instead of a guarantee.
- A daemon not run by `postwarden.service` is invisible to both commands
  unless `--any-source` is given.
- On a host whose journal is volatile or small, older history needs an
  explicit `--file`; the coverage line makes the gap visible instead of
  returning silently short totals.
- Not taken: trusted-only with no fallback; keeping the identifier match;
  preferring `/var/log/mail.log` when it exists (forgeable, slower, and on
  the reference production host it kept about 8 days against the journal's
  4 weeks).
