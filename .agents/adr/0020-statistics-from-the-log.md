# ADR-0020: Operational statistics are counted from the log, not kept by the daemon

- Status: Accepted
- Date: 2026-09-25

## Context

The plan asked for operational counters (accept/reject/defer/bypass, DNS
errors, limit hits). 1.0 shipped without them: every decision is already one
`key=value` log line with stable `action`, `rule` and `reason` fields, so any
count can be derived from the log. The options were in-daemon counters
exposed by a periodic `event=stats` line, a metrics endpoint (Prometheus
style), or a command that counts the existing log lines.

## Decision

Add a `postwarden stats` command that reads the same sources as `lookup`
(the journal, or syslog files including rotated `.gz` with `--file`) and
prints totals per action, rule and reason for a period (`--since`). It
also ranks senders by sending-limit key (SASL login, envelope sender of local
mail, `mynetworks` relay IP; ADR-0007), so abuse is visible from the log and
limits can be chosen from real traffic before they are enabled: per key,
messages and recipients for the period, sorted by recipients, top 20 by
default. The key is read from a `limit_key=` field that the daemon logs on
`mail` and `eom` lines of mail that has one (authenticated submission, local
mail, `mynetworks` relays; absent for untrusted inbound), so `stats` never
re-derives keys or their case folding. The daemon keeps no counters and
exposes no metrics listener.

## Consequences

- No daemon change, no new network surface, no dependency; counts survive
  daemon restarts because they come from the log.
- Lines written before `limit_key=` existed are counted in the totals but
  not ranked.
- Counts are only as complete as the log: `logging.level` above `info`
  drops decision lines, and log retention bounds the period.
- Reading the journal needs root or the `adm`/`systemd-journal` group, and
  large periods are slower than reading a counter.
- Not taken: a periodic `event=stats` line (daemon state that resets on
  restart) and a metrics endpoint (new listener, against the project's
  no-extra-surface rule). Either can be revisited if a monitoring system
  needs push-style numbers.
