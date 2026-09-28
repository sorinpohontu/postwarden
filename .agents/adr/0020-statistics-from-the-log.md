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

Measures are named, never raw line counts:

- **messages accepted**: end-of-message lines with `action=accept`;
- **recipients delivered**: on those lines, `rcpts` minus `rejected_rcpts`
  and `deferred_rcpts`, which count only refusals actually sent (a
  two-recipient message with one RCPT refusal adds one). "Delivered" means
  handed on to Postfix by postwarden; final delivery is Postfix's and is not
  in postwarden's log. The report legend says so;
- **recipients allowed**: recipients delivered minus `would_rejected_rcpts`
  and `would_deferred_rcpts`, the observe-mode refusals (global mode or the
  sending limits' own mode) that enforcement would have sent; equal to
  recipients delivered when nothing is observed;
- **refusals** per rule and reason: `reject`/`defer` decision lines, each a
  recipient (RCPT stage) or a message (MAIL/EOM stage), reported separately;
- **observe-mode outcomes** (`would_reject`, `would_defer`) in their own
  columns, never mixed with real refusals.

A transaction without an end-of-message line (abort, refusal at MAIL)
contributes only its refusal lines. Held local mail retried by `pickup`
produces one deferral per retry and is shown as such. The ranking per limit
key uses recipients delivered; recipients of keys logged with
`limit_measured=no` (a full key store in observe mode, ADR-0007) are shown in
their own column; with `limit_measured=off` (limits switched off) senders are
still ranked and the report says limits were off. Mail without a limit key (untrusted inbound) counts in the
totals only.

Interface: `postwarden stats [--since -24h] [--file GLOB] [--any-source]
[--top 20] [--config FILE] [--json]`. The default output is aligned text in
sections: a header with source, verification status, period and completeness,
then totals, refusals by rule and reason, and the top senders. `--json` gives
the same content for monitoring scripts; its field names are a documented
interface. The ranking shows per key: messages, recipients delivered,
recipients allowed, sending-limit deferrals, and the key's effective
`per_hour`/`per_day` from the selected configuration (multiplier applied),
labelled as such; the counts are labelled totals for the period. A login
without a domain takes its domain multiplier from each message's envelope
sender (ADR-0007), so it gets one row per sender domain, each with its own
effective limits, plus a total row for the login; an account multiplier
that overrides them gives a single row. `stats`
makes no claim about remaining quota or peaks: a period total does not show
how close a rolling window came to its limit, and the configuration in force
when the lines were written may differ. `stats` reads `config.toml` for this
(`--config` for another file).

Line format: `stats` reads the 1.1 log format only. 1.0.x was never deployed
in production, so no older lines need to be recognised or converted.

Time and sources: `--since` applies to the journal only. With `--file`, or
when `journalctl` is missing and the syslog files are read instead, `stats`
reports whole-file totals and refuses `--since`. Every report states its
source and whether it is verified (ADR-0021). Totals are best-effort for the
period: lines lost to retention, rotation or a `logging.level` above `info`
cannot be reconstructed. The `event=start` line records `logging_level=`;
when a start line in the period shows a level above `info`, or none is found,
the report says so. The current setting alone never marks a period complete.

## Consequences

- No daemon change, no new network surface, no dependency; counts survive
  daemon restarts because they come from the log.
- Counts are only as complete as the log: `logging.level` above `info`
  drops decision lines, and log retention bounds the period.
- Reading the journal needs root or the `adm`/`systemd-journal` group, and
  large periods are slower than reading a counter.
- Not taken: a periodic `event=stats` line (daemon state that resets on
  restart) and a metrics endpoint (new listener, against the project's
  no-extra-surface rule). Either can be revisited if a monitoring system
  needs push-style numbers.
