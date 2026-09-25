# ADR-0021: The daemon saves its sending-limit windows to a state file

- Status: Accepted
- Date: 2026-09-25
- Amends: ADR-0007 (State: "A daemon restart resets the windows")

## Context

ADR-0007 keeps sending-limit counts in process memory, with reservations for
in-flight transactions, and accepts that a restart resets every window. A
configuration change restarts the daemon, so the daily window would restart
from zero more often than "rare" suggests.

Rebuilding the windows from logs was considered:

- Enforcing from the log per message: too slow, parallel sessions of one key
  overshoot before their accept lines exist, and enforcement would depend on
  `logging.level`.
- Seeding from `/var/log/mail.log`: any local user, including a customer's
  PHP script, can write `postwarden`-tagged lines with `logger` and exhaust
  another sender's quota. rsyslog can annotate lines with trusted properties,
  but only by changing the operator's rsyslog configuration and the format
  of every mail log line.
- Seeding from the journal (trusted `_SYSTEMD_UNIT`): unforgeable, but needs
  a root pre-start step, and where the journal is volatile (Debian 12 with
  rsyslog) a reboot empties it.

## Decision

- Enforcement stays in process as ADR-0007 describes.
- The daemon writes its hour and day windows (committed counts only, not
  in-flight reservations) to `/var/lib/postwarden/limits.json`, owned by
  `postwarden`, mode `0600`, every minute and on a clean stop, by atomic
  replace.
- At start it loads the file and drops buckets older than the day window.
- A missing, unreadable or invalid file means empty windows, reported on the
  `event=start` line and in a `warning`; mail keeps flowing.
- No log source (journal or syslog files) is used for limits.

## Consequences

- Restarts and reboots keep the windows, on every host, whatever its logging
  setup.
- Only the daemon's own account can write the state, so it cannot be forged
  from local scripts or log lines.
- No root helper, no journal access, no parsing of log lines.
- A crash loses at most the last minute of counts.
- Downtime still ages the windows normally: buckets expire by wall-clock time.
- Not taken: enforcement from the log; seeding from the journal; seeding from
  `mail.log` with or without rsyslog annotation; memcached (ADR-0007).
