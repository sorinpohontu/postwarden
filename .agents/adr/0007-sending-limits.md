# ADR-0007: Per-sender sending limits in postwarden (planned for 1.1)

- Status: Accepted
- Date: 2026-09-22; rewritten 2026-09-25 before implementation (state file,
  multipliers, one recipient counter)

## Context

A compromised mailbox password or a hacked web script can send spam through
the server until someone notices. Postfix's own limits (`anvil`,
`smtpd_client_message_rate_limit` and related settings) count per client IP,
while a stolen login is typically used from many addresses. postwarden already
sees the SASL login, ingress, trust class and recipients of every message.
Each account submits through one server; cross-host counters are not needed.
On a hosting server most exceptions follow a pattern: a customer domain that
sends more than average, one marketing account that sends much more, an
internal application relaying from a fixed address.

## Decision

- **Where:** a new postwarden rule, `sending_limit`, not a separate policy
  daemon.
- **Who is counted, by limit key:**
  - `authenticated_submission`: the SASL login (case-folded lookup key);
  - `local_pickup` and `local_smtp`: the envelope sender (`<>` for null sender);
  - `mynetworks` relays without a login: the client IP address;
  - untrusted inbound mail is not limited.
- **Host-wide local cap:** one extra key over all `local_pickup`/`local_smtp`
  mail, because a script can rotate envelope senders. It has its own two
  numbers and takes no multiplier.
- **What:** recipients, per rolling hour and rolling day, checked at every
  RCPT; no fixed boundaries to wait for. There is no separate message counter:
  every message has at least one recipient, so the recipient count is never
  below the message count and already stops floods of single-recipient
  messages. A message to 100 recipients and 100 messages to one recipient each
  both count 100.
- **Defaults (enabled):** per key 100 recipients per hour and 500 per day;
  host-wide local cap 1000 per hour and 5000 per day.
- **Exceptions are multipliers** that scale both per-key defaults:
  - per account: the limit key itself (SASL login, or envelope sender of
    local mail), e.g. `"marketing@example.com" = 10`;
  - per domain: the domain of that key, exact match only (no subdomains),
    e.g. `"example.com" = 2`;
  - per relay: an IP address or CIDR for `mynetworks` relays without a login,
    e.g. `"192.0.2.10" = 5`; domain multipliers do not apply to relays.
  - The most specific match wins and factors are never combined: account over
    domain; for relays, the longest matching prefix.
  - A multiplier is a positive number; fractions tighten (`0.5`). There is no
    0 and no "unlimited". Scaled limits are rounded down, minimum 1.
  - `check-config` rejects invalid entries (non-positive values, malformed
    addresses, domains or networks, duplicates); `show-config` prints the
    effective limits per listed entry.
- **Postfix's own rate limits** (`smtpd_client_recipient_rate_limit`,
  `smtpd_client_message_rate_limit`, per client IP per `anvil_rate_time_unit`,
  exempting `smtpd_client_event_limit_exceptions`, `$mynetworks` by default)
  are an independent layer: both apply and the stricter refuses first;
  recipients Postfix refuses never reach postwarden and are not counted. The
  installer never sets or changes them.
  - `check-config` and `inspect` show their effective values, globally and per
    SMTP service (`postconf -P` overrides), like `mynetworks`.
  - They warn (non-blocking; `configure-postfix` is not refused) when, on a
    submission service, Postfix's per-IP recipient rate scaled to an hour is
    below the highest effective per-key `per_hour` (the default times the
    largest multiplier): that postwarden limit cannot be reached from a single
    client IP, so the multiplier appears to have no effect.
- **Counting:** each recipient is checked at RCPT against committed counts
  plus those reserved by in-flight transactions. Reservations are
  committed when the message is accepted at end of message and released on
  abort, rejection or deferral, so refused or aborted mail does not count.
- **Action:** over the limit → temporary failure. SMTP: `451` at RCPT from the
  first recipient over the limit; earlier recipients of the same message
  proceed. Local pickup: accumulated and returned at
  end of message, like other non-SMTP decisions; the resulting queue behavior
  must be verified on both Debian releases before release. New reply key
  `sending_limit`, default `451 4.7.1 Sending limit exceeded - try again later`,
  with the usual `(ref <mid>)`. Observe mode logs `would_defer`.
- **Logging:** each refusal is an `info` decision (`rule=sending_limit`,
  reasons `per_hour`, `per_day`, and `host_per_hour`, `host_per_day` for the
  host-wide cap) with the key;
  the first refusal per key per window is additionally logged at `warning`
  (`event=limit_reached`) for alerting from existing log tooling. postwarden
  never sends mail itself.
- **State:** in-process, bucketed sliding windows (minute buckets for the hour,
  larger buckets for the day) with a bound on tracked keys and eviction of idle
  ones. The daemon writes the committed counts (not in-flight reservations) to
  `/var/lib/postwarden/limits.json`, owned by `postwarden`, mode `0600`, every
  minute and on a clean stop, by atomic replace. At start it loads the file and
  drops buckets older than the day window. A missing, unreadable or invalid
  file means empty windows, reported on the `event=start` line and in a
  `warning`; mail keeps flowing. No log source is used for limits.

Illustrative configuration (final key names are set with the implementation):

```toml
[sending_limits]
per_hour = 100          # recipients
per_day = 500

[sending_limits.multipliers]
"example.com" = 2
"marketing@example.com" = 10
"192.0.2.10" = 5
```

## Consequences

- A stolen login or hacked script is throttled within minutes instead of
  sending until detected, whatever IP addresses it uses.
- One counter, two default numbers: one message to many addresses and many
  single-recipient messages are caught alike. A sender who occasionally mails
  a large list in one message (say 250 recipients) needs a multiplier.
- Legitimate bursts beyond the defaults need a multiplier; raising the
  defaults raises every exception proportionally. No key can be exempt: a
  compromised bulk account is throttled at its raised limit instead of never.
- Deferral rather than rejection means an affected user's mail is delayed,
  not lost.
- Restarts and reboots keep the windows on every host, whatever its logging
  setup; only the daemon's own account can write the state, so it cannot be
  forged. A crash loses at most the last minute of counts. Downtime still ages
  the windows normally, because buckets expire by wall-clock time.
- Postfix's per-IP limits and postwarden's per-key limits complement each
  other: anvil does not see logins, local mail or `mynetworks` relays;
  postwarden does not see refused recipients. The warning makes a Postfix
  limit that silently caps a multiplier visible.
- Options not taken:
  - memcached: restart-proof, but a network hop per recipient, a new
    dependency and an undefined failure mode, for a cross-host need that does
    not exist;
  - a separate policy daemon such as postfwd; per-IP anvil limits only;
    rejecting or holding over-limit mail; alert mail from the milter;
  - enforcing from the log per message: too slow, parallel sessions of one key
    overshoot before their accept lines exist, and enforcement would depend
    on `logging.level`;
  - rebuilding the windows from `/var/log/mail.log`: any local user can write
    `postwarden`-tagged lines with `logger` and exhaust another sender's
    quota; rsyslog trusted-property annotation would change the operator's
    rsyslog configuration and every mail log line;
  - rebuilding from the journal (trusted `_SYSTEMD_UNIT`): needs a root
    pre-start step, and a volatile journal (Debian 12 with rsyslog) is empty
    after a reboot;
  - separate message and recipient counters (four defaults): they differ only
    when the message limit is below the recipient limit, i.e. to allow one
    large broadcast while blocking many separate messages, which a multiplier
    covers;
  - skipping postwarden's limit where Postfix already limits: a per-IP limit
    does not stop a stolen login used from many addresses;
  - letting the installer set Postfix rate limits: postwarden would own
    unrelated Postfix policy;
  - absolute per-key overrides; multiplying domain and account factors; an
    "unlimited" value; whole-number-only factors; relays without overrides.
