# ADR-0007: Per-sender sending limits in postwarden (planned for 1.1)

- Status: Accepted
- Date: 2026-09-22

## Context

A compromised mailbox password or a hacked web script can send spam through
the server until someone notices. Postfix's own limits (`anvil`,
`smtpd_client_message_rate_limit` and related settings) count per client IP,
while a stolen login is typically used from many addresses. postwarden already
sees the SASL login, ingress, trust class and recipients of every message.
Each account submits through one server; memcached runs on the mail hosts but
cross-host counters are not needed. 1.0.0 is the build that passed acceptance
on Debian 12 and 13, so this ships afterwards with its own acceptance round.

## Decision

- **Where:** a new postwarden rule, `sending_limit`, not a separate policy daemon.
- **Who is counted, by key:**
  - `authenticated_submission`: the SASL login (case-folded lookup key);
  - `local_pickup` and `local_smtp`: the envelope sender (`<>` for null sender);
  - `mynetworks` relays without a login: the client IP address;
  - untrusted inbound mail is not limited.
- **Host-wide local cap:** one extra key over all `local_pickup`/`local_smtp`
  mail, because a script can rotate envelope senders.
- **What:** messages and recipients, with separate limits.
- **Windows:** rolling hour and rolling day, each checked at every decision;
  no fixed boundaries to wait for.
- **Defaults (enabled):** per key 100 messages/h, 500/day, 300 recipients/h,
  1000/day; host-wide local cap 1000 messages/h, 5000/day, 3000 recipients/h,
  10000/day. Per-key overrides in `config.toml` for bulk senders.
- **Counting:** recipients are checked at RCPT against committed counts plus
  those reserved by in-flight transactions; messages at MAIL. Reservations are
  committed when the message is accepted at end of message and released on
  abort, rejection or deferral, so refused or aborted mail does not count.
- **Action:** over the limit → temporary failure. SMTP: `451` at MAIL (message
  limit) or RCPT (recipient limit). Local pickup: accumulated and returned at
  end of message, like other non-SMTP decisions; the resulting queue behavior
  must be verified on both Debian releases before release. New reply key
  `sending_limit`, default `451 4.7.1 Sending limit exceeded - try again later`,
  with the usual `(ref <mid>)`. Observe mode logs `would_defer`.
- **Logging:** each refusal is an `info` decision (`rule=sending_limit`,
  reasons `messages_per_hour`, `messages_per_day`, `recipients_per_hour`,
  `recipients_per_day`, prefixed `host_` for the host-wide cap) with the key;
  the first refusal per key per window is additionally logged at `warning`
  (`event=limit_reached`) for alerting from existing log tooling. postwarden
  never sends mail itself.
- **State:** in-process, bucketed sliding windows (minute buckets for the hour,
  larger buckets for the day) with a bound on tracked keys and eviction of idle
  ones. A daemon restart resets the windows.

## Consequences

- A stolen login or hacked script is throttled within minutes instead of
  sending until detected, whatever IP addresses it uses.
- Legitimate bursts beyond the defaults need per-key overrides; deferral rather
  than rejection means an affected user's mail is delayed, not lost.
- A restart gives every key a fresh window; acceptable because restarts are
  rare and not attacker-triggered.
- Options not taken: memcached (restart-proof but a network hop per recipient,
  a new dependency and an undefined failure mode, for a cross-host need that
  does not exist); a separate policy daemon such as postfwd; per-IP anvil limits
  only; rejecting or holding over-limit mail; alert mail from the milter.
