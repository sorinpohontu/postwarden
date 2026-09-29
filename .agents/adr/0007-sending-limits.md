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
- **Local cap:** one extra key over all `local_pickup`/`local_smtp`
  mail, because a script can rotate envelope senders. It has its own two
  numbers and takes no multiplier.
- **What:** recipients, per rolling hour and rolling day, checked at every
  RCPT; no fixed boundaries to wait for. There is no separate message counter:
  every message has at least one recipient, so the recipient count is never
  below the message count and already stops floods of single-recipient
  messages. A message to 100 recipients and 100 messages to one recipient each
  both count 100.
- **Defaults:** per key 100 recipients per hour and 500 per day; local
  cap 1000 per hour and 5000 per day.
- **Own mode:** `[sending_limits] mode = "observe" | "enforce" | "off"`,
  default `observe`, so a host can enforce the other rules while its limits
  only log `would_defer`; the operator uses `postwarden stats` to set
  multipliers, then chooses `enforce`.
  The global `mode = "observe"` still wins. In `observe`, counts follow what
  enforcement would have committed: recipients that would have been deferred
  are not counted. `off` neither counts nor logs.
- **Exceptions are multipliers** that scale both per-key defaults:
  - per account: the limit key itself (SASL login, or envelope sender of
    local mail), e.g. `"marketing@example.com" = 10`. `"<>"` is the one
    special account key: the shared null-sender key of local mail (for
    example Sieve vacation replies sent with `sendmail`);
  - per domain: the domain of that key, exact match only (no subdomains),
    e.g. `"example.com" = 2`. A login without a domain (such as `john`) takes
    the domain of its envelope sender for this lookup; its account key stays
    the login. Its own account multiplier is written with an explicit prefix,
    `"login:john" = 3`, and beats the sender-domain multiplier;
  - per relay: an IP address or CIDR for `mynetworks` relays without a login,
    e.g. `"192.0.2.10" = 5`; domain multipliers do not apply to relays.
  - The most specific match wins and factors are never combined: account over
    domain; for relays, the longest matching prefix.
  - A multiplier is a positive number; fractions tighten (`0.5`). There is no
    0 and no "unlimited". Scaled limits are rounded down, minimum 1.
  - Keys are classified exactly: `"<>"` (null sender); `"login:NAME"` (a
    login without `@`; `NAME` has no `@` and is case-folded like the limit
    key); an IP address or CIDR (relay); a key containing `@` (account); any
    other key must be a domain with at least one dot. `"login:"` with an
    `@` is rejected (write the address itself), so each account has one
    spelling.
  - `check-config` rejects invalid entries (non-positive values, malformed
    addresses, domains or networks, duplicates after case folding, such as
    `"login:John"` next to `"login:john"`); `show-config` prints the
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
- **Counting (transaction contract):**
  - A recipient is reserved only when every rule allows it at RCPT; a
    recipient refused by any rule reserves nothing.
  - The per-key and the local-cap reservation are taken together, under one
    lock, or neither is taken.
  - At end of message, if the message is finally accepted, the reserved
    count (the accepted recipients) is committed. Every other exit releases
    all of that message's reservations: rejection or deferral at end of
    message (for example sender authentication), deferral of held local mail,
    abort, RSET, a new MAIL, disconnect, and callback exceptions.
  - Two sessions of one key at the limit cannot both pass: the check and the
    reservation are one atomic step.
  - In `observe` mode two figures are kept apart: the hypothetical count
    (what enforcement would have committed, which drives `would_defer`) and
    the delivered count; only the hypothetical count drives decisions.
- **Action:** over the limit → temporary failure. SMTP: `451` at RCPT from the
  first recipient over the limit; earlier recipients of the same message
  proceed. Local pickup: accumulated and returned at
  end of message, like other non-SMTP decisions. Verified on Debian 12 and
  13 (2026-09-25): Postfix keeps the original file in `maildrop`, `pickup`
  retries it at every scan (every 60 s, and whenever new local mail is
  submitted: verified 2026-09-29 on Debian 12) with a fresh `cleanup` pass, no backoff, no bounce
  and no queue lifetime, so the message is delivered once the window allows.
  Every retry is a full decision and one log line. `inspect` reports the
  number and oldest age of files in `maildrop`, with a finding at 100 files
  or a file older than 1 hour (fixed values; normally `maildrop` empties
  within a minute); the operations guide explains how to list and remove held local
  mail. New reply key
  `sending_limit`, default `451 4.7.1 Sending limit exceeded - try again later`,
  with the usual `(ref <mid>)`. Observe mode logs `would_defer`.
- **Logging:** each refusal is an `info` decision (`rule=sending_limit`,
  reasons `per_hour`, `per_day`, and `local_per_hour`, `local_per_day` for
  the local cap) with the key;
  the first refusal per key per window is additionally logged at `warning`
  (`event=limit_reached`) for alerting from existing log tooling. postwarden
  never sends mail itself.
- **State:** in-process, bucketed sliding windows (minute buckets for the hour,
  larger buckets for the day), stored sparsely.
  - Capacity: a fixed maximum of 20000 keys (not configurable; a later
    release can expose it if `key_store_full` warnings show a need). A key whose
    windows have fully expired and that holds no reservation is freed
    first. A key with unexpired counts or a reservation is never evicted,
    so no counted sender regains quota. When the store is still full, a new
    key is deferred (`451`, `reason=key_store_full`) and a `warning` is
    logged once per minute. The local-cap key is fixed and outside
    the store.
  - The full-store result follows the mode: `enforce` sends the `451`;
    `observe` (own or global) only logs `would_defer reason=key_store_full`
    and lets the mail continue, and that new key is not counted (its quota is
    not measured; the end-of-message line carries `limit_measured=no`).
    `limit_measured` has three values on every end-of-message line with
    `limit_key=`: `yes` (counted), `no` (full store in observe mode) and
    `off` (`[sending_limits] mode = "off"`: nothing counted, no
    `sending_limit` decision lines, but the key is still logged so `stats`
    can rank senders before limits are switched on). The local-cap
    local counter is outside the store and still counts such local mail.
    `off` has no store.
  - The daemon writes the committed counts (not in-flight reservations; in
    `observe`, the hypothetical counts enforcement would have committed, so a
    switch to `enforce` starts from them) to
  `/var/lib/postwarden/limits.json`, owned by `postwarden`, mode `0600`, every
  60 s (fixed, matching the minute buckets) and on a clean stop: write a temporary file, `fsync` it, rename it
  over the old one and `fsync` the directory. The durability claim is exactly
  that sequence; the crash-loss bound is the save interval.
  - Clean stop: when libmilter returns after `systemctl stop` (SIGTERM),
    in-flight reservations are released and the committed counts saved,
    within the unit's stop timeout.
  - A failed periodic save logs a `warning` with the age of the last
    successful snapshot and is retried at the next interval; mail keeps
    flowing. The `event=start` line also reports that age.
  - The file carries a schema version. On load it is checked strictly: size,
    number of keys (at most the key limit), bucket counts, value ranges and
    timestamps; buckets older than the day window are dropped and buckets in
    the future are discarded.
  - A missing, unreadable, oversized, invalid or incompatible file means
    empty windows, reported on the `event=start` line and in a `warning`;
    mail keeps flowing. No log source is used for limits.

Illustrative configuration (final key names are set with the implementation):

```toml
[sending_limits]
per_hour = 100          # recipients
per_day = 500

[sending_limits.multipliers]
"example.com" = 2
"marketing@example.com" = 10
"192.0.2.10" = 5
"<>" = 5
"login:john" = 3
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
  forged. A crash loses the counts since the last successful save: at most
  one minute while saves succeed, more after repeated save failures (reported
  with the snapshot age). Downtime still ages
  the windows normally, because buckets expire by wall-clock time.
- Postfix's per-IP limits and postwarden's per-key limits complement each
  other: anvil does not see logins, local mail or `mynetworks` relays;
  postwarden does not see refused recipients. The warning makes a Postfix
  limit that silently caps a multiplier visible.
- For a login without a domain, the domain multiplier follows the envelope
  sender, which the client chooses. Where Postfix does not enforce sender
  ownership (`reject_sender_login_mismatch` with `smtpd_sender_login_maps`), a
  stolen short login can pick a sender domain with a larger multiplier.
- A flood of local mail held in `maildrop` is re-checked at every `pickup`
  scan, and every new submission starts another scan. Measured on Debian 12
  (2026-09-29, 250 held files, 250 submissions in 10 s): after a first burst,
  about one decision per second whatever the number of held files, consistent
  with Postfix's `in_flow_delay` (1 s) pausing `pickup` while retries keep the
  queue manager idle. So a flood costs at most about 3,600 decisions and 7,200
  log lines an hour, and delays new local mail (and possibly SMTP intake, by
  up to `in_flow_delay` per message) until the windows allow the held mail or
  the operator removes it. Every retry stays an `info` line; a per-key
  summary of repeated deferrals was designed and not built, as the measured
  volume did not justify it. Accepted for complete logs; the
  operator removes the backlog.
- A local message with more recipients than its sender's limit, or the local
  cap, can never pass and is held until the operator raises the limit with a
  multiplier or removes the message; SMTP clients instead get the excess
  deferred and send it later. Rejecting it was not taken: the bounce would go
  to an envelope sender that a hacked script chooses.
- Under an attack with many distinct senders, a full key store delays new
  legitimate senders (deferred, not lost) rather than letting counted senders
  regain quota or new keys go unlimited.
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
  - limits following the global mode (they would defer from the first
    enforce switch, before multipliers are known); limits enforced by default;
    limits off unless configured;
  - skipping the domain level for logins without a domain;
  - a bare single label (`"john"`) as the short-login key, classified by
    shape: implicit, and it makes a single-label key ambiguous between login
    and domain;
  - accepting new keys uncounted, or evicting the least recently used key,
    when the key store is full;
  - a configurable key limit (`max_keys`): one more setting few operators
    could size; `key_store_full` warnings show if a later release should
    expose it;
  - logging only the first deferral per key and window;
  - a postwarden command that removes held local mail;
  - absolute per-key overrides; multiplying domain and account factors; an
    "unlimited" value; whole-number-only factors; relays without overrides.
