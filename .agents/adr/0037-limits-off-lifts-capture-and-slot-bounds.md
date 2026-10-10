# ADR-0037: `[limits] mode = "off"` lifts the capture and slot bounds, not the time and DKIM safeguards

- Status: Accepted
- Date: 2026-10-10
- Refines: ADR-0023 (its `[limits] mode = "off"` consequence)

## Context

ADR-0023 says `off` "removes the daemon's own bounds on size, headers,
recipients, DNS time and open messages". The 1.2.0rc4 implementation only
silenced the `limits` rule: capture still truncated at `message_bytes` and the
headers caps, recipients over `max_recipients` were still cut, and the
open-message and verification slots still applied, so with an enforced
section an `off` limit could still defer mail (`rule=limits`). The
implementation review (I6) found the mismatch. ADR-0035 later added DKIM
worker processes as a memory safeguard, and DNS time bounds whether a message
finishes within Postfix's `content_timeout`.

## Decision

With `[limits] mode = "off"`:

- no cap on `message_bytes`, `max_headers`, `max_header_bytes` and
  `max_recipients`: the whole message and every recipient are evaluated;
- no open-message (`max_open_messages`) or verification
  (`max_concurrent_messages`) slots;
- unchanged: `dns_timeout_seconds`, `authentication_deadline_seconds`,
  `max_signatures`, and DKIM worker isolation (`dkim_workers`,
  `dkim_worker_memory`).

`simulate` follows the same rule.

## Consequences

`off` means what the modes table says for these bounds: nothing is deferred
for them. Spool and memory grow with the mail received, bounded only by
Postfix's own limits; that is the operator's choice. The time and DKIM
safeguards stay because removing them could stall a message past Postfix's
`content_timeout` or let one message exhaust memory, which no mode is meant
to allow. Not taken: `off` as a silent `observe` (bounds still cut input and
defer enforced checks, contradicting the mode); `off` also lifting DNS time,
the deadline and DKIM isolation.
