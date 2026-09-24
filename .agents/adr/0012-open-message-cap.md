# ADR-0012: Cap open messages at MAIL FROM

- Status: Accepted
- Date: 2026-09-23

## Context

`limits.max_concurrent_messages` bounded only concurrent SPF/DKIM
verification. Every open SMTP transaction could already hold a capture and
spool file, and messages waiting for verification kept theirs, so memory and
spool use were not bounded by postwarden (review 2026-09-23, R08).

## Decision

- New `limits.max_open_messages` (default 100, matching Postfix's default
  process limit): a transaction takes a slot at MAIL FROM and releases it at
  end of message, abort or close. Without a free slot, MAIL FROM gets the
  `temporary_failure` reply (`rule=limits reason=max_open_messages`).
- Local pickup is deferred at end of message instead, as non-SMTP callbacks
  require.
- Header capture stops retaining data once `max_headers` or
  `max_header_bytes` is exceeded; body capture already stopped at
  `message_bytes`.
- Worst-case spool use is `max_open_messages` × `message_bytes`.

## Consequences

- postwarden bounds its own resource use independently of Postfix settings.
- A burst above the cap is deferred, never lost; senders retry.
- Option not taken: rely on Postfix process limits alone.
