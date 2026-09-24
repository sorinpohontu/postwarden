# ADR-0013: Unparseable addresses fail closed

- Status: Accepted
- Date: 2026-09-23

## Context

An envelope sender postwarden could not parse was treated as the null sender,
so an ordinary message could obtain the bounce exception of ADR-0005. An
unparseable recipient was skipped by every rule (review 2026-09-23, R01).

## Decision

- Null sender means only an empty reverse path (`MAIL FROM:<>`).
- An unparseable sender is an unknown sender: SPF receives the raw address,
  the null-sender exception never applies, protected addresses refuse it
  (`sender_login_mismatch`) and the self-sender rule cannot match it. Logged
  as `sender_unparseable`.
- An unparseable recipient is rejected at RCPT with the new
  `invalid_recipient` reply (`550 5.1.3`); other recipients continue. On local
  pickup the rejection is decided at end of message.

## Consequences

- No input that postwarden cannot interpret receives an exemption or skips a
  rule.
- A legitimate but exotic recipient address is refused visibly with a
  reference.
- Option not taken: deferring every unparseable sender at MAIL FROM.
