# ADR-0005: Null-sender mail passes on an aligned DKIM signature alone by default

- Status: Accepted; key renamed to `sender_authentication.null_sender` by ADR-0009
- Date: 2026-09-22

## Context

The confirmed external policy requires SPF and DKIM to both pass and align with
the visible From domain. For a null reverse path (`MAIL FROM:<>`, used by
bounces and delivery-status notifications) the SPF identity is the HELO
hostname, which for large providers (`mail-xx.google.com` vs From
`googlemail.com`) never aligns. Observation on the test server showed every
Gmail DSN would be rejected, so senders would not learn that their mail failed.

## Decision

`authentication.null_sender` selects the rule for null-sender mail:
`"dkim_aligned"` (default) accepts an aligned, non-partial DKIM pass alone,
defers on a DKIM temporary error and rejects otherwise; `"both"` applies the
unchanged strict rule. SPF is still evaluated and logged in both modes. All
other mail keeps the both-must-pass requirement.

## Consequences

- Legitimate bounces from DKIM-signing providers are delivered.
- A forged bounce needs a valid signature from the From domain, the same bar
  DMARC applies; unsigned bounces are still rejected.
- Option not taken: strict SPF alignment for null senders, retained as `"both"`.
