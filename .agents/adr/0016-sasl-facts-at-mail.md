# ADR-0016: Read SASL and TLS facts at MAIL FROM only

- Status: Accepted
- Date: 2026-09-23

## Context

The daemon snapshots connection facts (ingress marker, port, SASL login, TLS)
at CONNECT and MAIL FROM and uses that snapshot for every RCPT and for end of
message. The installer guaranteed `{auth_type}`/`{auth_authen}` only in
`milter_rcpt_macros`. Postfix's default `milter_mail_macros` includes them, but
a customised list without them made an authorized login look unauthenticated
(third review, R27).

## Decision

- Facts are read at MAIL FROM, the first stage where the SMTP session state
  is final (AUTH is not allowed inside a transaction). RCPT reads only
  `{rcpt_mailer}`.
- One list, `REQUIRED_MACROS`, names the macros per stage. The renderer adds
  missing ones, refuses a rendering that still lacks one, and `inspect`
  reports a missing macro on an attached host.

## Consequences

- One snapshot drives RCPT and end-of-message decisions, so both agree on
  the trust class.
- A hand-edited Postfix configuration without the MAIL macros is caught only
  by `inspect`; the daemon treats the client as unauthenticated (fail-closed).
- Options not taken: re-reading macros at each RCPT (trust could differ within
  one message); both, with a defer on mismatch (extra reason code for a
  configuration error `inspect` already reports).
