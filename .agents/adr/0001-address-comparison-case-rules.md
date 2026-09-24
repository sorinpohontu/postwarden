# ADR-0001: Fold local-part case for lookups; keep login equality byte-exact

- Status: Accepted
- Date: 2026-09-22

## Context

Protected-recipient lookup, self-sender matching and the envelope-sender/SASL
login equality check all compare mailboxes. RFC 5321 makes local parts
case-sensitive, but Dovecot and typical hosting setups treat mailbox names case-insensitively,
so a client sending to `All@example.com` reaches the same group as
`all@example.com`. The design forbids silently lowercasing SASL identities.

## Decision

- Domains are always case-folded (and IDNA-normalized) before comparison.
- Protected-recipient lookup and self-sender matching fold local-part case.
- Envelope sender versus SASL login equality is byte-exact on the local part
  after domain folding.
- Plus tags are never stripped by normalization itself.

## Consequences

- A case variant of a protected address cannot bypass protection without
  listing every spelling.
- An authorized login `manager@example.com` does not authorize a MAIL FROM of
  `Manager@example.com`; operators must configure logins exactly as Dovecot
  reports them. This must be verified against real `{auth_authen}` values on
  the test server.
- Option not taken: fully case-insensitive comparison, which would have equated
  distinct logins on a case-sensitive SASL backend.
