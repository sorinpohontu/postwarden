# ADR-0002: Strip the Postfix recipient delimiter for protected-recipient lookup only

- Status: Accepted; configuration source superseded by ADR-0009
- Date: 2026-09-22

## Context

Postfix delivers `all+tag@example.com` to the same alias as `all@example.com`
when `recipient_delimiter` is set. A milter that compares only the literal
RCPT address lets a plus tag bypass protection unless every variant is listed.

## Decision

- `config.toml` exposes `recipient_delimiter`; the installer defaults it from
  `postconf -h recipient_delimiter` and validation reports a mismatch.
- The delimiter is applied only when looking up protected recipients.
- Self-sender matching and envelope-sender/login equality use the address as
  supplied (after ADR-0001 case rules); tags are identity there.

## Consequences

- Operators list one address per protected recipient; tagged ingress is covered.
- A server with an empty `recipient_delimiter` gets literal matching.
- Option not taken: require listing all variants, which cannot enumerate
  arbitrary tags.
