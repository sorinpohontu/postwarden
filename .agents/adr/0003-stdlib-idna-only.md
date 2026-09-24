# ADR-0003: Normalize domains with the standard-library IDNA codec

- Status: Accepted
- Date: 2026-09-22

## Context

Domain alignment and address matching need case folding and a canonical form
for internationalized domains. Python's `encodings.idna` implements IDNA2003;
`python3-idna` adds IDNA2008/UTS-46 but is an extra runtime package.

## Decision

Use the standard library only: lowercase ASCII domains; encode non-ASCII
domains to A-labels with `encodings.idna`; treat non-ASCII local parts as
opaque strings compared with the ADR-0001 rules. Revisit `python3-idna` only if
a real case requires IDNA2008 semantics.

## Consequences

- No additional Debian package for the daemon.
- Domains that differ between IDNA2003 and IDNA2008 (e.g. `ß`) may normalize
  differently from other verifiers; document this limitation.
- Option not taken: depend on `python3-idna` from the start.
