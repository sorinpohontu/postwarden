# ADR-0031: The DKIM failure rate is computed from a fixed-size summary field

- Status: Accepted
- Date: 2026-10-08

## Context

ADR-0029 logs per-signature results as one bounded list, `dkim=d1:pass,...`,
marked `dkim_truncated=yes` when the field limit cuts it. A cut list can drop
a late `pass` and look like an all-failure message; the parser can notice the
cut but cannot recover the result (plan review F8).

## Decision

- End-of-message lines of checked mail carry
  `dkim_summary=pass:N,fail:N,permerror:N,temperror:N,neutral:N,policy:N`,
  counted from every evaluated signature before any truncation. Its size is
  fixed and always fits the field limit.
- `stats` computes the rate only from `dkim_summary`. The `dkim=` list is for
  people; it is cut at an entry boundary, never inside an entry.

## Consequences

- The rate is correct for many-signature mail and long domains.
- One more log field; `dkim=` stays readable.
- Not taken: excluding truncated records from the rate (many-signature mail
  would drop out of the measurement).
