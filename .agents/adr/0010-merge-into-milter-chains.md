# ADR-0010: Merge postwarden into every effective milter chain

- Status: Accepted
- Date: 2026-09-23

## Context

The installer added postwarden only to the global `smtpd_milters`, replaced
`non_smtpd_milters` with `$smtpd_milters`, and replaced
`milter_macro_defaults` globally and per service. A service with its own
`-o smtpd_milters=...` kept a list without postwarden, so enforcement looked
active while that port bypassed it; a distinct local chain (for example a
local-only signer) was discarded; other milters lost their macro defaults
(review 2026-09-23, R03/R07/R13).

## Decision

- postwarden is placed first in every effective chain and other members keep
  their order: global `smtpd_milters`; each 25/587/465 service override,
  including an explicit empty one; `non_smtpd_milters`, unless it already
  refers to `$smtpd_milters`, and an empty local chain gets postwarden alone.
- `milter_macro_defaults` are merged: only `postwarden_ingress` is set or
  replaced, globally and per service; other defaults are kept.
- `inspect` reports every ingress whose effective chain lacks postwarden, and
  `configure-postfix` refuses to finish while one remains.

## Consequences

- Sites with split chains or per-service signers keep their other milters.
- The renderer must parse service overrides and Postfix `$parameter`
  references; tests cover global inheritance, non-empty and empty overrides,
  and distinct and shared local chains.
- Option not taken: refusing non-stock layouts and asking the operator to edit
  by hand.
