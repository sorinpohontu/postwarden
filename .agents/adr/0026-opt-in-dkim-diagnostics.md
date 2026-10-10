# ADR-0026: DKIM diagnostics are opt-in, after an SPF pass only, with RFC 8601 result words

- Status: Accepted; wording of the SPF-failure case corrected 2026-10-08 (plan review F4); "not measured" rule and failure set superseded by ADR-0029
- Date: 2026-10-08

## Context

Postwarden checks SPF first and skips DKIM when SPF alone settles the
verdict (ADR-0019): an aligned SPF pass under `require = "either"`, a
definitive SPF failure or unaligned pass under `"both"`. A later DMARC design
needs to know how often mail with an SPF pass carries a failing DKIM
signature, which the skip hides. Verifying DKIM costs CPU, DNS and a
concurrency slot; on forged mail that is pure cost.

## Decision

- `[sender_authentication] dkim_diagnostics = false | true`, default `false`.
  When `true`, DKIM is verified after any SPF `pass`, aligned or not, even when
  SPF already settled the verdict. Diagnostics add optional work only after an
  SPF pass; all mandatory DKIM work stays (an SPF failure under `either`, the
  null-sender exception, SPF temporary errors). An SPF failure skips DKIM only
  where it settles the verdict on its own, as before.
  Nothing runs with `[sender_authentication] mode = "off"`.
- Diagnostics never change a verdict: incomplete or failed optional work cannot
  turn a settled allow or reject into a defer.
- Per-signature results use RFC 8601 words, shared by the log and the 1.3
  `Authentication-Results` header: `none` (no signature), `pass`, `fail`
  (verification false), `permerror` (key or syntax), `temperror` (DNS or
  deadline during lookup), `neutral` "not evaluated" (signature or deadline
  limit), `policy` "partial body" (`l=`). The log carries one
  `dkim=<domain>:<result>` per signature plus `dkim_incomplete=limit|deadline`.
  Only an eligible `pass` counts for the policy.
- `postwarden stats` reports the rate: SPF-pass messages whose evaluated
  signatures all failed, over SPF-pass messages with at least one evaluated
  signature; skipped and incomplete checks excluded; "not measured" when no
  start line in the period had diagnostics on.

## Consequences

- Hosts pay the cost only when they want DMARC data; the data exists only
  where someone turned diagnostics on.
- Forged mail that fails SPF triggers no diagnostic verification; only the
  DKIM work the verdict already needed runs.
- The DKIM log field changes format (no compatibility kept before production).
- Not taken: always on (cost on every host); verifying every checked message
  (forged mail would hold concurrency slots); `dkim = "when_needed" | "always"`
  (hides that "always" still needs an SPF pass); a runbook `journalctl` query
  instead of `stats` (breaks silently when the format moves); keeping today's
  log words and mapping only in the header (two vocabularies).
