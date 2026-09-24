# ADR-0018: Merge required macros into per-service overrides

- Status: Accepted
- Date: 2026-09-23

## Context

ADR-0016 repaired and checked only the main.cf macro lists. A master.cf
service with its own `-o milter_mail_macros=` (or connect/rcpt) replaces the
main.cf list, so that service still withheld the SASL, TLS and ingress facts
while rendering and `inspect` reported success (fourth review, R27 follow-up).

## Decision

- The renderer adds missing `REQUIRED_MACROS` to every service override of
  those three lists, keeping the existing entries first and writing the list
  comma-separated. This extends ADR-0010's "merge automatically" rule from
  milter chains to macro lists.
- `macro_gaps()`, used by the renderer's final check and by `inspect`, checks
  main.cf and every service override, naming `service/type/parameter`.

## Consequences

- Services with custom macro lists get the facts postwarden reads; repeated
  rendering changes nothing.
- The override is rewritten in comma form, so its original spacing is lost.
- Overrides on services that never reach postwarden are also extended;
  harmless, since extra macros are only offered to milters.
- Option not taken: refuse and ask the operator to edit (inconsistent with
  ADR-0010).
