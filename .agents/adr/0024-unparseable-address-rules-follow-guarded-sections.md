# ADR-0024: Unparseable-address rules follow the sections they guard

- Status: Accepted
- Date: 2026-10-08

## Context

ADR-0013 rejects an unparseable recipient (`invalid_recipient`) and an
unparseable visible From (`invalid_from`), so no input postwarden cannot
interpret skips a rule. Both followed the global mode. ADR-0022 removed it and
gave each section its own mode; these two rules belong to no section.

## Decision

- `invalid_recipient` follows `[protection] mode`.
- `invalid_from` enforces when `[self_sender]` or `[sender_authentication]`
  enforces, and is observed when the enforcing one of them is absent and at
  least one observes; it is skipped when both are `off`.

## Consequences

- While protection enforces, an unparseable recipient cannot slip past it
  during a trial of the other rules.
- A server that only observes From-based rules does not refuse odd but real
  From headers.
- `invalid_from` is the one rule decided by two sections.
- Not taken: always enforcing both (an odd From refused while every From-based
  rule only observes); a separate `[addresses]` section (an unfamiliar switch,
  and its observe would reopen the protection bypass).
