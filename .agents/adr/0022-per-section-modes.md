# ADR-0022: Every policy section has its own mode; there is no global mode

- Status: Accepted
- Date: 2026-10-08

## Context

Up to 1.1.0 one top-level `mode` covered protected recipients, self-sender,
sender authentication and the resource limits; sending limits had their own
mode, but a global `observe` overrode it (ADR-0007). A server in observe mode
therefore delivered mail for protected recipients such as `all@` to the whole
group: the rule only logged `would_reject`. On a server where postwarden is
the only filter, the observation period left every protected group open, and
the recommended rollout starts with that period.

Giving protected recipients their own mode that ignores the global one, and
making sending limits independent as well, left the top-level `mode` deciding
only for self-sender, sender authentication and the resource limits. A setting
that controls some rules and not others, with different precedence per rule,
is harder to read than one switch per rule.

## Decision

- Each policy section has `mode = "observe" | "enforce" | "off"`:
  `[protection]`, `[self_sender]`, `[sender_authentication]`, `[limits]`,
  `[sending_limits]`. No section overrides another.
- The top-level `mode` key is removed, and `configure-postfix --phase` with it.
- Defaults: `[protection]` `enforce`; every other section `observe`. A fresh
  install refuses unauthorized mail to protected recipients at once and only
  logs the other rules.
- `mode = "off"` is the only off switch; `[self_sender] enabled` is removed.
- Ships in 1.2.0: the configuration schema and an installer command change.
  Nothing is in production, so no 1.1.x configuration is migrated.

## Consequences

- Observation no longer opens protected groups; trialling a new protected list
  is done with `[protection] mode = "observe"` while the other rules keep their
  own mode.
- Replaces the "global observe wins" clause of ADR-0007; sending limits keep
  their own default `observe` and their counting rules.
- What a rule does is read in its own section only. The cost is more keys and
  no single switch to put the whole daemon in observe mode.
- Resource limits also default to `observe`: until enforced, an over-limit
  message is logged with `would_defer` and still received.
- The milter's Postfix `default_action` can no longer follow a single phase;
  `configure-postfix` derives it from the sections when it applies, and
  `inspect`, `check-config` and the bare `postwarden` overview report a
  mismatch after a hand edit.
- Not taken: protection always enforced with no mode (no safe trial of a new
  list); a top-level mode as default for sections without one (two places to
  read); protection and sending limits only (a global mode covering three
  rules with different precedence); a 1.1.1 patch (breaks configurations).
