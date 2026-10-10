# ADR-0023: Postfix's failure action follows whether any section enforces

- Status: Accepted; "derived only" superseded by ADR-0025 (explicit `[postfix] failure_action`)
- Date: 2026-10-08

## Context

Postfix applies the milter's `default_action` when postwarden is down,
restarting or times out. Up to 1.1 it followed the phase: `accept` while
observing, `tempfail` while enforcing, both set by `configure-postfix
--phase`. ADR-0022 removed the global mode and the phase, so a server can
enforce some sections and observe others, and the failure action needs a rule
of its own. With `accept`, every enforced rule is skipped for the duration of
an outage, including protected recipients.

## Decision

- `tempfail` when any section enforces; `[protection]` counts only when at
  least one protected address is listed. `accept` only when nothing enforces.
- `configure-postfix --apply` derives the action from the configuration it
  reads, restarts the daemon so it uses the same file, and updates Postfix if
  the action changes, with the usual backup and rollback. Changing a mode is:
  edit the section, run `configure-postfix --apply`.
- `inspect`, `check-config` and the bare `postwarden` overview compare the
  derived action with Postfix's and report a mismatch.
- `[protection] mode = "off"` is refused while protected addresses are listed,
  so protected groups cannot be left open by a mode change alone. Every other
  section, `[limits]` included, accepts `off`.

## Consequences

- An enforced rule is never bypassed by a restart or crash. The cost is `451`
  replies to all mail while the daemon is down on nearly every install, since
  protection enforces by default.
- A hand edit followed only by `systemctl restart` changes the daemon but not
  Postfix; the mismatch report is the safeguard.
- Stopping protection in an emergency means emptying the list or setting
  `observe`, not `off`.
- `[limits] mode = "off"` removes the daemon's own bounds on size, headers,
  recipients, DNS time and open messages; that is the operator's choice.
- Not taken: protection alone deciding the action (an enforced sender
  authentication rule skipped during every outage); a per-section installer
  flag (a second syntax for the configuration); restart only (the action is
  corrected only when someone reads the warning); allowing `[protection]
  mode = "off"` with a warning; resource limits limited to observe and enforce.
