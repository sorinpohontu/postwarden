# ADR-0036: The stock-layout test repeats only when the Postfix integration changes

- Status: Accepted
- Date: 2026-10-09

## Context

The publication gate requires operation on a stock Debian Postfix layout
(`smtp/inet` without postscreen, submission services enabled by the operator, no
other milters). The regular test hosts both run postscreen and OpenDKIM, so this
needs a separate host (niobe). It was run for 1.0 only; 1.1 was published
without it. Layout variance affects how postwarden attaches to Postfix, not how
it decides on a message.

## Decision

The stock-layout run (automated install, attachment, an authorized and an
unauthorized protected-recipient case, rollback) is part of a release's gate
when the release changes the Postfix integration: `configure-postfix` staging
or ordering, service and ingress-marker detection, the milter chain or macros,
`master.cf` handling, or the installer's attachment, repair and rollback. A
release that changes only policy, authentication, limits, logging or tools does
not repeat it; its gate record states why. 1.2 changes the integration
(detached root record, repair, failure action from sections) and repeats it.

## Consequences

A host round is spent only where layout variance can matter. The judgement of
"no integration change" is made per release from the diff and recorded in the
gate record. Options not taken: every release (a round per policy-only
release), every minor release (ignores what changed).
