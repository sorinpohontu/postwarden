# ADR-0027: With mixed modes, only enforced outcomes stop checks, and limits count real deliveries

- Status: Accepted; observe-count wording corrected 2026-10-08 (second review)
- Date: 2026-10-08

## Context

Per-section modes (ADR-0022) let one section observe while another enforces.
The 1.1 decision flow assumed one mode for all rules, and a review of the 1.2
plan (F1–F3) found three places where an observed outcome changes what an
enforced rule does:

- resource bounds are checked first and skip later rules: a recipient over
  `max_recipients`, a message without a capture slot, truncated headers or
  body, or no verification slot leave protection or authentication
  unevaluated;
- any rejection, observed or not, stops sender authentication, combines with
  other recipient decisions before modes apply, and removes the recipient from
  the accepted set used by the header self-sender check;
- sending limits skip and do not commit recipients that another rule only
  would have refused, so a sender could exceed an enforced limit with mail
  that observed rules let through.

## Decision

- A resource bound never skips a check whose section enforces. Protection
  evaluates every recipient, including those over `max_recipients`. When an
  enforced From or authentication check cannot run because a bound cut its
  input, the message gets an enforced temporary failure (`rule=limits`,
  reason of the bound), whatever `[limits] mode` says. With nothing enforced
  that needs the input, the bound follows `[limits] mode`.
- Every rule's mode is applied before any short-circuit or combination: only
  an enforced refusal stops later checks or decides an outcome. Recipients
  Postfix actually accepted are tracked separately from hypothetical refusals.
  `simulate` uses the same composition.
- Sending limits, in both modes, count the recipients actually delivered under
  the current section modes. Another rule's `would_reject`/`would_defer` does
  not exempt a recipient. Refused recipients, an enforced final refusal, abort
  and held local-mail retries do not commit.

## Consequences

- No observed section can open a path around an enforced one; the 1.2 default
  (protection enforced, everything else observed) is safe.
- An observed `[limits]` can still defer mail when an enforced check needs the
  input it bounded; the log shows `rule=limits` with an enforced action.
- Observe-mode sending limits measure the load actually delivered under the
  current modes. They do not reproduce what enforcement would have delivered:
  enforcement would have refused, and not counted, some of the recipients
  observe mode counts. Supersedes ADR-0007's hypothetical count ("what
  enforcement would have committed"), which assumed every rule enforced.
- Not taken: `[limits]` following the strictest section (its own mode would
  rarely mean anything); refusing `[limits]` observe while other sections
  enforce (the default configuration would be invalid); counting delivered
  minus hypothetical refusals (the bypass found in review F3).
