# ADR-0019: Sender authentication: SPF first, both required by default, either by choice

- Status: Accepted
- Date: 2026-09-24

## Context

Untrusted mail had to pass SPF and DKIM, both aligned exactly with the visible
From domain. `[sender_authentication]` carried three single-value keys
(`require`, `alignment`, `temporary_error`; kept as documented defaults by
ADR-0009) and the example showed the whole section commented out, so a reader
could conclude the check was off. The Debian 13 load test showed that DKIM
work on mail whose SPF result had already decided the outcome is expensive: a
39 MiB forged message with ten signatures used the whole 20 s budget and was
deferred instead of rejected, and a retrying sender would pay that cost again.
Some operators want to accept mail that passes only one mechanism (forwarded
mail breaks SPF; many senders do not sign).

## Decision

- The check is always on. The example shows `[sender_authentication]`
  uncommented and says so; tunable keys stay commented with their defaults.
- `require = "both" | "either"`, default `"both"`:
  - `both`: an aligned SPF pass and an aligned DKIM pass are both needed.
  - `either`: one aligned pass of SPF or DKIM is enough. A temporary error
    with no pass defers; no pass and no temporary error rejects
    (`no_aligned_pass`). An aligned pass settles the result even when
    evaluation was incomplete. `null_sender` does not apply.
- Named for what is checked. `dmarc`/`relaxed` were rejected: postwarden does
  not look up a DMARC policy and does not use organisational-domain
  alignment. `mode` was rejected: it clashes with the top-level
  observe/enforce `mode`.
- Alignment is fixed at exact From-domain equality; DNS and verifier trouble
  always defers. `alignment` and `temporary_error` are removed;
  `check-config` explains the fixed behaviour when either appears.
- SPF is evaluated first and DKIM is skipped (`dkim=skipped` in the log) when
  the SPF result already decides: with `both`, a definitive SPF failure
  (non-pass other than `temperror`, or a pass for another domain), except
  null-sender mail under `null_sender = "dkim_aligned"`; with `either`, an
  aligned SPF pass. `temperror` never decides.

## Consequences

- Forged or misconfigured mail costs one SPF evaluation and is rejected rather
  than deferred when DKIM would have exhausted the budget.
- Log lines for decisions settled by SPF carry no DKIM result.
- `either` accepts mail a stricter operator would refuse (a forwarded message
  with a valid signature, or unsigned mail from a permitted server); it is
  opt-in.
- Options not taken: keep verifying DKIM for complete diagnostics; separate
  on/off flags per mechanism (allows disabling both); a DMARC-policy lookup.
- Nothing is released; only the test hosts' configurations are affected.
