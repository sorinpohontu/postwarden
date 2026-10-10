# ADR-0029: DKIM diagnostics coverage is recorded on each message line

- Status: Accepted; rate source superseded by ADR-0031; coverage wording corrected 2026-10-08 (second review)
- Date: 2026-10-08

## Context

ADR-0026 had `stats` report "not measured" when no start line in the period had
diagnostics on. A daemon started before the period measures it fully without a
start line inside it, and a toggle within the period makes it partly measured
(plan review F6). The ADR also left open which results count as a failure, and
repeating `dkim=` per signature loses all but the last in the parser.

## Decision

- Each end-of-message line of checked mail carries `dkim_diagnostics=on|off`.
  `stats` reports coverage from those lines: disabled, partial (with counts),
  or enabled with zero eligible messages (checked lines say `on`, none had an
  evaluated signature after an SPF pass). Lines without the field, and periods
  without checked lines, count as unknown; existing log-completeness reporting
  still applies.
- The rate: SPF-pass messages whose evaluated signatures are all `fail` or
  `permerror`, over SPF-pass messages with at least one signature evaluated to
  `pass`, `fail` or `permerror`. `temperror`, `neutral` and `policy` are
  reported separately, never as failures. Aligned and unaligned SPF passes are
  split.
- Per-signature results are one bounded field: `dkim=d1:pass,d2:fail`, at most
  `max_signatures` entries, with `dkim_truncated=yes` when the field limit
  cuts it; the parser reads the list.

## Consequences

- Coverage is correct for any period as far as the log records it, and needs
  no start-line history.
- Supersedes ADR-0026's start-line rule for "not measured".
- Not taken: start lines inside or before the period (wrong for long-running
  daemons, complex to recover); repeated `dkim=` fields (lost by the parser).
