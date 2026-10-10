# ADR-0025: An explicit failure action, refused while protection enforces; restart on a changed configuration

- Status: Accepted
- Date: 2026-10-08

## Context

ADR-0023 derives Postfix's failure action from the sections: `tempfail` when
any enforces. Configuration management raised two cases it did not cover.
Some hosts prefer mail flow during an outage for rules other than protection.
And with `--phase` gone, the configuration is edited outside the installer
(by hand or by a template), so `configure-postfix --apply` cannot tell whether
the running daemon loaded the file it now reads.

## Decision

- `[postfix] failure_action = "auto" | "accept" | "tempfail"`, default `auto`
  (ADR-0023's rule). `configure-postfix --apply` writes the selected action;
  the mismatch report compares Postfix with it.
- `"accept"` is refused by validation while `[protection]` enforces with at
  least one listed address: an outage never opens protected recipients.
- A mismatch between Postfix and the selected action is a warning in
  `inspect`, `check-config` and the overview; exit status stays 0.
- The daemon records the SHA-256 of the configuration it loaded in a runtime
  file. `configure-postfix --apply` restarts it only when the file on disk
  differs, so a repeat run changes nothing.
- `configure-postfix` output stays text; no machine-readable change summary.

## Consequences

- A host can keep mail flowing during an outage while sender authentication or
  self-sender enforce, provided protection is observed or protects nothing.
  With protected addresses enforced, the action is always `tempfail`.
- Supersedes ADR-0023's "derived only"; its derivation remains the `auto` rule.
- A template followed by a pre-apply `check-config` is not broken by a
  transient mismatch.
- Configuration management detects a change from the existing text
  ("nothing to change").
- Not taken: no override (one policy for every host); `accept` allowed with a
  warning or silently; a top-level key (reads like the removed global mode);
  always restarting (a repeat run sends `451`s); never restarting (old modes
  keep running unreported); a `--json` summary (another interface to keep
  stable); a failing `check-config` on mismatch.
