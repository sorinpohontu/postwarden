# ADR-0011: Rollback refuses files changed after the deployment

- Status: Accepted
- Date: 2026-09-23

## Context

Rollback compared current files with the pre-deployment backup and overwrote
any difference after a log line, so edits made after a deployment were lost
silently; application rollback also restored every file as 0644, making the
launcher unexecutable (review 2026-09-23, R02/R14).

## Decision

- Every deployment records the checksum and mode of each file it wrote, after
  writing it, and the application tree digest.
- Rollback compares current files with those post-deployment records. Any
  difference lists the files and stops; `--force` overwrites them.
- Restored files get their recorded mode and ownership (the launcher stays
  0755, the configuration root:postwarden 0640).

## Consequences

- Operator edits after a deployment are never lost without an explicit flag.
- Deployments made before this change have no post-deployment record; rollback
  of those requires `--force`.
- Option not taken: warn and overwrite.
