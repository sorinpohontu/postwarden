# ADR-0032: A no-op needs Postfix in step too, and history starts from a detached root

- Status: Accepted
- Date: 2026-10-09

## Context

ADR-0030 treats `--apply` as a no-op when the file, the active record and the
daemon's hash match, without checking Postfix: a hand edit of the failure
action, milter chain or macros stays unrepaired. It also gives the first
attachment no predecessor, so neither a failed first attachment nor a rollback
of a successful one has a state to restore (plan review F9, F10).

## Decision

- `--apply` decides on two questions: does the daemon need the file
  (file ≠ daemon hash), and does Postfix need changes (non-empty staged diff).
  - Neither, and the file matches the active record: no-op, no record.
  - Postfix only: apply and reload Postfix, record the activation, no daemon
    restart.
  - Daemon only, or both: full activation as before (ADR-0028 ordering).
  - Neither, but the file differs from the active record: metadata-only record.
- The first attachment first writes a root record of the detached state: the
  pre-attachment `main.cf`/`master.cf` and configuration, marked detached. It
  is not an activation and has no predecessor.
  - A failed first attachment restores the root's files and writes nothing
    more.
  - Rolling back the first attachment restores the root and writes a new
    detached record; a later attachment takes that record as predecessor.
- Removing the application (ADR-0015) stays a separate operation, allowed only
  after detachment. The root record says nothing about whether the service
  existed before installation.

## Consequences

- Postfix drift is repaired by `--apply` without restarting a daemon that
  already runs the right configuration; the next apply is a no-op.
- Attachment history always has a restorable start, for clean automated
  installs and for manually installed daemons alike.
- Amends ADR-0030 (no-op condition, first attachment).
