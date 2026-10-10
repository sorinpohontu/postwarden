# ADR-0030: Every configuration activation is a record with its predecessor

- Status: Accepted; no-op condition and first attachment amended by ADR-0032
- Date: 2026-10-08

## Context

ADR-0028 keeps the configuration each `--apply` activated and rolls back to
"the previous successful deployment's copy". After a rollback that is the
wrong one: apply A, apply B, roll back to A, apply C; rolling C back must
restore A, not B. A hand edit followed by `systemctl restart` also leaves the
running configuration unrecorded when the next apply needs no service change
(plan review F7).

## Decision

- Every activation writes an immutable record with the configuration bytes,
  the Postfix files and the record that was active before it: a forward apply,
  a rollback, and a metadata-only apply. The newest record is the active one;
  history only grows.
- Rollback restores the active record's predecessor and writes a new record
  of that state, whose predecessor is the restored record's own predecessor.
  A failed activation restores the active record and writes nothing.
- `--apply` compares three identities: the file on disk, the active record and
  the running daemon's hash. File equals active record and daemon: nothing to
  do, no record. File differs from the record but the daemon already runs it
  and Postfix needs no change: a metadata-only record, no restart, no reload.
  Otherwise a full activation.
- The first apply that attaches postwarden to Postfix has no predecessor and
  rolls back as ADR-0015 describes; a first application installation without
  attachment creates no record.

## Consequences

- A→B→rollback→C→rollback restores A; A→edit B and manual restart→apply→C→
  rollback restores B.
- A genuine repeat apply changes nothing and records nothing.
- Records accumulate; pruning follows the existing backup retention.
- Supersedes ADR-0028's "previous successful deployment's copy".
- Not taken: a mutable active pointer moved by rollback (must be updated
  atomically with the restore; harder to audit).
