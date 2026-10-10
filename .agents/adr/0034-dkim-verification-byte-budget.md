# ADR-0034: DKIM verification shares a byte budget

- Status: Superseded by ADR-0035
- Date: 2026-10-09

## Context

DKIM verification needs the whole message in memory, and dkimpy canonicalises
the body into further copies: measured on Debian 12 (dkimpy 1.1.4), verifying a
39 MiB message added 144 MiB on top of the message itself. Only the number of
verifications at once was bounded (`max_concurrent_messages`, default 32), not
their size. In the 1.2.0rc2 load round on an 8 GB host, ten concurrent 40 MB
signed messages took the daemon to 4.2 GB and the kernel killed it. The exposure
dates from 1.0: with `require = "both"`, every large signed message with an
aligned SPF pass is verified; DKIM diagnostics only extend it to `"either"`.

Alternatives considered: skipping DKIM above a size (under `"both"` a large
aligned-SPF signed message could then never be accepted), lowering the
concurrency default (the bound would still scale with `message_bytes`), and a
systemd `MemoryMax` alone (an overrun kills the daemon, and Postfix then defers
all mail).

## Decision

- `[limits] max_verification_bytes` (bytes, default 268435456, at least
  `message_bytes`) caps the total size of the messages under DKIM verification
  at once. A message waits for room within its authentication deadline; if none
  frees, its signatures are not evaluated: `neutral`, `dkim_incomplete=memory`.
  The existing rules then decide: `evaluation_incomplete` (a deferral) where the
  verdict needs DKIM, the SPF verdict where DKIM is only diagnostic.
- The message is read into memory only when DKIM runs, after SPF and only for
  signed mail, not before SPF.
- The shipped unit sets `MemoryHigh=2G` as a soft throttle; no `MemoryMax`.

## Consequences

Peak memory for verification is bounded by about five to six times the budget
(about 1.5 GB at the default) independently of `max_concurrent_messages`. Under
load, large signed messages queue behind each other and may be deferred for a
retry instead of exhausting memory. One new key; `check-config` refuses a budget
below `message_bytes`, so the largest accepted message can always be verified.
