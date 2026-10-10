# ADR-0035: Large messages are DKIM-verified in memory-limited worker processes

- Status: Accepted
- Date: 2026-10-09
- Supersedes: ADR-0034

## Context

ADR-0034 weighted a shared budget by message size. Load tests on Debian 12 showed
that dkimpy's memory does not follow size: relaxed body canonicalisation
(`re.sub` per whitespace run) and `rfc822_parse` (a list of every line) allocate
per match and per line. Measured for a 40 MiB body: base64 about 0, ordinary text
1.4 GB (35×), double spaces 2.4 GB, `"a "` repeated 3.6 GB (90×). One verification
under a one-message budget peaked at 1.56 GB, and the daemon was killed by the
kernel at 4.2 GB. Any in-process weighting by size, or by an estimate from
line and whitespace counts, is not a hard bound and depends on CPython and dkimpy
internals. The body is controlled by the sender.

## Decision

- A message whose body spooled to disk (over 256 KiB) is verified in a child
  process (`python3 -P -m postwarden.dkimworker`) that sets `RLIMIT_AS` to
  `[limits] dkim_worker_memory` (default 1 GiB) before importing dkimpy, reads
  the body from the spool file through an inherited descriptor, and returns the
  outcomes as JSON. The parent never loads a large body.
- At most `[limits] dkim_workers` (default 2) children run at once; a message
  waits for one within its authentication deadline. A child still running at the
  deadline is killed.
- Smaller messages are verified in-process as before (worst case about 90 × 256
  KiB each, within `max_concurrent_messages`).
- A child over its limit gives `dkim_incomplete=memory`; no free child in time,
  or a killed child, gives `dkim_incomplete=deadline`. The existing rules decide:
  `evaluation_incomplete` where the verdict needs DKIM, the SPF verdict where DKIM
  is diagnostic.
- `max_verification_bytes` (ADR-0034) is removed; the unit's `MemoryHigh` is 3G.

## Consequences

Verification memory is bounded by the operating system at about
`dkim_workers × dkim_worker_memory` plus about 32 × 23 MB in-process, whatever
the content. The authentication deadline becomes hard for large messages. Each
large signed message costs a process start (about 0.1–0.2 s). A large body dense
in whitespace may exceed the child's limit and stay unverified, which under
`require = "both"` defers it until it expires; base64 attachments, the usual
large mail, need little.

Options not taken: an estimate-weighted budget (not a hard bound, version
dependent); a DKIM size cap (legitimate large signed mail would fail under the
default `"both"`).
