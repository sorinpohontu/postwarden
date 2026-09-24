# ADR-0017: The release archive holds only what is installed

- Status: Accepted
- Date: 2026-09-23

## Context

Archives carried `tests/unit` and `MANIFEST.sha256`, which the installer did
not copy into `/etc/postwarden`. A manual installation unpacks the archive
there, so a later `install` treated both as unmanaged and moved them to
backups (third review, observation).

## Decision

- Tests are not part of the release archive; they run from a git checkout,
  including the real-library runs on the test servers.
- `MANIFEST.sha256` is installed and managed; installing from a checkout,
  which has none, removes a stale one.

## Consequences

- The installed tree equals the archive plus `config.toml`; manual and
  automated installations match.
- `sha256sum -c MANIFEST.sha256` in `/etc/postwarden` checks installed files.
- Archive users cannot run the unit tests without a checkout.
- Options not taken: installing the tests too; keeping them in the archive
  only and changing the manual instructions to copy a subset.
