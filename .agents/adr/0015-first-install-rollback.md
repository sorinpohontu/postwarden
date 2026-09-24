# ADR-0015: Rolling back a first installation removes the service, not the data

- Status: Accepted
- Date: 2026-09-23

## Context

A first installation has no previous unit, launcher or configuration. Rollback
restored nothing, restarted the newly installed daemon and reported success
(follow-up review 2026-09-23, R22).

## Decision

- Rolling back an installation whose manifest records a file as absent before
  the deployment stops and disables `postwarden.service` and removes that unit
  and launcher, provided they are unchanged since the deployment (ADR-0011;
  `--force` otherwise).
- `/etc/postwarden` with `config.toml`, the `postwarden` user, the socket and
  state directories and all backups stay; rollback lists what it kept.
- Refused while Postfix still references postwarden: detach first with
  a `configure-postfix` rollback.

## Consequences

- Reversing a first install leaves the host as it was for mail delivery, and
  operator data survives for a later reinstall.
- Option not taken: refusing first-install rollback and pointing at manual
  removal steps.
