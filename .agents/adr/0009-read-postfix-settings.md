# ADR-0009: Take trust inputs from Postfix; fix what the services already define

- Status: Accepted
- Date: 2026-09-23

## Context

`config.toml` carried copies of Postfix's `mynetworks` and
`recipient_delimiter`, plus `local_smtp_networks` for the server's own
addresses. Operators had to copy values by hand, `install.py inspect` could only
report drift, and a stale copy silently changed who was trusted. The server's
own addresses are not a Postfix setting at all, and listing them by hand breaks
when addresses change.

## Decision

- At start, the daemon, `check-config`, `show-config` and the installer's
  validation run `postconf -xh mynetworks recipient_delimiter` once. No
  per-message Postfix queries.
- Supported `mynetworks` entries: literal addresses, CIDR networks (bracketed
  IPv6 included), pattern files and `cidr:` tables. Negation, hostnames and
  other map types stop the daemon with an error naming each entry; there is no
  configuration override.
- A protected address written with a delimiter tag is refused at start.
- `local_smtp` is a port-25 client on loopback, or whose address equals the
  server address it connected to (`{daemon_addr}`, added to
  `milter_connect_macros` by the installer). Only a process on the host can use
  a local address as its source.
- The `[trust]` section is removed: `mynetworks`, `local_smtp_networks`,
  `recipient_delimiter` and `local_ingress_marker`. The pickup marker is fixed
  as `LOCAL_PICKUP`, like the SMTP ingress markers, because the installer and
  the manual instructions always set that value and any other only broke
  local-mail recognition. `check-config` names the replacement. This
  supersedes ADR-0002's configuration source; its lookup rule is unchanged.
- Ports follow the service markers: `SMTP25` is port 25, `SUBMISSION587` port
  587, `SUBMISSION465` port 465; a marker on another port is untrusted and
  cannot reach a protected address. `self_sender.ports` and
  `authentication.allow_authenticated_ports` are removed. The self-sender rule
  applies on port 25 whatever the marker, so a missing marker cannot disable it.
- `service.socket` and `logging.backend`/`facility`/`identifier` are fixed
  (the installer, unit and Postfix entry assume them); `run --stderr` covers
  foreground debugging. `schema_version` is optional, default 1.
- `[authentication]` is renamed `[sender_authentication]` so it cannot be
  read as SASL login authentication. Its keys, including the single-value
  `require`/`alignment`/`temporary_error`, stay as documented defaults,
  commented out in the example; the log rule name stays `authentication`.
- If `postconf` is missing, `check-config` validates the file and says the
  Postfix values were not read; the daemon refuses to start.

## Consequences

- One source of truth: Postfix. No drift findings, no copy step.
- Changing either value in Postfix needs `systemctl restart postwarden`;
  a reload of Postfix alone keeps the old values.
- The daemon depends on `postconf` and readable Postfix map files at start,
  under its systemd hardening; to be verified on both Debian releases.
- `local_smtp` no longer has to lie inside `mynetworks`; a server whose
  `mynetworks` omits its public address still recognises its own connections.
- Options not taken: keeping explicit copies with an `inspect` check; an
  optional override for unsupported `mynetworks` forms (two sources of truth);
  enumerating host interfaces at start (misses address changes, needs extra
  privileges); an optional extra list for same-host containers.
