# Changelog

All notable changes to postwarden are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release, planned as 1.0.0: a mail filter (milter) for Postfix on Debian 12 and 13.

### Added

#### Mail checks

- **Protected addresses.** Addresses such as `all@example.com` accept mail only from the logins you list for each one. The sender must log in on port 587 or 465 over TLS and send as their own login. Mail to these addresses from port 25 or from local `sendmail` is always refused.
- **Protected groups.** One `all@*` entry protects `all@` on every domain whose mailboxes are on this server. With no logins listed, a newly added domain's `all@` stays closed until you list it as a protected address. `all@` addresses at other organisations are not affected.
- **Self-sent mail on port 25.** Outside mail that uses the recipient's own address as the envelope sender or `From` is refused. Clients in `mynetworks`, the server itself and listed addresses are exempt.
- **Sender authentication for outside mail**, always on. SPF (the sending server is allowed by the sender domain) and DKIM (a valid signature from the sender domain) must both pass and match the `From` domain exactly. `sender_authentication.require = "either"` accepts mail that passes one of them. SPF is checked first; when it already decides, DKIM is skipped (`dkim=skipped` in the log), so forged mail is refused quickly. Bounces pass on a matching DKIM signature alone. Local mail and `mynetworks` clients are exempt by default; both exemptions can be turned off. DNS trouble defers mail and never rejects it.
- **Address checks.** Mail that must authenticate needs exactly one valid `From` address. Recipient addresses that cannot be parsed are refused with `550 5.1.3`.
- **Observe and enforce modes.** In observe mode postwarden only logs what it would do. Enforce mode applies its decisions.

#### Configuration

- **One file**, `/etc/postwarden/config.toml`. `postwarden check-config` reports every problem at once, and `postwarden show-config` prints the settings in effect.
- **Values read from Postfix.** Trusted networks (`mynetworks`) and the recipient delimiter are read from Postfix at start, not copied by hand. Connections from the server itself are recognised automatically.
- **Configurable replies.** The wording and codes of each SMTP reply can be changed, but a rejection can never be turned into a deferral or an acceptance.
- **Resource limits.** Bounds on message size, headers, recipients, messages received at once, concurrent SPF/DKIM checks and total SPF/DKIM time per message. Anything over a limit is deferred, never lost.

#### Logs and troubleshooting

- **One log line per decision** in syslog (`journalctl -t postwarden`). Each line is `key=value` pairs, with values that contain spaces in double quotes, and gives the rule, reason, trust class, recipient transport, SPF/DKIM results and the time spent on them (`auth_elapsed`). Message bodies, passwords and raw headers are never logged. The start line records the values read from Postfix.
- **Reply references.** Every reply ends with `(ref <id>)`. `postwarden lookup <id>` shows why that message was refused, from the journal or from syslog files (including rotated `.gz` files).

#### Installation and updates

- **Installer** `scripts/install.py`:
  - `inspect` is read-only and reports problems.
  - `install` installs the daemon and systemd unit.
  - `configure-postfix` attaches postwarden to Postfix in observe or enforce mode, and switches Postfix's behaviour when postwarden is down to match.
  - `rollback` undoes any deployment by its id.
- **Safe changes.** Every command can run first as a dry run. Each change is backed up, and a change is refused if the files were edited in the meantime. A run that would change nothing records no deployment, so every deployment id can be rolled back meaningfully.
- **Safe rollback.** Rollback refuses to overwrite files changed after the deployment unless you pass `--force`. Rolling back a first installation stops and removes the service but keeps your configuration; it is refused while any part of Postfix still uses postwarden. A failed Postfix change is undone automatically.
- **Stock and customised layouts.** The port-465 service is recognised as `submissions` (current Postfix and Debian 13) or `smtps` (older layouts); port 25 as `smtp` or, behind postscreen, `smtpd`.
- **Works with existing milters.** postwarden runs first in every Postfix milter chain; other milters (such as OpenDKIM) and their settings are kept.
- **Migration from pipe filters.** `--remove-legacy` removes old `content_filter` pipe filters and the SPF policy service in the same step as enabling enforcement; the migration guide also gives the manual commands.
- **`postwarden run --socket`** starts a second instance on a test socket, for load tests alongside the live daemon.
- **systemd unit** with hardening. A restart returns only when postwarden is ready to accept connections.
- **Documentation** for installation (automated and manual), configuration, operations, testing and migration.
- **Reproducible release archives** with a sha256 checksum and a per-file manifest (`MANIFEST.sha256`), which is installed with the application.

#### Requirements

- Debian 12 or 13 with Python 3.11 or 3.13 and Debian's own PyMilter, SPF, DKIM and DNS packages. Nothing is installed with pip.
