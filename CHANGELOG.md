# Changelog

All notable changes to postwarden are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Sending limits

- **Sending limits.** Recipients are counted per login (587/465), per envelope sender of local mail and per `mynetworks` client without a login, over a rolling hour and day, plus one cap over all local mail. Defaults: 100 per hour and 500 per day per sender; 1000 and 5000 for all local mail. Over the limit, SMTP mail is deferred at RCPT with the new `sending_limit` reply (`451 4.7.1 Sending limit exceeded - try again later`); local `sendmail` mail is deferred at end of message and waits in `maildrop`. Outside mail is never limited.
- **`[sending_limits]` configuration** with its own `mode` (`observe` by default, `enforce`, `off`; the top-level observe mode still wins) and `[sending_limits.multipliers]` for a domain, account, `login:NAME`, client address or network, or `<>`. `check-config` validates them; `show-config` prints the resulting limits. When observed limits and an enforced rule both refuse a message, the enforced refusal is sent.
- **Sending-limit state file.** Counts are saved to `/var/lib/postwarden/limits.json` every minute and on stop, and restored at start, so restarts and reboots keep them. The start line reports `limit_state=`, `limit_keys=` and `limit_state_age=`; the stop line whether the state was saved. A missing or damaged file starts empty with an `event=limit_state_empty` warning; a failed save logs `event=limit_state_save_failed` and is retried.
- **Log fields and events.** `limit_key=` and `limit_measured=` on end-of-message lines of limited mail; `rule=sending_limit` with reasons `per_hour`, `per_day`, `local_per_hour`, `local_per_day` and `key_store_full`; `event=limit_reached` and `event=key_store_full` warnings. The start line reports `sending_limits=`, and `check-config` its mode.
- **`inspect` and `check-config` show Postfix's per-client rate limits**, globally and per SMTP service, and warn when a submission service's recipient rate is below the highest sending limit. `inspect` also reports local mail waiting in `maildrop` and warns at 100 files or a file older than an hour. Warnings, marked `~`, never block the installer.

#### Statistics

- **`postwarden stats`.** Counts postwarden's log lines for a period (journal, default the last 24 hours; or whole syslog files with `--file`): messages accepted, recipients delivered and allowed, refusals by rule and reason, observe-mode outcomes apart, and the top senders by limit key with their `per_hour`/`per_day` from the configuration. `--json` for scripts. Reports name their source and say when the period may be incomplete.

### Changed

#### Logs and troubleshooting

- **Recipient refusal counts on the end-of-message line.** `rejected_rcpts` and `deferred_rcpts` now count only refusals actually sent. Refusals that observe mode only logged are counted in the new fields `would_rejected_rcpts` and `would_deferred_rcpts`.
- **Start line.** `event=start` also reports `logging_level=`.
- **One end-of-message line per message.** Every message that reaches end of message gets exactly one `stage=eom` line with `rcpts=` and, where it has one, `limit_key=`. New: a message that observe mode let through after a refusal at MAIL FROM (`max_open_messages`) gets a `would_defer` end-of-message line; before, it had none.
- **`lookup` reads only lines written by `postwarden.service`** from the journal, so lines forged with `logger -t postwarden` no longer appear. `--any-source` matches the `postwarden` tag instead, for a daemon started by hand. Output names its source; lines from `--file`, or from `/var/log/mail.log*` when `journalctl` is missing, are labelled unverified. A note says when `--since` reaches before the journal's oldest entry.

### Fixed

#### Logs and troubleshooting

- **`lookup` message when nothing matches.** It mentions journal permissions only when the journal was read; the searched source is named on the first line.

## [1.0.1] - 2026-09-25

### Fixed

#### Installation and updates

- **Installation directory permissions.** `install --apply` now also removes group and other write permission in `/etc/postwarden`, including the directory itself, and repairs it even when the release is unchanged. `inspect` reports writable paths.
- **Macro repair.** `configure-postfix` now repairs missing Postfix macros, as `inspect` recommends, instead of refusing because of that finding.
- **`--apply` with `--dry-run`** is refused; before, `--apply` won.
- **`install.py --config`** applies to `inspect` only. `install`, `configure-postfix` and `rollback` refuse it, since they always use `/etc/postwarden/config.toml`; use `install --import-config` to install another file.

#### Documentation

- **Clearer structure and terms**; corrected the installer's dry-run guarantee, which recipients a refusal affects, and the load-test commands.

## [1.0.0] - 2026-09-24

First release: a mail filter (milter) for Postfix on Debian 12 and 13.

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
