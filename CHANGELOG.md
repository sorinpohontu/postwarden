# Changelog

All notable changes to postwarden are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-09-29

Sending limits slow down a stolen password or a hacked script; `postwarden stats` shows who sends how much, and `postwarden simulate` tries a decision without sending anything. Upgrading keeps your configuration, and the new limits start in observe mode, so nothing is refused until you enforce them.

### Added

#### Sending limits

- **Recipients per sender are capped** over a rolling hour and a rolling day. A sender is a login (587/465), the envelope sender of local mail, or a `mynetworks` client without a login; all local mail together has one more cap. Outside mail is never limited.
  - Defaults: 100 per hour and 500 per day per sender; 1000 and 5000 for all local mail.
  - Over the limit, SMTP mail gets `451 4.7.1 Sending limit exceeded - try again later` (the new `sending_limit` reply) at RCPT, so the sender retries later. Local `sendmail` mail waits in `maildrop` and is retried by Postfix.
- **Configuration in `[sending_limits]`**, with its own `mode`: `observe` (the default), `enforce` or `off`. A top-level `mode = "observe"` still wins.
  - `[sending_limits.multipliers]` gives busier senders more: a domain, an account, `login:NAME`, a client address or network, or bounces (`<>`).
  - `check-config` validates the section and `show-config` prints the resulting limits.
  - When an observed limit and an enforced rule both refuse a message, the enforced refusal is sent.
- **Counts survive restarts and reboots.** They are saved to `/var/lib/postwarden/limits.json` every minute and when the service stops, and loaded at start.
  - A missing or damaged file starts empty, with an `event=limit_state_empty` warning.
  - A failed save logs `event=limit_state_save_failed` and is retried.
- **Log fields.** End-of-message lines of limited mail carry `limit_key=` and `limit_measured=`. Refusals use `rule=sending_limit` with the reasons `per_hour`, `per_day`, `local_per_hour`, `local_per_day` and `key_store_full`. New warnings: `event=limit_reached` and `event=key_store_full`. The start line reports `sending_limits=`, `limit_state=`, `limit_keys=` and `limit_state_age=`; the stop line says whether the counts were saved.
- **Postfix's own rate limits are shown** by `inspect` and `check-config`, globally and per SMTP service, with a warning when a submission service allows fewer recipients than the highest sending limit.
- **Local mail waiting in `maildrop` is reported** by `inspect`, with a warning at 100 files or a file older than an hour. Warnings are marked `~` and never block the installer.

#### Statistics

- **`postwarden stats`** summarises postwarden's log for the last 24 hours (`--since` for another period, `--file` for syslog files):
  - messages accepted, recipients delivered and allowed, and refusals by rule and reason, with observe-mode results apart;
  - the busiest senders by limit key, next to their limits from the configuration;
  - readable tables that leave out empty columns and sections; `--json` for scripts, with the version and host;
  - the source, the period covered, and a note when lines may be missing.

#### Trying a decision

- **`postwarden simulate`** shows what postwarden would decide for a message, with the daemon's own rules: one line per recipient and the end-of-message outcome, with rule, reason and reply, plus the sender's limits.
  - Give the connection facts (`--ingress`, `--peer`, `--login`, `--from`, `--to`) and, optionally, a message file.
  - SPF and DKIM come from DNS, or are set with `--spf` and `--dkim`.
  - `--config` tries a candidate file. Nothing is sent and the running daemon is not affected.
  - Exit status: 0 allowed, 1 refused, 2 usage error, 3 RCPT stage only.

#### Command line

- **`postwarden` on its own** shows an overview and exits 0: version and host, the configuration file, the global mode (which covers all rules except sending limits), the sending-limit mode and limits, multipliers, `[limits]` values changed from their defaults, the protected addresses, whether the service runs, where the documentation is, and the commands. Long lists stop at five rows and point to `show-config`.
- **The same header** opens `stats` and `simulate`: version and host, then the configuration file. `postwarden --help` names the documentation too.

#### Installation

- **Manual upgrade steps** in the installation guide, with the way back.

### Changed

#### Logs and troubleshooting

- **`lookup` trusts only the postwarden service.** It reads journal lines written by `postwarden.service`, so lines forged with `logger -t postwarden` no longer appear. `--any-source` matches the `postwarden` tag instead, for a daemon started by hand. The output names its source; lines from `--file`, or from `/var/log/mail.log*` when `journalctl` is missing, are labelled unverified. A note says when `--since` reaches before the journal's oldest entry.
- **Recipient counts on the end-of-message line** now separate refusals that were sent (`rejected_rcpts`, `deferred_rcpts`) from those observe mode only logged (new `would_rejected_rcpts`, `would_deferred_rcpts`).
- **Exactly one end-of-message line per message**, with `rcpts=` and, where there is one, `limit_key=`. A message that observe mode let through after a refusal at MAIL FROM (`max_open_messages`) now gets a `would_defer` line; before, it had none.
- **The start line** also reports `logging_level=`.

### Fixed

#### Logs and troubleshooting

- **`--since -30d` on Debian 12.** Python 3.11 read `-30d` as another option, so `lookup` refused the documented example. Relative times now work with `lookup` and `stats` on every supported Python.
- **`lookup` when nothing matches** mentions journal permissions only when the journal was read.

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
