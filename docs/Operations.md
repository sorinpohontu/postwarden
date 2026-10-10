# Operations

Day-to-day commands, the log format, and what to do when something goes wrong.

## Commands

| Command                                           | What it does                                                                           |
| ------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `postwarden`                                      | version, host, modes, protected addresses, service state and the commands              |
| `systemctl status postwarden`                     | service state                                                                          |
| `postwarden check-config`                         | validates `/etc/postwarden/config.toml` and shows what it read from Postfix            |
| `postwarden show-config`                          | prints the settings in effect                                                          |
| `install.py configure-postfix --apply`            | applies configuration changes                                                          |
| `postwarden wait-ready`                           | exits 0 once the socket accepts connections (default timeout 15 s); run by the unit, it also publishes the hash of the loaded configuration |
| `postwarden lookup <ref>`                         | prints the log lines for a reply reference                                             |
| `postwarden simulate …`                           | shows what postwarden would decide for given facts and a message file; nothing is sent |
| `postwarden stats`                                | totals, refusals and top senders for the last 24 hours, counted from the log           |
| `ls -l /var/spool/postfix/postwarden/policy.sock` | the socket Postfix connects to (`srwxrwx--- postwarden postfix`)                       |

## Changing the configuration

1. Edit `/etc/postwarden/config.toml`.
2. Run `postwarden check-config`.
3. Run `python3 /etc/postwarden/scripts/install.py configure-postfix --apply`.

Step 3 restarts postwarden when the file changed since it started, sets Postfix's failure action to match the configuration, and records the change for [rollback](#rollback). Run again, it reports nothing to change. `postwarden`, `check-config` and `install.py inspect` warn while the running daemon or Postfix does not match the file.

Always check first. A restart stops the running daemon first and validates the file only when starting, so a broken file leaves postwarden **stopped**, and Postfix applies the failure action described in [When postwarden is down](#when-postwarden-is-down); `configure-postfix` then restores the previous configuration. A plain `systemctl restart postwarden` also loads the file, but records nothing; the next `configure-postfix --apply` records it without restarting again.

The restart returns once the new daemon accepts connections. Messages that arrive during the restart itself (usually a few seconds, mostly spent stopping) also get the failure action: with `accept` they pass unchecked, with `tempfail` they get `451` and the sender retries. Restart during quiet periods when practical.

## Logs

postwarden logs to syslog, facility `mail`, tag `postwarden`:

```sh
journalctl -t postwarden
grep postwarden /var/log/mail.log      # where rsyslog writes mail logs
```

Each event is one line of `key=value` fields. A value containing spaces, `=`, `"` or `\` is written in double quotes, with `"` and `\` escaped by a backslash and control characters written as `\xNN`. Values are cut at 256 characters.

```text
action=reject reply="550 5.7.1 Recipient address rejected: Access denied (ref 3f9c2a7b41d0)" mid=3f9c2a7b41d0 ingress=SMTP25 trust=untrusted peer=198.51.100.7 port=25 stage=rcpt rule=protected_recipient reason=ingress_smtp25 rcpt=all@example.com transport=dovecot
```

Message bodies, passwords and raw headers are never logged; only envelope addresses and the parsed `From` domain appear.

### Fields

| Field                                          | Meaning                                                                                                                                                              |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `action`                                       | what happened; see [Actions](#actions)                                                                                                                               |
| `stage`                                        | when: `connect`, `mail`, `rcpt`, `eom` (end of message) or `abort`                                                                                                   |
| `rule`, `reason`                               | the deciding rule and its reason; see [Reasons](#reasons)                                                                                                            |
| `reply`                                        | the SMTP reply sent, or in observe mode the reply that would be sent                                                                                                 |
| `cid`, `mid`                                   | connection id and message id; `mid` is the reference in replies                                                                                                      |
| `queue_id`                                     | Postfix queue id, once Postfix has assigned one                                                                                                                      |
| `ingress`, `trust`                             | how the message arrived and its trust class (see [Configuration](Configuration.md#trust-classes))                                                                    |
| `peer`, `port`, `sasl`                         | client address, server port, login                                                                                                                                   |
| `sender`, `rcpt`                               | envelope sender; recipient (on `rcpt` lines)                                                                                                                         |
| `transport`                                    | Postfix transport the recipient resolves to (`rcpt` lines only)                                                                                                      |
| `rcpts`                                        | number of recipients in the transaction (`eom` lines; every message that reaches end of message has exactly one)                                                     |
| `rejected_rcpts`, `deferred_rcpts`             | recipients refused at RCPT, by class; absent when zero                                                                                                               |
| `would_rejected_rcpts`, `would_deferred_rcpts` | observe mode: recipients that enforce mode would have refused, by class; absent when zero                                                                            |
| `limit_key`                                    | what the message counts against for sending limits; absent for outside mail                                                                                          |
| `limit_measured`                               | `yes` the key is measured (its recipients count when the message is accepted); `no` not measured because the key store was full (observe mode); `off` limits are off |
| `limit`                                        | the limit that was reached (`event=limit_reached`)                                                                                                                   |
| `from_domain`                                  | domain of the visible `From` address                                                                                                                                 |
| `spf`, `spf_domain`                            | SPF result and the domain it was evaluated for                                                                                                                       |
| `dkim`                                         | DKIM results as `domain:result,...` (results below); `skipped` when SPF already decided; `none` without signatures. Cut between entries when it gets long             |
| `dkim_truncated`                               | `yes` when `dkim` lists fewer signatures than the message has                                                                                                        |
| `dkim_summary`                                 | count of every signature by result, `pass:N,fail:N,permerror:N,temperror:N,neutral:N,policy:N`; not cut                                                               |
| `dkim_incomplete`                              | `limit` (more than `max_signatures`), `deadline` (time budget, or no free DKIM process in time) or `memory` (the check exceeded `dkim_worker_memory`): the remaining signatures were not checked |
| `dkim_diagnostics`                             | `on` or `off`: whether DKIM is also checked after an SPF pass (`eom` lines where SPF/DKIM ran, and the start line)                                                   |
| `elapsed`                                      | seconds from MAIL FROM to the decision, including receiving the message                                                                                              |
| `auth_elapsed`                                 | seconds spent on SPF/DKIM, including waiting for a free slot; only when they ran                                                                                     |

DKIM results per signature: `pass`; `fail` (does not verify); `permerror` (missing or broken key, malformed signature); `temperror` (DNS failure or timeout); `neutral` (not checked: signature limit or time budget); `policy` (verifies, but covers only part of the body with `l=`, so it does not count).

### Actions

| `action`                      | Meaning                                                                                                |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ |
| `accept`                      | end of message; the message continues. Recipients refused earlier are logged on their own `rcpt` lines |
| `reject`, `defer`             | reply sent (enforce mode)                                                                              |
| `would_reject`, `would_defer` | observe mode: the reply enforce mode would have sent                                                   |
| `pending_eom`                 | a refusal on the local `sendmail` path; decided at end of message                                      |
| `event=start`, `event=stop`   | daemon start and stop; see below                                                                       |

The **start line** gives the mode, the sending-limits mode, the log level, the socket and configuration file, the numbers of protected addresses and groups, and the `mynetworks` count and `recipient_delimiter` read from Postfix. It also reports the sending-limit state: `limit_state=loaded`, `missing`, `invalid` or `off`, with `limit_keys=` and `limit_state_age=` in seconds. The **stop line** says whether that state was saved.

### Reasons

| Rule                  | Reasons                                                                                                                                                                                                                                                                                                                      |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `protected_recipient` | `ingress_smtp25`, `ingress_local_pickup`, `ingress_unclassified` (defer), `port_not_allowed`, `tls_required`, `not_authenticated`, `no_authorized_logins` (address not listed, or listed without logins), `login_not_authorized`, `sender_login_mismatch`, `authorized`                                                      |
| `self_sender`         | `envelope_matches_recipient`, `header_from_matches_recipient`, `envelope_allowlisted`, `header_allowlisted`                                                                                                                                                                                                                  |
| `invalid_from`        | the parser's description: missing, duplicate, malformed, or several mailboxes                                                                                                                                                                                                                                                |
| `invalid_recipient`   | `recipient_unparseable`: the RCPT address cannot be parsed, so it is refused                                                                                                                                                                                                                                                 |
| `authentication`      | `spf_and_dkim_aligned`; `spf_<result>` (such as `spf_softfail`), `spf_unaligned`, `dkim_absent`, `dkim_no_aligned_pass`; `spf_temperror`, `dkim_temperror`, `evaluation_incomplete` (defer); `null_sender_dkim_aligned`; with `require = "either"`: `spf_aligned`, `dkim_aligned`, `no_aligned_pass`; `exempt_<trust class>` |
| `limits`              | `message_bytes`, `max_headers`, `max_header_bytes`, `max_recipients`, `max_concurrent_messages`, `max_open_messages` (all defer)                                                                                                                                                                                             |
| `sending_limit`       | `per_hour`, `per_day`, `local_per_hour`, `local_per_day`, `key_store_full` (all defer)                                                                                                                                                                                                                                       |
| `trust`               | `exempt_<trust class>`: no rule refused the message and its trust class exempted it from sender authentication (`accept` only)                                                                                                                                                                                               |
| `none`                | `sender_authentication_off`: no rule refused the message and `[sender_authentication]` is `off` (`accept` only); `no_rule_matched`: a recipient no rule matched (`RCPT`, `debug`)                                                                                                                                            |

### Log level

`logging.level` is `debug`, `info`, `warning` or `error`. Decisions are logged at `info`, so keep `info` in production; at `warning` or above no accept, reject or defer is logged. Start and stop lines are always logged.

## Simulating a decision

`postwarden simulate` evaluates the facts of one message against a configuration, with the same policy code the daemon runs. Nothing is sent, delivered or counted, and the running daemon keeps its configuration until restarted, so it is the way to try a candidate file:

```sh
postwarden --config /tmp/candidate.toml simulate message.eml --ingress 587 --peer 192.0.2.10 \
    --login demo@example.com --from demo@example.com --to all@example.com --to carol@example.net
```

| Option            | Meaning                                                                                                                           |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `MESSAGE.eml`     | optional message file. Without it only the RCPT stage runs, and the end of message shows as not evaluated; when every recipient is refused over SMTP it shows as not reached, as in Postfix |
| `--ingress`       | `25`, `587`, `465` or `local` (sendmail)                                                                                          |
| `--from`, `--to`  | envelope sender (`<>` for a bounce) and recipients; repeat `--to`                                                                 |
| `--login`         | SASL login, for 587/465                                                                                                           |
| `--peer`          | client address; required for 25, 587 and 465, since it decides `mynetworks` and same-host trust. `local` uses `127.0.0.1`         |
| `--helo`          | HELO name, used by SPF for bounces                                                                                                |
| `--no-tls`        | the submission connection is not encrypted (587/465 are assumed to use TLS)                                                       |
| `--spf`, `--dkim` | `pass`, `fail`, `none` or `temperror`: the aligned result for the `From` domain, instead of a DNS check. Each can be forced alone |
| `--transport`     | Postfix transport of the recipients; without it every recipient counts as locally delivered                                       |
| `--config`        | the configuration to evaluate (before or after `simulate`)                                                                        |

The output has three parts:

1. **The same box as `postwarden`**: version and host, the configuration file, then its settings:
   - `Protection`, `Self-sender`, `Sender authentication`: each section's mode;
   - `Limits`: its mode, followed by the `[limits]` keys changed from their defaults;
   - `Sending limits`: their mode, with the per-sender and local limits, and `Multipliers`, each with its resulting limits (only when present);
   - `Failure action`: what Postfix does while postwarden is down, marked `(auto)` when derived from the modes;
   - `Protected`: the protected addresses and groups.

   Lists stop at five rows and point to `show-config`.
2. **The connection**: the trust class, and the sending-limit key with its multiplier and limits. Current counts are not shown, so there is no verdict on the limit itself.
3. **The decisions**: one line per recipient, then the end-of-message outcome with its rule, reason and reply.

SPF and DKIM come from live DNS unless forced; a DNS failure shows as `temperror`. Live checks need the Debian SPF and DKIM packages.

| Exit status | Meaning                                     |
| ----------- | ------------------------------------------- |
| 0           | everything allowed                          |
| 1           | a recipient or the message would be refused |
| 2           | a usage or configuration error              |
| 3           | RCPT stage only (no message file was given) |

## Investigating a refusal

1. **Find the lines.** If the sender quotes a reply ending in `(ref <id>)`, run `postwarden lookup <id>`. Without a reference, search the log for the `queue_id=`; Postfix's own `milter-reject` line also contains the reference.
   - By default it searches the journal for the last 7 days, and only lines written by `postwarden.service`. `--since -30d` looks further back; a note says when that reaches before the journal's oldest entry.
   - `--file '/var/log/mail.log*'` searches syslog files, including rotated `.gz` files. Their lines are labelled unverified, because any local user can write a `postwarden` line to syslog.
   - `--any-source` is for a daemon started by hand, outside the unit.
   - The first line of output names the source.
2. **Read `rule` and `reason`.** They name the check that failed. For sender authentication, `spf=` and `dkim=` show the raw results.
3. **`spf_temperror`, `dkim_temperror`:** a DNS problem, not policy. Check the resolver, for example `dig TXT <selector>._domainkey.<domain>`.
4. **`ingress_unclassified`:** Postfix did not tell postwarden how the message arrived. Check `postconf -P | grep postwarden_ingress` and `postconf -h milter_macro_defaults`, or run `python3 scripts/install.py inspect`.

## Sending limits

A sender over its limit is deferred with `rule=sending_limit`. The first refusal per sender and hour (or day, for daily limits) is also logged at `warning` as `event=limit_reached`, with `limit_key=` and the `limit=` reached, so existing log alerts can pick it up. A full key store logs `event=key_store_full` at most once a minute.

```sh
journalctl -t postwarden -p warning | grep limit_reached
```

Counts are kept in `/var/lib/postwarden/limits.json` (owner `postwarden`, mode `0600`), written every minute and when the daemon stops, and read at start, so restarts and reboots keep the windows. Downtime still ages them. A crash loses at most the last minute of counts.

- A missing, damaged or incompatible file is never fatal: postwarden starts with empty windows and logs `event=limit_state_empty` with the reason. On a first start, `reason=missing` is expected.
- A failed save logs `event=limit_state_save_failed` with `snapshot_age=`, the age in seconds of the last good snapshot (absent when none was saved or loaded since the start), and is retried a minute later; mail keeps flowing.
- To reset all counts, stop postwarden, delete the file and start it again.

### Common situations

- **A legitimate sender needs more:** add a multiplier in `[sending_limits.multipliers]`, run `postwarden check-config`, then `install.py configure-postfix --apply`. `postwarden stats` shows who reaches how many recipients.
- **A compromised account:** change its password; the limit only slows it down.
- **Local mail over a limit:** see below.

### Local mail waiting in `maildrop`

Local `sendmail` mail over a limit stays in Postfix's `maildrop` directory. Postfix retries it at every `pickup` scan (every minute, and whenever new local mail is submitted) until the limits allow it. It never expires or bounces, and every retry is logged.

- During a flood Postfix paces `pickup` to about one message a second. That adds at most a few thousand log lines an hour, but other local mail waits until the backlog clears.
- `install.py inspect` warns at 100 files or a file older than an hour. `mailq` lists these messages too, without a reason.

```sh
find /var/spool/postfix/maildrop -type f | wc -l       # how many are waiting
postcat /var/spool/postfix/maildrop/<file>             # read one
rm /var/spool/postfix/maildrop/<file>                  # delete an unwanted one
```

The rest go through once the window allows.

## Statistics

`postwarden stats` counts postwarden's own log lines for a period and prints totals, refusals by rule and reason, and the senders that reached the most recipients:

```sh
postwarden stats                              # journal, last 24 hours, top 20 senders
postwarden stats --since -7d --top 50
postwarden stats --file '/var/log/mail.log*'  # syslog files: whole-file totals, unverified
postwarden stats --json                       # for scripts and monitoring
```

It reads the same sources as `lookup`: the journal lines of `postwarden.service` (verified), the `postwarden` tag with `--any-source`, or syslog files with `--file` (unverified; `--since` is refused there, since the totals cover whole files).

The report is a set of tables:

- **The first box** names the postwarden version and host, the configuration file used for the limits column, the source, the period its lines cover (first to last timestamp), and whether the period may be incomplete: no daemon start line in the period, or a `logging_level` above `info`, which does not log decisions.
- **Totals, refusals sent, observe mode and senders** follow, as described below. The limits column shows `per_hour/per_day`.
- **DKIM after an SPF pass** shows, for SPF passes aligned with `From` and for the others, how many messages had DKIM signatures evaluated and how many of those had **all** evaluated signatures fail (`fail` or `permerror`), as a rate. Unsigned, skipped and incomplete messages are counted apart and are not in the rate; so are messages with `temperror`, `neutral` or `policy` signatures, which never count as failures. The rate comes from `dkim_summary`, so it is exact even when the `dkim` list was cut. `diagnostics` says whether the checked messages had [`dkim_diagnostics`](Configuration.md#sender_authentication) `enabled`, `disabled` or a mix (`partial`, with counts); `unknown` when none logged it. With diagnostics off, DKIM is skipped wherever SPF decides, so the rate covers only messages where the decision needed DKIM.
- **What carries nothing is left out:** `recipients allowed` when it equals `recipients delivered` (no observe-mode refusals), the observe-mode table when it is empty, and sender columns that are 0 for every sender.

| Measure              | Meaning                                                                                                                                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| messages accepted    | messages postwarden let through, from their end-of-message line (in observe mode, including those it would have refused)                                                                                             |
| recipients delivered | their recipients minus the refusals actually sent: handed on to Postfix. Final delivery is in Postfix's own log                                                                                                      |
| recipients allowed   | recipients delivered minus observe-mode refusals: what enforcement would have let through. A message that observe mode would have refused as a whole counts as delivered, not allowed                                |
| refusals sent        | `reject` and `defer` lines by rule and reason, per recipient (RCPT) or per message (MAIL, end of message). Held local mail counts once per retry                                                                     |
| observe mode         | `would_reject` and `would_defer` lines, kept apart from refusals sent                                                                                                                                                |
| senders              | per limit key: messages, recipients delivered and allowed, recipients not measured (full key store in observe mode), sending-limit deferrals sent and observed, and `per_hour`/`per_day` from the configuration used |

Sender counts are totals for the period, not peaks: they do not show how close a rolling hour came to its limit, and the limits column comes from the configuration file `stats` reads (`--config` for another), which may differ from the one in force when the lines were written. A login without a domain gets one row per sender domain, since each domain can have its own multiplier, below a total row. Outside mail has no limit key and appears in the totals only.

`--json` gives the same content. Its field names are stable:

| Field                        | Contents                                                                                                                                 |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `version`, `host`            | postwarden version and host name that produced the report                                                                                |
| `source`                     | `kind` (`journal`, `journal_tag`, `files`), `description`, `verified`, `since`, `pattern`                                                |
| `config`                     | the configuration file used for the limits                                                                                               |
| `complete`, `notes`          | `false` with the reasons in `notes` when lines may be missing; `notes` also carries the journal coverage and whole-file notes            |
| `lines`                      | postwarden event lines read                                                                                                              |
| `totals`                     | `messages`, `delivered`, `allowed`, `unmeasured`                                                                                         |
| `refusals`, `observed`       | lists of `action`, `rule`, `reason`, `scope` (`recipient` or `message`), `count`                                                         |
| `senders`                    | top senders: `limit_key`, `messages`, `delivered`, `allowed`, `unmeasured`, `limit_deferred`, `limit_would_defer`, `per_hour`, `per_day` |
| `senders[].by_sender_domain` | logins without a domain: the same counts per `sender_domain`; `per_hour`/`per_day` of the login are `null` when the domains differ       |
| `senders_total`              | number of limit keys in the period                                                                                                       |
| `dkim`                       | `diagnostics` (`enabled`, `disabled`, `partial`, `unknown`), `checked` (messages by `on`/`off`/`unknown`), and `spf_pass.aligned`/`spf_pass.unaligned` with `messages`, `unsigned`, `skipped`, `incomplete`, `evaluated`, `failed`, `temperror`, `neutral`, `policy` and `rate` (`failed`/`evaluated`, `null` when nothing was evaluated) |

## When postwarden is down

Postfix applies the milter's `default_action`, set from [`[postfix] failure_action`](Configuration.md#postfix) by `configure-postfix`:

| `default_action` | When (with `"auto"`)          | Effect                                                   |
| ---------------- | ----------------------------- | -------------------------------------------------------- |
| `tempfail`       | any section enforces          | clients get `451 4.7.1` and retry later; nothing is lost |
| `accept`         | every section observes or off | mail flows unchecked                                     |

Restore service with `systemctl restart postwarden`; the socket is recreated on start.

## Resource limits

Deferrals with `rule=limits` mean a configured bound was reached. Senders retry, so nothing is lost.

- `max_concurrent_messages`: a message waits for a free SPF/DKIM slot within the authentication deadline, then is deferred.
- `max_open_messages`: new messages are deferred while that many are being received.
- `dkim_workers`, `dkim_worker_memory`: a signed message over 256 KiB waits for a free DKIM process within the deadline; a check that runs out of time or memory is stopped (`dkim_incomplete=deadline` or `memory`), and the message is deferred (`evaluation_incomplete`) where the decision needs DKIM.

If one fires under normal load, raise it (or the deadline) after checking memory: each DKIM check holds its message in memory, several times over while it runs. The unit sets `MemoryHigh=3G`: above it the kernel reclaims memory from postwarden first and slows it down, without stopping it. See [Configuration](Configuration.md#limits).

## Updates

Unpack the new release archive outside `/etc/postwarden` and run, from there:

```sh
python3 scripts/install.py install --dry-run
python3 scripts/install.py install --apply
```

The previous application is archived in `/var/backups/postwarden/<deployment-id>/application.tar.gz`, and `config.toml` is kept. A run that would change nothing records no deployment. Without the installer, follow [Manual upgrade](Installation.md#9-manual-upgrade).

## Rollback

```sh
python3 scripts/install.py rollback --deployment-id <id> --dry-run
python3 scripts/install.py rollback --deployment-id <id> --apply
```

- **`configure-postfix` deployments:** only the active one (the newest, shown by `install.py inspect`) can be rolled back. It restores `main.cf`, `master.cf` and `config.toml` as they were recorded before it, reloads Postfix and restarts postwarden as needed, and records the result as a new deployment, so the next rollback goes one step further back. The first deployment goes back to the state before postwarden was attached.
- **`install` deployments:** restore the application, unit and launcher; undo the newest first, after detaching Postfix.
- **Changed files:** rollback refuses when a file it would restore was changed after the deployment (content, permissions or owner, for example an edit or `chmod` of `config.toml`). It lists them; `--force` overwrites them. Restored files keep their original permissions.
- **First installation:** rolling it back stops and disables the service and removes the unit and launcher it created. `config.toml`, the application and the backups stay. It is refused while any part of Postfix still uses postwarden, and names where; roll back the `configure-postfix` deployments until Postfix is detached first.
- **Safety checks:** the installer handles regular files only and refuses if `config.toml`, the unit, the launcher, `main.cf` or `master.cf` is a symlink. It also refuses if a file changes while the command runs; each `--apply` makes its own plan and does not reuse an earlier dry run. If `configure-postfix` or a rollback fails part-way, it restores the previous state itself, says so and records nothing; the files it started from stay under `before/` in that run's directory.
- **Layout:** `configure-postfix` edits `master.cf` through `postconf`, which rewrites the file in its own layout, so comment lines between services may move. The dry run shows the diff.

Each backup directory contains a `manifest.json` describing what it holds.
