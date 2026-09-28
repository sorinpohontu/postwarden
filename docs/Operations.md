# Operations

Day-to-day commands, the log format, and what to do when something goes wrong.

## Commands

| Command                                           | What it does                                                                           |
| ------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `systemctl status postwarden`                     | service state                                                                          |
| `postwarden check-config`                         | validates `/etc/postwarden/config.toml` and shows what it read from Postfix            |
| `postwarden show-config`                          | prints the settings in effect                                                          |
| `systemctl restart postwarden`                    | applies configuration changes                                                          |
| `postwarden wait-ready`                           | exits 0 once the socket accepts connections (default timeout 15 s)                     |
| `postwarden lookup <ref>`                         | prints the log lines for a reply reference                                             |
| `postwarden simulate …`                           | shows what postwarden would decide for given facts and a message file; nothing is sent |
| `postwarden stats`                                | totals, refusals and top senders for the last 24 hours, counted from the log           |
| `ls -l /var/spool/postfix/postwarden/policy.sock` | the socket Postfix connects to (`srwxrwx--- postwarden postfix`)                       |

## Changing the configuration

1. Edit `/etc/postwarden/config.toml`.
2. Run `postwarden check-config`.
3. Run `systemctl restart postwarden`.

Always check before restarting. The restart stops the running daemon first and validates the file only when starting, so a broken file leaves postwarden **stopped**, and Postfix applies the failure action described in [When postwarden is down](#when-postwarden-is-down).

`systemctl restart` returns once the new daemon accepts connections. Messages that arrive during the restart itself (usually a few seconds, mostly spent stopping) also get the failure action: in observe mode they pass unchecked, in enforce mode they get `451` and the sender retries. Restart during quiet periods when practical.

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

| Field                                          | Meaning                                                                                                          |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `action`                                       | what happened; see [Actions](#actions)                                                                           |
| `stage`                                        | when: `connect`, `mail`, `rcpt`, `eom` (end of message) or `abort`                                               |
| `rule`, `reason`                               | the deciding rule and its reason; see [Reasons](#reasons)                                                        |
| `reply`                                        | the SMTP reply sent, or in observe mode the reply that would be sent                                             |
| `cid`, `mid`                                   | connection id and message id; `mid` is the reference in replies                                                  |
| `queue_id`                                     | Postfix queue id, once Postfix has assigned one                                                                  |
| `ingress`, `trust`                             | how the message arrived and its trust class (see [Configuration](Configuration.md#trust-classes))                |
| `peer`, `port`, `sasl`                         | client address, server port, login                                                                               |
| `sender`, `rcpt`                               | envelope sender; recipient (on `rcpt` lines)                                                                     |
| `transport`                                    | Postfix transport the recipient resolves to (`rcpt` lines only)                                                  |
| `rcpts`                                        | number of recipients in the transaction (`eom` lines; every message that reaches end of message has exactly one) |
| `rejected_rcpts`, `deferred_rcpts`             | recipients refused at RCPT, by class; absent when zero                                                           |
| `would_rejected_rcpts`, `would_deferred_rcpts` | observe mode: recipients that enforce mode would have refused, by class; absent when zero                        |
| `limit_key`                                    | what the message counts against for sending limits; absent for outside mail                                      |
| `limit_measured`                               | `yes` counted; `no` not counted because the key store was full (observe mode); `off` limits are off              |
| `limit`                                        | the limit that was reached (`event=limit_reached`)                                                               |
| `from_domain`                                  | domain of the visible `From` address                                                                             |
| `spf`, `spf_domain`                            | SPF result and the domain it was evaluated for                                                                   |
| `dkim`                                         | DKIM results as `domain:result,...`; `skipped` when SPF already decided; `none` without signatures               |
| `elapsed`                                      | seconds from MAIL FROM to the decision, including receiving the message                                          |
| `auth_elapsed`                                 | seconds spent on SPF/DKIM, including waiting for a free slot; only when they ran                                 |

### Actions

| `action`                      | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `accept`                      | end of message; the message continues. Recipients refused earlier are logged on their own `rcpt` lines                                                                                                                                                                                                                                                                                                                           |
| `reject`, `defer`             | reply sent (enforce mode)                                                                                                                                                                                                                                                                                                                                                                                                        |
| `would_reject`, `would_defer` | observe mode: the reply enforce mode would have sent                                                                                                                                                                                                                                                                                                                                                                             |
| `pending_eom`                 | a refusal on the local `sendmail` path; decided at end of message                                                                                                                                                                                                                                                                                                                                                                |
| `event=start`, `event=stop`   | daemon start and stop. The start line gives the mode, the sending-limits mode, log level, socket, configuration file, numbers of protected addresses and groups, the `mynetworks` count and `recipient_delimiter` read from Postfix, and the sending-limit state (`limit_state=loaded`, `missing`, `invalid` or `off`, with `limit_keys=` and `limit_state_age=` in seconds). The stop line reports whether that state was saved |

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
| `trust`               | `exempt_<trust class>`: no rule refused the message and its trust class exempted it from the remaining checks (`accept` only)                                                                                                                                                                                                |

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
| `MESSAGE.eml`     | optional message file. Without it only the RCPT stage runs, and the end of message shows as not evaluated                         |
| `--ingress`       | `25`, `587`, `465` or `local` (sendmail)                                                                                          |
| `--from`, `--to`  | envelope sender (`<>` for a bounce) and recipients; repeat `--to`                                                                 |
| `--login`         | SASL login, for 587/465                                                                                                           |
| `--peer`          | client address; required for 25, 587 and 465, since it decides `mynetworks` and same-host trust. `local` uses `127.0.0.1`         |
| `--helo`          | HELO name, used by SPF for bounces                                                                                                |
| `--no-tls`        | the submission connection is not encrypted (587/465 are assumed to use TLS)                                                       |
| `--spf`, `--dkim` | `pass`, `fail`, `none` or `temperror`: the aligned result for the `From` domain, instead of a DNS check. Each can be forced alone |
| `--transport`     | Postfix transport of the recipients; without it every recipient counts as locally delivered                                       |
| `--config`        | the configuration to evaluate (before or after `simulate`)                                                                        |

The output shows the trust class, the sending-limit key with its multiplier and limits (no current counts, no quota verdict), one line per recipient, and the end-of-message outcome with its rule, reason and reply. SPF and DKIM come from live DNS unless forced; a DNS failure shows as `temperror`, and live checks need the Debian SPF and DKIM packages. Exit status: 0 everything allowed, 1 a recipient or the message would be refused, 2 a usage or configuration error, 3 RCPT stage only (no message file).

## Investigating a refusal

1. **Find the lines.** If the sender quotes a reply ending in `(ref <id>)`, run `postwarden lookup <id>`. It searches the journal for the last 7 days, only lines written by `postwarden.service`; add `--since -30d` to look further back, or `--file '/var/log/mail.log*'` for syslog files, including rotated `.gz` files (their lines cannot be verified: any local user can write a `postwarden` line to syslog). For a daemon started by hand, outside the unit, add `--any-source`. The first line of output names the source; a note says when `--since` reaches before the journal's oldest entry. Without a reference, search for the `queue_id=`; Postfix's own `milter-reject` line also contains the reference.
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
- A failed save logs `event=limit_state_save_failed` with `snapshot_age=`, the age in seconds of the last good snapshot, and is retried a minute later; mail keeps flowing.
- To reset all counts, stop postwarden, delete the file and start it again.

- **A legitimate sender needs more:** add a multiplier in `[sending_limits.multipliers]`, run `postwarden check-config`, then `systemctl restart postwarden`.
- **A compromised account:** change its password; the limit only slows it down.
- **Local mail over a limit** waits in Postfix's `maildrop` directory (`install.py inspect` warns at 100 files or a file older than an hour) and is retried every minute, without a lifetime or bounce, until the limits allow it; every retry is logged. Count it with `find /var/spool/postfix/maildrop -type f | wc -l`, read one with `postcat /var/spool/postfix/maildrop/<file>`, and delete unwanted files with `rm`; the rest go through once the window allows.

## Statistics

`postwarden stats` counts postwarden's own log lines for a period and prints totals, refusals by rule and reason, and the senders that reached the most recipients:

```sh
postwarden stats                              # journal, last 24 hours, top 20 senders
postwarden stats --since -7d --top 50
postwarden stats --file '/var/log/mail.log*'  # syslog files: whole-file totals, unverified
postwarden stats --json                       # for scripts and monitoring
```

It reads the same sources as `lookup`: the journal lines of `postwarden.service` (verified), the `postwarden` tag with `--any-source`, or syslog files with `--file` (unverified; `--since` is refused there, since the totals cover whole files). The first lines name the source and the configuration used for the limits column, and say when the period may be incomplete: no daemon start line in the period, or a `logging_level` above `info`, which does not log decisions.

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
| `source`                     | `kind` (`journal`, `journal_tag`, `files`), `description`, `verified`, `since`, `pattern`                                                |
| `config`                     | the configuration file used for the limits                                                                                               |
| `complete`, `notes`          | `false` with the reasons in `notes` when lines may be missing; `notes` also carries the journal coverage and whole-file notes            |
| `lines`                      | postwarden event lines read                                                                                                              |
| `totals`                     | `messages`, `delivered`, `allowed`, `unmeasured`                                                                                         |
| `refusals`, `observed`       | lists of `action`, `rule`, `reason`, `scope` (`recipient` or `message`), `count`                                                         |
| `senders`                    | top senders: `limit_key`, `messages`, `delivered`, `allowed`, `unmeasured`, `limit_deferred`, `limit_would_defer`, `per_hour`, `per_day` |
| `senders[].by_sender_domain` | logins without a domain: the same counts per `sender_domain`; `per_hour`/`per_day` of the login are `null` when the domains differ       |
| `senders_total`              | number of limit keys in the period                                                                                                       |

## When postwarden is down

Postfix applies the milter's `default_action`:

| Mode    | `default_action` | Effect                                                   |
| ------- | ---------------- | -------------------------------------------------------- |
| observe | `accept`         | mail flows unchecked                                     |
| enforce | `tempfail`       | clients get `451 4.7.1` and retry later; nothing is lost |

Restore service with `systemctl restart postwarden`; the socket is recreated on start.

## Resource limits

Deferrals with `rule=limits` mean a configured bound was reached. Senders retry, so nothing is lost.

- `max_concurrent_messages`: a message waits for a free SPF/DKIM slot within the authentication deadline, then is deferred.
- `max_open_messages`: new messages are deferred while that many are being received.

If either fires under normal load, raise it (or the deadline) after checking memory: each check holds one message in memory. See [Configuration](Configuration.md#limits).

## Updates

Unpack the new release archive outside `/etc/postwarden` and run, from there:

```sh
python3 scripts/install.py install --dry-run
python3 scripts/install.py install --apply
```

The previous application is archived in `/var/backups/postwarden/<deployment-id>/application.tar.gz`, and `config.toml` is kept. A run that would change nothing records no deployment.

## Rollback

```sh
python3 scripts/install.py rollback --deployment-id <id> --dry-run
python3 scripts/install.py rollback --deployment-id <id> --apply
```

- **Order:** undo the newest deployment first. `configure-postfix` deployments restore `main.cf`, `master.cf` and `config.toml` and reload Postfix; `install` deployments restore the application, unit and launcher.
- **Changed files:** rollback refuses when a file it would restore was changed after the deployment (content, permissions or owner, for example an edit or `chmod` of `config.toml`). It lists them; `--force` overwrites them. Restored files keep their original permissions.
- **First installation:** rolling it back stops and disables the service and removes the unit and launcher it created. `config.toml`, the application and the backups stay. It is refused while any part of Postfix still uses postwarden, and names where; roll back the `configure-postfix` deployments first.
- **Safety checks:** the installer handles regular files only and refuses if `config.toml`, the unit, the launcher, `main.cf` or `master.cf` is a symlink. It also refuses if a file changes while the command runs; each `--apply` makes its own plan and does not reuse an earlier dry run. If `configure-postfix` fails part-way, it restores the previous files itself and says so.
- **Layout:** `configure-postfix` edits `master.cf` through `postconf`, which rewrites the file in its own layout, so comment lines between services may move. The dry run shows the diff.

Each backup directory contains a `manifest.json` describing what it holds.
