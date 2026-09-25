# Operations

Day-to-day commands, the log format, and what to do when something goes wrong.

## Commands

| Command                                           | What it does                                                                |
| ------------------------------------------------- | --------------------------------------------------------------------------- |
| `systemctl status postwarden`                     | service state                                                               |
| `postwarden check-config`                         | validates `/etc/postwarden/config.toml` and shows what it read from Postfix |
| `postwarden show-config`                          | prints the settings in effect                                               |
| `systemctl restart postwarden`                    | applies configuration changes                                               |
| `postwarden wait-ready`                           | exits 0 once the socket accepts connections (default timeout 15 s)          |
| `postwarden lookup <ref>`                         | prints the log lines for a reply reference                                  |
| `ls -l /var/spool/postfix/postwarden/policy.sock` | the socket Postfix connects to (`srwxrwx--- postwarden postfix`)            |

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

| Field                              | Meaning                                                                                            |
| ---------------------------------- | -------------------------------------------------------------------------------------------------- |
| `action`                           | what happened; see [Actions](#actions)                                                             |
| `stage`                            | when: `connect`, `mail`, `rcpt`, `eom` (end of message) or `abort`                                 |
| `rule`, `reason`                   | the deciding rule and its reason; see [Reasons](#reasons)                                          |
| `reply`                            | the SMTP reply sent, or in observe mode the reply that would be sent                               |
| `cid`, `mid`                       | connection id and message id; `mid` is the reference in replies                                    |
| `queue_id`                         | Postfix queue id, once Postfix has assigned one                                                    |
| `ingress`, `trust`                 | how the message arrived and its trust class (see [Configuration](Configuration.md#trust-classes))  |
| `peer`, `port`, `sasl`             | client address, server port, login                                                                 |
| `sender`, `rcpt`                   | envelope sender; recipient (on `rcpt` lines)                                                       |
| `transport`                        | Postfix transport the recipient resolves to (`rcpt` lines only)                                    |
| `rcpts`                            | number of recipients in the transaction (`eom` lines)                                              |
| `rejected_rcpts`, `deferred_rcpts` | recipients refused at RCPT, by class (in observe mode: would have been); absent when zero          |
| `from_domain`                      | domain of the visible `From` address                                                               |
| `spf`, `spf_domain`                | SPF result and the domain it was evaluated for                                                     |
| `dkim`                             | DKIM results as `domain:result,...`; `skipped` when SPF already decided; `none` without signatures |
| `elapsed`                          | seconds from MAIL FROM to the decision, including receiving the message                            |
| `auth_elapsed`                     | seconds spent on SPF/DKIM, including waiting for a free slot; only when they ran                   |

### Actions

| `action`                      | Meaning                                                                                                                                                                                             |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `accept`                      | end of message; the message continues. Recipients refused earlier are logged on their own `rcpt` lines                                                                                              |
| `reject`, `defer`             | reply sent (enforce mode)                                                                                                                                                                           |
| `would_reject`, `would_defer` | observe mode: the reply enforce mode would have sent                                                                                                                                                |
| `pending_eom`                 | a protected address on the local `sendmail` path; decided at end of message                                                                                                                         |
| `event=start`, `event=stop`   | daemon start and stop. The start line gives the mode, socket, configuration file, numbers of protected addresses and groups, and the `mynetworks` count and `recipient_delimiter` read from Postfix |

### Reasons

| Rule                  | Reasons                                                                                                                                                                                                                                                                                                                      |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `protected_recipient` | `ingress_smtp25`, `ingress_local_pickup`, `ingress_unclassified` (defer), `port_not_allowed`, `tls_required`, `not_authenticated`, `no_authorized_logins` (address not listed, or listed without logins), `login_not_authorized`, `sender_login_mismatch`, `authorized`                                                      |
| `self_sender`         | `envelope_matches_recipient`, `header_from_matches_recipient`, `envelope_allowlisted`, `header_allowlisted`                                                                                                                                                                                                                  |
| `invalid_from`        | the parser's description: missing, duplicate, malformed, or several mailboxes                                                                                                                                                                                                                                                |
| `invalid_recipient`   | `recipient_unparseable`: the RCPT address cannot be parsed, so it is refused                                                                                                                                                                                                                                                 |
| `authentication`      | `spf_and_dkim_aligned`; `spf_<result>` (such as `spf_softfail`), `spf_unaligned`, `dkim_absent`, `dkim_no_aligned_pass`; `spf_temperror`, `dkim_temperror`, `evaluation_incomplete` (defer); `null_sender_dkim_aligned`; with `require = "either"`: `spf_aligned`, `dkim_aligned`, `no_aligned_pass`; `exempt_<trust class>` |
| `limits`              | `message_bytes`, `max_headers`, `max_header_bytes`, `max_recipients`, `max_concurrent_messages`, `max_open_messages` (all defer)                                                                                                                                                                                             |
| `trust`               | `exempt_<trust class>`: no rule refused the message and its trust class exempted it from the remaining checks (`accept` only)                                                                                                                                                                                                |

### Log level

`logging.level` is `debug`, `info`, `warning` or `error`. Decisions are logged at `info`, so keep `info` in production; at `warning` or above no accept, reject or defer is logged. Start and stop lines are always logged.

## Investigating a refusal

1. **Find the lines.** If the sender quotes a reply ending in `(ref <id>)`, run `postwarden lookup <id>`. It searches the journal for the last 7 days; add `--since -30d` to look further back, or `--file '/var/log/mail.log*'` for syslog files, including rotated `.gz` files. Without a reference, search for the `queue_id=`; Postfix's own `milter-reject` line also contains the reference.
2. **Read `rule` and `reason`.** They name the check that failed. For sender authentication, `spf=` and `dkim=` show the raw results.
3. **`spf_temperror`, `dkim_temperror`:** a DNS problem, not policy. Check the resolver, for example `dig TXT <selector>._domainkey.<domain>`.
4. **`ingress_unclassified`:** Postfix did not tell postwarden how the message arrived. Check `postconf -P | grep postwarden_ingress` and `postconf -h milter_macro_defaults`, or run `python3 scripts/install.py inspect`.

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
