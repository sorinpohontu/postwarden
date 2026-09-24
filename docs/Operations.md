# Operations

## Logs

Events go to syslog facility `mail`, tag `postwarden`, one line per event in `key=value` form (logfmt style: a value containing spaces, `=`, `"` or `\` is written in double quotes, with `"` and `\` escaped by a backslash and control characters as `\xNN`; fields truncated at 256 characters). Read them with `journalctl -t postwarden` or `grep postwarden /var/log/mail.log`.

Fields: `action`, `stage` (`rcpt`, `eom`, `mail`, `connect`, `abort`), `rule`, `reason`, `reply`, `cid` (connection), `mid` (message), `queue_id`, `ingress`, `trust`, `peer`, `port`, `sasl`, `sender`, `rcpt`/`rcpts`, `transport` (Postfix transport of the recipient, RCPT lines only), `rcpts` (end-of-message line: number of RCPTs in the transaction), `rejected_rcpts` / `deferred_rcpts` (on the end-of-message line, how many of them were refused at RCPT by class — in observe mode, would have been; absent when zero), `from_domain`, `spf`, `spf_domain`, `dkim` (`domain:result,...`, or `skipped` when SPF already decided), `elapsed` (seconds from MAIL FROM to the end-of-message decision, including receiving the message), `auth_elapsed` (seconds spent on SPF/DKIM, including waiting for a verification slot; only when authentication ran; bounded by `limits.authentication_deadline_seconds` plus at most one DNS timeout or verification in progress).

| `action` | Meaning |
| --- | --- |
| `accept` | end of message, message continues; `rule`/`reason` name the deciding rule. Recipient-stage refusals are logged separately at `stage=rcpt` and counted in `rejected_rcpts`/`deferred_rcpts` |
| `reject` / `defer` | reply sent (enforce mode) |
| `would_reject` / `would_defer` | observe mode; the reply that enforce mode would send |
| `pending_eom` | protected-address violation on the local sendmail path, decided at end of message |
| `event=start` / `event=stop` | daemon lifecycle; the start line gives mode, socket, configuration path, numbers of protected addresses and protected groups, and the `mynetworks` entry count and `recipient_delimiter` read from Postfix; always logged, whatever `logging.level` is |

Reasons by rule:

| Rule | Reasons |
| --- | --- |
| `protected_recipient` | `ingress_smtp25`, `ingress_local_pickup`, `ingress_unclassified` (defer), `port_not_allowed`, `tls_required`, `not_authenticated`, `no_authorized_logins` (protected address not listed, or listed without logins), `login_not_authorized`, `sender_login_mismatch`, `authorized` |
| `self_sender` | `envelope_matches_recipient`, `header_from_matches_recipient`, `envelope_allowlisted`, `header_allowlisted` |
| `invalid_from` | free text from the parser (missing, duplicate, malformed, multiple mailboxes) |
| `invalid_recipient` | `recipient_unparseable`: postwarden cannot parse the RCPT address; refused rather than skipped by the other rules |
| `authentication` | `evaluation_incomplete` (deadline or signature limit reached before a deciding pass; defer), `spf_<result>`, `spf_unaligned`, `dkim_absent`, `dkim_no_aligned_pass`, `spf_temperror`, `dkim_temperror`, `spf_and_dkim_aligned`, `spf_aligned`, `dkim_aligned`, `no_aligned_pass` (the last three with `require = "either"`), `null_sender_dkim_aligned`, `exempt_<trust>` |
| `limits` | `message_bytes`, `max_headers`, `max_header_bytes`, `max_recipients`, `max_concurrent_messages`, `max_open_messages` (all defer) |
| `trust` | `exempt_<trust class>` — not a policy rule: no rule refused the message and its trust class exempted it from the remaining checks (end-of-message `accept` only) |

`logging.level` (`debug`, `info`, `warning`, `error`) filters everything except lifecycle events. Decisions are `info`; at `warning` or above no accept, reject or defer is logged, so keep `info` in production.

Bodies, passwords and raw headers are never logged; only the parsed From domain and envelope addresses appear.

## Investigating a rejection

1. If the sender quotes a reply ending in `(ref <id>)`, run `postwarden lookup <id>` (the journal for the last 7 days; `--since -30d` to go further back, `--file '/var/log/mail.log*'` for syslog files). It prints every line of that message, including RCPT-stage rejections that never got a queue id. Otherwise search by `queue_id=`, or by the reference in Postfix's own `milter-reject` line, which contains the full reply.
2. `reason=` tells which check failed; `spf=`/`dkim=` show the raw results for authentication decisions.
3. For `dkim_temperror`/`spf_temperror`, check the resolver (`dig TXT <selector>._domainkey.<domain>`); repeated deferrals mean DNS trouble, not policy.
4. `ingress_unclassified` means Postfix did not send the `postwarden_ingress` macro: check `postconf -P | grep postwarden_ingress` and `postconf -h milter_macro_defaults`.

## Service

```sh
systemctl status postwarden
postwarden check-config          # validates /etc/postwarden/config.toml
postwarden show-config           # effective settings
systemctl restart postwarden     # after configuration changes
postwarden wait-ready            # exits 0 once the socket accepts connections (default timeout 15 s)
postwarden lookup <ref>          # log lines for a reply reference
ls -l /var/spool/postfix/postwarden/policy.sock
```

Startup runs `check-config` first and refuses to start on an invalid file. `systemctl restart` stops the running daemon before that check, so a restart with a broken file leaves the daemon **stopped** and Postfix applies `default_action` (`451` in enforcement). Always run `check-config` before restarting.

`systemctl restart` returns only after the socket accepts connections (the unit's `ExecStartPost` runs `wait-ready`). Connections that arrive during the restart itself still get `default_action`: in observation mode such a message passes the milter unobserved, in enforcement it gets `451` and is retried. The window is dominated by stopping: libmilter checks for shutdown only between listener poll intervals, so a stop takes up to about 5 s (measured on Debian 12: stop 4.6 s, start 0.4 s). Restart during quiet periods when practical.

## When the daemon is down

Postfix applies the per-milter `default_action`: `accept` in the observation phase (mail flows, no policy), `tempfail` in enforcement (clients get `451`, retry later). Restore service with `systemctl restart postwarden`; the socket is recreated on start.

## Resource pressure

Deferrals with `rule=limits` indicate the configured bounds were hit. `max_concurrent_messages` waits within the authentication deadline before deferring; `max_open_messages` defers new messages while that many are being received; if this fires under normal load, raise it or the deadline after checking memory (each verification holds one message in memory).

## Updates and rollback

Unpack a new release archive outside `/etc/postwarden`, run `python3 scripts/install.py install --apply` from it; the previous application tree is archived in `/var/backups/postwarden/<id>/application.tar.gz`. Roll back with `python3 scripts/install.py rollback --deployment-id <id> --apply`; Postfix-integration deployments restore `main.cf`/`master.cf` and reload Postfix. Restored files keep their original permissions. Rollback refuses when a file it would restore changed after the deployment — content, permissions or owner (for example an edit or `chmod` of `config.toml`) — lists those files, and needs `--force` to overwrite them. The check is repeated after the deployment lock is taken. Rolling back a first installation stops and disables `postwarden.service` and removes the unit and launcher it created; `config.toml`, the application tree and backups are kept, and it refuses while any Postfix chain still references postwarden — global, `non_smtpd_milters` or a service override — naming where (roll back the `configure-postfix` deployment first). The installer manages regular files only: if `config.toml`, the unit, the launcher, `main.cf` or `master.cf` is a symlink, `inspect` reports it and every mutating command refuses. Files changed between the plan and the apply step are refused as concurrent edits. A run that would change nothing records no deployment. `configure-postfix` changes `master.cf` through `postconf`, which rewrites the file in its own layout, so comment lines between services may move; the dry run shows the diff. If `configure-postfix` fails part-way, it restores the previous files and mode itself and says so. Every backup directory contains `manifest.json` describing what it holds.
