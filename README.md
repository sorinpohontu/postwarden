# postwarden

postwarden is a mail filter (milter) for Postfix. While a message is still being received, it decides whether Postfix should accept it:

- **Protected addresses.** Only the logins you list may send to addresses such as `all@example.com`.
- **Self-sender mail.** Outside mail that pretends to come from the recipient's own address is refused.
- **Sender authentication.** Outside mail must prove, with SPF and DKIM, that it comes from the domain in its `From` address.
- **Sending limits.** Each login, local sender and trusted client may reach only so many recipients per hour and per day, which slows down a stolen password or a hacked website.

Mail that arrives over SMTP is refused with an SMTP error before Postfix takes responsibility for it, so the sender finds out at once. Mail submitted with local `sendmail` is checked after submission: if it is refused, it bounces to the sender; if a sending limit holds it back, Postfix keeps it and retries until the limit allows it.

**Status: 1.1.0.** Adds sending limits, `postwarden stats` and `postwarden simulate` to 1.0. See the [changelog](CHANGELOG.md) for each release and the [roadmap](#roadmap) for what comes next.

Tested on Debian 12 (Postfix 3.7) and Debian 13 (Postfix 3.10), on customised servers and on a stock installation: automated and manual installation, observe and enforce modes, rollback, migration from pipe-based content filters, DNS failure, load, and alias, forwarder and BCC delivery. A release is published only after its archive has passed these tests on both Debian versions.

## What it checks

### Protected addresses

Each protected address has a list of **authorized logins**. Only those users can send to it, and only like this:

| How the message arrives                   | Sending to a protected address                                                   |
| ----------------------------------------- | -------------------------------------------------------------------------------- |
| Port 587 (STARTTLS) or 465 (implicit TLS) | Allowed only for an authorized login whose envelope sender is exactly that login |
| Port 25                                   | Refused, even from trusted networks (`mynetworks`)                               |
| Local `sendmail`                          | Refused; authorized users send through 587 or 465                                |

A **protected group**, written `all@*`, protects `all@` on every domain whose mailboxes are on this server. A newly hosted domain's `all@` is therefore closed until you list it as a protected address. `all@` at other organisations is not affected.

Group members stay in your Postfix alias maps. postwarden only decides who may send to the group address, whatever stores the members.

### Self-sender mail

On port 25, a message is refused when its envelope sender or visible `From` address equals a recipient, for example `me@example.com` sending to `me@example.com`. Clients in Postfix's `mynetworks`, the server itself and sender addresses you list are exempt.

### Sender authentication (SPF and DKIM)

Outside mail must show that it really comes from the domain in its visible `From` address:

- **SPF**: the sending server's IP address is allowed by the SPF record of the envelope sender's domain, and that domain is the `From` domain.
- **DKIM**: a signature in the message verifies against the signing domain's published key, and the signing domain is the `From` domain.

By default **both** must pass. With `require = "either"` in `[sender_authentication]`, one is enough; this also accepts forwarded and unsigned mail that the default refuses. SPF is checked first, and when its result already decides, DKIM is skipped.

- Domains must match exactly: `bounce.example.com` does not match `example.com`.
- A signature that is merely present counts for nothing; it must verify.
- DNS or verifier trouble on its own defers mail (`451`) instead of rejecting it; a definitive failure of the other check still rejects.
- DMARC policies are not looked up.
- Bounces (`MAIL FROM:<>`) pass on a matching DKIM signature alone, because their SPF identity is the sending host's name; `null_sender = "both"` applies the full rule.

Local mail, `mynetworks` clients and logged-in users on 587/465 are exempt from sender authentication. These exemptions never open a protected address.

### Sending limits

postwarden counts recipients per sender over a rolling hour and a rolling day, and defers mail over the limit with `451`, so nothing is lost. Who counts as one sender (the **limit key**):

- logged-in users (587/465): their login;
- local `sendmail` and SMTP from the server itself: the envelope sender, plus one cap over all local mail, because a script can change its sender;
- `mynetworks` clients without a login: the client address;
- outside mail is never limited.

The defaults are 100 recipients per hour and 500 per day per sender, and 1000 per hour and 5000 per day for all local mail. A message to 100 recipients counts the same as 100 messages to one recipient each. Busier senders get a **multiplier** instead of their own numbers:

```toml
[sending_limits.multipliers]
"example.com" = 2               # every account of this domain
"marketing@example.com" = 10    # one account
```

Sending limits have their own mode and start in observe mode, even when everything else is enforced. They only log `would_defer` until you set `[sending_limits] mode = "enforce"`; `postwarden stats` shows who would have been held back.

### Observe and enforce modes

In **observe** mode postwarden only logs what it would do, and every message continues. In **enforce** mode it sends its replies. Start in observe mode: the default rule refuses unsigned mail and forwarded mail that fails SPF, so review the log before enforcing.

## Requirements

- Debian 12 or 13, Postfix 3.7 or newer, systemd.
- Debian's own packages `python3 python3-milter python3-spf python3-dkim python3-dnspython` (Python 3.11 or 3.13). Nothing is installed with pip.
- An outgoing DKIM signer such as OpenDKIM, if you sign mail; postwarden only verifies.

No hosting control panel or mailbox database is needed.

## Installation

Download `postwarden-<version>.tar.gz` and its `.sha256` from the project's [releases](https://github.com/sorinpohontu/postwarden/releases), then, as root:

```sh
sha256sum -c postwarden-1.1.0.tar.gz.sha256
mkdir /root/postwarden-1.1.0 && tar -xzf postwarden-1.1.0.tar.gz -C /root/postwarden-1.1.0
cd /root/postwarden-1.1.0
python3 scripts/install.py inspect                      # read-only report
mkdir -p /etc/postwarden
cp etc/config.example.toml /etc/postwarden/config.toml  # then list your protected addresses
python3 scripts/install.py install --apply
python3 scripts/install.py configure-postfix --phase observe --apply
```

When the log looks right, `configure-postfix --phase enforce --apply` switches postwarden and Postfix's failure action to enforcement together.

- Every command has a read-only form (`inspect`, `--dry-run`).
- Every applied change is backed up under a **deployment id** and can be undone with `rollback --deployment-id <id> --apply`.
- To upgrade, unpack the new release the same way and run `install --apply` again; your `config.toml` is kept.
- If your SMTP services pass mail through reinjecting content filters, read [Migration](docs/Migration.md) first: removing them and enforcing must happen in one step, and the installer refuses otherwise.

[Installation](docs/Installation.md) has the full automated path and the equivalent manual steps, including a manual upgrade.

## Configuration

All settings are in one file, `/etc/postwarden/config.toml`, and every command uses it by default. The commented example [etc/config.example.toml](etc/config.example.toml) lists every setting.

You set the protected addresses and their logins, self-sender exceptions and sending limits, and optionally whether SPF and DKIM must both pass, exemptions, resource limits, the log level and the wording of replies. A rejection can never be configured into a deferral or an acceptance. Trusted networks (`mynetworks`) and the recipient delimiter are read from Postfix at start, never copied by hand.

```sh
postwarden check-config    # reports every problem at once, with the values read from Postfix
postwarden show-config     # prints the settings in effect
```

See [Configuration](docs/Configuration.md) for every key. Postfix and OpenDKIM keep their own configuration files.

## Everyday use

| Command                       | What it tells you                                                                                     |
| ----------------------------- | ----------------------------------------------------------------------------------------------------- |
| `postwarden`                  | version, modes, sending limits, protected addresses, whether the service runs, and the commands       |
| `postwarden lookup <ref>`     | why a message was refused, from the reference in the reply                                            |
| `postwarden stats`            | messages, recipients, refusals and the busiest senders for the last 24 hours                          |
| `postwarden simulate …`       | what postwarden would decide for a message, without sending anything                                  |
| `postwarden check-config`     | whether the configuration is valid                                                                    |
| `journalctl -t postwarden -f` | decisions as they happen                                                                              |

### Why was my message refused?

Replies are deliberately short, so they don't explain the policy to someone probing it. Each ends with a **reference**, which the sender sees in their bounce or mail client:

```text
550 5.7.1 Recipient address rejected: Access denied (ref 3f9c2a7b41d0)
```

Ask for the reference and look it up:

```sh
postwarden lookup 3f9c2a7b41d0                              # journal, last 7 days
postwarden lookup 3f9c2a7b41d0 --since -30d
postwarden lookup 3f9c2a7b41d0 --file '/var/log/mail.log*'  # syslog files, including rotated .gz
```

It prints every postwarden line for that message: the rule, the exact reason, the trust class and the SPF/DKIM results, and exits 1 when nothing matches. Reading the journal needs root or the `adm` or `systemd-journal` group. Only lines written by the `postwarden` service count; lines from syslog files are labelled unverified, since anyone on the server can write to syslog.

Each decision is one line of `key=value` fields in syslog's `mail` facility, next to Postfix:

```text
postwarden[1234]: action=reject reply="550 5.7.1 Recipient address rejected: Access denied (ref 3f9c2a7b41d0)" mid=3f9c2a7b41d0 ingress=SMTP25 trust=untrusted peer=198.51.100.7 port=25 stage=rcpt rule=protected_recipient reason=ingress_smtp25 rcpt=all@example.com transport=dovecot
```

### Trying a change first

`simulate` evaluates the facts of one message against a configuration file with the daemon's own rules. Nothing is sent, and the running daemon is not affected, so it is the way to test a candidate configuration:

```sh
postwarden --config /tmp/candidate.toml simulate message.eml --ingress 25 --peer 198.51.100.7 \
    --from bob@example.org --to all@example.com --to carol@example.com --spf pass --dkim none
```

### Choosing sending limits

`postwarden stats` counts postwarden's log lines: messages accepted, recipients delivered, refusals by rule and reason, and the senders that reached the most recipients, next to their limits. Run it while sending limits are in observe mode to see who would be held back, and give those senders a multiplier before you enforce.

[Operations](docs/Operations.md) lists every reason code and log field, and covers updates, rollback and what happens when the daemon is down.

## Replacing other tools

**SPF policy service.** postwarden checks SPF itself, so [postfix-policyd-spf-python](https://launchpad.net/pypolicyd-spf) (the `policyd-spf` service) is no longer needed. Keep the `python3-spf` package, which postwarden uses. postwarden is not a drop-in copy of it:

- it adds no `Received-SPF` or `Authentication-Results` header;
- an SPF pass counts only when the envelope sender's domain is the visible `From` domain, and by default DKIM must pass as well;
- it decides after the message has been received, not at `RCPT`;
- `mynetworks`, local mail and logged-in users are exempt, as described above.

**Pipe content filters.** Scripts that read each message from a `content_filter` pipe and reinject it with `sendmail` can be replaced by postwarden's rules. Mail then passes Postfix once, so OpenDKIM signs it once.

`configure-postfix --phase enforce --remove-legacy` detaches both in the same step that turns on enforcement; [Migration](docs/Migration.md) explains the order and the manual commands.

**Weighted client scoring.** postwarden does not replace [policyd-weight](https://github.com/policyd-weight/policyd-weight), which scores clients on DNS blocklists and HELO, reverse-DNS and sender-domain checks. Postfix covers that itself: `postscreen` weighs DNS blocklist listings (`postscreen_dnsbl_sites`, `postscreen_dnsbl_threshold`) before a message reaches postwarden, and `smtpd` restrictions such as `reject_unknown_helo_hostname`, `reject_unknown_client_hostname` and `reject_unknown_sender_domain` cover the name checks. Content scoring is the job of a spam filter.

## Documentation

| Document                               | Contents                                                       |
| -------------------------------------- | -------------------------------------------------------------- |
| [Installation](docs/Installation.md)   | automated and manual installation and upgrade, rollback        |
| [Configuration](docs/Configuration.md) | every setting, the SPF/DKIM decision tables, replies           |
| [Operations](docs/Operations.md)       | logs, reason codes, statistics, updates, troubleshooting       |
| [Migration](docs/Migration.md)         | replacing pipe-based content filters and an SPF policy service |
| [Changelog](CHANGELOG.md)              | changes per release                                            |

## Development

From a git checkout, with Python 3.11 or newer and no extra packages, the configuration tools run directly (`bin/postwarden check-config`, `bin/postwarden --config path/to/file.toml check-config`) and the unit tests with:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests/unit -t tests/unit
```

The tests, the server test matrix (`docs/Testing.md`) and the release procedure (`docs/Releasing.md`) are in the source repository only, not in release archives.

## Roadmap

Planned for 1.2:

- an `Authentication-Results` header with the SPF and DKIM results on checked mail, replacing any forged header that claims this server;
- with `require = "both"`, refusing a definitive SPF failure already at `MAIL FROM`, before the message body is received.

## License

BSD 3-Clause; see [LICENSE](LICENSE).
