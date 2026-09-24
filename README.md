# postwarden

A Postfix mail filter (milter) that decides, while a message is still being received, whether Postfix should accept it. It:

- limits who may send to **protected addresses** such as `all@example.com`;
- refuses outside mail that uses the recipient's own address as the sender (**self-sender** mail);
- requires outside mail to prove it comes from the domain in its `From` address, using **SPF and DKIM**.

Refused mail gets an SMTP error before Postfix takes responsibility for it, so nothing is accepted and bounced later.

**Status: 1.0.0, the first release.** Tested on Debian 12 (Postfix 3.7) and Debian 13 (Postfix 3.10), on customised servers and on a stock installation: automated and manual installation, observe and enforce modes, rollback, migration from pipe-based content filters, DNS failure, load, and alias, forwarder and BCC delivery. See the [changelog](CHANGELOG.md) for what 1.0.0 contains and the [roadmap](#roadmap) for what comes next.

## What it checks

### Protected addresses

Each protected address has a list of **authorized logins**; only those users can send to it.

| How the message arrives                   | Sending to a protected address                                                   |
| ----------------------------------------- | -------------------------------------------------------------------------------- |
| Port 587 (STARTTLS) or 465 (implicit TLS) | Allowed only for an authorized login whose envelope sender is exactly that login |
| Port 25                                   | Refused, even from trusted networks (`mynetworks`)                               |
| Local `sendmail`                          | Refused; authorized users send through 587 or 465                                |

A **protected group**, written `all@*`, protects `all@` on every domain whose mailboxes are on this server. A newly hosted domain's `all@` is therefore closed until you list it as a protected address. `all@` at other organisations is not affected.

Group members stay in your Postfix alias maps; postwarden only decides who may send to the group address, whatever backend stores the members.

### Self-sender mail

On port 25, a message is refused when its envelope sender or visible `From` address equals a recipient, for example `me@example.com` sending to `me@example.com`. Clients in Postfix's `mynetworks`, the server itself and listed sender addresses are exempt.

### Sender authentication (SPF and DKIM)

Outside mail must show that it really comes from the domain in its visible `From` address:

- **SPF**: the sending server's IP address is permitted by the SPF record of the envelope sender's domain, and that domain equals the `From` domain.
- **DKIM**: a signature in the message verifies against the signing domain's published key, and the signing domain equals the `From` domain.

By default **both** must pass. With `require = "either"` in `[sender_authentication]`, one is enough, which also accepts forwarded and unsigned mail that the default refuses. SPF is checked first; when its result already decides, DKIM is skipped.

- Domains must match exactly: `bounce.example.com` does not match `example.com`.
- A signature that is merely present counts for nothing; it must verify.
- DNS or verifier trouble defers mail (`451`), it never rejects it.
- DMARC policies are not looked up.
- Bounces (`MAIL FROM:<>`) pass on a matching DKIM signature alone, because their SPF identity is the sending host's name; `null_sender = "both"` applies the full rule.

Local mail, `mynetworks` clients and logged-in users on 587/465 are exempt from sender authentication. These exemptions never grant access to protected addresses.

### Observe and enforce modes

In **observe** mode postwarden only logs what it would do and every message continues. In **enforce** mode it sends its replies. Start in observe mode: the default rule refuses unsigned mail and forwarded mail that fails SPF, so review the log before enforcing.

## Requirements

- Debian 12 or 13, Postfix 3.7 or newer, systemd.
- Debian's own packages `python3 python3-milter python3-spf python3-dkim python3-dnspython` (Python 3.11 or 3.13). Nothing is installed with pip.
- An outgoing DKIM signer such as OpenDKIM, if you sign mail; postwarden only verifies.

No hosting control panel or mailbox database is needed.

## Installation

Download `postwarden-<version>.tar.gz` and its `.sha256` from the project's [releases](https://github.com/sorinpohontu/postwarden/releases), then, as root:

```sh
sha256sum -c postwarden-1.0.0.tar.gz.sha256
mkdir /root/postwarden-1.0.0 && tar -xzf postwarden-1.0.0.tar.gz -C /root/postwarden-1.0.0
cd /root/postwarden-1.0.0
python3 scripts/install.py inspect                      # read-only report
mkdir -p /etc/postwarden
cp etc/config.example.toml /etc/postwarden/config.toml  # then list your protected addresses
python3 scripts/install.py install --apply
python3 scripts/install.py configure-postfix --phase observe --apply
```

Later, `configure-postfix --phase enforce --apply` switches postwarden and Postfix's failure action to enforcement together.

- Every command has a read-only form (`inspect`, `--dry-run`).
- Every applied change is backed up under a **deployment id** and can be undone with `rollback --deployment-id <id> --apply`.
- If your SMTP services pass mail through reinjecting content filters, read [Migration](docs/Migration.md) first: removing them and enforcing must happen in one step, and the installer refuses otherwise.

[Installation](docs/Installation.md) has the full automated path and the equivalent manual steps.

## Configuration

All settings are in one file, `/etc/postwarden/config.toml`; every command uses it by default. The commented example [etc/config.example.toml](etc/config.example.toml) lists every setting.

You set the protected addresses and their logins, self-sender exceptions and, optionally, whether SPF and DKIM must both pass, exemptions, resource limits, the log level and the wording of replies. A rejection can never be configured into a deferral or an acceptance. Trusted networks (`mynetworks`) and the recipient delimiter are read from Postfix at start, never copied by hand.

```sh
postwarden check-config    # reports every problem at once, with the values read from Postfix
postwarden show-config     # prints the settings in effect
```

See [Configuration](docs/Configuration.md) for every key. Postfix and OpenDKIM keep their own configuration files.

## Logs and troubleshooting

postwarden logs to syslog's `mail` facility as `postwarden`, next to Postfix (`journalctl -t postwarden` or `/var/log/mail.log`). Each decision is one line of `key=value` fields; values with spaces are quoted:

```text
postwarden[1234]: action=reject reply="550 5.7.1 Recipient address rejected: Access denied (ref 3f9c2a7b41d0)" mid=3f9c2a7b41d0 ingress=SMTP25 trust=untrusted peer=198.51.100.7 port=25 stage=rcpt rule=protected_recipient reason=ingress_smtp25 rcpt=all@example.com transport=dovecot
```

Replies are deliberately short so they don't explain the policy to someone probing it. Each ends with a **reference**, which the sender sees in their bounce or mail client:

```text
550 5.7.1 Recipient address rejected: Access denied (ref 3f9c2a7b41d0)
```

When someone reports a refusal, ask for the reference and look it up:

```sh
postwarden lookup 3f9c2a7b41d0                              # journal, last 7 days
postwarden lookup 3f9c2a7b41d0 --since -30d
postwarden lookup 3f9c2a7b41d0 --file '/var/log/mail.log*'  # syslog files, including rotated .gz
```

It prints every postwarden line for that message: the rule, the exact reason, the trust class and the SPF/DKIM results. It exits 1 when nothing matches. Reading the journal needs root or the `adm` or `systemd-journal` group.

[Operations](docs/Operations.md) lists every reason code and common tasks: updates, rollback, and what happens when the daemon is down.

## Documentation

| Document                               | Contents                                                       |
| -------------------------------------- | -------------------------------------------------------------- |
| [Installation](docs/Installation.md)   | automated and manual installation, verification, rollback      |
| [Configuration](docs/Configuration.md) | every setting, the SPF/DKIM decision tables, replies           |
| [Operations](docs/Operations.md)       | logs, reason codes, updates, troubleshooting                   |
| [Migration](docs/Migration.md)         | replacing pipe-based content filters and an SPF policy service |
| [Changelog](CHANGELOG.md)              | changes per release                                            |

## Development

From a git checkout, with Python 3.11 or newer and no extra packages, the configuration tools run directly (`bin/postwarden check-config`, `bin/postwarden --config path/to/file.toml check-config`) and the unit tests with:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests/unit -t tests/unit
```

The tests, the server test matrix (`docs/Testing.md`) and the release procedure (`docs/Releasing.md`) are in the source repository only, not in release archives.

## Roadmap

Planned for future releases; no dates are set.

- **1.1: sending limits.** Rolling hourly and daily caps on messages and recipients per login, local sender and trusted relay, plus a host-wide cap for local mail, to contain compromised accounts and hacked scripts. Over the limit, mail is deferred, not lost.

## License

BSD 3-Clause; see [LICENSE](LICENSE).
