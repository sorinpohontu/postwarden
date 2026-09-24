# postwarden

A custom mail filter for Postfix that controls access to group addresses, checks self-addressed mail, and verifies external senders using SPF and DKIM.

A **milter** checks mail while Postfix receives it, allowing prohibited SMTP messages to be rejected before Postfix accepts them for delivery.

**Status: 1.0.0, the first release.** The policy daemon with SPF/DKIM verification, configuration tools (`check-config`, `show-config`, `lookup`), the systemd unit, the installer (`scripts/install.py`: inspect, dry-run, apply, rollback) and operator documentation ([Installation](docs/Installation.md), [Configuration](docs/Configuration.md), [Operations](docs/Operations.md), [Migration](docs/Migration.md)). The test matrix and release procedure (`docs/Testing.md`, `docs/Releasing.md`) are in the source repository only. Before release it was tested on Debian 12 (Postfix 3.7) and Debian 13 (Postfix 3.10): the automated installer and the manual instructions, observation and enforcement, migration from pipe-based content filters, rollback, DNS failure, load, and alias, forwarder and BCC delivery, on customised servers and on a stock Debian installation. See the [changelog](CHANGELOG.md) for what 1.0.0 contains and the [roadmap](#roadmap) for what comes next.

## Try the configuration tools

From a checkout, with Python 3.11 or newer and no extra packages:

```sh
mkdir -p /etc/postwarden
cp etc/config.example.toml /etc/postwarden/config.toml   # edit the protected addresses
bin/postwarden check-config                              # validates /etc/postwarden/config.toml
bin/postwarden show-config                               # prints the effective settings
bin/postwarden --config path/to/candidate.toml check-config
```

`check-config` reports every problem at once (unknown keys, wrong types, invalid addresses, duplicate protected addresses, reply codes outside their class) and exits non-zero. It also reads `mynetworks` and `recipient_delimiter` from Postfix when `postconf` is available and shows what it found. From a git checkout, run the unit tests with `PYTHONPATH=src python3 -m unittest discover -s tests/unit -t tests/unit`; release archives do not include them.

## Behavior

### Control who can send to group addresses

Protect addresses such as `all@example.com` with a list of authorized users per address. A **protected group**, written `all@*`, protects `all@` on every domain the server hosts, so a newly hosted domain's `all@` is closed to everyone until you list it; `all@` at other organisations is not affected.

| Connection | Sending to a protected address |
| --- | --- |
| Port 587 with STARTTLS | Allowed only for an authorized, authenticated user whose envelope sender exactly matches their login |
| Port 465 with implicit TLS | Same authorization requirements as port 587 |
| Port 25 | Rejected, including connections from trusted networks |
| Local sendmail submission | Not permitted; use authenticated submission to reach a protected address |

Group membership is managed through Postfix alias maps. The milter controls who can send to the group address, independently of how its members are stored.

### Control self-addressed mail

On port 25, optionally reject messages where either the envelope sender or the visible `From` address matches a recipient—for example, `me@example.com` sending to `me@example.com`.

Clients in Postfix's `mynetworks` and connections from the server itself are exempt from this check. Specific sender exceptions can also be configured.

### Require authenticated external mail

Two standard checks show whether mail really comes from the domain in its visible `From` address:

- **SPF**: the sending server's IP address is permitted by the SPF record of the envelope sender's domain, and that domain exactly matches the `From` domain.
- **DKIM**: a signature in the message verifies against the signing domain's published key, and that signing domain exactly matches the `From` domain.

By default untrusted external mail must pass **both**. With `sender_authentication.require = "either"`, one of them is enough, which accepts forwarded and unsigned mail that the default refuses. SPF is checked first; when its result already decides, DKIM is skipped.

A subdomain is not an exact match: `bounce.example.com` and `example.com` are different domains under this policy. Merely including a DKIM signature does not count as verification. DNS trouble defers mail instead of rejecting it. postwarden does not look up DMARC policies.

Local mail, clients in `mynetworks`, and authenticated users on ports 587/465 are exempt from these external-authentication checks. These exemptions do not grant access to protected group addresses.

Bounces and delivery-status notifications (null envelope sender) pass on an aligned DKIM signature alone by default, because their SPF identity is the sending host's HELO name and never matches the `From` domain of large providers; `sender_authentication.null_sender = "both"` restores the strict rule.

The default can reject legitimate unsigned mail and forwarded messages that fail SPF. Run in observe mode first to review what would be refused before enforcing.

## Roadmap

Planned work, without dates. Items move to the [changelog](CHANGELOG.md) when released.

- **1.1 — sending limits.** Rolling hourly and daily caps on messages and recipients per SASL login, local sender and trusted relay, plus a host-wide cap for local mail, to contain compromised accounts and hacked scripts. Over the limit, mail is deferred, not lost.

## One configuration file

The standard installation directory is `/etc/postwarden/`. All milter settings live in:

```text
/etc/postwarden/config.toml
```

The installer and daemon use this configuration path by default. A complete commented example is in [etc/config.example.toml](etc/config.example.toml).

The file defines protected addresses and their authorized users, self-sender exceptions, and optionally whether SPF and DKIM must both pass, SPF/DKIM exemptions, resource limits, the log level and SMTP reply wording; the example lists the optional settings commented out with their defaults. Trusted networks (`mynetworks`) and the recipient delimiter are read from Postfix when postwarden starts, so they are never copied by hand. Reply wording is configurable per rule; a rejection cannot be turned into a deferral or acceptance by configuration.

Postfix integration uses its native `main.cf` and `master.cf` files. Outgoing DKIM signing is handled by a separate signer, such as OpenDKIM.

## Logs and troubleshooting

The milter logs to syslog's `mail` facility with the identifier `postwarden`, alongside Postfix (`journalctl -t postwarden` or `/var/log/mail.log`). Each decision is one `key=value` line, for example:

```text
postwarden[1234]: action=reject reply=550\ 5.7.1\ Recipient\ address\ rejected:\ Access\ denied\ (ref\ 3f9c2a7b41d0) mid=3f9c2a7b41d0 ingress=SMTP25 trust=untrusted peer=198.51.100.7 port=25 stage=rcpt rule=protected_recipient reason=ingress_smtp25 rcpt=all@example.com transport=dovecot
```

### Looking up a rejection by its reference

Replies sent to clients are deliberately short so they do not explain the policy to someone probing it. Each one ends with a reference, which a sender sees in their bounce or mail client:

```text
550 5.7.1 Recipient address rejected: Access denied (ref 3f9c2a7b41d0)
```

The reference is the `mid` of the log lines holding the full decision: which rule, the precise reason, the trust class, and the raw SPF/DKIM results. When someone reports a rejection, ask for the reference and look it up:

```sh
postwarden lookup 3f9c2a7b41d0                        # the journal, last 7 days; "(ref 3f9c2a7b41d0)" also works
postwarden lookup 3f9c2a7b41d0 --since -30d
postwarden lookup 3f9c2a7b41d0 --file '/var/log/mail.log*'   # syslog files, including rotated .gz
```

It prints every postwarden line of that message and exits 1 when there is none. Reading the journal needs root or membership in the `adm` or `systemd-journal` group. Postfix's own `milter-reject` line for the same message contains the reference too: `grep 'ref 3f9c2a7b41d0' /var/log/mail.log*`.

Reason codes and further investigation steps are listed in [docs/Operations.md](docs/Operations.md). Reply wording is configurable ([docs/Configuration.md](docs/Configuration.md)); Postfix's own replies, including those for an unavailable milter, remain Postfix's.

## Installation and testing

Install from a release archive (`postwarden-<version>.tar.gz`, verified with its `.sha256`) or from a git checkout; the steps in [docs/Installation.md](docs/Installation.md) are the same for both. Until 1.0.0 is published, a checkout is the only source. The implementation uses Python and Debian-packaged milter, SPF, DKIM and DNS libraries and requires no hosting control panel or mailbox database integration.

Quick start (Debian 12/13, as root, from the checkout):

```sh
python3 scripts/install.py inspect
mkdir -p /etc/postwarden
cp etc/config.example.toml /etc/postwarden/config.toml && $EDITOR /etc/postwarden/config.toml
python3 scripts/install.py install --apply
python3 scripts/install.py configure-postfix --phase observe --apply
```

Every command has a read-only form (`inspect`, `--dry-run`), records a backup with a deployment id, and can be reverted with `rollback --deployment-id <id> --apply`. The daemon starts in observation mode and logs the decision it would take; `configure-postfix --phase enforce` switches both the daemon and Postfix's failure action to enforcement together. If your SMTP services currently pass mail through reinjecting content filters, read [Migration](docs/Migration.md) first: enforcement and removing those filters must happen in one step, and the installer refuses otherwise.
