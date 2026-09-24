# Configuration

One file: `/etc/postwarden/config.toml`, root-owned, group `postwarden`, mode 0640. Validate with `postwarden check-config`; print the effective values with `postwarden show-config`. Unknown keys, wrong types and inconsistent values are errors, and every problem is reported at once. Changes take effect after `systemctl restart postwarden`. Run `check-config` first: the restart stops the running daemon before the unit's `ExecStartPre` validates the file, so a broken file leaves the daemon stopped until it is fixed and restarted.

A complete commented example is `etc/config.example.toml`.

## Top level

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `schema_version` | integer | `1` | Optional; must be `1` when present |
| `mode` | `"observe"` \| `"enforce"` | `"observe"` | Observe logs `would_reject`/`would_defer` and lets mail continue; enforce returns the configured replies. Change it with `install.py configure-postfix --phase`, which switches Postfix's milter failure action at the same time |

Fixed, not configurable: the milter socket `unix:/var/spool/postfix/postwarden/policy.sock` (Postfix refers to it as `unix:postwarden/policy.sock`), and logging to syslog, facility `mail`, tag `postwarden`. For foreground debugging, `postwarden run --stderr` logs to standard error.

## `[logging]`

| Key | Default | Values |
| --- | --- | --- |
| `level` | `"info"` | `debug`, `info`, `warning`, `error`. `debug` adds per-connection and per-allow events |

## Settings read from Postfix

postwarden reads two values from the Postfix configuration when it starts (`postconf -xh mynetworks recipient_delimiter`), so they are never copied by hand:

| Postfix parameter | Used for |
| --- | --- |
| `mynetworks` | the `mynetworks` trust class. Literal addresses, CIDR networks, pattern files (`/path`) and `cidr:` tables are supported; negation (`!`), hostnames and other map types stop the daemon with an error naming the entry |
| `recipient_delimiter` | protected-address lookup only, so `all+tag@` matches `all@`. A protected address written with a tag is refused at start |

After changing either in Postfix, restart postwarden (`systemctl restart postwarden`). `check-config` and `show-config` show the values in use; `install.py inspect` reports entries postwarden cannot read.

## Trust classes

Trust is derived from the Postfix-supplied ingress marker and addresses only:

| Class | When | Exempt from |
| --- | --- | --- |
| `local_pickup` | marker `LOCAL_PICKUP`, set by Postfix on the `postwarden-cleanup` service that local `sendmail` uses | external authentication (unless `allow_local = false`), self-sender |
| `authenticated_submission` | marker `SUBMISSION587` on port 587 or `SUBMISSION465` on port 465, SASL login present | external authentication, self-sender (port not 25) |
| `local_smtp` | marker `SMTP25`, client on loopback or using the server address it connected to (`{daemon_addr}`): a process on this server | external authentication (unless `allow_local = false`), self-sender |
| `mynetworks` | client in Postfix `mynetworks` | external authentication (unless `sender_authentication.allow_mynetworks = false`), self-sender |
| `untrusted` | anything else, including unknown markers | nothing |

No class exempts protected recipients.

## `[self_sender]`

Applies to connections on port 25 only.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | |
| `identity` | `"envelope_or_header_from"` | Also `envelope` or `header_from` |
| `allow_mynetworks` | `true` | Exempt `mynetworks` and same-server (`local_smtp`) clients |
| `allow_senders` | `[]` | Addresses exempt from this rule only (compared case-insensitively) |

Envelope matches are rejected at `RCPT TO`; a visible-From match is rejected at end of message and affects the whole message. An allow-listed envelope sender does not hide a prohibited From address.

## `[sender_authentication]`

Checks that outside mail really comes from the domain in its visible `From` address. The check is always on; it cannot be switched off. Local mail, `mynetworks` clients and logged-in users (587/465) are exempt.

Two independent mechanisms are checked:

- **SPF** asks whether the sending server's IP address is permitted by the SPF record of the envelope sender's domain (`MAIL FROM`; the HELO name for bounces). It **passes and aligns** when the result is `pass` and that domain equals the `From` domain.
- **DKIM** verifies a cryptographic signature in the message against the public key published by the signing domain (`d=`). It **passes and aligns** when a signature verifies, covers the whole body (no `l=` tag) and its `d=` equals the `From` domain.

Alignment is always exact: `bounce.example.com` does not align with `example.com`. A signature that is merely present counts for nothing. DNS or verifier trouble (`temperror`, timeouts) always defers the message, never rejects it. There is no DMARC policy lookup: the domain's `_dmarc` record is not consulted.

| Key | Default | Meaning |
| --- | --- | --- |
| `require` | `"both"` | `"both"`: SPF **and** DKIM must pass and align. `"either"`: one aligned pass of SPF **or** DKIM is enough |
| `allow_local` | `true` | `false`: local sendmail and same-server SMTP mail must pass SPF/DKIM and carry a valid `From`, like outside mail |
| `allow_mynetworks` | `true` | `false`: `mynetworks` clients must pass SPF/DKIM, like outside mail. Other rules keep treating them as trusted |
| `null_sender` | `"dkim_aligned"` | With `require = "both"`, for bounces (`MAIL FROM:<>`): `"dkim_aligned"` needs an aligned DKIM pass only; `"both"` applies the full rule. Ignored with `"either"` |

`require = "both"` is the stricter choice and the default. It refuses unsigned mail, and forwarded mail, because the forwarding server is not in the original domain's SPF record. `require = "either"` accepts both of those, at the cost of trusting a single mechanism.

Mail that must authenticate carries exactly one syntactically valid `From` with one mailbox; otherwise it is rejected with the `invalid_from` reply before any DNS work.

SPF is checked first. When its result already decides the outcome, DKIM is not verified and the log shows `dkim=skipped`: with `"both"`, a definitive SPF failure (anything but `pass` or `temperror`, or a pass for another domain) rejects at once; with `"either"`, an aligned SPF pass accepts at once. An SPF `temperror` never decides.

With `require = "both"`:

| SPF (envelope domain, or HELO for `<>`) | DKIM (best aligned signature) | Result |
| --- | --- | --- |
| pass, aligned | pass, aligned, no `l=` | allow (`spf_and_dkim_aligned`) |
| none/neutral/softfail/fail/permerror, or unaligned pass | not checked | reject (`spf_<result>`, `spf_unaligned`) |
| pass, aligned, or temperror | absent, failed, unaligned, or only `l=` signatures | reject (`dkim_absent`, `dkim_no_aligned_pass`) |
| temperror | pass or temperror | defer (`spf_temperror`) |
| pass, aligned | temperror | defer (`dkim_temperror`) |

With `require = "either"`:

| SPF | DKIM | Result |
| --- | --- | --- |
| pass, aligned | not checked | allow (`spf_aligned`) |
| anything else | pass, aligned, no `l=` | allow (`dkim_aligned`) |
| temperror | no aligned pass | defer (`spf_temperror`) |
| no aligned pass | temperror, no aligned pass | defer (`dkim_temperror`) |
| no aligned pass, no temperror | no aligned pass, no temperror | reject (`no_aligned_pass`) |

Up to `limits.max_signatures` signatures are evaluated; a good one is not cancelled by bad ones. If the time budget or signature limit stops evaluation before a decisive pass, the message is deferred (`evaluation_incomplete`).

## `[protection]`

A **protected address** (`all@example.com`) accepts mail only from its listed logins. A **protected group** (`all@*`) does the same for that local part on every domain this server hosts. Postfix still expands the groups; postwarden only decides who may address them.

```toml
[protection.addresses."all@example.com"]
authorized_logins = ["director@example.com"]

[protection.addresses."all@example.net"]
authorized_logins = ["office@example.net", "hr@example.net"]

[protection.addresses."ceo@example.net"]
authorized_logins = ["assistant@example.net"]

[protection.addresses."all@*"]          # protected group: all@ on every other hosted domain, nobody
authorized_logins = []
```

| Key | Default | Meaning |
| --- | --- | --- |
| `addresses."<address>".authorized_logins` | `[]` | Logins exactly as Postfix reports `{auth_authen}` that may write to that address. An empty list closes it |
| `remote_transports` | `["smtp", "relay"]` | Postfix transports that deliver to other servers; see below. Usually left out |

An address is written without the recipient delimiter tag and matched case-insensitively. In a protected group, `*` as the whole domain (`all@*`) stands for every domain this server delivers; no other `*` form exists.

Which recipients are protected, after the recipient delimiter tag is removed:

| Recipient | Protected | Who may write |
| --- | --- | --- |
| A protected address | yes, wherever it is delivered | its `authorized_logins` |
| In a protected group (`<local>@*`), domain delivered here | yes | the group's logins (none in the example, so the address is closed until listed as a protected address) |
| In a protected group, domain elsewhere (`remote_transports`) | no | not restricted |
| Anything else | no | not restricted |

Without a protected group, only the protected addresses are.

Why `remote_transports`: the protected group `all@*` must protect `all@` on the domains this server hosts, but not `all@` at other organisations that your users write to. Postfix tells postwarden where each recipient goes: the `{rcpt_mailer}` macro holds the transport the address resolves to, for example `dovecot`, `virtual`, `lmtp` or `local` for local delivery. A transport not in the list counts as delivered here. Local `sendmail` submissions carry no transport, so they count as delivered here; they can never reach a protected address anyway. The default fits a stock Postfix, where external mail leaves through `smtp` or `relay`. `install.py inspect` reports when Postfix's `default_transport` or `relay_transport` is missing from the list; add any other relaying transport from `transport_maps` yourself. Each RCPT log line shows the transport as `transport=`. A missing name is safe but visible: `all@` at another organisation through that transport is refused.

A protected address is allowed only when all of: submission marker, its matching port (587 or 465), TLS, a SASL login listed for that address, envelope sender byte-equal to the login. Otherwise `550 5.7.1` at `RCPT TO` on SMTP; on the local sendmail path the message is rejected at end of message and Postfix bounces the entire message, including other recipients. An unknown ingress marker on a protected address defers.

## `[limits]`

| Key | Default | Meaning |
| --- | --- | --- |
| `message_bytes` | 41943040 | Larger messages are deferred with `temporary_failure` |
| `max_signatures` | 10 | DKIM signatures evaluated per message |
| `max_headers` | 1000 | |
| `max_header_bytes` | 65536 | |
| `max_recipients` | 1000 | Further recipients are deferred |
| `dns_timeout_seconds` | 5 | Per DNS query |
| `authentication_deadline_seconds` | 20 | Total SPF+DKIM budget per message; must be ≥ `dns_timeout_seconds`. It bounds DNS waits and discards results that arrive late (deferred as incomplete); a DKIM signature check already running is not interrupted. Keep Postfix `content_timeout` (60 s in `postwarden_milter`) above it |
| `max_concurrent_messages` | 32 | Concurrent SPF/DKIM evaluations; others wait within the deadline, then defer |
| `max_open_messages` | 100 | Messages being received at once; above it `MAIL FROM` is deferred (local `sendmail` at end of message). Spool use stays below this × `message_bytes` |

## `[responses.<rule>]`

Rules: `protected_recipient`, `self_sender`, `authentication_failed`, `invalid_from`, `invalid_recipient` (rejections, codes 550 or 554) and `temporary_failure` (deferral, codes 450/451/452). Each has `smtp_code`, `enhanced_code` (`class.subject.detail`, class matching the code) and `message` (printable ASCII, whole reply ≤ 510 bytes including the reference suffix). Wording changes never change the reject/defer class.

The daemon appends ` (ref <mid>)` to every reply it sends. `mid` is the message id on the matching log line, so a remote administrator can quote the reference and you can find the exact `rule` and `reason` with `postwarden lookup <ref>`. The default texts are deliberately terse: standard enhanced codes and Postfix-style wording tell an administrator which class of problem occurred, without spelling out the policy to someone probing it.

| Key | Default reply |
| --- | --- |
| `protected_recipient` | `550 5.7.1 Recipient address rejected: Access denied` |
| `self_sender` | `550 5.7.1 Sender address rejected: Access denied` |
| `authentication_failed` | `550 5.7.26 Message rejected: Sender domain authentication failed (SPF, DKIM)` — RFC 7372 "multiple authentication checks failed" |
| `invalid_from` | `550 5.7.1 Message rejected: From header does not conform to RFC 5322` |
| `invalid_recipient` | `550 5.1.3 Recipient address rejected: Bad address syntax` |
| `temporary_failure` | `451 4.7.1 Service unavailable - try again later` — the same text Postfix uses when the milter is unreachable, so an outage and an internal temporary failure look alike from outside |
