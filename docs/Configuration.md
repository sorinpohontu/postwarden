# Configuration

All settings are in one file, `/etc/postwarden/config.toml` (owner `root`, group `postwarden`, mode `0640`). The commented example `etc/config.example.toml` lists every setting with its default.

```sh
postwarden check-config          # reports every problem at once
postwarden show-config           # prints the settings in effect
systemctl restart postwarden     # applies changes
```

Unknown keys, wrong types and inconsistent values are errors. Run `check-config` before restarting: a restart with a broken file leaves postwarden stopped (see [Operations](Operations.md#changing-the-configuration)).

## Top level

| Key              | Default     | Meaning                                                                                      |
| ---------------- | ----------- | -------------------------------------------------------------------------------------------- |
| `schema_version` | `1`         | optional; must be `1` when present                                                           |
| `mode`           | `"observe"` | `"observe"` logs what would be refused and lets mail continue; `"enforce"` sends the replies |

Change `mode` with `python3 scripts/install.py configure-postfix --phase observe|enforce`, which also switches Postfix's failure action to match.

These are fixed, not configurable:

- the socket `unix:/var/spool/postfix/postwarden/policy.sock` (in Postfix: `unix:postwarden/policy.sock`);
- logging to syslog, facility `mail`, tag `postwarden`. For debugging in the foreground, `postwarden run --stderr` logs to standard error.

## `[logging]`

| Key     | Default  | Values                                                                                |
| ------- | -------- | ------------------------------------------------------------------------------------- |
| `level` | `"info"` | `debug`, `info`, `warning`, `error`; `debug` adds per-connection and per-allow events |

## Settings read from Postfix

postwarden reads two Postfix settings when it starts (`postconf -xh mynetworks recipient_delimiter`), so they are never copied by hand:

| Postfix parameter     | Used for                                                                                                                                                                                               |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `mynetworks`          | the `mynetworks` trust class. Addresses, CIDR networks, pattern files (`/path`) and `cidr:` tables work; negation (`!`), host names and other map types stop the daemon with an error naming the entry |
| `recipient_delimiter` | protected-address lookup, so `all+tag@` matches `all@`. A protected address written with a tag is refused at start                                                                                     |

After changing either in Postfix, restart postwarden. `check-config` and `show-config` show the values in use; `install.py inspect` reports entries postwarden cannot read.

## Trust classes

The trust class comes only from what Postfix reports: the ingress marker it sets per service and the client address. Message headers are never trusted.

| Class                      | When                                                                                        | Exempt from                         |
| -------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------- |
| `local_pickup`             | local `sendmail` (marker `LOCAL_PICKUP`, set on the `postwarden-cleanup` service)           | sender authentication¹, self-sender |
| `authenticated_submission` | port 587 (`SUBMISSION587`) or 465 (`SUBMISSION465`) with a login                            | sender authentication, self-sender  |
| `local_smtp`               | port 25 (`SMTP25`) from loopback or from the server's own address: a process on this server | sender authentication¹, self-sender |
| `mynetworks`               | client in Postfix `mynetworks`                                                              | sender authentication², self-sender |
| `untrusted`                | anything else, including unknown markers                                                    | nothing                             |

¹ unless `sender_authentication.allow_local = false`. ² unless `sender_authentication.allow_mynetworks = false`.

No class is exempt from the protected-address rule.

## `[self_sender]`

Refuses mail on port 25 whose sender equals a recipient.

| Key                | Default                     | Meaning                                                     |
| ------------------ | --------------------------- | ----------------------------------------------------------- |
| `enabled`          | `true`                      | turns the rule on or off                                    |
| `identity`         | `"envelope_or_header_from"` | what is compared: also `"envelope"` or `"header_from"`      |
| `allow_mynetworks` | `true`                      | exempts `mynetworks` and same-server (`local_smtp`) clients |
| `allow_senders`    | `[]`                        | addresses exempt from this rule only (case-insensitive)     |

- An envelope match is refused at `RCPT TO`, for that recipient only.
- A `From` match is refused at end of message, for the whole message.
- An exempt envelope sender does not hide a refused `From` address.

## `[sender_authentication]`

Checks that outside mail really comes from the domain in its visible `From` address. It is always on. Local mail, `mynetworks` clients and logged-in users (587/465) are exempt.

Two independent mechanisms are checked:

- **SPF** asks whether the sending server's IP address is permitted by the SPF record of the envelope sender's domain (the HELO name for bounces). It **passes and aligns** when the result is `pass` and that domain equals the `From` domain.
- **DKIM** verifies a signature in the message against the public key published by the signing domain (`d=`). It **passes and aligns** when a signature verifies, covers the whole body (no `l=` tag) and its `d=` equals the `From` domain.

Rules that always apply:

- Domains must match exactly: `bounce.example.com` does not align with `example.com`.
- A signature that is merely present counts for nothing.
- DNS or verifier trouble (`temperror`, timeouts) on its own defers the message instead of rejecting it. A definitive failure of the other mechanism still rejects, for example SPF `temperror` with no DKIM signature (see the tables below).
- No DMARC policy is looked up: the domain's `_dmarc` record is not consulted.
- The message must have exactly one valid `From` header with one address; otherwise it is refused (`invalid_from`) before any DNS lookup.

| Key                | Default          | Meaning                                                                                                                                                     |
| ------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `require`          | `"both"`         | `"both"`: SPF **and** DKIM must pass and align. `"either"`: one of them is enough                                                                           |
| `allow_local`      | `true`           | `false`: local `sendmail` and same-server SMTP mail are checked like outside mail                                                                           |
| `allow_mynetworks` | `true`           | `false`: `mynetworks` clients are checked like outside mail; other rules still trust them                                                                   |
| `null_sender`      | `"dkim_aligned"` | bounces (`MAIL FROM:<>`) with `require = "both"`: `"dkim_aligned"` needs only an aligned DKIM pass, `"both"` applies the full rule. Ignored with `"either"` |

**Choosing `require`.** `"both"` is the stricter default. It refuses unsigned mail, and forwarded mail, because the forwarding server is not in the original domain's SPF record. `"either"` accepts both, at the cost of trusting a single mechanism.

**SPF first.** When the SPF result already decides, DKIM is not checked and the log shows `dkim=skipped`:

- with `"both"`, a definitive SPF failure (anything but `pass` or `temperror`, or a pass for another domain) rejects at once;
- with `"either"`, an aligned SPF pass accepts at once;
- an SPF `temperror` never decides.

### Decisions with `require = "both"`

| SPF (envelope domain, or HELO for `<>`)                     | DKIM (best signature)                              | Result                                         |
| ----------------------------------------------------------- | -------------------------------------------------- | ---------------------------------------------- |
| pass, aligned                                               | pass, aligned, no `l=`                             | accept (`spf_and_dkim_aligned`)                |
| none, neutral, softfail, fail, permerror, or unaligned pass | not checked                                        | reject (`spf_<result>`, `spf_unaligned`)       |
| pass aligned, or temperror                                  | absent, failed, unaligned, or only `l=` signatures | reject (`dkim_absent`, `dkim_no_aligned_pass`) |
| temperror                                                   | pass or temperror                                  | defer (`spf_temperror`)                        |
| pass, aligned                                               | temperror                                          | defer (`dkim_temperror`)                       |

### Decisions with `require = "either"`

| SPF                           | DKIM                          | Result                     |
| ----------------------------- | ----------------------------- | -------------------------- |
| pass, aligned                 | not checked                   | accept (`spf_aligned`)     |
| anything else                 | pass, aligned, no `l=`        | accept (`dkim_aligned`)    |
| temperror                     | no aligned pass               | defer (`spf_temperror`)    |
| no aligned pass               | temperror, no aligned pass    | defer (`dkim_temperror`)   |
| no aligned pass, no temperror | no aligned pass, no temperror | reject (`no_aligned_pass`) |

Up to `limits.max_signatures` signatures are checked; one good signature is not cancelled by bad ones. If the time budget or the signature limit stops the check before a deciding pass, the message is deferred (`evaluation_incomplete`).

## `[protection]`

A **protected address** accepts mail only from its listed logins. A **protected group**, written `<local>@*`, does the same for that local part on every domain this server delivers. Group members stay in your Postfix alias maps; postwarden only decides who may send to the address.

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

| Key                                       | Default             | Meaning                                                                                                          |
| ----------------------------------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `addresses."<address>".authorized_logins` | `[]`                | logins, exactly as Postfix reports them (`{auth_authen}`), that may send to the address. An empty list closes it |
| `remote_transports`                       | `["smtp", "relay"]` | Postfix transports that deliver to other servers; see below. Usually left out                                    |

Addresses are written without a recipient delimiter tag and matched case-insensitively. In a group, `*` must be the whole domain; no other `*` form exists.

Which recipients are protected (after the tag is removed):

| Recipient                                                    | Protected                     | Who may send                                                                        |
| ------------------------------------------------------------ | ----------------------------- | ----------------------------------------------------------------------------------- |
| a protected address                                          | yes, wherever it is delivered | its `authorized_logins`                                                             |
| in a protected group, domain delivered here                  | yes                           | the group's logins (in the example: nobody, until the address is listed on its own) |
| in a protected group, domain elsewhere (`remote_transports`) | no                            | anyone                                                                              |
| anything else                                                | no                            | anyone                                                                              |

### When sending to a protected address is allowed

All of these must hold:

- the message arrives on port 587 or 465, with the matching submission marker;
- the connection uses TLS;
- the login is listed for that address;
- the envelope sender is exactly the login.

Otherwise:

- over SMTP, the recipient is refused with `550 5.7.1` at `RCPT TO`;
- from local `sendmail`, the message is refused at end of message, and Postfix bounces the whole message, including its other recipients;
- with an unknown ingress marker, the recipient is deferred.

### `remote_transports`

The group `all@*` must protect `all@` on the domains this server hosts, but not `all@` at other organisations your users write to. Postfix tells postwarden where each recipient goes: the `{rcpt_mailer}` macro is the transport the address resolves to, for example `dovecot`, `virtual`, `lmtp` or `local` for local delivery.

- A transport **not** in the list counts as delivered here.
- Local `sendmail` submissions carry no transport, so they count as delivered here (they can never reach a protected address anyway).
- The default fits a stock Postfix, where outgoing mail leaves through `smtp` or `relay`.
- `install.py inspect` reports when Postfix's `default_transport` or `relay_transport` is missing from the list. Add any other relaying transport from `transport_maps` yourself.
- Each `rcpt` log line shows the transport as `transport=`. A missing name is safe but visible: `all@` at another organisation through that transport is refused.

## `[limits]`

| Key                               | Default    | Meaning                                                                                                                                                                                                                                                            |
| --------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `message_bytes`                   | `41943040` | larger messages are deferred                                                                                                                                                                                                                                       |
| `max_signatures`                  | `10`       | DKIM signatures checked per message                                                                                                                                                                                                                                |
| `max_headers`                     | `1000`     | header fields per message                                                                                                                                                                                                                                          |
| `max_header_bytes`                | `65536`    | total header size                                                                                                                                                                                                                                                  |
| `max_recipients`                  | `1000`     | further recipients are deferred                                                                                                                                                                                                                                    |
| `dns_timeout_seconds`             | `5`        | per DNS query                                                                                                                                                                                                                                                      |
| `authentication_deadline_seconds` | `20`       | total SPF and DKIM time per message; at least `dns_timeout_seconds`. Results that arrive later are discarded and the message is deferred; a DKIM check already running is not interrupted. Keep Postfix's `content_timeout` (60 s in `postwarden_milter`) above it |
| `max_concurrent_messages`         | `32`       | SPF/DKIM checks running at once; others wait within the deadline, then are deferred                                                                                                                                                                                |
| `max_open_messages`               | `100`      | messages being received at once; above it `MAIL FROM` is deferred (local `sendmail`: at end of message). Spool use stays below this × `message_bytes`                                                                                                              |

Every limit defers, so senders retry and nothing is lost. Postfix's own `message_size_limit` (about 10 MB by default) usually refuses large mail before postwarden sees it.

## `[responses.<rule>]`

Each reply can be reworded, but its class cannot change: a rejection stays a rejection and a deferral stays a deferral.

| Key             | Meaning                                                                      |
| --------------- | ---------------------------------------------------------------------------- |
| `smtp_code`     | `550` or `554` for rejections; `450`, `451` or `452` for `temporary_failure` |
| `enhanced_code` | `class.subject.detail`, with the class matching the code                     |
| `message`       | printable ASCII; the whole reply, including the reference, at most 510 bytes |

postwarden adds ` (ref <mid>)` to every reply. `<mid>` is the message id in the log, so an administrator elsewhere can quote the reference and you can find the exact rule and reason with `postwarden lookup <ref>`. The default texts are deliberately short: the standard codes tell an administrator what kind of problem occurred without spelling out the policy to someone probing it.

| Rule                    | Default reply                                                                  |
| ----------------------- | ------------------------------------------------------------------------------ |
| `protected_recipient`   | `550 5.7.1 Recipient address rejected: Access denied`                          |
| `self_sender`           | `550 5.7.1 Sender address rejected: Access denied`                             |
| `authentication_failed` | `550 5.7.26 Message rejected: Sender domain authentication failed (SPF, DKIM)` |
| `invalid_from`          | `550 5.7.1 Message rejected: From header does not conform to RFC 5322`         |
| `invalid_recipient`     | `550 5.1.3 Recipient address rejected: Bad address syntax`                     |
| `temporary_failure`     | `451 4.7.1 Service unavailable - try again later`                              |

`5.7.26` is the RFC 7372 code for "multiple authentication checks failed". `temporary_failure` uses the same text as Postfix when the milter is unreachable, so an outage and an internal temporary failure look alike from outside.
