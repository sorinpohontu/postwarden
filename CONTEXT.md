# postwarden — domain context

Shared vocabulary for code, docs and conversation. Policy detail lives in
the local plan (not distributed); decisions with alternatives live in `.agents/adr/`.

## Glossary

### postwarden

The product: a Postfix milter daemon enforcing sender policy (protected
recipients, self-sender, SPF/DKIM alignment) during SMTP. One lowercase
identifier for the package, module, CLI, unit, user, paths, syslog tag and
repository (ADR-0006). Not OpenDKIM or any other milter on the same host.

### Protected recipient

An envelope recipient (typically a group address such as `all@`) that may only
be addressed by an authorized login whose envelope sender equals that login,
over TLS-authenticated submission (587, 465). Decided
by a protected address or a protected group (ADR-0008). Not a
mailbox membership list: expansion stays in Postfix alias maps.

### Protected address

One exact address listed in `[protection.addresses]`, such as
`all@example.com`, with its own `authorized_logins`. Protected wherever it is
delivered.

### Protected group

A local part protected on every locally delivered domain, written `<local>@*`
in `[protection.addresses]` (`all@*` is the `all` group). A protected address
overrides it for that one domain; with no logins it keeps every hosted
domain's `all@` closed until listed. Never covers other organisations' domains.
Not a membership list: members stay in Postfix alias maps.
Also seen as: hosted-domain wildcard (prefer protected group).

### Locally delivered

A recipient whose Postfix transport (`{rcpt_mailer}`) is not listed in
`[protection] remote_transports`; a missing transport counts as local.
Distinguishes this server's domains from other organisations' without a
domain list.

### Authorized login

A SASL login name, as Postfix supplies it in `{auth_authen}`, listed in a
protected address's `authorized_logins`. Exact logins only, no wildcards.
Compared byte-exactly with the envelope sender after domain folding; never
lowercased or mapped (see ADR-0001).

### Self-sender

A message whose envelope sender or visible `From` mailbox equals one of its
envelope recipients. Checked on port 25 only; `mynetworks` and listed senders
are exempt from this rule alone.

### Visible From

The single mailbox parsed from the message's `From:` header field. Untrusted
mail must carry exactly one valid `From` with one mailbox. Display names,
`Reply-To` and `Sender` are never identities.

### Alignment

Exact equality between a normalized domain and the visible From domain.
Subdomains and organizational domains do not align.

### Aligned pass

An SPF `pass` for the From domain, or a verified whole-body DKIM signature
with `d=` equal to the From domain. `sender_authentication.require` decides
whether `both` or `either` is needed (ADR-0019). Not DMARC: no `_dmarc`
policy is read. Avoid calling `either` "DMARC mode".

### Null sender

`MAIL FROM:<>` only: bounces and DSNs. An envelope sender postwarden cannot parse is an unknown sender, never a null sender (ADR-0013). SPF evaluates the HELO identity for them;
by default they pass external authentication on an aligned DKIM signature alone
(ADR-0005). Never authorizes a protected recipient.

### Ingress

The classified path a message entered through: `SMTP25`, `SUBMISSION587`,
`SUBMISSION465`, `LOCAL_PICKUP` (non-SMTP sendmail/pickup), or `UNCLASSIFIED`.
Taken from the Postfix-supplied `{postwarden_ingress}` macro plus connection
metadata, never from message headers. Local pickup is marked by the
`postwarden-cleanup` service.

### Trust classes

Five classifications of a connection, decided from ingress and peer address:
`local_pickup` (non-SMTP injection), `local_smtp` (port-25 clients on this
server: loopback, or the client address equals `{daemon_addr}`),
`authenticated_submission`, `mynetworks` (Postfix's, read at start), and
`untrusted`. All but `untrusted` bypass external
authentication. `local_pickup` never meets the self-sender rule, and
`local_smtp` and `mynetworks` bypass it while `self_sender.allow_mynetworks`
is on. None bypass protected recipients.

### Mode

`observe` logs the decision that would be taken and lets the message continue;
`enforce` returns the configured SMTP reply. One global daemon setting; from
1.1 sending limits also have their own mode (`observe`, `enforce`, `off`,
default `observe`), and a global `observe` overrides it (ADR-0007).

### Phase

The coupled pair of daemon mode and the milter's Postfix `default_action`:
observation = `observe` + `accept`, enforcement = `enforce` + `tempfail`.
Changed only through `configure-postfix --phase`, never by editing `mode`
alone; enforce mode behind `default_action=accept` admits everything while
the daemon is down.

### Legacy components

The pre-milter policy wiring that `configure-postfix --remove-legacy` takes
out: `content_filter` and `receive_override_options` overrides on the SMTP
services, and the `check_policy_service` SPF call. Not the pipe or
`policyd-spf` service definitions, which stay until their queue drains.
Removing components that are already absent is a no-op.
Also seen in docs as: "old filters", "pipe filters" (prefer Legacy components).

### Recipient refusal

A recipient whose RCPT-stage decision was not `allow`. Counted on the
end-of-message line by class, `rejected_rcpts` and `deferred_rcpts`, in both
modes; only `action` (`reject` vs `would_reject`) says whether it was enforced.

### Reply reference

The ` (ref <mid>)` suffix the daemon appends to every SMTP reply it sends (and
to observe-mode `would_*` replies). Equals `mid=` on the log line, which holds
the precise rule and reason that the terse public reply leaves out.

### Sending limit (planned, 1.1)

A rolling-hour and rolling-day cap on recipients per **limit key**, enforced by the `sending_limit` rule with a temporary failure
(ADR-0007). Protects against compromised logins and hacked scripts; not a
per-message recipient cap (`limits.max_recipients`) and not Postfix's per-IP
`anvil` limits.

### Limit key

What a sending limit counts against: the SASL login for authenticated
submission, the envelope sender for local mail, the client IP for `mynetworks`
relays without a login, plus one **host-wide local cap** over all local mail.
Untrusted inbound mail has no limit key.

### Limit multiplier (planned, 1.1)

A positive factor that scales both default sending limits for one
account (limit key), one domain (exact match) or one relay IP/CIDR. The most
specific match wins; factors are never combined and there is no "unlimited"
(ADR-0007). Not an absolute limit.

### Window state file (planned, 1.1)

`/var/lib/postwarden/limits.json`: the daemon's own snapshot of its
sending-limit windows, written every minute and on stop, loaded at start, so
restarts and reboots do not reset the limits (ADR-0007). Counts never come
from logs.

### Open message

A transaction between `MAIL FROM` and end of message, holding a capture and spool
file. Capped by `limits.max_open_messages` (ADR-0012); not the same as
`max_concurrent_messages`, which caps SPF/DKIM verification only.

### Rule `trust`

Not a policy rule: the end-of-message `rule` value when no rule refused the
message and its trust class exempted it (`reason=exempt_<class>`).

### Lifecycle event

`event=start` / `event=stop`, carrying mode, socket and configuration path.
Emitted regardless of `logging.level`; policy decisions are `info`.

### Decision classes

`allow` (continue with remaining rules), `reject` (definitive, 5xx),
`defer` (temporary, 4xx). A reply's wording is configurable; its class is not.

### Normalized address

A mailbox with the domain case-folded (and IDNA-normalized with the standard
library, ADR-0003) and the local part case-folded for lookup purposes. Plus
tags are not stripped by normalization.
Also seen as: "address matching", "identity comparison" (prefer Normalized address).

### Recipient delimiter

Postfix's `recipient_delimiter` (usually `+`), read from Postfix at start. Applied only when looking up a
protected recipient, so `all+tag@` matches protected `all@` (ADR-0002). Not
applied to self-sender or login comparisons.

### Feasibility gate

The platform probe in `tests/integration/feasibility/`, run on a test host
before the daemon was built and again whenever a new Debian, Postfix, PyMilter
or dkimpy version is to be supported: (a) DKIM verification of
PyMilter-captured bytes under simple and relaxed canonicalization, (b) macro
delivery on 25/587/465/pickup, (c) non-SMTP end-of-message rejection behavior.
In git, not in release archives.
