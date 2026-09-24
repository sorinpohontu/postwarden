# ADR-0008: Protect addresses one by one; `all@*` closes hosted domains by default

- Status: Accepted
- Date: 2026-09-23

## Context

Protection applied only to exact addresses listed in `[[protected_recipients]]`
tables, each table grouping the addresses that share one list of authorized
logins. On a server where every hosted domain has an `all@` alias, a domain
missing from the configuration left its `all@` open: authenticated users could
write to it freely, and aligned external mail reached it. Nothing warned about
the omission, and postwarden cannot enumerate aliases because group expansion
stays in Postfix maps it does not read. Grouping addresses by shared login
lists was also found unintuitive to write.

Postfix passes `{rcpt_mailer}` at RCPT: the transport a recipient resolves to.
It is Postfix metadata, so it can tell recipients delivered on this server from
recipients relayed elsewhere without a domain list.

## Decision

- Configuration moves to one `[protection]` section with one table per
  protected address:

  ```toml
  [protection.addresses."all@a.ro"]
  authorized_logins = ["director@a.ro"]

  [protection.addresses."ceo@b.ro"]
  authorized_logins = ["assistant@b.ro"]

  [protection.addresses."all@*"]       # every other hosted domain's all@
  authorized_logins = []
  ```

- A recipient (after the recipient delimiter is removed, ADR-0002) that is
  listed exactly is protected wherever it is delivered and uses its own
  `authorized_logins`.
- `<local>@*` covers that local part on every **locally delivered** domain:
  one whose `{rcpt_mailer}` is not in `remote_transports`. A missing
  `{rcpt_mailer}` counts as local, so an unknown path fails closed. Local
  pickup never carries `{rcpt_mailer}`, so sendmail to `all@` at another
  organisation is refused; it could never reach a protected address anyway.
  Only a whole-domain `*` is accepted.
- An exact address overrides `<local>@*`. With `authorized_logins = []` on
  `all@*`, a hosted domain's `all@` that is not listed exactly is **closed**
  (`reason=no_authorized_logins`, 550). Logins listed on `all@*` may write to
  `all@` of every hosted domain. Writing to `all@` at other organisations is
  unaffected.
- There is no per-domain exemption: a domain whose `all@` should be open gets
  no `all@*` entry at all, or an exact entry listing its senders.
- `authorized_logins` lists exact logins; no domain wildcards. The existing
  invariants still hold for every protected recipient: TLS-authenticated
  submission on 587 or 465 (ADR-0009), envelope sender
  equal to the login, never port 25 or local sendmail.
- `remote_transports` defaults to `["smtp", "relay"]` and is left out of the
  example; `install.py inspect` reports Postfix `default_transport` or
  `relay_transport` values missing from it.
- `allowed_ports`, `require_tls` and `sender_must_equal_sasl_login` are
  removed because they only restated the submission requirement.
- `[[protected_recipients]]` is removed without a compatibility path; no release
  used it. `check-config` rejects it and names the replacement.

## Consequences

- Adding a customer domain can no longer silently expose its `all@`; the
  failure mode is a visible `550` with a reference until its address is listed.
- One concept to learn: an address and who may write to it. Duplicates are
  caught after case and IDNA normalization. `*` means hosted domains only, which
  the example and documentation must state because it could be read as every
  domain.
- Addresses of one domain that share senders repeat the login list.
- The transport names must match the site: a custom remote transport missing
  from `remote_transports` makes `all@` at external domains closed through it
  (fail closed, visible), never open.
- `{rcpt_mailer}` values for virtual-mailbox, alias and relay domains must be
  verified on both Debian releases before release.
- The default is an address pattern, not a separate key: a list of local
  parts (`localparts`, `on_hosted_domains`) named neither its content nor its
  fail-closed effect clearly, and a pattern needs no second concept.
- Options not taken: keeping grouped tables; per-domain tables with a shared
  login list and a per-domain local-part override (less repetition, but the
  operator has to work out which local parts a domain covers); an explicit
  local-domain list (a second list to keep in sync with the hosting setup);
  reading the transports from `postconf` at daemon start (misses
  `transport_maps` relays); domain wildcards in `authorized_logins`; a
  per-address `open = true` exemption.
