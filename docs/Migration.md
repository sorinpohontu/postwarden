# Migration from pipe-based content filters

For sites that currently implement sender/recipient policy with `content_filter` pipe transports (a script that reads the message and reinjects it with `sendmail`) and a separate SPF policy daemon. A fresh installation without such components only needs [Installation.md](Installation.md).

## Before

Typical existing configuration:

- `master.cf` SMTP services with `-o content_filter=<pipe-service>` and `-o receive_override_options=no_address_mappings`.
- Pipe services running the filter script as an unprivileged user; success reinjects through `sendmail`, which runs the message through pickup and cleanup a second time (so `non_smtpd_milters` such as OpenDKIM run twice and the delivered copy carries two signatures).
- `check_policy_service unix:private/policyd-spf` in `smtpd_recipient_restrictions` and a `policyd-spf` service.

The first and third items are the **legacy components**: what `configure-postfix --remove-legacy` removes. It leaves service definitions alone, and it skips any component that is already absent, so it is safe to use on a host that has only some of them.

Inventory with `python3 scripts/install.py inspect` (shows content filters and the `policyd-spf` service) and `postconf -n | grep -E 'policy|milter'`.

## Phase 1 — observe alongside the legacy components

`install --apply` and `configure-postfix --phase observe --apply` add the milter without touching the legacy components. Both policies run: the pipe filters still reject what they reject (after the milter has already seen and logged the message), the SPF policy service still rejects at `RCPT` before the milter sees that recipient (so the milter's view of those is inconclusive), and every message is logged twice by the milter — once from SMTP and once as `ingress=LOCAL_PICKUP` after reinjection. Compare `would_reject` lines with the pipe filters' decisions for at least one full business cycle.

## Phase 2 — cutover

```sh
python3 scripts/install.py configure-postfix --phase enforce --remove-legacy --dry-run
python3 scripts/install.py configure-postfix --phase enforce --remove-legacy --apply
```

Enforcement and removal must happen together: `--phase enforce` without `--remove-legacy` is refused while content filters remain, because reinjected copies of authorized group mail would be refused on the pickup path and bounce.

In one operation this sets `mode = "enforce"`, restarts the daemon, switches the milter's `default_action` to `tempfail`, removes `content_filter` and `receive_override_options` from the SMTP services, removes the `policyd-spf` policy call, validates and reloads Postfix. It does **not** delete the pipe or `policyd-spf` service definitions.

Immediately verify:

- The queue: messages accepted before the cutover keep their content filter and still drain through the old pipe services (see Phase 3 for listing them).
- One authenticated submission: delivered with exactly one `DKIM-Signature`.
- Aliases, forwarders and BCC maps: address mappings are active again on the SMTP services (they were disabled by `no_address_mappings`); check for duplicates or loops.
- A protected-recipient rejection on 25 and an authorized send on 587.

### Manual cutover

The same change without the installer, in one sitting (list the services that carry a filter with `postconf -P | grep content_filter`; the example uses the usual `smtpd/pass` or `smtp/inet`, `submission/inet` and `smtps/inet`):

```sh
cp -p /etc/postfix/main.cf /etc/postfix/master.cf /etc/postwarden/config.toml /root/    # copies for undo
sed -i 's/^mode *=.*/mode = "enforce"/' /etc/postwarden/config.toml
grep -q '^mode' /etc/postwarden/config.toml || sed -i '1i mode = "enforce"' /etc/postwarden/config.toml
postwarden check-config && systemctl restart postwarden
postconf -PX smtpd/pass/content_filter smtpd/pass/receive_override_options \
             submission/inet/content_filter submission/inet/receive_override_options \
             smtps/inet/content_filter smtps/inet/receive_override_options
r=$(postconf -h smtpd_recipient_restrictions | sed -E \
  's#(^|,)[[:space:]]*check_policy_service[[:space:]]+unix:private/policyd-spf[[:space:]]*(,|$)#\1\2#; s#,,#,#; s#^,[[:space:]]*##; s#,[[:space:]]*$##')
printf '%s\n' "$r"                          # check: every other restriction still there, in order
postconf -e "smtpd_recipient_restrictions = $r"
postconf -e 'postwarden_milter = { unix:postwarden/policy.sock, default_action=tempfail, content_timeout=60s }'
postfix check && postfix reload
```

The restrictions edit expects a comma-separated list; for a list separated only by spaces, edit it by hand. `postconf -PX` rewrites `master.cf` in its own layout, so comment lines between services may move; review the file afterwards. To undo, copy the three files back from `/root/`, then `postfix reload` and `systemctl restart postwarden`.

## Phase 3 — retire the old services

A queued message records the content filter it was accepted with. List the messages that still carry one; retire the services once this prints nothing (deferred mail can take up to `maximal_queue_lifetime`, 5 days by default):

```sh
postqueue -j | grep -o '"queue_id": *"[^"]*"' | cut -d'"' -f4 | while read -r id; do
  postcat -eq "$id" 2>/dev/null | grep -q '^content_filter:' && echo "$id"
done
```

Then remove the service definitions, using the names from your `master.cf` (`python3 scripts/install.py inspect` listed them before the cutover; `<pipe-service>` is each filter service):

```sh
postconf -MX '<pipe-service>/unix'            # once per filter service
postconf -MX 'policyd-spf/unix'               # if you used the SPF policy service
postconf -X policyd-spf_time_limit            # if set
postfix check && postfix reload
apt-get remove postfix-policyd-spf-python     # keep python3-spf: the milter needs it
```

Keep the filter scripts and old configuration in your backups; `rollback --deployment-id <enforce-id>` restores the pre-cutover `main.cf`/`master.cf` and `config.toml`, and reinstating the package restores the SPF policy daemon if you retired it.

## Behavior differences to communicate

- Rejections happen during SMTP (`550` at `RCPT TO` or after `DATA`) instead of after acceptance; senders see the reason immediately.
- A prohibited recipient no longer blocks the other recipients of the same SMTP transaction.
- Local `sendmail`/PHP `mail()` cannot address a protected group; such messages bounce entirely, including other recipients.
- SPF alone no longer decides: external mail needs SPF and DKIM aligned with the From domain, except null-sender bounces (aligned DKIM only).
