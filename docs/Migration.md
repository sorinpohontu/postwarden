# Migration from pipe-based content filters

This guide is for servers that enforce sender and recipient policy with `content_filter` pipe services (a script that reads each message and reinjects it with `sendmail`) and a separate SPF policy service. A server without them only needs [Installation](Installation.md).

The migration has three phases:

1. **Observe:** postwarden runs alongside the old filters and only logs.
2. **Cutover:** enforcement is switched on and the old filters are detached, in one step.
3. **Retire:** the old services are removed once no queued mail needs them.

## Before you start

A typical existing setup has:

- SMTP services in `master.cf` with `-o content_filter=<pipe-service>` and `-o receive_override_options=no_address_mappings`;
- pipe services that run the filter script and reinject accepted mail through `sendmail`. That mail passes pickup and cleanup a second time, so milters such as OpenDKIM run twice and the delivered copy carries two signatures;
- `check_policy_service unix:private/policyd-spf` in `smtpd_recipient_restrictions`, and a `policyd-spf` service.

The content filter settings and the policy call are the **legacy components** that `configure-postfix --remove-legacy` removes. It leaves the service definitions alone and skips any component that is already absent, so it is safe on a server that has only some of them.

List what you have:

```sh
python3 scripts/install.py inspect            # content filters and the policyd-spf service
postconf -n | grep -E 'policy|milter'
```

## Phase 1: observe alongside the old filters

Install postwarden and attach it in observe mode, as in [Installation](Installation.md#automated-installation) steps 1–4. The legacy components are not touched, and both policies run:

- the pipe filters still refuse what they refuse, after postwarden has seen and logged the message;
- the SPF policy service still refuses at `RCPT` before postwarden sees that recipient, so postwarden's view of those messages is incomplete;
- postwarden logs every message twice: once from SMTP and once as `ingress=LOCAL_PICKUP` after reinjection.

Compare postwarden's `would_reject` lines with the filters' decisions for at least one full business cycle.

## Phase 2: cutover

```sh
python3 scripts/install.py configure-postfix --phase enforce --remove-legacy --dry-run
python3 scripts/install.py configure-postfix --phase enforce --remove-legacy --apply
```

Enforcement and removal must happen together. `--phase enforce` without `--remove-legacy` is refused while content filters remain: reinjected copies of authorized group mail would be refused on the `sendmail` path and bounce.

In one step this:

- sets `mode = "enforce"` and restarts postwarden;
- switches the milter's `default_action` to `tempfail`;
- removes `content_filter` and `receive_override_options` from the SMTP services;
- removes the `policyd-spf` call from `smtpd_recipient_restrictions`;
- validates and reloads Postfix.

It does **not** delete the pipe or `policyd-spf` service definitions. The remaining restrictions keep their order, but `postconf` writes the list on one line, so comment lines from a multi-line layout stay behind. A `{ }`-grouped restriction list is refused; edit it by hand.

Check right away:

- **The queue:** messages accepted before the cutover keep their content filter and still drain through the old pipe services (see Phase 3).
- **One authenticated submission:** delivered with exactly one `DKIM-Signature`.
- **Aliases, forwarders and BCC maps:** address mappings are active again on the SMTP services (`no_address_mappings` disabled them); look for duplicates or loops.
- **Policy:** a refused protected recipient on port 25, and an authorized send on 587.

### Manual cutover

The same change without the installer, in one sitting. List the services that carry a filter with `postconf -P | grep content_filter`; the example uses `smtpd/pass`, `submission/inet` and `smtps/inet`, so replace them with yours (for example `smtp/inet` or `submissions/inet`).

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

- The restrictions edit expects a comma-separated list; edit a list separated only by spaces by hand.
- `postconf -PX` rewrites `master.cf` in its own layout, so comment lines between services may move; review the file afterwards.
- To undo, copy the three files back from `/root/`, then run `postfix reload` and `systemctl restart postwarden`.

## Phase 3: retire the old services

A queued message keeps the content filter it was accepted with. This lists the messages that still have one; retire the services once it prints nothing. Deferred mail can take up to `maximal_queue_lifetime` (5 days by default).

```sh
postqueue -j | grep -o '"queue_id": *"[^"]*"' | cut -d'"' -f4 | while read -r id; do
  postcat -eq "$id" 2>/dev/null | grep -q '^content_filter:' && echo "$id"
done
```

Then remove the service definitions, using the names from your `master.cf` (`inspect` listed them before the cutover):

```sh
postconf -MX '<pipe-service>/unix'            # once per filter service
postconf -MX 'policyd-spf/unix'               # if you used the SPF policy service
postconf -X policyd-spf_time_limit            # if set
postfix check && postfix reload
apt-get remove postfix-policyd-spf-python     # keep python3-spf: postwarden needs it
```

Keep the filter scripts and the old configuration in your backups. `rollback --deployment-id <enforce-id>` restores the `main.cf`, `master.cf` and `config.toml` from before the cutover; reinstalling the package brings back the SPF policy service if you removed it.

## What changes for users

- Refusals happen during SMTP (`550` at `RCPT TO` or after `DATA`) instead of after acceptance, so senders see them immediately.
- A refused recipient no longer blocks the other recipients of the same message.
- Local `sendmail` and PHP `mail()` cannot send to a protected address; such messages bounce entirely, including their other recipients.
- SPF alone no longer decides. By default outside mail needs both SPF and DKIM matching the `From` domain (`require = "either"` accepts one of them); bounces need only a matching DKIM signature.
