# Installation

Two equivalent paths: the automated installer (`scripts/install.py`) and the manual steps below. Both produce the same files, permissions and services. Debian 12 and 13 with the distribution's Postfix and Python 3.

## Requirements

- Debian 12 (bookworm) or 13 (trixie), Postfix 3.7 or newer, systemd.
- Packages: `python3 python3-milter python3-spf python3-dkim python3-dnspython`.
- Mail logging through syslog (`mail` facility); the daemon logs there with identifier `postwarden`.
- An outbound DKIM signer (for example OpenDKIM) stays in place; this milter verifies only.

## Automated path

Download a release archive `postwarden-<version>.tar.gz` and its `.sha256` from the project's releases.
The archive contains only what is installed, plus `MANIFEST.sha256`, a checksum of every file in it.

Unpack it anywhere outside `/etc/postwarden` and run the installer from there; `install --apply` copies the application into `/etc/postwarden/`, where it lives next to `config.toml`:

```sh
# 0. Verify and unpack
sha256sum -c postwarden-<version>.tar.gz.sha256
mkdir -p /root/postwarden-<version> && tar -xzf postwarden-<version>.tar.gz -C /root/postwarden-<version>
cd /root/postwarden-<version>

# 1. Inspect (read-only; works before the runtime packages are installed)
python3 scripts/install.py inspect

# 2. Create the configuration
mkdir -p /etc/postwarden
cp etc/config.example.toml /etc/postwarden/config.toml
chmod 0640 /etc/postwarden/config.toml
$EDITOR /etc/postwarden/config.toml         # [protection] addresses and logins
PYTHONPATH=src python3 -m postwarden check-config

# 3. Install the daemon (packages, user, directories, release, unit) without touching Postfix
python3 scripts/install.py install --dry-run
sudo python3 scripts/install.py install --apply

# 4. Attach to Postfix in observation mode, then later in enforcement
python3 scripts/install.py configure-postfix --phase observe --dry-run
sudo python3 scripts/install.py configure-postfix --phase observe --apply
sudo python3 scripts/install.py configure-postfix --phase enforce --dry-run
sudo python3 scripts/install.py configure-postfix --phase enforce --apply
```

`inspect` and every `--dry-run` change nothing. `--apply` needs root, takes a lock, records a backup under `/var/backups/postwarden/<deployment-id>/` and refuses to run if `config.toml`, `main.cf`, `master.cf` or the installed files changed between inspection and application. It manages regular files only and refuses if any of them is a symlink. Re-running an identical `install --apply` is a no-op except for reporting.

Upgrades: unpack the new release archive elsewhere (for example `/root/postwarden-new`) and run `python3 scripts/install.py install --apply` from there; the installer archives the previous `/etc/postwarden` tree into the deployment backup, copies the new files in and restarts the daemon. `config.toml` is never overwritten unless `--import-config` is given.

`/etc/postwarden` holds only the release content and `config.toml`. Anything else found there is moved, not deleted, to `/var/backups/postwarden/<time>-unmanaged/`, and the whole tree is reset to root ownership (`config.toml` stays `root:postwarden`). A user who owns the directory or any file in it could replace the code the daemon and the installer run, so `inspect` reports non-root ownership as a finding. Put site notes and backups elsewhere.

`configure-postfix --phase enforce` sets `mode = "enforce"` in `/etc/postwarden/config.toml`, restarts the daemon, and switches the Postfix milter entry to `default_action=tempfail` in one operation. While any SMTP service still has a `content_filter`, `--phase enforce` is refused: a filter that reinjects through `sendmail` hands every message to the milter a second time as local pickup, where protected recipients are always refused, so authorized group mail would be accepted on 587 and then bounce. Use `--remove-legacy` for the cutover, or `--keep-legacy` to enforce anyway on a test host. `--remove-legacy` additionally removes the legacy components — `content_filter`/`receive_override_options` on the SMTP services and a `check_policy_service … policyd-spf` entry in `smtpd_recipient_restrictions` (comma- or whitespace-separated; a `{ }`-grouped list is refused for manual editing). The remaining restrictions keep their order and arguments, but `postconf -e` writes the list as one line: comment lines from a multi-line layout stay behind, harmless but orphaned. Components already absent are skipped; keep the old pipe service definitions in `master.cf` until queued mail using them has drained.

Rollback:

```sh
python3 scripts/install.py rollback --deployment-id <id> --dry-run
sudo python3 scripts/install.py rollback --deployment-id <id> --apply
```

Roll back in reverse order: the `configure-postfix` deployments first, then `install`. Rolling back the first `install` stops and disables the service and removes the unit and launcher, keeping `config.toml`, `/etc/postwarden` and the backups. Rollback refuses files changed after the deployment (content, permissions or owner) unless `--force` is given; see [Operations](Operations.md#updates-and-rollback).

## Manual path

### 1. Packages

```sh
apt-get update
apt-get install --no-install-recommends python3 python3-milter python3-spf python3-dkim python3-dnspython
```

### 2. Service account and directories

```sh
groupadd --system postwarden
useradd --system --gid postwarden --groups postfix --home-dir /var/lib/postwarden \
        --shell /usr/sbin/nologin --no-create-home postwarden
install -d -m 0755 /etc/postwarden
install -d -o postwarden -g postfix -m 2750 /var/spool/postfix/postwarden
install -d -o postwarden -g postwarden -m 0700 /var/lib/postwarden
```

The setgid bit on the socket directory makes the socket group `postfix`, so chrooted and non-chrooted Postfix processes can connect while nothing else can.

### 3. Application, launcher, configuration

```sh
tar -xzf postwarden-<version>.tar.gz -C /etc/postwarden   # src/ bin/ scripts/ packaging/ etc/ docs/
cd /etc/postwarden
install -m 0755 bin/postwarden /usr/local/sbin/postwarden
cp etc/config.example.toml /etc/postwarden/config.toml   # then edit
chown root:postwarden /etc/postwarden/config.toml
chmod 0640 /etc/postwarden/config.toml
postwarden check-config
```

`mynetworks` and `recipient_delimiter` are read from Postfix; `check-config` shows the values it found.

### 4. systemd unit

```sh
install -m 0644 packaging/systemd/postwarden.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now postwarden.service
ls -l /var/spool/postfix/postwarden/policy.sock     # srwxrwx--- postwarden postfix
journalctl -t postwarden -n 5                        # or grep postwarden /var/log/mail.log
```

Postfix behaves exactly as before at this point; the daemon is running but not attached.

### 5. Postfix integration

Observation phase (`default_action=accept`, daemon `mode = "observe"`):

```sh
# helpers for this shell session: put an entry first in a list, add missing macros to a list
prepend() { v=$(postconf -h "$1"); postconf -e "$1 = $2${v:+, $v}"; }
add_macros() { v=$(postconf -h "$1"); n=$1; shift; for m in "$@"; do case " $v " in *" $m "*) ;; *) v="${v:+$v }$m";; esac; done; postconf -e "$n = $v"; }

postconf -e 'milter_protocol = 6'
postconf -e 'postwarden_milter = { unix:postwarden/policy.sock, default_action=accept, content_timeout=60s }'
prepend smtpd_milters '$postwarden_milter'
[ "$(postconf -h non_smtpd_milters)" = '$smtpd_milters' ] || prepend non_smtpd_milters '$postwarden_milter'
prepend milter_macro_defaults 'postwarden_ingress=UNCLASSIFIED'
add_macros milter_connect_macros '{daemon_addr}' '{daemon_port}' '{client_port}' '{postwarden_ingress}'
add_macros milter_mail_macros '{daemon_port}' '{auth_type}' '{auth_authen}' '{cipher_bits}' '{tls_version}' '{postwarden_ingress}'
add_macros milter_rcpt_macros '{rcpt_mailer}'

postconf -P 'smtpd/pass/milter_macro_defaults = postwarden_ingress=SMTP25'      # smtp/inet when there is no postscreen
postconf -P 'submission/inet/milter_macro_defaults = postwarden_ingress=SUBMISSION587'
postconf -P 'submissions/inet/milter_macro_defaults = postwarden_ingress=SUBMISSION465'  # smtps/inet on older layouts
postconf -M 'postwarden-cleanup/unix = postwarden-cleanup unix n - y - 0 cleanup'
postconf -P 'postwarden-cleanup/unix/milter_macro_defaults = postwarden_ingress=LOCAL_PICKUP'
postconf -P 'pickup/unix/cleanup_service_name = postwarden-cleanup'

postfix check && postfix reload
```

`postconf` warns once `unused parameter: postwarden_milter` right after it is defined; the next line references it. postwarden reads the login and TLS facts once, at `MAIL FROM`, so `{auth_type}` and `{auth_authen}` must be in `milter_mail_macros` (Postfix's default list has them). A service with its own `-o milter_connect_macros=`, `-o milter_mail_macros=` or `-o milter_rcpt_macros=` ignores the main.cf list: add the same macros to that override, comma-separated (`postconf -P 'submission/inet/milter_mail_macros=i,{auth_type},{auth_authen},...'`). `inspect` reports any macro missing from its stage, globally or per service; the installer merges them automatically. A service in `master.cf` that sets its own `-o smtpd_milters=` or `-o milter_macro_defaults=` overrides these lines: put `$postwarden_milter` first in its milter list (`postconf -P 'submission/inet/smtpd_milters=$postwarden_milter,<its other milters>'`) and keep its other defaults after `postwarden_ingress=...`. The socket path is relative to `queue_directory` and resolves for both chrooted and non-chrooted services.

Enforcement phase: set `mode = "enforce"` in `/etc/postwarden/config.toml`, run `postwarden check-config`, `systemctl restart postwarden`, then change `default_action=accept` to `default_action=tempfail` in `postwarden_milter` and `postfix reload`. Do both; a daemon in enforce mode behind `default_action=accept` silently admits every message when the daemon is down.

### 6. Verify

- `postconf -n | grep milter` and `postconf -P | grep -e postwarden_ingress -e smtpd_milters` show the values above; `python3 scripts/install.py inspect` reports any ingress whose milter chain lacks postwarden and any macro Postfix does not send.
- Send a message through each path (25, 587, 465, `sendmail`) and check `journalctl -t postwarden` for one `stage=eom` event per message with the expected `ingress=` and `trust=` values.
- `postwarden show-config` prints the effective settings.

### 7. Manual rollback

Restore `main.cf` and `master.cf` from your backup, `postfix check && postfix reload`, and confirm nothing uses postwarden any more: `postconf -nx; postconf -Px` must not show `unix:postwarden/policy.sock` outside `postwarden_milter`. Then `systemctl disable --now postwarden`. The application files under `/etc/postwarden/` can stay in place.
