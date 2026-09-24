# Installation

There are two equivalent ways to install postwarden: the **automated installer** (`scripts/install.py`) and the **manual steps**. Both produce the same files, permissions and services.

In both, postwarden starts in **observe** mode: it logs what it would refuse and lets all mail through. Switch to **enforce** mode once the log looks right.

## Requirements

- Debian 12 (bookworm) or 13 (trixie), Postfix 3.7 or newer, systemd.
- Debian packages `python3 python3-milter python3-spf python3-dkim python3-dnspython`; the installer installs them.
- Mail logging through syslog (the journal, or rsyslog's `/var/log/mail.log`).
- An outgoing DKIM signer such as OpenDKIM, if you sign mail. It stays in place; postwarden only verifies.

## Get the release

Download `postwarden-<version>.tar.gz` and its `.sha256` from the project's releases. Check it and unpack it anywhere **outside** `/etc/postwarden`:

```sh
sha256sum -c postwarden-<version>.tar.gz.sha256
mkdir /root/postwarden-<version>
tar -xzf postwarden-<version>.tar.gz -C /root/postwarden-<version>
cd /root/postwarden-<version>
```

The archive contains only what is installed, plus `MANIFEST.sha256`, a checksum of every file in it.

## Automated installation

Run everything as root, from the unpacked directory.

**1. Inspect.** This is read-only and works before the Python packages are installed. It reports what is missing and how Postfix is set up.

```sh
python3 scripts/install.py inspect
```

**2. Create the configuration** and list your protected addresses and their logins (see [Configuration](Configuration.md#protection)):

```sh
mkdir -p /etc/postwarden
cp etc/config.example.toml /etc/postwarden/config.toml
chmod 0640 /etc/postwarden/config.toml
$EDITOR /etc/postwarden/config.toml
PYTHONPATH=src python3 -m postwarden check-config
```

**3. Install the daemon.** This installs the packages, creates the `postwarden` user and directories, copies the application into `/etc/postwarden/`, and installs and starts the service. Postfix is not touched yet.

```sh
python3 scripts/install.py install --dry-run
python3 scripts/install.py install --apply
```

**4. Attach to Postfix in observe mode:**

```sh
python3 scripts/install.py configure-postfix --phase observe --dry-run
python3 scripts/install.py configure-postfix --phase observe --apply
```

**5. Switch to enforce mode** after reviewing the log (`journalctl -t postwarden`):

```sh
python3 scripts/install.py configure-postfix --phase enforce --dry-run
python3 scripts/install.py configure-postfix --phase enforce --apply
```

This sets `mode = "enforce"`, restarts the daemon and switches Postfix's failure action to `tempfail`, all in one step.

If your SMTP services pass mail through content filters that reinject it with `sendmail`, `--phase enforce` is refused: read [Migration](Migration.md) first. On a test host, `--keep-legacy` enforces anyway.

### How the installer works

- `inspect` and every `--dry-run` change nothing.
- `--apply` needs root and takes a lock. It backs up everything it changes under `/var/backups/postwarden/<deployment-id>/` and prints the **deployment id**.
- It refuses if `config.toml`, `main.cf`, `master.cf` or the installed files changed between the dry run and the apply, and if any of them is a symlink.
- A run that would change nothing records no deployment.
- `configure-postfix` edits Postfix through `postconf`, which rewrites `master.cf` in its own layout, so comment lines between services may move. The dry run shows the diff.

`/etc/postwarden` holds only the release and `config.toml`. Anything else found there is moved (not deleted) to `/var/backups/postwarden/<time>-unmanaged/`, and the directory is reset to root ownership (`config.toml` stays `root:postwarden`). A user who could write there could replace the code postwarden runs, so `inspect` reports other owners. Keep notes and backups elsewhere.

### Upgrades

Unpack the new release outside `/etc/postwarden` and run `install` from it:

```sh
python3 scripts/install.py install --dry-run
python3 scripts/install.py install --apply
```

The previous application is kept in the deployment backup, the new one is copied in and the daemon restarted. `config.toml` is never overwritten, unless you pass `--import-config <file>`.

### Rollback

```sh
python3 scripts/install.py rollback --deployment-id <id> --dry-run
python3 scripts/install.py rollback --deployment-id <id> --apply
```

Roll back in reverse order: the `configure-postfix` deployments first, then `install`. Rolling back the first `install` stops and disables the service and removes the unit and launcher, keeping `config.toml`, `/etc/postwarden` and the backups. Rollback refuses files changed since the deployment unless you pass `--force`; see [Operations](Operations.md#rollback).

## Manual installation

Run as root. Keep the unpacked release from [Get the release](#get-the-release) at hand.

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

The setgid bit on the socket directory gives the socket the group `postfix`, so Postfix processes can connect, chrooted or not, and nothing else can.

### 3. Application, launcher and configuration

```sh
tar -xzf postwarden-<version>.tar.gz -C /etc/postwarden
cd /etc/postwarden
install -m 0755 bin/postwarden /usr/local/sbin/postwarden
cp etc/config.example.toml /etc/postwarden/config.toml
chown root:postwarden /etc/postwarden/config.toml
chmod 0640 /etc/postwarden/config.toml
$EDITOR /etc/postwarden/config.toml
postwarden check-config
```

`check-config` also shows the `mynetworks` and `recipient_delimiter` values it read from Postfix.

### 4. systemd unit

```sh
install -m 0644 packaging/systemd/postwarden.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now postwarden.service
ls -l /var/spool/postfix/postwarden/policy.sock     # srwxrwx--- postwarden postfix
journalctl -t postwarden -n 5
```

postwarden is now running but not attached; Postfix behaves exactly as before.

### 5. Attach to Postfix (observe mode)

First, back up the Postfix configuration; you need it for [rollback](#8-manual-rollback):

```sh
install -d -m 0700 /root/postfix-before-postwarden
cp -p /etc/postfix/main.cf /etc/postfix/master.cf /root/postfix-before-postwarden/
```

Each way into Postfix gets an **ingress marker**, so postwarden knows how a message arrived. Find your service names with `postconf -M`:

| Path             | Service name in `master.cf`                          | Marker          |
| ---------------- | ---------------------------------------------------- | --------------- |
| Port 25          | `smtp/inet`, or `smtpd/pass` behind postscreen       | `SMTP25`        |
| Port 587         | `submission/inet`                                    | `SUBMISSION587` |
| Port 465         | `submissions/inet`, or `smtps/inet` on older layouts | `SUBMISSION465` |
| Local `sendmail` | `postwarden-cleanup/unix`, created below             | `LOCAL_PICKUP`  |

The commands below use the names of a stock Debian 13 Postfix; change the three service lines (`smtp/inet`, `submission/inet`, `submissions/inet`) if yours differ.

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

postconf -P 'smtp/inet/milter_macro_defaults = postwarden_ingress=SMTP25'
postconf -P 'submission/inet/milter_macro_defaults = postwarden_ingress=SUBMISSION587'
postconf -P 'submissions/inet/milter_macro_defaults = postwarden_ingress=SUBMISSION465'
postconf -M 'postwarden-cleanup/unix = postwarden-cleanup unix n - y - 0 cleanup'
postconf -P 'postwarden-cleanup/unix/milter_macro_defaults = postwarden_ingress=LOCAL_PICKUP'
postconf -P 'pickup/unix/cleanup_service_name = postwarden-cleanup'

postfix check && postfix reload
```

`postconf` warns once `unused parameter: postwarden_milter` right after defining it; the next line uses it.

If a service in `master.cf` has its own settings, they override the ones above:

- **`-o smtpd_milters=`:** put `$postwarden_milter` first in its list, for example `postconf -P 'submission/inet/smtpd_milters=$postwarden_milter,<its other milters>'`.
- **`-o milter_macro_defaults=`:** put `postwarden_ingress=...` first and keep its other values after it.
- **`-o milter_connect_macros=`, `-o milter_mail_macros=` or `-o milter_rcpt_macros=`:** add the same macros to it, comma-separated, for example `postconf -P 'submission/inet/milter_mail_macros=i,{auth_type},{auth_authen},...'`.

postwarden reads the login and TLS details once, at `MAIL FROM`, so `{auth_type}` and `{auth_authen}` must be in `milter_mail_macros`; Postfix's default list has them. `python3 /etc/postwarden/scripts/install.py inspect` reports any missing macro or chain, globally or per service. The socket path is relative to Postfix's `queue_directory`, so it works for chrooted and non-chrooted services.

### 6. Verify

- `postconf -n | grep milter` and `postconf -P | grep -e postwarden_ingress -e smtpd_milters` show the values above.
- `python3 /etc/postwarden/scripts/install.py inspect` shows `attached=True` and no findings.
- Send a message through each path (25, 587, 465, `sendmail`). `journalctl -t postwarden` shows one `stage=eom` line per message, with the expected `ingress=` and `trust=`.

### 7. Enforce mode

After reviewing the log, change both the daemon and Postfix:

```sh
sed -i 's/^mode = "observe"/mode = "enforce"/' /etc/postwarden/config.toml
postwarden check-config && systemctl restart postwarden
postconf -e 'postwarden_milter = { unix:postwarden/policy.sock, default_action=tempfail, content_timeout=60s }'
postfix check && postfix reload
```

Both are needed: an enforcing daemon behind `default_action=accept` lets every message through unchecked whenever it is down.

### 8. Manual rollback

```sh
cp -p /root/postfix-before-postwarden/main.cf /root/postfix-before-postwarden/master.cf /etc/postfix/
postfix check && postfix reload
postconf -nx | grep -c 'postwarden/policy.sock'; postconf -Px | grep -c 'postwarden/policy.sock'
systemctl disable --now postwarden
```

Both counts must be `0`. The files under `/etc/postwarden/` can stay.
