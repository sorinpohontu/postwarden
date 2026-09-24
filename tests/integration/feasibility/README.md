# Platform feasibility probe

Probe milter and scripts that prove, on a real Debian Postfix, the three
assumptions the daemon design depends on. Run it on a test host before
supporting a new Debian release or new Postfix, PyMilter or dkimpy versions;
it edits `main.cf`/`master.cf` directly (with its own backup and revert
script) and is not part of the release. Assumptions checked:

- (a) bytes captured through PyMilter callbacks verify with dkimpy under
  `simple/simple`, `relaxed/relaxed` and `relaxed/simple`, including folded
  headers, trailing spaces, duplicate headers and trailing blank lines;
- (b) `{daemon_port}`, `{auth_authen}`, `{auth_type}`, `{cipher_bits}` and the
  `postwarden_ingress` marker arrive on 25-via-postscreen, 587, 465 and pickup;
- (c) a non-SMTP (sendmail/pickup) message rejected at end-of-message bounces
  instead of failing synchronously.

The probe never rejects anything except `GATE_REJECT_RCPT`, and Postfix is
attached with `default_action=accept`, so a probe failure lets mail through.

## Run (root on the test server)

```sh
install -d /opt/postwarden-gate
cp gate_milter.py make_signed_fixture.py gate_lifecycle.py gate-*.sh /opt/postwarden-gate/
cd /opt/postwarden-gate

cp gate-env.example.sh gate-env.sh && chmod 600 gate-env.sh
vi gate-env.sh                                 # host, login, mailboxes
printf '%s' 'the-password' > /root/gate.pass && chmod 600 /root/gate.pass

sh gate-apply.sh     # scripts source ./gate-env.sh themselves     # packages, backup, probe unit, postconf changes, reload
sh gate-run.sh       # T1..T9 and the log excerpt to paste back
sh gate-revert.sh    # restore main.cf/master.cf from the backup, stop the probe
```

`gate-run.sh` passes the password on the swaks command line, which is visible
in the process list on the test server for the duration of each call.

## What to paste back

`gate-apply.sh` and `gate-run.sh` save their complete output under `logs/`
next to the scripts (`/opt/postwarden-gate/logs/`; ignored by git when
copied back into the repository). Share those files. Sanitize real customer addresses; the test addresses above
are expected to appear.

## Reading the result

| Item | Pass evidence |
| --- | --- |
| (a) | `dkim idx=0 d=gate.test result=pass` for T1, T2, T3 and T6; `d=<login domain> result=pass` on the LOCAL_PICKUP copy of T4 |
| (b) | `stage=mail` macros show `{daemon_port}='25'/'587'/'465'`, `{auth_authen}` and `{cipher_bits}` on T2/T3, `{postwarden_ingress}` = `SMTP25` / `SUBMISSION587` / `SUBMISSION465` / `LOCAL_PICKUP` |
| (c) | T5: `550 5.7.1` at RCPT; T7: `sendmail exit=0`, then a bounce in the Postfix log; T8: ordinary recipient outcome recorded separately |
| Lifecycle | T9: three `stage=mail` entries on one `cid`, `550` for the reject RCPT, `stage=abort` after RSET, T9b carries no recipient from the aborted transaction |
| Socket | the relative `unix:postwarden-gate/gate.sock` path works from non-chrooted `smtpd/pass` and chrooted submission/cleanup |

Record results outside the repository, without credentials or message bodies.

## Status

Debian 13 run on 2026-09-22 passed (a), (b) and (c); see the local acceptance record. Lifecycle case T9 passed on rerun with `gate_lifecycle.py`. Debian 12 is pending.
