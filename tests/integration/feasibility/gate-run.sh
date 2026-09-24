#!/bin/sh
# Drive the gate transactions and print the probe's log lines. Run on the test server after gate-apply.sh.
set -u

ENV_FILE=$(dirname "$0")/gate-env.sh
test -f "$ENV_FILE" && . "$ENV_FILE"

LOG_DIR=$(cd "$(dirname "$0")" && pwd)/logs
if [ -z "${GATE_LOGGING:-}" ]; then
  mkdir -p "$LOG_DIR"
  LOG_FILE=$LOG_DIR/$(basename "$0" .sh)-$(date +%Y%m%dT%H%M%S).log
  echo "output saved to $LOG_FILE"
  GATE_LOGGING=1 sh "$0" "$@" 2>&1 | tee "$LOG_FILE"
  exit
fi

GATE_DIR=${GATE_DIR:-/opt/postwarden-gate}
GATE_HOST=${GATE_HOST:?server name matching the TLS certificate}
GATE_LOGIN=${GATE_LOGIN:?SASL login (also used as envelope sender)}
GATE_PASSFILE=${GATE_PASSFILE:?file containing the SASL password}
GATE_RCPT=${GATE_RCPT:?ordinary test mailbox}
GATE_REJECT_RCPT=${GATE_REJECT_RCPT:?address the gate rejects}
F=$GATE_DIR/fixtures
PW=$(cat "$GATE_PASSFILE")
START=$(date '+%Y-%m-%d %H:%M:%S')

step() { echo; echo "#### $1"; }

step "T1 port 25 via postscreen, localhost (mynetworks), simple/simple fixture"
swaks --server 127.0.0.1:25 --from "$GATE_LOGIN" --to "$GATE_RCPT" --data "@$F/signed-simple-simple.eml"

step "T2 port 587 STARTTLS + AUTH, relaxed/relaxed fixture"
swaks --server "$GATE_HOST:587" --tls --auth PLAIN --auth-user "$GATE_LOGIN" --auth-password "$PW" \
  --from "$GATE_LOGIN" --to "$GATE_RCPT" --data "@$F/signed-relaxed-relaxed.eml"

step "T3 port 465 implicit TLS + AUTH, relaxed/simple fixture"
swaks --server "$GATE_HOST:465" --tlsc --auth PLAIN --auth-user "$GATE_LOGIN" --auth-password "$PW" \
  --from "$GATE_LOGIN" --to "$GATE_RCPT" --data "@$F/signed-relaxed-simple.eml"

step "T4 port 587 unsigned mail from the login domain (OpenDKIM signs; reinjected copy verified via live DNS)"
swaks --server "$GATE_HOST:587" --tls --auth PLAIN --auth-user "$GATE_LOGIN" --auth-password "$PW" \
  --from "$GATE_LOGIN" --to "$GATE_RCPT" --header "Subject: gate T4 opendkim" --body "gate T4"

step "T5 port 587 to the reject address (expect 550 at RCPT)"
swaks --server "$GATE_HOST:587" --tls --auth PLAIN --auth-user "$GATE_LOGIN" --auth-password "$PW" \
  --from "$GATE_LOGIN" --to "$GATE_REJECT_RCPT" --header "Subject: gate T5 reject" --body "gate T5"

step "T6 local sendmail, single ordinary recipient"
/usr/sbin/sendmail -f "$GATE_LOGIN" "$GATE_RCPT" < "$F/signed-simple-simple.eml"; echo "sendmail exit=$?"

step "T7 local sendmail to the reject address (expect EOM reject -> bounce, not synchronous error)"
printf 'From: %s\nTo: %s\nSubject: gate T7 local reject\n\ngate T7\n' "$GATE_LOGIN" "$GATE_REJECT_RCPT" \
  | /usr/sbin/sendmail -f "$GATE_LOGIN" "$GATE_REJECT_RCPT"; echo "sendmail exit=$?"

step "T8 local sendmail, ordinary + reject recipient in one message"
printf 'From: %s\nTo: %s, %s\nSubject: gate T8 local mixed\n\ngate T8\n' "$GATE_LOGIN" "$GATE_RCPT" "$GATE_REJECT_RCPT" \
  | /usr/sbin/sendmail -f "$GATE_LOGIN" "$GATE_RCPT" "$GATE_REJECT_RCPT"; echo "sendmail exit=$?"

step "T9 port 25, two messages in one connection, rejected RCPT and RSET between them"
python3 "$GATE_DIR/gate_lifecycle.py"

sleep 8
step "probe log since $START"
journalctl -t postwarden-gate --since "$START" --no-pager -o cat 2>/dev/null \
  || grep 'postwarden-gate' /var/log/mail.log
step "postfix log since $START (milter, bounce, reject, opendkim)"
journalctl -u postfix@- --since "$START" --no-pager -o cat 2>/dev/null | grep -Ei 'milter|bounce|reject|opendkim|status=' \
  || grep -Ei 'milter|bounce|reject|opendkim|status=' /var/log/mail.log | tail -60
step "captured spool"
ls -l "$(postconf -h queue_directory)/postwarden-gate/spool"
