#!/bin/sh
# Attach the feasibility-gate milter to the running Postfix (default_action=accept).
# Reversible with gate-revert.sh. Run as root on the test server.
set -eu

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
GATE_REJECT_RCPT=${GATE_REJECT_RCPT:?set GATE_REJECT_RCPT to the test address the gate may reject}
GATE_RCPT=${GATE_RCPT:?set GATE_RCPT to an ordinary test mailbox}
QUEUE_DIR=$(postconf -h queue_directory)
SOCK_DIR=$QUEUE_DIR/postwarden-gate
BACKUP=/var/backups/postwarden-gate/$(date +%Y%m%dT%H%M%S)
OPENDKIM=$(postconf -h smtpd_milters)

echo "== packages"
apt-get install -y --no-install-recommends python3-milter python3-dkim python3-spf python3-dnspython swaks libnet-ssleay-perl libauthen-sasl-perl
dpkg-query -W -f='${Package} ${Version}\n' postfix python3 python3-milter python3-dkim python3-spf python3-dnspython opendkim swaks

echo "== backup to $BACKUP"
mkdir -p "$BACKUP"
cp -p /etc/postfix/main.cf /etc/postfix/master.cf "$BACKUP/"
postconf -n > "$BACKUP/postconf-n.txt"
postconf -M > "$BACKUP/postconf-M.txt"
postconf -P > "$BACKUP/postconf-P.txt"
echo "$OPENDKIM" > "$BACKUP/smtpd_milters.txt"
echo "$BACKUP" > /var/backups/postwarden-gate/latest

echo "== socket directory and fixtures"
install -d -o postfix -g postfix -m 0750 "$SOCK_DIR"
install -d -o postfix -g postfix -m 0700 "$SOCK_DIR/spool"
install -d -m 0755 "$GATE_DIR/fixtures"
python3 "$GATE_DIR/make_signed_fixture.py" --out "$GATE_DIR/fixtures" --rcpt "$GATE_RCPT"
chmod 0644 "$GATE_DIR/fixtures/gate.txt"

echo "== start probe milter"
systemctl stop postwarden-gate.service 2>/dev/null || true
rm -f "$SOCK_DIR/gate.sock"
systemd-run --unit=postwarden-gate --uid=postfix --gid=postfix \
  -p Environment=GATE_SOCKET="$SOCK_DIR/gate.sock" \
  -p Environment=GATE_SPOOL="$SOCK_DIR/spool" \
  -p Environment=GATE_REJECT_RCPT="$GATE_REJECT_RCPT" \
  -p Environment=GATE_DKIM_PUBKEY="$GATE_DIR/fixtures/gate.txt" \
  /usr/bin/python3 "$GATE_DIR/gate_milter.py"
sleep 2
ls -l "$SOCK_DIR"
if ! systemctl is-active --quiet postwarden-gate.service || ! test -S "$SOCK_DIR/gate.sock"; then
  echo "probe milter failed to start; Postfix left unchanged" >&2
  journalctl -u postwarden-gate.service --no-pager -o cat | tail -30 >&2
  exit 1
fi

echo "== postfix main.cf"
GATE="{ unix:postwarden-gate/gate.sock, default_action=accept, content_timeout=60s }"
case "$OPENDKIM" in
  *postwarden-gate*) echo "gate already present in smtpd_milters; leaving main.cf as is"; SKIP_MAIN=1 ;;
  *) SKIP_MAIN=0 ;;
esac
if [ "$SKIP_MAIN" = 0 ]; then
postconf -e "milter_protocol=6"
postconf -e "smtpd_milters=$GATE, $OPENDKIM"
postconf -e "non_smtpd_milters=\$smtpd_milters"
postconf -e "milter_macro_defaults=postwarden_ingress=UNCLASSIFIED"
postconf -e "milter_connect_macros=$(postconf -h milter_connect_macros) {daemon_port} {client_port} {if_name} {if_addr} {client_connections} {postwarden_ingress}"
postconf -e "milter_helo_macros=$(postconf -h milter_helo_macros) {daemon_port} {postwarden_ingress}"
postconf -e "milter_mail_macros=$(postconf -h milter_mail_macros) {daemon_port} {cipher_bits} {tls_version} {postwarden_ingress}"
postconf -e "milter_rcpt_macros=$(postconf -h milter_rcpt_macros) {daemon_port} {auth_type} {auth_authen} {postwarden_ingress}"
postconf -e "milter_end_of_header_macros=$(postconf -h milter_end_of_header_macros) {daemon_port} {auth_type} {auth_authen} {postwarden_ingress}"
postconf -e "milter_end_of_data_macros=$(postconf -h milter_end_of_data_macros) {daemon_port} {auth_type} {auth_authen} {postwarden_ingress}"
fi

echo "== postfix master.cf"
postconf -P "smtpd/pass/milter_macro_defaults=postwarden_ingress=SMTP25"
postconf -P "submission/inet/milter_macro_defaults=postwarden_ingress=SUBMISSION587"
postconf -P "smtps/inet/milter_macro_defaults=postwarden_ingress=SUBMISSION465"
postconf -M "postwarden-cleanup/unix=postwarden-cleanup unix n - y - 0 cleanup"
postconf -P "postwarden-cleanup/unix/milter_macro_defaults=postwarden_ingress=LOCAL_PICKUP"
postconf -P "pickup/unix/cleanup_service_name=postwarden-cleanup"

echo "== validate and reload"
postfix check
diff -u "$BACKUP/main.cf" /etc/postfix/main.cf || true
diff -u "$BACKUP/master.cf" /etc/postfix/master.cf || true
postfix reload
echo "gate applied; backup: $BACKUP"
