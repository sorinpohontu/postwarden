#!/bin/sh
# Restore the Postfix files saved by gate-apply.sh and remove the probe milter.
set -eu

BACKUP=${1:-$(cat /var/backups/postwarden-gate/latest)}
QUEUE_DIR=$(postconf -h queue_directory)
SOCK_DIR=$QUEUE_DIR/postwarden-gate

test -f "$BACKUP/main.cf" && test -f "$BACKUP/master.cf" || { echo "no backup at $BACKUP" >&2; exit 1; }

cp -p "$BACKUP/main.cf" /etc/postfix/main.cf
cp -p "$BACKUP/master.cf" /etc/postfix/master.cf
postfix check
postfix reload
systemctl stop postwarden-gate.service 2>/dev/null || true
systemctl reset-failed postwarden-gate.service 2>/dev/null || true
rm -f "$SOCK_DIR/gate.sock"
echo "restored $BACKUP; probe stopped; captured spool left in $SOCK_DIR/spool (remove manually after review)"
postconf -n | grep -E '^(smtpd_milters|non_smtpd_milters|milter_protocol|milter_macro)'
postconf -M | grep -E 'postwarden-cleanup|^pickup' || true
