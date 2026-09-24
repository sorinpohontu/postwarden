# Copy to gate-env.sh on the test server, edit, then run the gate-*.sh scripts (they source it).
# gate-env.sh is ignored by git; keep it and the password file root-only.

GATE_DIR=/opt/postwarden-gate
GATE_HOST=mail.example.test            # name on the TLS certificate
GATE_LOGIN=gate@example.test           # existing SASL login, used as envelope sender
GATE_RCPT=gate-inbox@example.test      # ordinary test mailbox
GATE_REJECT_RCPT=gate-reject@example.test   # any address in a hosted domain; the probe rejects it
GATE_PASSFILE=/root/gate.pass          # file containing only the SASL password (chmod 600)

export GATE_DIR GATE_HOST GATE_LOGIN GATE_RCPT GATE_REJECT_RCPT GATE_PASSFILE
