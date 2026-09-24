#!/usr/bin/python3
"""Feasibility-gate probe milter. Logs macros, captures raw bytes, verifies DKIM.

Not the product daemon. Rejects only the address in GATE_REJECT_RCPT.
"""
import logging
import logging.handlers
import os
import sys
import time
import uuid

import Milter

import dkim
import dkim.dnsplug

SOCKET = os.environ.get("GATE_SOCKET", "/var/spool/postfix/postwarden-gate/gate.sock")
SPOOL = os.environ.get("GATE_SPOOL", "/var/spool/postfix/postwarden-gate/spool")
REJECT_RCPT = os.environ.get("GATE_REJECT_RCPT", "").lower()
FIXTURE_DOMAIN = os.environ.get("GATE_DKIM_DOMAIN", "gate.test")
FIXTURE_SELECTOR = os.environ.get("GATE_DKIM_SELECTOR", "gate")
FIXTURE_PUBKEY_FILE = os.environ.get("GATE_DKIM_PUBKEY", "")

P_HDR_LEADSPC = getattr(Milter, "P_HDR_LEADSPC", 0x100000)

MACROS = [
    "j", "v", "_", "i", "{daemon_name}", "{daemon_addr}", "{daemon_port}",
    "{if_name}", "{if_addr}", "{client_addr}", "{client_port}", "{client_name}",
    "{client_connections}", "{auth_type}", "{auth_authen}", "{auth_author}",
    "{mail_addr}", "{mail_host}", "{mail_mailer}", "{rcpt_addr}", "{rcpt_host}",
    "{rcpt_mailer}", "{tls_version}", "{cipher}", "{cipher_bits}",
    "{cert_subject}", "{cert_issuer}", "{postwarden_ingress}",
]

log = logging.getLogger("postwarden-gate")


def setup_logging():
    handler = logging.handlers.SysLogHandler(
        address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_MAIL)
    handler.setFormatter(logging.Formatter("postwarden-gate[%(process)d]: %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)


def load_fixture_txt():
    if not FIXTURE_PUBKEY_FILE:
        return None
    with open(FIXTURE_PUBKEY_FILE, "rb") as fh:
        return fh.read().strip()


FIXTURE_TXT = None


def gate_dnsfunc(name, timeout=5):
    if isinstance(name, bytes):
        name_s = name.decode("ascii", "replace")
    else:
        name_s = name
    fixture_name = f"{FIXTURE_SELECTOR}._domainkey.{FIXTURE_DOMAIN}"
    if name_s.rstrip(".").lower() == fixture_name and FIXTURE_TXT:
        log.info("dns=fixture name=%s", name_s)
        return FIXTURE_TXT
    log.info("dns=live name=%s", name_s)
    return dkim.dnsplug.get_txt(name, timeout)


def to_bytes(value):
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", "surrogateescape")


class GateMilter(Milter.Base):
    def __init__(self):
        self.cid = uuid.uuid4().hex[:12]
        self.leadspc = False
        self.reset_message()

    def reset_message(self):
        self.mid = None
        self.headers = []
        self.body_chunks = []
        self.rcpts = []
        self.pending_reject = False
        self.started = None

    def macros(self, stage):
        pairs = []
        for name in MACROS:
            value = self.getsymval(name)
            if value is not None:
                pairs.append(f"{name}={value!r}")
        log.info("cid=%s mid=%s stage=%s macros: %s", self.cid, self.mid, stage, " ".join(pairs))

    def negotiate(self, opts):
        offered = opts[1]
        rc = super().negotiate(opts)
        self.leadspc = bool(offered & P_HDR_LEADSPC)
        if self.leadspc:
            opts[1] |= P_HDR_LEADSPC
        log.info("cid=%s stage=negotiate actions=%#x protocol_offered=%#x protocol_used=%#x leadspc=%s",
                 self.cid, opts[0], offered, opts[1], self.leadspc)
        return rc

    def connect(self, hostname, family, hostaddr):
        log.info("cid=%s stage=connect host=%r family=%r addr=%r", self.cid, hostname, family, hostaddr)
        self.macros("connect")
        return Milter.CONTINUE

    def hello(self, hostname):
        log.info("cid=%s stage=helo helo=%r", self.cid, hostname)
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *args):
        self.reset_message()
        self.mid = uuid.uuid4().hex[:12]
        self.started = time.monotonic()
        log.info("cid=%s mid=%s stage=mail from=%r args=%r", self.cid, self.mid, mailfrom, args)
        self.macros("mail")
        return Milter.CONTINUE

    def envrcpt(self, to, *args):
        addr = to.strip("<>").lower()
        self.rcpts.append(addr)
        ingress = self.getsymval("{postwarden_ingress}")
        log.info("cid=%s mid=%s stage=rcpt to=%r ingress=%s", self.cid, self.mid, to, ingress)
        self.macros("rcpt")
        if REJECT_RCPT and addr == REJECT_RCPT:
            if ingress == "LOCAL_PICKUP":
                self.pending_reject = True
                log.info("cid=%s mid=%s rule=gate_reject action=deferred_to_eom", self.cid, self.mid)
            else:
                log.info("cid=%s mid=%s rule=gate_reject action=reject_at_rcpt", self.cid, self.mid)
                self.setreply("550", "5.7.1", "gate: recipient rejected at RCPT")
                return Milter.REJECT
        return Milter.CONTINUE

    def header(self, name, hval):
        if len(self.headers) < 3:
            log.info("cid=%s mid=%s stage=header name=%r hval=%r", self.cid, self.mid, name, hval)
        self.headers.append((to_bytes(name), to_bytes(hval)))
        return Milter.CONTINUE

    def eoh(self):
        self.macros("eoh")
        return Milter.CONTINUE

    def body(self, chunk):
        self.body_chunks.append(chunk)
        return Milter.CONTINUE

    def reconstruct(self):
        sep = b":" if self.leadspc else b": "
        lines = []
        for name, hval in self.headers:
            hval = hval.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            lines.append(name + sep + hval + b"\r\n")
        body = b"".join(self.body_chunks)
        return b"".join(lines) + b"\r\n" + body

    def verify_all(self, message):
        sig_count = sum(1 for n, _ in self.headers if n.lower() == b"dkim-signature")
        results = []
        for idx in range(sig_count):
            verifier = dkim.DKIM(message)
            try:
                ok = verifier.verify(idx=idx, dnsfunc=gate_dnsfunc)
                results.append((idx, verifier.domain, "pass" if ok else "fail", ""))
            except Exception as exc:  # evidence: which exception class the library raises
                results.append((idx, getattr(verifier, "domain", None), "error",
                                f"{type(exc).__module__}.{type(exc).__name__}: {exc}"))
        return sig_count, results

    def eom(self):
        self.macros("eom")
        message = self.reconstruct()
        os.makedirs(SPOOL, exist_ok=True)
        path = os.path.join(SPOOL, f"{self.mid}.eml")
        with open(path, "wb") as fh:
            fh.write(message)
        queue_id = self.getsymval("i")
        sig_count, results = self.verify_all(message)
        elapsed = time.monotonic() - (self.started or time.monotonic())
        log.info("cid=%s mid=%s queue_id=%s stage=eom bytes=%d headers=%d signatures=%d spool=%s elapsed=%.3f",
                 self.cid, self.mid, queue_id, len(message), len(self.headers), sig_count, path, elapsed)
        for idx, domain, result, detail in results:
            log.info("cid=%s mid=%s queue_id=%s dkim idx=%d d=%s result=%s %s",
                     self.cid, self.mid, queue_id, idx, domain, result, detail)
        if self.pending_reject:
            log.info("cid=%s mid=%s queue_id=%s rule=gate_reject action=reject_at_eom", self.cid, self.mid, queue_id)
            self.setreply("550", "5.7.1", "gate: recipient rejected at end of message")
            return Milter.REJECT
        return Milter.ACCEPT

    def abort(self):
        log.info("cid=%s mid=%s stage=abort", self.cid, self.mid)
        self.reset_message()
        return Milter.CONTINUE

    def close(self):
        log.info("cid=%s stage=close", self.cid)
        return Milter.CONTINUE


def main():
    global FIXTURE_TXT
    setup_logging()
    FIXTURE_TXT = load_fixture_txt()
    os.makedirs(SPOOL, mode=0o700, exist_ok=True)
    os.umask(0o007)
    log.info("starting socket=%s reject_rcpt=%r fixture=%s pymilter=%s dkim=%s python=%s",
             SOCKET, REJECT_RCPT, bool(FIXTURE_TXT),
             getattr(Milter, "__version__", "?"), getattr(dkim, "__version__", "?"), sys.version.split()[0])
    Milter.factory = GateMilter
    Milter.set_flags(0)
    Milter.runmilter("postwarden-gate", "unix:" + SOCKET, 60)
    log.info("stopped")


if __name__ == "__main__":
    main()
