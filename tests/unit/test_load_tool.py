import importlib.util
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("milter_load", Path(__file__).resolve().parents[1] / "load" / "milter_load.py")
load = importlib.util.module_from_spec(SPEC)
sys.modules["milter_load"] = load
SPEC.loader.exec_module(load)

NR_HELO = 0x2000
NO_DATA = 0x200


class FakeMilter:
    """Speaks the milter side: records what it receives and answers like postwarden would."""

    def __init__(self, path, protocol, eom_reply=b"y", eom_text=b"550 5.7.26 Message rejected\0", mail_reply=b"c"):
        self.path, self.protocol = path, protocol
        self.eom_reply, self.eom_text, self.mail_reply = eom_reply, eom_text, mail_reply
        self.seen, self.macros = [], {}
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen(8)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        with conn:
            while True:
                try:
                    command, data = load.read_packet(conn)
                except load.ProtocolError:
                    return
                self.seen.append(command)
                if command == b"O":
                    conn.sendall(load.packet(b"O", struct.pack(">III", 6, 0, self.protocol)))
                elif command == b"D":
                    parts = data[1:].split(b"\0")
                    self.macros.update({parts[i].decode(): parts[i + 1].decode() for i in range(0, len(parts) - 1, 2)})
                elif command == b"M":
                    conn.sendall(load.packet(self.mail_reply, b"451 4.7.1 busy\0" if self.mail_reply == b"y" else b""))
                elif command == b"E":
                    conn.sendall(load.packet(b"h", b"X-Test\0x\0"))
                    conn.sendall(load.packet(self.eom_reply, self.eom_text if self.eom_reply == b"y" else b""))
                elif command in (b"A", b"Q"):
                    if command == b"Q":
                        return
                elif command == b"H" and self.protocol & NR_HELO:
                    continue
                else:
                    conn.sendall(load.packet(b"c"))

    def close(self):
        self.server.close()


class LoadTool(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "m.sock")

    def milter(self, **kw):
        fake = FakeMilter(self.path, **kw)
        self.addCleanup(fake.close)
        return fake

    def test_full_transaction_respects_negotiated_flags_and_reads_final_reply(self):
        fake = self.milter(protocol=NR_HELO | NO_DATA)
        result = load.run_message(f"unix:{self.path}", load.Scenario(signatures=3), 7, 5.0, load.body(200_000))
        self.assertEqual((result.reply, result.stage, result.error), ("550 5.7.26", "eom", ""))
        self.assertNotIn(b"T", fake.seen)
        self.assertEqual(fake.seen.count(b"B"), 4)
        self.assertEqual(fake.seen.count(b"L"), 8)
        self.assertEqual(fake.macros["{postwarden_ingress}"], "SMTP25")
        self.assertEqual(fake.macros["{rcpt_mailer}"], "dovecot")
        self.assertEqual(fake.macros["{daemon_addr}"], "198.51.100.25")

    def test_mail_stage_deferral_is_reported(self):
        self.milter(protocol=0, mail_reply=b"y")
        result = load.run_message(f"unix:{self.path}", load.Scenario(), 1, 5.0, b"x")
        self.assertEqual((result.reply, result.stage), ("451 4.7.1", "mail"))
        self.assertEqual(load.hold(f"unix:{self.path}", load.Scenario(), 3, 5.0), {"451 4.7.1": 3})

    def test_connection_failure_is_an_error_not_an_exception(self):
        result = load.run_message(f"unix:{self.path}", load.Scenario(), 1, 1.0, b"x")
        self.assertEqual(result.reply, "error")
        self.assertTrue(result.error)

    def test_connect_packet_encodes_family_and_port(self):
        self.assertEqual(load.connect_data("h", "192.0.2.1", 25), b"h\x004\x00\x19192.0.2.1\x00")
        self.assertTrue(load.connect_data("h", "2001:db8::1", 25).startswith(b"h\x006"))
