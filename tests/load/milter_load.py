#!/usr/bin/env python3
"""Load and capacity tool: drives a postwarden socket with the milter protocol, as Postfix would.

Messages are presented as untrusted port-25 mail, so every one takes the SPF/DKIM path. Nothing is
queued or delivered; only the milter sees the messages. Standard library only.
"""
from __future__ import annotations

import argparse
import base64
import os
import socket
import statistics
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

VERSION = 6
ALL_ACTIONS = 0x1FF
ALL_PROTOCOL = 0x1FFFFF
HDR_LEADSPC = 0x100000
CHUNK = 65535

# command -> (flag meaning "do not send", flag meaning "no reply expected")
FLAGS = {
    b"C": (0x1, 0x1000), b"H": (0x2, 0x2000), b"M": (0x4, 0x4000), b"R": (0x8, 0x8000),
    b"B": (0x10, 0x80000), b"L": (0x20, 0x80), b"N": (0x40, 0x40000), b"T": (0x200, 0x10000),
}
FINAL = {b"c": "continue", b"a": "accept", b"r": "reject", b"t": "tempfail", b"d": "discard", b"s": "skip"}


class ProtocolError(Exception):
    pass


def packet(command: bytes, data: bytes = b"") -> bytes:
    return struct.pack(">I", len(data) + 1) + command + data


def macros(stage: bytes, values: dict[str, str]) -> bytes:
    return packet(b"D", stage + b"".join(k.encode() + b"\0" + v.encode() + b"\0" for k, v in values.items()))


def connect_data(hostname: str, address: str, port: int) -> bytes:
    family = b"6" if ":" in address else b"4"
    return hostname.encode() + b"\0" + family + struct.pack(">H", port) + address.encode() + b"\0"


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProtocolError("milter closed the connection")
        data += chunk
    return data


def read_packet(sock: socket.socket) -> tuple[bytes, bytes]:
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    body = recv_exact(sock, length)
    return body[:1], body[1:]


def describe_reply(command: bytes, data: bytes) -> str:
    if command == b"y":
        return " ".join(data.rstrip(b"\0").decode(errors="replace").split()[:2])
    return FINAL.get(command, f"unknown:{command!r}")


def connect_socket(spec: str, timeout: float) -> socket.socket:
    kind, _, rest = spec.partition(":")
    if kind == "unix":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        target: object = rest
    else:
        port, _, host = rest.partition("@")
        family = socket.AF_INET6 if kind == "inet6" else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        target = (host or ("::1" if kind == "inet6" else "127.0.0.1"), int(port))
    sock.settimeout(timeout)
    try:
        sock.connect(target)
    except OSError:
        sock.close()
        raise
    return sock


class Session:
    def __init__(self, spec: str, timeout: float):
        self.sock = connect_socket(spec, timeout)
        try:
            self.sock.sendall(packet(b"O", struct.pack(">III", VERSION, ALL_ACTIONS, ALL_PROTOCOL)))
            command, data = read_packet(self.sock)
            if command != b"O" or len(data) < 12:
                raise ProtocolError(f"unexpected negotiation reply {command!r}")
        except (OSError, ProtocolError):
            self.sock.close()
            raise
        _, self.actions, self.protocol = struct.unpack(">III", data[:12])

    def send(self, command: bytes, data: bytes = b"", stage_macros: dict[str, str] | None = None) -> tuple[bytes, bytes]:
        skip, no_reply = FLAGS.get(command, (0, 0))
        if self.protocol & skip:
            return b"c", b""
        if stage_macros:
            self.sock.sendall(macros(command, stage_macros))
        self.sock.sendall(packet(command, data))
        if self.protocol & no_reply:
            return b"c", b""
        while True:
            reply, payload = read_packet(self.sock)
            if reply in FINAL or reply == b"y":
                return reply, payload

    def header(self, name: str, value: str) -> tuple[bytes, bytes]:
        lead = " " if self.protocol & HDR_LEADSPC else ""
        return self.send(b"L", name.encode() + b"\0" + (lead + value).encode() + b"\0")

    def close(self, abort: bool = False) -> None:
        try:
            if abort:
                self.sock.sendall(packet(b"A"))
            self.sock.sendall(packet(b"Q"))
        except OSError:
            pass
        self.sock.close()


@dataclass
class Scenario:
    sender: str = "postwarden-load@gmail.com"
    recipient: str = "load-test@example.net"
    dkim_domain: str = "gmail.com"
    selector: str = "20230601"
    signatures: int = 1
    body_bytes: int = 65536
    peer_prefix: str = "192.0.2."
    daemon_addr: str = "198.51.100.25"
    transport: str = "dovecot"


@dataclass
class Result:
    reply: str
    stage: str
    elapsed: float
    error: str = ""


def dkim_headers(scenario: Scenario, index: int) -> list[str]:
    headers = []
    for n in range(scenario.signatures):
        canon = ("relaxed/relaxed", "simple/simple", "relaxed/simple", "simple/relaxed")[n % 4]
        bh = base64.b64encode(os.urandom(32)).decode()
        b = base64.b64encode(os.urandom(256)).decode()
        headers.append(f"v=1; a=rsa-sha256; c={canon}; d={scenario.dkim_domain}; s={scenario.selector}; "
                       f"t={int(time.time())}; h=from:to:subject:date:message-id; bh={bh}; b={b}")
    return headers


def body(size: int) -> bytes:
    line = b"postwarden load test line: the quick brown fox jumps over the lazy dog 0123456789\r\n"
    return (line * (size // len(line) + 1))[:size]


def run_message(spec: str, scenario: Scenario, index: int, timeout: float, payload: bytes) -> Result:
    started = time.monotonic()
    peer = f"{scenario.peer_prefix}{index % 250 + 1}"
    stage = "connect"
    try:
        session = Session(spec, timeout)
        try:
            steps = [
                ("connect", b"C", connect_data(f"load{index}.example", peer, 40000 + index % 20000),
                 {"j": "mx.example", "{daemon_name}": "smtpd", "{daemon_addr}": scenario.daemon_addr, "{daemon_port}": "25",
                  "{client_port}": str(40000 + index % 20000), "{postwarden_ingress}": "SMTP25"}),
                ("helo", b"H", f"load{index}.example\0".encode(), None),
                ("mail", b"M", f"<{scenario.sender}>\0".encode(),
                 {"i": f"LOAD{index:08X}", "{daemon_port}": "25", "{postwarden_ingress}": "SMTP25", "{tls_version}": "TLSv1.3",
                  "{cipher_bits}": "256"}),
                ("rcpt", b"R", f"<{scenario.recipient}>\0".encode(), {"{rcpt_mailer}": scenario.transport}),
                ("data", b"T", b"", None),
            ]
            for stage, command, data, stage_macros in steps:
                reply, reply_data = session.send(command, data, stage_macros)
                if reply != b"c":
                    return Result(describe_reply(reply, reply_data), stage, time.monotonic() - started)
            stage = "headers"
            for value in dkim_headers(scenario, index):
                session.header("DKIM-Signature", value)
            for name, value in (("From", f"<{scenario.sender}>"), ("To", f"<{scenario.recipient}>"),
                                ("Subject", f"postwarden load {index}"), ("Date", time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())),
                                ("Message-ID", f"<load{index}.{time.time_ns()}@{scenario.sender.split('@')[1]}>")):
                reply, reply_data = session.header(name, value)
                if reply != b"c":
                    return Result(describe_reply(reply, reply_data), stage, time.monotonic() - started)
            stage = "eoh"
            reply, reply_data = session.send(b"N")
            if reply != b"c":
                return Result(describe_reply(reply, reply_data), stage, time.monotonic() - started)
            stage = "body"
            for offset in range(0, len(payload), CHUNK):
                reply, reply_data = session.send(b"B", payload[offset:offset + CHUNK])
                if reply != b"c":
                    return Result(describe_reply(reply, reply_data), stage, time.monotonic() - started)
            stage = "eom"
            reply, reply_data = session.send(b"E", b"", {"i": f"LOAD{index:08X}"})
            return Result(describe_reply(reply, reply_data), stage, time.monotonic() - started)
        finally:
            session.close()
    except (OSError, ProtocolError) as exc:
        return Result("error", stage, time.monotonic() - started, f"{type(exc).__name__}: {exc}")


def hold(spec: str, scenario: Scenario, count: int, timeout: float) -> dict[str, int]:
    """Open `count` transactions up to MAIL FROM and keep them open; count the MAIL replies."""
    sessions, replies = [], {}
    try:
        for index in range(count):
            session = Session(spec, timeout)
            sessions.append(session)
            session.send(b"C", connect_data(f"hold{index}.example", f"{scenario.peer_prefix}{index % 250 + 1}", 40000),
                         {"{daemon_addr}": scenario.daemon_addr, "{daemon_port}": "25", "{postwarden_ingress}": "SMTP25"})
            reply, data = session.send(b"M", f"<{scenario.sender}>\0".encode(),
                                       {"{daemon_port}": "25", "{postwarden_ingress}": "SMTP25"})
            key = describe_reply(reply, data)
            replies[key] = replies.get(key, 0) + 1
    finally:
        for session in sessions:
            session.close(abort=True)
    return replies


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--socket", required=True, help="milter socket, e.g. unix:/tmp/pwload/policy.sock")
    parser.add_argument("--messages", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--signatures", type=int, default=1, help="DKIM-Signature headers per message")
    parser.add_argument("--body-kib", type=int, default=64)
    parser.add_argument("--sender", default=Scenario.sender)
    parser.add_argument("--recipient", default=Scenario.recipient)
    parser.add_argument("--dkim-domain", default=Scenario.dkim_domain)
    parser.add_argument("--selector", default=Scenario.selector)
    parser.add_argument("--timeout", type=float, default=120.0, help="seconds per socket operation")
    parser.add_argument("--slow-after", type=float, default=60.0, help="report messages slower than this (Postfix content_timeout)")
    parser.add_argument("--hold", type=int, help="instead: open this many transactions at MAIL FROM and count the replies")
    args = parser.parse_args(argv)
    scenario = Scenario(sender=args.sender, recipient=args.recipient, dkim_domain=args.dkim_domain, selector=args.selector,
                        signatures=args.signatures, body_bytes=args.body_kib * 1024)

    if args.hold:
        first = hold(args.socket, scenario, args.hold, args.timeout)
        print(f"hold {args.hold}: " + ", ".join(f"{k}={v}" for k, v in sorted(first.items())))
        after = hold(args.socket, scenario, 1, args.timeout)
        print("after release: " + ", ".join(f"{k}={v}" for k, v in sorted(after.items())))
        return 0

    payload = body(scenario.body_bytes)
    started = time.monotonic()
    lock, results = threading.Lock(), []

    def one(index: int) -> None:
        result = run_message(args.socket, scenario, index, args.timeout, payload)
        with lock:
            results.append(result)

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        list(pool.map(one, range(args.messages)))
    wall = time.monotonic() - started

    counts: dict[str, int] = {}
    for result in results:
        key = f"{result.reply} at {result.stage}"
        counts[key] = counts.get(key, 0) + 1
    elapsed = [r.elapsed for r in results]
    print(f"messages {len(results)}, concurrency {args.concurrency}, signatures {args.signatures}, body {args.body_kib} KiB")
    print(f"wall {wall:.1f}s, {len(results) / wall:.1f} msg/s")
    print(f"latency p50 {statistics.median(elapsed):.2f}s p90 {percentile(elapsed, 0.9):.2f}s "
          f"p99 {percentile(elapsed, 0.99):.2f}s max {max(elapsed):.2f}s")
    for key, value in sorted(counts.items(), key=lambda item: -item[1]):
        print(f"  {value:6d}  {key}")
    slow = [r for r in results if r.elapsed > args.slow_after]
    if slow:
        print(f"  {len(slow)} message(s) slower than {args.slow_after:g}s")
    for result in [r for r in results if r.error][:5]:
        print(f"  error at {result.stage}: {result.error}")
    return 0 if not slow and not any(r.error for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
