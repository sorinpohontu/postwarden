#!/usr/bin/python3
"""Generate a throwaway DKIM key and sign a fixture message under both canonicalizations."""
import argparse
import base64
import os
import subprocess
import time

import dkim

MESSAGE = b"""From: Gate Test <gate@{domain}>
To: {rcpt}
Subject: feasibility gate {canon}
  folded continuation
Message-ID: <{msgid}@{domain}>
Date: {date}
X-Gate-Trailing-Space: value with trailing spaces
X-Gate-Dup: one
X-Gate-Dup: two

Line one.
   Indented line with   internal   spacing.

Trailing blank lines follow.


"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--domain", default="gate.test")
    parser.add_argument("--selector", default="gate")
    parser.add_argument("--rcpt", required=True)
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    key = os.path.join(args.out, "gate.key")
    if not os.path.exists(key):
        subprocess.run(["openssl", "genrsa", "-out", key, "2048"], check=True,
                       stderr=subprocess.DEVNULL)
    pub = subprocess.run(["openssl", "rsa", "-in", key, "-pubout", "-outform", "DER"],
                         check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    txt = b"v=DKIM1; k=rsa; p=" + base64.b64encode(pub)
    with open(os.path.join(args.out, "gate.txt"), "wb") as fh:
        fh.write(txt + b"\n")
    with open(key, "rb") as fh:
        privkey = fh.read()

    date = time.strftime("%a, %d %b %Y %H:%M:%S %z").encode()
    for canon in (b"simple/simple", b"relaxed/relaxed", b"relaxed/simple"):
        msgid = f"{int(time.time())}.{canon.decode().replace('/', '-')}".encode()
        body = MESSAGE.replace(b"{domain}", args.domain.encode()) \
            .replace(b"{rcpt}", args.rcpt.encode()) \
            .replace(b"{canon}", canon).replace(b"{msgid}", msgid) \
            .replace(b"{date}", date).replace(b"\n", b"\r\n")
        sig = dkim.sign(body, args.selector.encode(), args.domain.encode(), privkey,
                        canonicalize=tuple(canon.split(b"/")),
                        include_headers=[b"from", b"to", b"subject", b"message-id", b"date",
                                         b"x-gate-trailing-space", b"x-gate-dup", b"x-gate-dup"])
        signed = sig + body
        name = os.path.join(args.out, f"signed-{canon.decode().replace('/', '-')}.eml")
        with open(name, "wb") as fh:
            fh.write(signed)
        with open(os.path.join(args.out, "gate.txt"), "rb") as fh:
            pubtxt = fh.read().strip()
        ok = dkim.verify(signed, dnsfunc=lambda n, timeout=5: pubtxt)
        print(f"{name}: local verify={'pass' if ok else 'FAIL'}")


if __name__ == "__main__":
    main()
