"""DKIM verification of one large message in a child process under a hard address-space limit.

Reads a JSON request on stdin, the body from an inherited descriptor, and writes the outcomes as JSON."""
from __future__ import annotations

import base64
import json
import os
import resource
import sys
import time


def main() -> int:
    request = json.loads(sys.stdin.buffer.read())
    resource.setrlimit(resource.RLIMIT_AS, (request["memory"], request["memory"]))
    try:
        from .authentication import dkim_verify
        from .config import LimitSettings
        limits = LimitSettings(dns_timeout_seconds=request["dns_timeout_seconds"],
                               max_signatures=request["max_signatures"])
        message = base64.b64decode(request["header"]) + os.pread(request["fd"], request["body_bytes"], 0)
        signatures = [base64.b64decode(raw) for raw in request["signatures"]]
        outcomes, incomplete = dkim_verify(message, signatures, limits, time.monotonic() + request["deadline_in"])
        reply = {"outcomes": [[o.status.value, o.domain, o.partial_body, o.detail, o.result] for o in outcomes],
                 "incomplete": incomplete}
    except MemoryError:
        reply = {"memory": True}
    sys.stdout.write(json.dumps(reply))
    return 0


if __name__ == "__main__":
    sys.exit(main())
