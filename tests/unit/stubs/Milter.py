"""Minimal stand-in for the PyMilter module so callback code can be exercised without libmilter."""

CONTINUE, REJECT, DISCARD, ACCEPT, TEMPFAIL = 0, 1, 2, 3, 4
P_HDR_LEADSPC = 0x100000
factory = None


class Base:
    macros: dict
    replies: list

    def negotiate(self, opts):
        opts[1] = opts[1] & 0x7ff
        return CONTINUE

    def getsymval(self, name):
        return self.__dict__.setdefault("macros", {}).get(name)

    def setreply(self, code, xcode, message):
        self.__dict__.setdefault("replies", []).append((code, xcode, message))


def set_flags(flags):
    pass


def set_exception_policy(code):
    pass


def runmilter(name, socket, timeout=0):
    raise RuntimeError("stub")
