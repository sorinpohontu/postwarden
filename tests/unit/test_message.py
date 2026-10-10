import unittest

from postwarden.config import LimitSettings
from postwarden.message import MessageCapture


class HeaderCapture(unittest.TestCase):
    def capture(self, **limits):
        c = MessageCapture(LimitSettings(**limits), None, False)
        self.addCleanup(c.close)
        return c

    def test_header_count_limit_stops_retention(self):
        c = self.capture(max_headers=2)
        for i in range(100):
            c.add_header(b"X-H", b"v%d" % i)
        self.assertEqual((len(c.headers), c.over_limit), (2, "max_headers"))

    def test_header_byte_limit_stops_retention(self):
        c = self.capture(max_header_bytes=20)
        for _ in range(100):
            c.add_header(b"X-Header", b"0123456789" * 10)
        self.assertEqual((c.headers, c.over_limit), ([], "max_header_bytes"))
        self.assertLessEqual(c.header_bytes, 20)

    def test_body_ignored_after_header_limit(self):
        c = self.capture(max_headers=1)
        c.add_header(b"A", b"1")
        c.add_header(b"B", b"2")
        c.add_body(b"x" * 1000)
        self.assertEqual(c.body_bytes, 0)

    def test_large_body_is_handed_over_by_descriptor(self):
        import os
        from postwarden.message import SPOOL_MEMORY_LIMIT
        c = self.capture()
        c.add_header(b"From", b" a@example.org")
        c.add_body(b"x" * SPOOL_MEMORY_LIMIT)
        self.assertIsNone(c.body_fd(), "a body within the memory spool stays in this process")
        c.add_body(b"y")
        fd = c.body_fd()
        self.assertIsNotNone(fd)
        self.assertEqual(c.header_block() + os.pread(fd, c.body_bytes, 0), c.message_bytes())
