import contextlib
import io
import unittest

from postwarden.config import LoggingSettings
from postwarden.logging import EventLogger


class LifecycleEvents(unittest.TestCase):
    def capture(self, level):
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            log = EventLogger(LoggingSettings(backend="stderr", identifier=f"pm-test-{level}", level=level))
        log.lifecycle(event="start", mode="enforce")
        log.info(action="accept", stage="eom")
        log.lifecycle(event="stop")
        return out.getvalue().splitlines()

    def test_emitted_even_when_level_suppresses_decisions(self):
        lines = self.capture("error")
        self.assertEqual(lines, ["pm-test-error: event=start mode=enforce", "pm-test-error: event=stop"])

    def test_emitted_alongside_decisions_at_info(self):
        lines = self.capture("info")
        self.assertEqual(len(lines), 3)
        self.assertIn("action=accept", lines[1])
