import json
import os
import tempfile
import threading
import unittest
import unittest.mock

from postwarden import limitstate
from postwarden.quota import DAY, HOUR, KEY_STORE_FULL, PER_HOUR, LimitKey, QuotaStore

from helpers import settings

NOW = 1_800_000_000.0


def store(capacity=3):
    return QuotaStore(settings().sending_limits, capacity=capacity)


def key(text, per_hour=3, per_day=5, local=False):
    return LimitKey(text, per_hour, per_day, 1.0, local)


def send(quota, k, recipients, now=NOW, commit=True):
    reservation = quota.begin(k)
    refused = [v.reason for v in (quota.reserve(reservation, now, observe=False) for _ in range(recipients)) if v]
    (quota.commit(reservation, now) if commit else quota.release(reservation))
    return refused


class StateFile(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = directory.name
        self.path = os.path.join(self.dir, "limits.json")

    def write(self, data):
        with open(self.path, "w") as handle:
            handle.write(data if isinstance(data, str) else json.dumps(data))

    def snapshot(self, **changes):
        data = {"version": 1, "saved": int(NOW), "local": {"hour": [], "day": []},
                "keys": {"a": {"hour": [[int(NOW), 2]], "day": [[int(NOW), 2]]}}}
        data.update(changes)
        return data

    def load(self, quota=None, now=NOW):
        return limitstate.load(quota if quota is not None else store(), self.path, now)

    def test_round_trip_keeps_committed_counts_but_not_reservations(self):
        quota = store()
        send(quota, key("a", local=True), 2)
        held = quota.begin(key("b"))
        quota.reserve(held, NOW, observe=False)
        limitstate.save(quota, self.path, NOW)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual(os.listdir(self.dir), ["limits.json"])
        restored = store()
        result = self.load(restored, NOW + 120)
        self.assertEqual((result.status, result.keys, result.age), ("loaded", 1, 120))
        self.assertEqual(restored.counts("a", NOW + 120), (2, 2))
        self.assertEqual(restored.counts("b", NOW + 120), (0, 0))
        self.assertEqual(restored.local_counts(NOW + 120), (2, 2))

    def test_restored_windows_keep_rolling(self):
        quota = store()
        send(quota, key("a"), 3)
        limitstate.save(quota, self.path, NOW)
        restored = store()
        self.load(restored, NOW + 60)
        self.assertEqual(send(restored, key("a"), 1, NOW + 60), [PER_HOUR])
        self.assertEqual(send(restored, key("a"), 1, NOW + HOUR + 60), [])

    def test_downtime_ages_the_windows(self):
        self.write(self.snapshot())
        result = self.load(now=NOW + DAY + 900)
        self.assertEqual((result.status, result.keys), ("loaded", 0))

    def test_buckets_in_the_future_are_discarded(self):
        self.write(self.snapshot(keys={"a": {"hour": [[int(NOW) + 600, 2]], "day": [[int(NOW) + 900, 2]]}}))
        quota = store()
        self.assertEqual(self.load(quota).keys, 0)

    def test_missing_file_starts_empty(self):
        self.assertEqual(self.load().status, "missing")

    def test_damaged_files_start_empty_and_say_why(self):
        cases = {
            "truncated": (json.dumps(self.snapshot())[:-5], "not valid JSON"),
            "wrong version": (self.snapshot(version=2), "unsupported version 2"),
            "future-dated": (self.snapshot(saved=int(NOW) + 3600), "invalid or future save time"),
            "too many keys": (self.snapshot(keys={t: {"hour": [], "day": []} for t in "abcd"}), "4 keys, more than 3"),
            "misaligned bucket": (self.snapshot(keys={"a": {"hour": [[int(NOW) + 1, 2]], "day": []}}), "invalid hour bucket"),
            "zero count": (self.snapshot(keys={"a": {"hour": [[int(NOW), 0]], "day": []}}), "invalid hour bucket"),
            "boolean count": (self.snapshot(keys={"a": {"hour": [], "day": [[int(NOW), True]]}}), "invalid day bucket"),
            "duplicate bucket": (self.snapshot(keys={"a": {"hour": [[int(NOW), 1], [int(NOW), 1]], "day": []}}),
                                 "invalid hour bucket"),
            "extra field": (self.snapshot(note="x"), "unexpected structure"),
            "not a number": ('{"version": 1, "saved": NaN, "local": {}, "keys": {}}', "not valid JSON"),
        }
        for name, (content, detail) in cases.items():
            with self.subTest(name):
                self.write(content)
                quota = store()
                send(quota, key("x"), 1)
                result = self.load(quota)
                self.assertEqual((result.status, result.detail), ("invalid", detail))
                self.assertEqual(quota.counts("x", NOW), (1, 1))

    def test_oversized_file_is_not_read(self):
        self.write(self.snapshot())
        with unittest.mock.patch.object(limitstate, "MAX_STATE_BYTES", 10):
            result = self.load()
        self.assertEqual(result.status, "invalid")
        self.assertTrue(result.detail.startswith("oversized"))

    def test_symlink_is_refused(self):
        target = os.path.join(self.dir, "elsewhere.json")
        with open(target, "w") as handle:
            json.dump(self.snapshot(), handle)
        os.symlink(target, self.path)
        self.assertEqual(self.load().status, "invalid")

    def test_full_store_stays_full_after_a_restart(self):
        quota = store()
        for text in "abc":
            send(quota, key(text), 1)
        limitstate.save(quota, self.path, NOW)
        restored = store()
        self.load(restored, NOW + 60)
        self.assertEqual(send(restored, key("d"), 1, NOW + 60), [KEY_STORE_FULL])
        self.assertEqual(send(restored, key("a"), 3, NOW + 60), [PER_HOUR])


class PeriodicSave(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = os.path.join(directory.name, "state", "limits.json")

    def test_failed_save_reports_snapshot_age_and_is_retried(self):
        failures = []
        saved = threading.Event()
        quota = store()
        send(quota, key("a"), 1, NOW)
        saver = limitstate.Saver(quota, lambda detail, age: failures.append((detail, age)), self.path,
                                 interval=0.01, last_saved=None)
        self.assertFalse(saver.save_now())
        self.assertEqual(failures, [("No such file or directory", None)])
        os.mkdir(os.path.dirname(self.path))
        self.assertTrue(saver.save_now())
        os.rename(os.path.dirname(self.path), os.path.dirname(self.path) + ".gone")
        self.assertFalse(saver.save_now())
        self.assertEqual(failures[-1][1], 0)
        os.rename(os.path.dirname(self.path) + ".gone", os.path.dirname(self.path))
        original = limitstate.save

        def counting(*args, **kwargs):
            result = original(*args, **kwargs)
            saved.set()
            return result
        with unittest.mock.patch.object(limitstate, "save", counting):
            saver.start()
            self.assertTrue(saved.wait(5))
            self.assertTrue(saver.stop())


if __name__ == "__main__":
    unittest.main()
