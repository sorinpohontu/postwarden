import threading
import unittest

from postwarden.addresses import parse_mailbox
from postwarden.quota import (DAY, HOUR, KEY_STORE_FULL, LOCAL_PER_DAY, LOCAL_PER_HOUR, PER_DAY, PER_HOUR, LimitKey,
                              QuotaStore, limit_key)

from helpers import settings

M = parse_mailbox
T0 = 1_800_000_000.0

MULTIPLIERS = """
[sending_limits.multipliers]
"example.com" = 2
"marketing@example.com" = 10
"login:john" = 3
"192.0.2.0/24" = 5
"192.0.2.10" = 7
"<>" = 4
"""


def key(text, per_hour=3, per_day=5, local=False):
    return LimitKey(text, per_hour, per_day, 1.0, local)


def store(extra="", capacity=3):
    return QuotaStore(settings(extra).sending_limits, capacity=capacity)


def send(quota, k, recipients, now, observe=False, commit=True):
    """One message: reserve each recipient, then commit or release. Returns the refusal reasons."""
    reservation = quota.begin(k)
    refused = [v.reason for v in (quota.reserve(reservation, now, observe=observe) for _ in range(recipients)) if v]
    (quota.commit(reservation, now) if commit else quota.release(reservation))
    return refused


class LimitKeys(unittest.TestCase):
    def setUp(self):
        self.limits = settings(MULTIPLIERS).sending_limits

    def key(self, trust, **kwargs):
        return limit_key(self.limits, trust, **kwargs)

    def test_submission_counts_the_login_and_its_domain_multiplier(self):
        k = self.key("authenticated_submission", login="Sales@Example.COM", sender=M("other@example.org"))
        self.assertEqual((k.text, k.multiplier, k.per_hour, k.per_day, k.local), ("sales@example.com", 2, 200, 1000, False))
        k = self.key("authenticated_submission", login="Marketing@example.com", sender=M("marketing@example.com"))
        self.assertEqual((k.text, k.per_hour), ("marketing@example.com", 1000))

    def test_short_login_takes_the_sender_domain_unless_listed(self):
        k = self.key("authenticated_submission", login="Mary", sender=M("mary@example.com"))
        self.assertEqual((k.text, k.multiplier), ("login:mary", 2))
        k = self.key("authenticated_submission", login="mary", sender=M("mary@example.org"))
        self.assertEqual((k.text, k.multiplier), ("login:mary", 1))
        k = self.key("authenticated_submission", login="JOHN", sender=M("john@example.com"))
        self.assertEqual((k.text, k.multiplier), ("login:john", 3))

    def test_local_mail_counts_the_envelope_sender(self):
        k = self.key("local_pickup", sender=M("Web@Example.com"))
        self.assertEqual((k.text, k.multiplier, k.local), ("web@example.com", 2, True))
        k = self.key("local_smtp", null_sender=True)
        self.assertEqual((k.text, k.per_hour, k.local), ("<>", 400, True))
        k = self.key("local_pickup", raw_sender="Not An Address")
        self.assertEqual((k.text, k.multiplier), ("not an address", 1))

    def test_relays_count_the_client_address_by_longest_prefix(self):
        self.assertEqual(self.key("mynetworks", peer_ip="192.0.2.10").multiplier, 7)
        self.assertEqual(self.key("mynetworks", peer_ip="::ffff:192.0.2.11").text, "192.0.2.11")
        self.assertEqual(self.key("mynetworks", peer_ip="::ffff:192.0.2.11").multiplier, 5)
        self.assertEqual(self.key("mynetworks", peer_ip="198.51.100.1", sender=M("a@example.com")).multiplier, 1)

    def test_untrusted_mail_has_no_limit_key(self):
        self.assertIsNone(self.key("untrusted", sender=M("a@example.com"), peer_ip="198.51.100.1"))
        self.assertIsNone(self.key("authenticated_submission", login=None, sender=M("a@example.com")))


class Windows(unittest.TestCase):
    def test_recipients_count_alike_whether_in_one_message_or_many(self):
        one, many = store(), store()
        self.assertEqual(send(one, key("a"), 3, T0), [])
        for _ in range(3):
            self.assertEqual(send(many, key("a"), 1, T0), [])
        self.assertEqual(send(one, key("a"), 1, T0), [PER_HOUR])
        self.assertEqual(send(many, key("a"), 1, T0), [PER_HOUR])

    def test_earlier_recipients_of_a_message_proceed_when_a_later_one_is_over(self):
        quota = store()
        self.assertEqual(send(quota, key("a"), 5, T0), [PER_HOUR, PER_HOUR])
        self.assertEqual(quota.counts("a", T0), (3, 3))

    def test_hour_rolls_and_day_limit_holds(self):
        quota = store()
        send(quota, key("a"), 3, T0)
        self.assertEqual(send(quota, key("a"), 1, T0 + HOUR - 60), [PER_HOUR])
        self.assertEqual(send(quota, key("a"), 2, T0 + HOUR + 60), [])
        self.assertEqual(send(quota, key("a"), 1, T0 + 2 * HOUR + 120), [PER_DAY])
        self.assertEqual(send(quota, key("a"), 1, T0 + DAY + 900), [])

    def test_windows_never_undercount_at_bucket_edges(self):
        quota = store()
        send(quota, key("a"), 3, T0 + 59)
        self.assertEqual(send(quota, key("a"), 1, T0 + HOUR + 30), [PER_HOUR])

    def test_first_refusal_per_key_and_window_is_marked(self):
        quota = store()
        send(quota, key("a"), 3, T0)
        reservation = quota.begin(key("a"))
        firsts = [quota.reserve(reservation, T0 + i, observe=False).first for i in range(3)]
        self.assertEqual(firsts, [True, False, False])
        send(quota, key("b"), 3, T0)
        self.assertTrue(quota.reserve(quota.begin(key("b")), T0, observe=False).first)
        self.assertFalse(quota.reserve(quota.begin(key("a")), T0 + HOUR - 1, observe=False).first)
        self.assertTrue(quota.reserve(quota.begin(key("a")), T0 + HOUR + 1, observe=False).first)


class Reservations(unittest.TestCase):
    def test_released_and_aborted_messages_consume_nothing(self):
        quota = store()
        self.assertEqual(send(quota, key("a", local=True), 3, T0, commit=False), [])
        self.assertEqual(quota.counts("a", T0), (0, 0))
        self.assertEqual(quota.local_counts(T0), (0, 0))

    def test_reservations_count_before_commit(self):
        quota = store()
        first, second = quota.begin(key("a")), quota.begin(key("a"))
        for _ in range(3):
            self.assertIsNone(quota.reserve(first, T0, observe=False))
        self.assertEqual(quota.reserve(second, T0, observe=False).reason, PER_HOUR)
        quota.release(first)
        self.assertIsNone(quota.reserve(second, T0, observe=False))

    def test_commit_and_release_are_final_and_idempotent(self):
        quota = store()
        reservation = quota.begin(key("a"))
        quota.reserve(reservation, T0, observe=False)
        quota.commit(reservation, T0)
        quota.release(reservation)
        quota.commit(reservation, T0)
        self.assertEqual(quota.counts("a", T0), (1, 1))

    def test_concurrent_sessions_of_one_key_cannot_overshoot(self):
        quota = store()
        k = key("a", per_hour=50, per_day=50)
        barrier = threading.Barrier(8)
        results = []

        def session():
            reservation = quota.begin(k)
            barrier.wait()
            accepted = sum(quota.reserve(reservation, T0, observe=False) is None for _ in range(20))
            quota.commit(reservation, T0)
            results.append(accepted)

        threads = [threading.Thread(target=session) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(results), 50)
        self.assertEqual(quota.counts("a", T0), (50, 50))


class LocalCap(unittest.TestCase):
    CAP = '\n[sending_limits]\nlocal_per_hour = 4\nlocal_per_day = 6\n'

    def test_rotating_local_senders_meet_the_local_cap(self):
        quota = store(self.CAP, capacity=10)
        for n in range(4):
            self.assertEqual(send(quota, key(f"s{n}@example.com", local=True), 1, T0), [])
        self.assertEqual(send(quota, key("s9@example.com", local=True), 1, T0), [LOCAL_PER_HOUR])
        self.assertEqual(send(quota, key("s9@example.com", local=True), 2, T0 + HOUR + 60), [])
        self.assertEqual(send(quota, key("s8@example.com", local=True), 1, T0 + HOUR + 60), [LOCAL_PER_DAY])

    def test_key_and_local_cap_are_reserved_together_or_not_at_all(self):
        quota = store(self.CAP, capacity=10)
        send(quota, key("a@example.com", local=True), 3, T0)
        self.assertEqual(send(quota, key("a@example.com", local=True), 1, T0), [PER_HOUR])
        self.assertEqual(quota.local_counts(T0), (3, 3))
        send(quota, key("b@example.com", local=True), 1, T0)
        self.assertEqual(send(quota, key("c@example.com", local=True), 1, T0), [LOCAL_PER_HOUR])
        self.assertEqual(quota.counts("c@example.com", T0), (0, 0))

    def test_relays_and_logins_do_not_count_toward_the_local_cap(self):
        quota = store(self.CAP, capacity=10)
        send(quota, key("192.0.2.10"), 3, T0)
        self.assertEqual(quota.local_counts(T0), (0, 0))


class KeyStore(unittest.TestCase):
    def fill(self, quota, now=T0):
        for text in ("a", "b", "c"):
            self.assertEqual(send(quota, key(text), 1, now), [])

    def test_full_store_defers_a_new_key_in_enforce_and_warns_once_a_minute(self):
        quota = store()
        self.fill(quota)
        reservation = quota.begin(key("d"))
        verdicts = [quota.reserve(reservation, T0 + s, observe=False) for s in (0, 30, 61)]
        self.assertEqual([(v.reason, v.first) for v in verdicts],
                         [(KEY_STORE_FULL, True), (KEY_STORE_FULL, False), (KEY_STORE_FULL, True)])
        self.assertEqual(quota.key_count(), 3)

    def test_full_store_in_observe_leaves_the_new_key_unmeasured(self):
        quota = store()
        self.fill(quota)
        reservation = quota.begin(key("d@example.com", local=True))
        self.assertEqual(quota.reserve(reservation, T0, observe=True).reason, KEY_STORE_FULL)
        quota.commit(reservation, T0)
        self.assertFalse(reservation.measured)
        self.assertEqual(quota.counts("d@example.com", T0), (0, 0))
        self.assertEqual(quota.local_counts(T0), (1, 1))

    def test_counted_keys_are_never_evicted_and_never_regain_quota(self):
        quota = store()
        self.fill(quota)
        send(quota, key("a"), 2, T0)
        send(quota, key("d"), 1, T0 + HOUR + 60)
        self.assertEqual(send(quota, key("a"), 1, T0 + HOUR + 60), [])
        self.assertEqual(send(quota, key("a"), 3, T0 + HOUR + 60), [PER_DAY, PER_DAY])

    def test_reserved_keys_are_not_freed(self):
        quota = store()
        held = quota.begin(key("a"))
        quota.reserve(held, T0, observe=False)
        send(quota, key("b"), 1, T0)
        send(quota, key("c"), 1, T0)
        later = T0 + DAY + 900
        self.assertEqual(send(quota, key("d"), 1, later), [])
        self.assertEqual(send(quota, key("e"), 1, later), [])
        self.assertEqual(send(quota, key("f"), 1, later), [KEY_STORE_FULL])
        quota.commit(held, T0 + DAY + 900)
        self.assertEqual(quota.counts("a", T0 + DAY + 900), (1, 1))

    def test_expired_keys_are_freed_for_new_keys(self):
        quota = store()
        self.fill(quota)
        self.assertEqual(send(quota, key("d"), 1, T0 + DAY + 900), [])
        self.assertEqual(quota.key_count(), 1)


if __name__ == "__main__":
    unittest.main()
