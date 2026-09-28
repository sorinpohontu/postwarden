import ipaddress
import unittest

from postwarden.postfix import (PostfixError, describe_rate_limits, parse_duration, parse_mynetworks, parse_rate_limits,
                               rate_limit_warnings, with_postfix)

from helpers import settings

N = ipaddress.ip_network


class Mynetworks(unittest.TestCase):
    def test_postconf_default_form(self):
        self.assertEqual(parse_mynetworks("127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 192.0.2.10"),
                         (N("127.0.0.0/8"), N("::ffff:127.0.0.0/104"), N("::1/128"), N("192.0.2.10/32")))

    def test_commas_and_tables(self):
        files = {"/etc/postfix/network_table": "# trusted\n10.1.0.0/16 OK\n\n[2001:db8::]/32  anything\n",
                 "/etc/postfix/extra": "198.51.100.0/24\n"}
        self.assertEqual(parse_mynetworks("127.0.0.1, cidr:/etc/postfix/network_table,/etc/postfix/extra", files.__getitem__),
                         (N("127.0.0.1/32"), N("10.1.0.0/16"), N("2001:db8::/32"), N("198.51.100.0/24")))

    def test_unsupported_entries_are_all_reported(self):
        def missing(path):
            raise FileNotFoundError(2, "No such file or directory")
        with self.assertRaises(PostfixError) as ctx:
            parse_mynetworks("127.0.0.1 !10.0.0.5 hash:/etc/postfix/nets mail.example.com cidr:/nope", missing)
        message = str(ctx.exception)
        for part in ("!10.0.0.5 (negation)", "hash:/etc/postfix/nets", "mail.example.com", "cidr:/nope (No such file or directory)"):
            self.assertIn(part, message)


class RecipientDelimiter(unittest.TestCase):
    def test_protected_address_with_delimiter_tag_refused(self):
        s = settings('\n[protection.addresses."team+x@example.com"]\nauthorized_logins = []\n'
                     '[protection.addresses."news-x@*"]\nauthorized_logins = []\n', recipient_delimiter="")
        with self.assertRaises(PostfixError) as ctx:
            with_postfix(s, (), "+-")
        self.assertIn("team+x@example.com, news-x@*: contains the Postfix recipient_delimiter '+-'", str(ctx.exception))

    def test_leading_delimiter_is_not_a_tag(self):
        s = settings('\n[protection.addresses."+all@example.com"]\nauthorized_logins = []\n', recipient_delimiter="")
        self.assertEqual(with_postfix(s, (), "+").trust.recipient_delimiter, "+")


class RateLimits(unittest.TestCase):
    MAIN = {"anvil_rate_time_unit": "60s", "smtpd_client_event_limit_exceptions": "127.0.0.0/8 [::1]/128",
            "smtpd_client_recipient_rate_limit": "0", "smtpd_client_message_rate_limit": "0"}
    SERVICES = ["smtp/inet", "submission/inet", "smtps/inet", "pickup/unix"]

    def limits(self, overrides="", **main):
        return parse_rate_limits({**self.MAIN, **main}, overrides, self.SERVICES)

    def test_service_overrides_apply_to_their_service_only(self):
        limits = self.limits("submission/inet/smtpd_client_recipient_rate_limit = 50\n"
                             "submission/inet/syslog_name = postfix/submission\n",
                             smtpd_client_message_rate_limit="30")
        self.assertEqual(limits.services["submission/inet"],
                         {"smtpd_client_recipient_rate_limit": 50, "smtpd_client_message_rate_limit": 30})
        self.assertEqual(limits.services["smtps/inet"]["smtpd_client_recipient_rate_limit"], 0)
        self.assertNotIn("submissions/inet", limits.services)
        self.assertEqual(describe_rate_limits(limits),
                         "main.cf: recipient_rate_limit off, message_rate_limit 30 per 60s, exceptions 127.0.0.0/8 "
                         "[::1]/128; submission/inet: recipient_rate_limit 50, message_rate_limit 30")

    def test_time_units(self):
        self.assertEqual([parse_duration(t) for t in ("60", "60s", "1m", "2h", "1d", "1w")],
                         [60, 60, 60, 7200, 86400, 604800])
        with self.assertRaises(PostfixError):
            parse_duration("soon")

    def test_warns_when_a_submission_client_cannot_reach_the_highest_limit(self):
        sending = settings('\n[sending_limits.multipliers]\n"marketing@example.com" = 10\n"192.0.2.10" = 50\n').sending_limits
        limits = self.limits("submission/inet/smtpd_client_recipient_rate_limit = 10\n")
        warnings = rate_limit_warnings(limits, sending)
        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith("submission/inet: Postfix smtpd_client_recipient_rate_limit 10 per 60s "
                                               "(about 600 per hour per client address) is below the highest "
                                               "sending limit, 1000 per hour"))
        self.assertEqual(rate_limit_warnings(self.limits("submission/inet/smtpd_client_recipient_rate_limit = 20\n"),
                                             sending), [])

    def test_no_warning_without_a_postfix_limit_or_with_limits_off(self):
        sending = settings().sending_limits
        self.assertEqual(rate_limit_warnings(self.limits(), sending), [])
        self.assertEqual(rate_limit_warnings(self.limits(smtpd_client_recipient_rate_limit="1"),
                                             settings('\n[sending_limits]\nmode = "off"\n').sending_limits), [])
        self.assertEqual(len(rate_limit_warnings(self.limits(smtpd_client_recipient_rate_limit="1"), sending)), 2)

    def test_non_numeric_values_are_reported(self):
        with self.assertRaises(PostfixError):
            self.limits(smtpd_client_recipient_rate_limit="lots")
