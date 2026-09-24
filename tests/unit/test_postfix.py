import ipaddress
import unittest

from postwarden.postfix import PostfixError, parse_mynetworks, with_postfix

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
