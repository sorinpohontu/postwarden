import unittest

from postwarden.addresses import (AddressError, Mailbox, normalize_domain, parse_envelope,
                                      parse_from_header, parse_mailbox)


class DomainNormalization(unittest.TestCase):
    def test_case_and_trailing_dot(self):
        self.assertEqual(normalize_domain("Example.COM."), "example.com")

    def test_idna_via_stdlib(self):
        self.assertEqual(normalize_domain("bücher.example"), "xn--bcher-kva.example")

    def test_empty_rejected(self):
        with self.assertRaises(AddressError):
            normalize_domain("")


class MailboxParsing(unittest.TestCase):
    def test_angle_brackets_and_domain_case(self):
        self.assertEqual(parse_mailbox("<User@Example.COM>"), Mailbox("User", "example.com"))

    def test_local_part_case_kept_but_folded_for_lookup(self):
        mailbox = parse_mailbox("All@example.com")
        self.assertEqual(mailbox.exact_key, "All@example.com")
        self.assertEqual(mailbox.lookup_key, "all@example.com")

    def test_extension_stripped_only_on_request(self):
        mailbox = parse_mailbox("all+news@example.com")
        self.assertEqual(mailbox.lookup_key, "all+news@example.com")
        self.assertEqual(mailbox.without_extension("+").lookup_key, "all@example.com")
        self.assertEqual(mailbox.without_extension("").lookup_key, "all+news@example.com")
        self.assertEqual(parse_mailbox("+lead@example.com").without_extension("+").local, "+lead")

    def test_null_and_invalid(self):
        self.assertIsNone(parse_envelope("<>"))
        self.assertIsNone(parse_envelope(""))
        for bad in ["nobody", "@example.com", "user@", "a b@example.com", "user@[127.0.0.1]",
                    "user@example..com", "user\x00@example.com", "<a@b@example.com>"]:
            with self.subTest(bad=bad), self.assertRaises(AddressError):
                parse_mailbox(bad)


class FromHeader(unittest.TestCase):
    def test_single_mailbox_with_display_name(self):
        self.assertEqual(parse_from_header(['"Doe, Jane" <Jane@Example.com>']), Mailbox("Jane", "example.com"))

    def test_folded_header(self):
        self.assertEqual(parse_from_header([" Jane Doe\r\n <jane@example.com>"]), Mailbox("jane", "example.com"))

    def test_missing_duplicate_multiple_malformed(self):
        cases = {
            "missing": [],
            "duplicate": ["a@example.com", "b@example.com"],
            "two mailboxes": ["a@example.com, b@example.com"],
            "group": ["undisclosed-recipients:;"],
            "no domain": ["jane"],
            "empty": [""],
            "unbalanced": ["Jane <jane@example.com"],
        }
        for name, values in cases.items():
            with self.subTest(name), self.assertRaises(AddressError):
                parse_from_header(values)

    def test_display_name_is_not_identity(self):
        self.assertEqual(parse_from_header(['"all@example.com" <someone@else.example>']).domain, "else.example")
        with self.assertRaises(AddressError):
            parse_from_header(["all@example.com <someone@else.example>"])


if __name__ == "__main__":
    unittest.main()
