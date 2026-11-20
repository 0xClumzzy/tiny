"""LDIF parsing tests."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tiny.ldif import merge_entries, parse_ldif


class ParseLdifTests(unittest.TestCase):
    def test_basic_entries(self):
        entries = parse_ldif(
            "dn: CN=Alice,DC=corp,DC=local\n"
            "objectClass: user\n"
            "sAMAccountName: alice\n"
            "\n"
            "dn: CN=Bob,DC=corp,DC=local\n"
            "objectClass: user\n"
            "sAMAccountName: bob\n"
        )
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].get("samaccountname"), "alice")
        self.assertEqual(entries[1].dn, "CN=Bob,DC=corp,DC=local")

    def test_folded_lines(self):
        entries = parse_ldif(
            "dn: CN=Alice,DC=corp,DC=local\n"
            "description: a long description that is\n"
            "  folded across lines\n"
        )
        self.assertEqual(
            entries[0].get("description"), "a long description that is folded across lines"
        )

    def test_base64_value(self):
        entries = parse_ldif("dn: CN=Alice,DC=corp,DC=local\ncn:: QWxpY2UgQWRtaW4=\n")
        self.assertEqual(entries[0].get("cn"), "Alice Admin")

    def test_attribute_options_and_hyphens(self):
        entries = parse_ldif(
            "dn: CN=WEB01,DC=corp,DC=local\n"
            "objectGUID;binary:: AQIDBA==\n"
            "msDS-AllowedToDelegateTo: HTTP/web01.corp.local\n"
        )
        self.assertEqual(entries[0].all("objectguid"), ["\x01\x02\x03\x04"])
        self.assertEqual(entries[0].all("msds-allowedtodelegateto"), ["HTTP/web01.corp.local"])

    def test_merge_duplicate_dns(self):
        entries = parse_ldif(
            "dn: CN=Alice,DC=corp,DC=local\ncn: Alice\n\n"
            "dn: CN=Alice,DC=corp,DC=local\nmail: alice@corp.local\n"
        )
        merged = merge_entries(entries)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].get("cn"), "Alice")
        self.assertEqual(merged[0].get("mail"), "alice@corp.local")


if __name__ == "__main__":
    unittest.main()
