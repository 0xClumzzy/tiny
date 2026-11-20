"""Scoring tests."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tiny.ldif import Entry
from tiny.score import score_entries


def entry(dn, **attrs):
    parsed = {}
    for key, value in attrs.items():
        parsed[key.lower()] = value if isinstance(value, list) else [value]
    return Entry(dn=dn, attrs=parsed)


def by_name(objects):
    return {obj.name.lower(): obj for obj in objects}


class ScoringTests(unittest.TestCase):
    def test_krbtgt_is_crown(self):
        objects = score_entries(
            [entry("CN=krbtgt,DC=corp,DC=local", objectClass="user", sAMAccountName="krbtgt")]
        )
        self.assertEqual(objects[0].score, 100)
        self.assertEqual(objects[0].tier, 0)

    def test_rid_500_is_crown(self):
        objects = score_entries(
            [
                entry(
                    "CN=Administrator,DC=corp,DC=local",
                    objectClass="user",
                    sAMAccountName="Administrator",
                    objectSid="S-1-5-21-1-2-3-500",
                )
            ]
        )
        self.assertEqual(objects[0].tier, 0)
        self.assertIn("RID 500", " ".join(objects[0].reasons))

    def test_nested_domain_admin(self):
        entries = [
            entry(
                "CN=Domain Admins,DC=corp,DC=local",
                objectClass="group",
                sAMAccountName="Domain Admins",
                member="CN=Nested,DC=corp,DC=local",
            ),
            entry(
                "CN=Nested,DC=corp,DC=local",
                objectClass="group",
                sAMAccountName="Nested",
                member="CN=Bob,DC=corp,DC=local",
            ),
            entry(
                "CN=Bob,DC=corp,DC=local",
                objectClass="user",
                sAMAccountName="bob",
                userAccountControl="512",
            ),
        ]
        bob = by_name(score_entries(entries))["bob"]
        self.assertEqual(bob.tier, 0)
        self.assertIn("nested", " ".join(bob.reasons))
        self.assertIn("privileged", bob.tags)

    def test_memberof_fallback_without_group_objects(self):
        objects = score_entries(
            [
                entry(
                    "CN=Alice,DC=corp,DC=local",
                    objectClass="user",
                    sAMAccountName="alice",
                    userAccountControl="512",
                    memberOf="CN=Domain Admins,DC=corp,DC=local",
                )
            ]
        )
        self.assertEqual(objects[0].tier, 0)
        self.assertIn("memberOf Domain Admins", objects[0].reasons)

    def test_kerberoastable_and_asrep(self):
        objects = score_entries(
            [
                entry(
                    "CN=svc_sql,DC=corp,DC=local",
                    objectClass="user",
                    sAMAccountName="svc_sql",
                    userAccountControl="512",
                    servicePrincipalName="MSSQLSvc/sql01.corp.local:1433",
                ),
                entry(
                    "CN=noauth,DC=corp,DC=local",
                    objectClass="user",
                    sAMAccountName="noauth",
                    userAccountControl=str(0x200 | 0x400000),
                ),
            ]
        )
        found = by_name(objects)
        self.assertIn("kerberoastable", found["svc_sql"].tags)
        self.assertEqual(found["svc_sql"].tier, 1)
        self.assertIn("asrep", found["noauth"].tags)
        self.assertEqual(found["noauth"].tier, 1)

    def test_laps_password_is_crown(self):
        objects = score_entries(
            [
                entry(
                    "CN=PC01,DC=corp,DC=local",
                    objectClass="computer",
                    sAMAccountName="PC01$",
                    **{"ms-Mcs-AdmPwd": "Sup3rS3cret!"},
                )
            ]
        )
        self.assertEqual(objects[0].score, 100)
        self.assertEqual(objects[0].tier, 0)
        self.assertIn("creds", objects[0].tags)

    def test_rbcd_and_shadow_credentials(self):
        objects = score_entries(
            [
                entry(
                    "CN=PC02,DC=corp,DC=local",
                    objectClass="computer",
                    sAMAccountName="PC02$",
                    **{"msDS-AllowedToActOnBehalfOfOtherIdentity": "AQID"},
                ),
                entry(
                    "CN=PC03,DC=corp,DC=local",
                    objectClass="user",
                    sAMAccountName="PC03",
                    userAccountControl="512",
                    **{"msDS-KeyCredentialLink": "B:828:..."},
                ),
            ]
        )
        found = by_name(objects)
        self.assertIn("rbcd", found["pc02$"].tags)
        self.assertIn("shadowcreds", found["pc03"].tags)

    def test_disabled_domain_admin_drops_a_tier(self):
        entries = [
            entry(
                "CN=Domain Admins,DC=corp,DC=local",
                objectClass="group",
                sAMAccountName="Domain Admins",
                member="CN=Old Admin,DC=corp,DC=local",
            ),
            entry(
                "CN=Old Admin,DC=corp,DC=local",
                objectClass="user",
                sAMAccountName="old.admin",
                userAccountControl="514",
            ),
        ]
        admin = by_name(score_entries(entries))["old.admin"]
        self.assertEqual(admin.tier, 1)
        self.assertIn("disabled", admin.tags)

    def test_unconstrained_dc(self):
        objects = score_entries(
            [
                entry(
                    "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
                    objectClass="computer",
                    sAMAccountName="DC01$",
                    userAccountControl=str(0x2000 | 0x80000),
                )
            ]
        )
        self.assertEqual(objects[0].score, 100)
        self.assertIn("dc", objects[0].tags)


if __name__ == "__main__":
    unittest.main()
