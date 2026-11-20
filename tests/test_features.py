"""Posture, attack-path, ADCS and playbook tests."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tiny.ldif import Entry
from tiny.playbook import password_hints, render_playbook
from tiny.posture import collect_posture, format_timespan, posture_rows
from tiny.report import attack_paths
from tiny.score import score_entries


def entry(dn, **attrs):
    parsed = {}
    for key, value in attrs.items():
        parsed[key.lower()] = value if isinstance(value, list) else [value]
    return Entry(dn=dn, attrs=parsed)


def domain_entry():
    return entry(
        "DC=corp,DC=local",
        objectClass=["top", "domain", "domainDNS"],
        lockoutThreshold="0",
        lockoutDuration="-18000000000",
        lockOutObservationWindow="18000000000",
        minPwdLength="7",
        maxPwdAge="36288000000000",
        pwdHistoryLength="24",
        pwdProperties="1",
        **{"ms-DS-MachineAccountQuota": "10"},
        domainFunctionality="7",
    )


class PostureTests(unittest.TestCase):
    def test_collects_policy_and_trust(self):
        trust = entry(
            "CN=other.local,CN=System,DC=corp,DC=local",
            objectClass="trustedDomain",
            trustPartner="other.local",
            flatName="OTHER",
            trustDirection="2",
            trustType="2",
            trustAttributes="8",
        )
        posture = collect_posture([domain_entry(), trust])
        self.assertTrue(posture["available"])
        self.assertEqual(posture["domain"], "corp.local")
        self.assertEqual(posture["machine_account_quota"], 10)
        self.assertEqual(posture["lockout_threshold"], 0)
        self.assertEqual(posture["min_password_length"], 7)
        self.assertEqual(posture["max_password_age"], "42 days")
        self.assertTrue(posture["complexity"])
        self.assertEqual(posture["functional_level"], "2016")
        self.assertEqual(posture["trusts"][0]["direction"], "outbound")
        self.assertIn("forest-transitive", posture["trusts"][0]["attributes"])

    def test_posture_rows_reflect_open_lockout(self):
        rows = dict(posture_rows(collect_posture([domain_entry()])))
        self.assertIn("spraying safe", rows["lockout threshold"])
        self.assertIn("RBCD viable", rows["machine account quota"])

    def test_missing_domain_is_safe(self):
        posture = collect_posture([entry("CN=Alice,DC=corp,DC=local", objectClass="user")])
        self.assertFalse(posture["available"])
        self.assertEqual(posture_rows(posture), [])

    def test_timespan_formatting(self):
        self.assertEqual(format_timespan(0), "0 seconds")
        self.assertEqual(format_timespan(18000000000), "30 minutes")
        self.assertEqual(format_timespan(-1), "never")


class AttackPathTests(unittest.TestCase):
    def test_nested_path_is_display_cased(self):
        objects = score_entries(
            [
                entry(
                    "CN=Domain Admins,CN=Users,DC=corp,DC=local",
                    objectClass="group",
                    sAMAccountName="Domain Admins",
                    member="CN=Nested Admins,OU=Groups,DC=corp,DC=local",
                ),
                entry(
                    "CN=Nested Admins,OU=Groups,DC=corp,DC=local",
                    objectClass="group",
                    sAMAccountName="Nested Admins",
                    member="CN=Helpdesk,OU=Groups,DC=corp,DC=local",
                ),
                entry(
                    "CN=Helpdesk,OU=Groups,DC=corp,DC=local",
                    objectClass="group",
                    sAMAccountName="Helpdesk",
                    member="CN=Carol,OU=Users,DC=corp,DC=local",
                ),
                entry(
                    "CN=Carol,OU=Users,DC=corp,DC=local",
                    objectClass="user",
                    sAMAccountName="carol",
                    userAccountControl="512",
                ),
            ]
        )
        paths = {chain[0]: chain for _, chain in attack_paths(objects)}
        self.assertEqual(paths["carol"], ["carol", "Helpdesk", "Nested Admins", "Domain Admins"])
        self.assertNotIn("Helpdesk", paths)


class AdcsTests(unittest.TestCase):
    def test_esc1_template_is_high_value(self):
        objects = score_entries(
            [
                entry(
                    "CN=UserTemplate,CN=Certificate Templates,DC=corp,DC=local",
                    objectClass=["top", "pKICertificateTemplate"],
                    cn="UserTemplate",
                    **{"msPKI-Certificate-Name-Flag": "1", "msPKI-Enrollment-Flag": "0"},
                    pKIExtendedKeyUsage="1.3.6.1.5.5.7.3.2",
                )
            ]
        )
        obj = objects[0]
        self.assertIn("adcs-esc1", obj.tags)
        self.assertEqual(obj.tier, 1)

    def test_pending_approval_suppresses_esc1(self):
        objects = score_entries(
            [
                entry(
                    "CN=SafeTemplate,CN=Certificate Templates,DC=corp,DC=local",
                    objectClass=["top", "pKICertificateTemplate"],
                    cn="SafeTemplate",
                    **{"msPKI-Certificate-Name-Flag": "1", "msPKI-Enrollment-Flag": "2"},
                    pKIExtendedKeyUsage="1.3.6.1.5.5.7.3.2",
                )
            ]
        )
        self.assertNotIn("adcs-esc1", objects[0].tags)


class DelegationAndPreAuthTests(unittest.TestCase):
    """userAccountControl bit checks — the bits are easy to get wrong."""

    def _obj(self, **attrs):
        objects = score_entries(
            [
                entry(
                    "CN=target,DC=corp,DC=local",
                    objectClass="user",
                    sAMAccountName="target",
                    **attrs,
                )
            ]
        )
        return objects[0]

    def test_unconstrained_delegation_flag(self):
        obj = self._obj(userAccountControl=str(0x200 | 0x80000))
        self.assertIn("unconstrained", obj.tags)
        self.assertIn("crown", obj.tags)
        self.assertEqual(obj.tier, 0)

    def test_mns_logon_account_is_not_unconstrained(self):
        obj = self._obj(userAccountControl=str(0x200 | 0x20000))
        self.assertNotIn("unconstrained", obj.tags)

    def test_asrep_preauth_disabled(self):
        obj = self._obj(userAccountControl=str(0x200 | 0x400000))
        self.assertIn("asrep", obj.tags)

    def test_password_expiry_bit_is_not_preauth(self):
        obj = self._obj(userAccountControl=str(0x200 | 0x800000))
        self.assertNotIn("asrep", obj.tags)

    def test_protocol_transition_flag(self):
        obj = self._obj(userAccountControl=str(0x200 | 0x1000000))
        self.assertIn("protocol-transition", obj.tags)

    def test_constrained_delegation_full_flag(self):
        obj = self._obj(
            userAccountControl=str(0x200 | 0x1000000),
            **{"msDS-AllowedToDelegateTo": "HTTP/web01.corp.local"},
        )
        self.assertIn("constrained", obj.tags)
        self.assertIn("TRUSTED_TO_AUTH_FOR_DELEGATION", " ".join(obj.reasons))

    def test_allowed_to_delegate_without_flag_is_candidate(self):
        obj = self._obj(
            userAccountControl="512", **{"msDS-AllowedToDelegateTo": "HTTP/web01.corp.local"}
        )
        self.assertIn("constrained", obj.tags)
        self.assertIn("verify", " ".join(obj.reasons).lower())

    def test_hex_exported_uac_is_understood(self):
        obj = self._obj(userAccountControl="0x82000")
        self.assertIn("unconstrained", obj.tags)

    def test_uac_flag_names(self):
        from tiny.score import uac_flags

        names = uac_flags(0x200 | 0x400000)
        self.assertIn("DONT_REQ_PREAUTH", names)
        self.assertIn("NORMAL_ACCOUNT", names)


class PlaybookTests(unittest.TestCase):
    def test_playbook_sections(self):
        entries = [
            domain_entry(),
            entry(
                "CN=Alice,DC=corp,DC=local",
                objectClass="user",
                sAMAccountName="alice",
                userAccountControl="512",
                servicePrincipalName="MSSQLSvc/sql01.corp.local:1433",
            ),
            entry(
                "CN=noauth,DC=corp,DC=local",
                objectClass="user",
                sAMAccountName="noauth",
                userAccountControl=str(0x200 | 0x400000),
            ),
            entry(
                "CN=DC01,DC=corp,DC=local",
                objectClass="computer",
                sAMAccountName="DC01$",
                userAccountControl=str(0x2000 | 0x80000),
            ),
            entry(
                "CN=svc_sql,DC=corp,DC=local",
                objectClass="user",
                sAMAccountName="svc_sql",
                userAccountControl="512",
                description="password: Winter2024!",
            ),
        ]
        objects = score_entries(entries)
        posture = collect_posture(entries)
        text = render_playbook(objects, ["dump.ldif"], posture)

        self.assertIn("# tiny playbook — corp.local", text)
        self.assertIn("## Kerberoasting", text)
        self.assertIn("## AS-REP roasting", text)
        self.assertIn("Lockout threshold is **0**", text)
        self.assertIn("## Unconstrained delegation", text)
        self.assertIn("nxc smb <DC_IP>", text)

    def test_password_hints(self):
        objects = score_entries(
            [
                entry(
                    "CN=svc_sql,DC=corp,DC=local",
                    objectClass="user",
                    sAMAccountName="svc_sql",
                    description="password: Winter2024!",
                )
            ]
        )
        hints = password_hints(objects)
        self.assertEqual(hints[0]["candidate"], "Winter2024!")


if __name__ == "__main__":
    unittest.main()
