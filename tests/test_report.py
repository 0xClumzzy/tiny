"""Report and export tests."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tiny.ldif import Entry
from tiny.report import export, json_report, render_markdown, render_report
from tiny.score import score_entries


def make_objects():
    entries = [
        Entry("CN=krbtgt,DC=corp,DC=local", {
            "objectclass": ["user"], "samaccountname": ["krbtgt"]}),
        Entry("CN=Alice,DC=corp,DC=local", {
            "objectclass": ["user"], "samaccountname": ["alice"],
            "useraccountcontrol": ["512"],
            "serviceprincipalname": ["MSSQLSvc/sql01.corp.local:1433"]}),
    ]
    return score_entries(entries)


class ReportTests(unittest.TestCase):
    def test_terminal_report(self):
        report = render_report(make_objects(), ["dump.ldif"], color=False,
                               top=10, show_all=False)
        self.assertIn("TINY", report)
        self.assertIn("LDAP", report)
        self.assertIn("CROWN JEWELS", report)
        self.assertIn("PRIORITY QUEUE", report)
        self.assertIn("QUICK WINS", report)
        self.assertIn("kerberoastable", report)
        self.assertIn("corp.local", report)
        self.assertNotIn("\033[", report)

    def test_markdown_report(self):
        report = render_markdown(make_objects(), ["dump.ldif"])
        self.assertIn("# tiny — LDAP triage report", report)
        self.assertIn("| 0 · CROWN JEWELS |", report)
        self.assertIn("`alice`", report)

    def test_json_report(self):
        report = json_report(make_objects(), ["dump.ldif"])
        self.assertEqual(report["tool"], "tiny")
        self.assertEqual(report["counts"]["total"], 2)
        self.assertIn("kerberoastable", report["quick_wins"])

    def test_export_files(self):
        with tempfile.TemporaryDirectory() as directory:
            written = export(make_objects(), directory, ["dump.ldif"], full=False)
            names = {name for name, _ in written}
            self.assertIn("tier0-crown-jewels.txt", names)
            self.assertIn("users.txt", names)
            self.assertIn("usernames.txt", names)
            self.assertIn("spray-users.txt", names)
            self.assertIn("attack-paths.txt", names)
            self.assertIn("domain-posture.txt", names)
            self.assertIn("playbook.md", names)
            self.assertIn("tiny.json", names)
            self.assertIn("report.md", names)
            self.assertIn("README.txt", names)

            crown = Path(directory, "tier0-crown-jewels.txt").read_text()
            self.assertIn("score=100", crown)
            self.assertIn("krbtgt", crown)
            self.assertNotIn("\033[", crown)

            data = json.loads(Path(directory, "tiny.json").read_text())
            self.assertEqual(data["counts"]["total"], 2)

    def test_export_has_no_ansi(self):
        with tempfile.TemporaryDirectory() as directory:
            export(make_objects(), directory, ["dump.ldif"], full=True)
            for path in Path(directory).glob("*.txt"):
                self.assertNotIn("\033[", path.read_text())


if __name__ == "__main__":
    unittest.main()
