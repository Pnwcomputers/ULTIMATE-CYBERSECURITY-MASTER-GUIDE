"""R9: every third-party action is pinned to a full commit SHA; permissions are least-privilege."""
import re
import unittest
from pathlib import Path

WF = Path(__file__).resolve().parents[2] / ".github" / "workflows"
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)", re.M)


class WorkflowPins(unittest.TestCase):
    def test_all_actions_pinned_to_commit_sha(self):
        bad = []
        for f in sorted(WF.glob("*.yml")):
            for ref in USES.findall(f.read_text()):
                if ref.startswith("./"):
                    continue
                if not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref):
                    bad.append(f"{f.name}: {ref}")
        self.assertEqual(bad, [])

    def test_pinned_actions_carry_a_version_comment(self):
        for f in sorted(WF.glob("*.yml")):
            for line in f.read_text().splitlines():
                if re.search(r"uses:\s*\S+@[0-9a-f]{40}", line):
                    self.assertRegex(line, r"#\s*v\d", f"{f.name}: {line.strip()}")

    def test_default_permissions_are_read_only_and_writes_are_job_scoped(self):
        for f in sorted(WF.glob("*.yml")):
            text = f.read_text()
            top = re.search(r"(?m)^permissions:\s*\n((?:[ \t]+.*\n)+)", text)
            self.assertIsNotNone(top, f"{f.name}: no top-level permissions")
            self.assertNotRegex(top.group(1), r"write", f"{f.name}: workflow-level write permission")

    def test_read_only_checkouts_do_not_persist_credentials(self):
        for name in ("guide-tests.yml", "link-check.yml", "markdownlint.yml", "cm5-parrot-checks.yml"):
            text = (WF / name).read_text()
            n_checkout = len(re.findall(r"uses:\s*actions/checkout@", text))
            n_off = len(re.findall(r"persist-credentials:\s*false", text))
            self.assertEqual(n_checkout, n_off, name)


if __name__ == "__main__":
    unittest.main()
