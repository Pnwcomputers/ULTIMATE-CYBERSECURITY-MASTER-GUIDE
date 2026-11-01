"""Static and CLI regression checks for conservative repair default.

Never invokes a real repair, boot edit, package installation or system probe.
"""
from pathlib import Path
import subprocess
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/uconsole-repair.sh"


class RepairSafetyTests(unittest.TestCase):
    def test_bash_parses(self):
        p = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_help_reports_explicit_apply(self):
        p = subprocess.run(["bash", str(SCRIPT), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("--apply", p.stdout)
        self.assertIn("default", p.stdout.lower())

    def test_read_only_default_in_source(self):
        s = SCRIPT.read_text()
        self.assertIn("APPLY_REPAIR=no", s)
        self.assertIn("DRY_RUN=yes", s)
        self.assertIn("DIAGNOSE_ONLY=yes", s)
        self.assertIn("--apply)     DRY_RUN=no; DIAGNOSE_ONLY=no; APPLY_REPAIR=yes", s)
        self.assertIn('[[ "$APPLY_REPAIR" == yes ]] || die', s)
        self.assertIn("LOG_FILE=/dev/null  # read-only", s)
        self.assertIn("confirm \"Apply the repair", s)


if __name__ == "__main__":
    unittest.main()
