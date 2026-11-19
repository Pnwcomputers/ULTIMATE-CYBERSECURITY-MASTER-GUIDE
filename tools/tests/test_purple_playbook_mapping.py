"""Offline editorial checks for evidence-backed Purple Team technique examples."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "PlayBooks/PurpleTeam_Detailed.md"


class PurpleTechniqueMappingTests(unittest.TestCase):
    def test_winrm_and_smb_are_distinct(self):
        guide = GUIDE.read_text(encoding="utf-8")
        winrm = guide.split("### Windows Remote Management", 1)[1].split("### SMB/Windows Admin Shares", 1)[0]
        smb = guide.split("### SMB/Windows Admin Shares", 1)[1].split("## Advanced Enhancements", 1)[0]
        self.assertIn("T1021.006", winrm)
        self.assertIn("DET0477", winrm)
        self.assertIn("WinRM", winrm)
        self.assertIn("T1021.002", smb)
        self.assertIn("DET0530", smb)
        self.assertIn("5140", smb)
        self.assertIn("5145", smb)
        self.assertIn("NOT TESTED", winrm)
        self.assertIn("NOT TESTED", smb)

    def test_no_claims_of_unperformed_tests_or_automatic_exploitation(self):
        guide = GUIDE.read_text(encoding="utf-8")
        self.assertNotIn("Result | Alert fired", guide)
        self.assertNotIn("new rule deployed, tested, and validated", guide.lower())
        self.assertNotIn("YARA rule for SMB session opening", guide)
        self.assertIn("Never", guide.split("### CI & Controlled Lab Runs", 1)[1].split("### Threat", 1)[0])
        self.assertIn("written authorization", guide.lower())
        self.assertIn("cti-to-approved-emulation-gates.svg", guide)


if __name__ == "__main__":
    unittest.main()
