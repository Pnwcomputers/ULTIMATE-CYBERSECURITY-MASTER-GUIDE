"""Hermetic uConsole CM4 safety regressions; never change host packages or storage."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/uconsole-cm4-setup.sh"


class Cm4SafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SCRIPT.read_text(encoding="utf-8")

    def test_syntax(self):
        result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_is_read_only_and_non_root(self):
        result = subprocess.run(["bash", str(SCRIPT), "--help"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("read-only preflight", result.stdout)
        self.assertIn("--with-aio", result.stdout)
        self.assertIn("native Kali", result.stdout)

    def test_no_legacy_mutation_or_script_execution(self):
        # An intentionally strict allowlist: no unreviewed file downloads,
        # package force-overwrite, cross-release apt sources, or boot edits.
        for forbidden in (
            "--force-overwrite",
            "curl -",
            "wget -",
            "rpi-clone",
            "rpi-eeprom-config --edit",
            "rm -rf",
            "dpkg-divert",
            "--break-system-packages",
            "full-upgrade",
            "sudo bash -c",
            "dtoverlay=",
            "dtparam=",
            "sed -i",
            "rpi-update",
        ):
            with self.subTest(forbidden=forbidden):
                # Comments and help may mention past features; focus on
                # actionable shell code only, never claim this is a full AST.
                code = "\n".join(
                    line for line in self.text.splitlines()
                    if not line.lstrip().startswith("#")
                    and not line.lstrip().startswith("cat <<")
                )
                self.assertNotIn(forbidden, code)

    def test_optional_installs_are_guarded(self):
        code = self.text
        self.assertIn('[[ "$hw" == cm4 ]]', code)
        self.assertIn('[[ "$os" == debian || "$os" == kali ]]', code)
        self.assertIn('mixed_sources', code)
        self.assertIn('[[ "$AIO" == yes && "$os" != debian ]]', code)
        self.assertIn('[[ "$KALI" == yes && "$os" != kali ]]', code)
        self.assertIn('apt-get -s --no-remove', code)
        self.assertIn("grep -q '^Remv '", code)
        self.assertIn('backup_configs ||', code)
        self.assertIn('if [[ "$DRY" == yes ]]', code)


if __name__ == "__main__":
    unittest.main()
