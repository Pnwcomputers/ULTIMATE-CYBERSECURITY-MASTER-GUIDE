"""Hermetic uConsole CM4 safety regressions; never change host packages or storage."""
from pathlib import Path
import subprocess
import shlex
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

    def fixture(self, os_name="debian", hw_name="cm4", mixed=False, args="--status"):
        # Override *functions* in an isolated Bash subprocess. No host changes,
        # package-manager shims or physical CM4 hardware are touched.
        source = shlex.quote(str(SCRIPT))
        mixed_result = "return 0" if mixed else "return 1"
        program = (
            f"source {source}\n"
            f"os_name() {{ echo {shlex.quote(os_name)}; }}\n"
            f"hw_name() {{ echo {shlex.quote(hw_name)}; }}\n"
            f"mixed_sources() {{ {mixed_result}; }}\n"
            f"main {args}\n"
        )
        return subprocess.run(["bash", "-c", program], capture_output=True, text=True)

    def test_debian_readonly_default(self):
        r = self.fixture(args="")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Read-only preflight complete", r.stdout)

    def test_debian_aio_dry_run(self):
        r = self.fixture(args="--with-aio --dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DRY RUN", r.stdout)

    def test_cross_distribution_install_is_refused(self):
        r = self.fixture(args="--kali-tools --dry-run")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("native Kali", r.stderr)

    def test_kali_can_preview_kali_metapackage(self):
        r = self.fixture(os_name="kali", args="--kali-tools --dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_wrong_hardware_and_mixed_repos_refused(self):
        a = self.fixture(hw_name="cm5", args="--with-aio --dry-run")
        b = self.fixture(mixed=True, args="--with-aio --dry-run")
        self.assertNotEqual(a.returncode, 0)
        self.assertNotEqual(b.returncode, 0)

    def test_status_cannot_trigger_install(self):
        r = self.fixture(args="--status --with-aio --dry-run")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--status", r.stderr)

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
