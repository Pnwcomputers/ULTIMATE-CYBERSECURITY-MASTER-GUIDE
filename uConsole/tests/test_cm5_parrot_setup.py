"""Fixture tests only: never install packages or access real CM5 hardware."""
import os
import pathlib
import shlex
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/uconsole-cm5-parrot-setup.sh"


class ParrotSetupTests(unittest.TestCase):
    def shell(self, body, root, input_text=None):
        prefix = "source " + shlex.quote(str(SCRIPT)) + "\n"
        prefix += "fixture=" + shlex.quote(str(root)) + "\n"
        prefix += """
STATE_DIR="$fixture/state"
STATE_FILE="$STATE_DIR/cm5-state"
VERSION_FILE="$STATE_DIR/cm5-version"
LOG_FILE="$fixture/log"
APT_DIR="$fixture/apt"
OS_RELEASE="$fixture/os-release"
MODEL_FILE="$fixture/model"
DRY_RUN=yes
"""
        env = dict(os.environ)
        for name in ("INSTALL_AIO", "INSTALL_PARROT_TOOLS", "INSTALL_WIFI_DKMS",
                     "PARROT_METAPACKAGE", "WIFI_DKMS_PACKAGE", "HOSTNAME_NEW",
                     "DRY_RUN", "ASSUME_YES"):
            env.pop(name, None)
        return subprocess.run(["bash", "-c", prefix + body], input=input_text,
                              text=True, capture_output=True, env=env)

    def test_syntax_and_help(self):
        result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No OS conversion", result.stdout)

    def test_only_parrot_accepted(self):
        for release, allowed in [
            ("ID=parrot\nVERSION_ID=7.2\n", True),
            ("ID=Parrot\n", True),
            ("ID=debian\nID_LIKE=parrot\n", False),
            ("ID=kali\n", False),
            ("ID=ubuntu\nID_LIKE=debian\n", False),
        ]:
            with self.subTest(release=release), tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                (root / "os-release").write_text(release)
                result = self.shell("detect_os", root)
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_sources(self):
        examples = [
            ("kali.list", "deb https://http.kali.org/kali kali-rolling main\n", False),
            ("local.list", "deb https://mirror.example/os kali-rolling main\n", False),
            ("mixed.sources", "Types: deb\nURIs: https://mirror.example/os\nSuites:\n kali-rolling\n", False),
            ("off.sources", "Types: deb\nURIs: https://http.kali.org/kali\nSuites: kali-rolling\nEnabled: no\n", True),
            ("safe.list", "# deb https://http.kali.org/kali kali-rolling main\ndeb https://deb.parrot.sh/parrot echo main\n", True),
            ("multi.sources", "Types: deb\nURIs: https://http.kali.org/kali\nEnabled: no\n\nTypes: deb\nURIs: https://mirror.example\nSuites: kali-rolling\n", False),
        ]
        for name, content, allowed in examples:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                sources = root / "apt/sources.list.d"
                sources.mkdir(parents=True)
                (sources / name).write_text(content)
                result = self.shell("check_sources", root)
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_plan_guards(self):
        for plan, allowed in [
            ("Inst nmap (7.95 Parrot:stable [arm64])\n", True),
            ("Inst parrot-tools-wireless (7.0 Parrot:stable [arm64])\n", True),
            ("Inst linux-image-6.12-rex (1.0 local [arm64])\n", False),
            ("Inst libfm4t64:arm64 [1.0] (2.0 Parrot [arm64])\n", False),
            ("Inst labwc [1.0] (2.0 Parrot [arm64])\n", False),
            ("Conf lightdm (1.0 Parrot [arm64])\n", False),
            ("Inst parrot-interface (7.0 Parrot [arm64])\n", False),
            ("Inst network-manager (1.0 Parrot [arm64])\n", False),
            ("Remv unrelated-package [1.0]\n", False),
        ]:
            with self.subTest(plan=plan), tempfile.TemporaryDirectory() as d:
                result = self.shell("check_package_plan", pathlib.Path(d), plan)
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_recommendations_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.shell("""
detect_os() { printf 'parrot\\n'; }
install_packages() { printf '%s\\n' "$@"; }
parse_args --parrot-meta=parrot-tools-wireless
phase_parrot_tools
""", pathlib.Path(d))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["--install-recommends", "parrot-tools-wireless"])

    def test_update_failure_prevents_resolution(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.shell("""
DRY_RUN=no
INSTALL_PARROT_TOOLS=yes
run() { printf 'UPDATE_FAILED\\n'; return 42; }
simulate_packages() { printf 'UNEXPECTED_SIMULATION\\n'; }
prepare_packages
""", pathlib.Path(d))
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("UNEXPECTED_SIMULATION", result.stdout)

    def test_blocked_or_failed_plan_never_installs(self):
        for mock in [
            "apt-get() { printf 'Inst lightdm (1.0 Parrot [arm64])\\n'; }",
            "apt-get() { printf 'Unable to locate package\\n'; return 100; }",
        ]:
            with self.subTest(mock=mock), tempfile.TemporaryDirectory() as d:
                result = self.shell(mock + """
run() { printf 'UNEXPECTED_INSTALL\\n'; }
install_packages --install-recommends parrot-tools-wireless
""", pathlib.Path(d))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("UNEXPECTED_INSTALL", result.stdout)

    def test_dry_run_does_not_write_or_refresh_lists(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            result = self.shell("""
preflight_checks() { :; }
detect_os() { printf 'parrot\\n'; }
apt-get() {
    [[ "$1" == --simulate ]] || { printf 'UNEXPECTED_APT_WRITE\\n'; return 99; }
    printf 'Inst nmap (7.95 Parrot [arm64])\\n'
}
main --dry-run --install-parrot-tools --with-aio
""", root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("UNEXPECTED_APT_WRITE", result.stdout)
            self.assertEqual(list(root.iterdir()), [])

    def test_default_has_no_package_operations(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.shell("""
preflight_checks() { :; }
apt-get() { printf 'UNEXPECTED_APT\\n'; return 99; }
main --dry-run
""", pathlib.Path(d))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("UNEXPECTED_APT", result.stdout)

    def test_forced_phase_ignores_other_package_flags(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.shell("""
parse_args --phase=preflight --with-aio --install-parrot-tools
apt-get() { printf 'UNEXPECTED_APT\\n'; return 99; }
prepare_packages
""", pathlib.Path(d))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("UNEXPECTED_APT", result.stdout)

    def test_failure_does_not_record_completion(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            result = self.shell("""
DRY_RUN=no
preflight_checks() { :; }
backup_config() { :; }
phase_aio() { return 42; }
main --yes
""", root)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "state/cm5-state").exists())
            self.assertNotIn("Phase: peripherals", result.stdout)

    def test_forced_phase_does_not_record_completion(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            result = self.shell("""
DRY_RUN=no
preflight_checks() { :; }
backup_config() { :; }
main --phase=preflight --yes
""", root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "state/cm5-state").exists())

    def test_invalid_arguments(self):
        for arg in ["--parrot-meta=kali-tools-top10", "--parrot-meta=parrot-tools;id",
                    "--parrot-meta=parrot-desktop-kde", "--wifi-dkms=--help",
                    "--hostname=x;id", "--phase=kali_tools", "--install-kali-tools"]:
            with self.subTest(arg=arg), tempfile.TemporaryDirectory() as d:
                result = self.shell("parse_args " + shlex.quote(arg), pathlib.Path(d))
                self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
