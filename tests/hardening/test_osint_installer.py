"""Tests for OSINT/Playbook/install_dependencies.sh (R3/R4 plus supply-chain checks).

The script is sourced (main() is guarded). HOME points at a temp directory and
every external command is a PATH shim, so nothing is installed or downloaded.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "OSINT" / "Playbook" / "install_dependencies.sh"
BASH = shutil.which("bash")  # absolute: tests restrict PATH to shims


class OsintInstallerBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.shims = self.root / "shims"
        self.shims.mkdir()
        self.pins = self.root / "pins.conf"
        self.pins.write_text("")
        self.calls = self.root / "calls.log"
        self.calls.write_text("")

    def shim(self, name, body="exit 0\n"):
        p = self.shims / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(0o755)
        return p

    def run_script(self, snippet, env=None, path=None):
        full_env = {
            "PATH": path if path is not None else f"{self.shims}:/usr/bin:/bin",
            "HOME": str(self.home),
        }
        full_env.update(env or {})
        prelude = (
            f'source "{SCRIPT}"\nset +e\n'
            f'PINS_FILE="{self.pins}"; LOGFILE=/dev/null\n'
        )
        return subprocess.run([BASH, "-c", prelude + snippet],
                              capture_output=True, text=True, env=full_env)


class VerifyInstallationTests(OsintInstallerBase):
    """R4: the missing-tool counter must not abort under set -e, and the result
    must be reported honestly."""

    MINIMAL = ["holehe", "h8mail", "maigret", "sherlock", "phoneinfoga", "nmap", "whois", "dig"]
    FULL_EXTRA = ["subfinder", "httpx", "dnsx", "waybackurls"]

    def populate(self, names):
        for n in names:
            self.shim(n)

    def verify(self, mode):
        # Source with a normal PATH (the script needs dirname/stat), then restrict
        # PATH to the shim dir so nothing from the host can satisfy `command -v`.
        return self.run_script(
            f'PATH="{self.shims}"; set -e; verify_installation {mode} && rc=0 || rc=$?; echo "rc=$rc"; echo reached')

    def test_zero_missing_succeeds(self):
        self.populate(self.MINIMAL)
        r = self.verify("minimal")
        self.assertIn("rc=0", r.stdout, r.stderr)
        self.assertIn("All expected tools are present", r.stdout)

    def test_one_missing_reports_and_fails_without_aborting(self):
        self.populate([t for t in self.MINIMAL if t != "sherlock"])
        r = self.verify("minimal")
        self.assertIn("1 expected tool(s) missing", r.stdout)
        self.assertIn("rc=1", r.stdout)
        self.assertIn("reached", r.stdout)       # the counter did not kill the shell
        self.assertNotIn("All expected tools are present", r.stdout)

    def test_multiple_missing_gives_complete_summary(self):
        self.populate(["holehe", "nmap"])
        r = self.verify("minimal")
        missing = len(self.MINIMAL) - 2
        self.assertIn(f"{missing} expected tool(s) missing", r.stdout)
        for t in self.MINIMAL:
            self.assertIn(t, r.stdout)           # every tool is listed, none skipped
        self.assertIn("rc=1", r.stdout)

    def test_full_mode_also_requires_go_tools(self):
        self.populate(self.MINIMAL)
        r = self.verify("full")
        self.assertIn(f"{len(self.FULL_EXTRA)} expected tool(s) missing", r.stdout)
        self.populate(self.FULL_EXTRA)
        self.assertIn("rc=0", self.verify("full").stdout)

    def test_minimal_mode_does_not_require_go_tools(self):
        self.populate(self.MINIMAL)
        self.assertIn("rc=0", self.verify("minimal").stdout)

    def test_expected_sherlock_executable_is_sherlock(self):
        text = SCRIPT.read_text()
        self.assertIn("sherlock-project sherlock", text)       # package -> executable
        self.assertIn("The Sherlock OSINT package is sherlock-project; its executable is sherlock.", text)
        self.assertNotIn('Sherlock\'s published PyPI name is just "sherlock"', text)


class VenvToolTests(OsintInstallerBase):
    def make_venv(self, name, executables=()):
        d = self.home / ".local" / "share" / "osint-investigator" / "venvs" / name
        (d / "bin").mkdir(parents=True)
        py = d / "bin" / "python"
        py.write_text(f'#!/bin/sh\necho "{name}: python $*" >> "{self.calls}"\n')
        py.chmod(0o755)
        for e in executables:
            x = d / "bin" / e
            x.write_text("#!/bin/sh\n")
            x.chmod(0o755)
        return d

    def test_pinned_package_installed_into_isolated_venv_and_linked(self):
        self.pins.write_text("pip:sherlock-project=0.16.2\n")
        d = self.make_venv("sherlock", ["sherlock"])
        (self.home / ".local" / "bin").mkdir(parents=True)
        r = self.run_script('OSINT_HOME="$HOME/.local/share/osint-investigator"; BIN_DIR="$HOME/.local/bin"; '
                            'venv_tool sherlock sherlock-project sherlock; echo "F=${FAILED_TOOLS[*]:-none}"')
        self.assertIn("F=none", r.stdout, r.stderr)
        self.assertIn("pip install --quiet sherlock-project==0.16.2", self.calls.read_text())
        link = self.home / ".local" / "bin" / "sherlock"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), str(d / "bin" / "sherlock"))

    def test_missing_executable_after_install_is_a_reported_failure(self):
        self.pins.write_text("pip:sherlock-project=0.16.2\n")
        self.make_venv("sherlock", [])
        (self.home / ".local" / "bin").mkdir(parents=True)
        r = self.run_script('OSINT_HOME="$HOME/.local/share/osint-investigator"; BIN_DIR="$HOME/.local/bin"; '
                            'venv_tool sherlock sherlock-project sherlock; echo "F=${FAILED_TOOLS[*]}"')
        self.assertIn("executable missing", r.stdout)
        self.assertFalse((self.home / ".local" / "bin" / "sherlock").exists())

    def test_pip_failure_is_recorded_not_swallowed(self):
        self.pins.write_text("pip:holehe=1.61\n")
        d = self.make_venv("holehe", ["holehe"])
        (d / "bin" / "python").write_text("#!/bin/sh\nexit 1\n")
        r = self.run_script('OSINT_HOME="$HOME/.local/share/osint-investigator"; BIN_DIR="$HOME/.local/bin"; '
                            'mkdir -p "$BIN_DIR"; venv_tool holehe holehe holehe; echo "F=${FAILED_TOOLS[*]}"')
        self.assertIn("F=pip:holehe", r.stdout)

    def test_unpinned_package_is_skipped(self):
        r = self.run_script('OSINT_HOME="$HOME/.local/share/osint-investigator"; BIN_DIR="$HOME/.local/bin"; '
                            'venv_tool x somepkg somepkg; echo "S=${SKIPPED_TOOLS[*]}"')
        self.assertIn("S=pip:somepkg (no pin)", r.stdout)
        self.assertFalse((self.home / ".local" / "share").exists())


class SupplyChainTests(OsintInstallerBase):
    def test_asn_without_pin_is_not_installed_and_is_reported(self):
        r = self.run_script('OSINT_HOME="$HOME/.local/share/osint-investigator"; BIN_DIR="$HOME/.local/bin"; '
                            'mkdir -p "$BIN_DIR"; install_asn_tool; echo "M=${MANUAL_TOOLS[*]}"')
        self.assertIn("M=asn (pin dl:asn:commit", r.stdout)
        self.assertEqual(list((self.home / ".local" / "bin").iterdir()), [])

    def test_phoneinfoga_without_pin_is_skipped(self):
        r = self.run_script('BIN_DIR="$HOME/.local/bin"; install_phoneinfoga; echo "S=${SKIPPED_TOOLS[*]}"')
        self.assertIn("no pinned version", r.stdout)

    def test_git_app_without_pin_creates_nothing(self):
        r = self.run_script('TOOLS_DIR="$HOME/tools"; PNWC_TOOLS_DIR="$TOOLS_DIR"; '
                            'OSINT_HOME="$HOME/osint"; BIN_DIR="$HOME/bin"; '
                            'python_app_from_git spiderfoot https://example.invalid/s.git requirements.txt sf.py spiderfoot; '
                            'echo "S=${SKIPPED_TOOLS[*]}"')
        self.assertIn("S=git:spiderfoot (no pin)", r.stdout)
        self.assertFalse((self.home / "tools").exists())
        self.assertFalse((self.home / "osint").exists())

    def test_go_tools_skip_without_pins_and_never_use_latest(self):
        self.shim("go", f'echo "go $*" >> "{self.calls}"\n')
        r = self.run_script('PNWC_GOPATH="$HOME/go"; install_go_tools; echo "S=${SKIPPED_TOOLS[*]}"')
        self.assertIn("go:github.com/projectdiscovery/subfinder/v2/cmd/subfinder (no pin)", r.stdout)
        self.assertNotIn("go install", self.calls.read_text())

    def test_wrapper_quotes_paths_safely(self):
        out = self.root / "wrap"
        # No slash in the name (illegal in a directory name); shell metacharacters only.
        weird = self.root / "a b;touch pwned1 $(touch pwned2) `touch pwned3`"
        weird.mkdir()
        py = weird / "python"
        py.write_text("#!/bin/sh\nexit 0\n")
        py.chmod(0o755)
        entry = weird / "entry.py"
        # Paths go through the environment so the harness itself never evaluates them.
        r = self.run_script('write_wrapper "$W_OUT" "$W_PY" "$W_ENTRY"',
                            env={"W_OUT": str(out), "W_PY": str(py), "W_ENTRY": str(entry)})
        self.assertEqual(r.returncode, 0, r.stderr)
        work = self.root / "cwd"
        work.mkdir()
        subprocess.run([BASH, str(out)], capture_output=True, cwd=work)
        for d in (work, self.root, Path.cwd()):
            for marker in ("pwned1", "pwned2", "pwned3"):
                self.assertFalse((d / marker).exists(), f"{marker} in {d}")

    @unittest.skipUnless(os.geteuid() == 0, "root-refusal can only be exercised as root")
    def test_refuses_to_run_as_root(self):
        r = subprocess.run([BASH, str(SCRIPT), "--minimal"], capture_output=True, text=True,
                           env={"PATH": os.environ["PATH"], "HOME": str(self.home)})
        self.assertEqual(r.returncode, 1)
        self.assertIn("Do not run this installer as root", r.stderr)

    def test_unknown_argument_exits_nonzero(self):
        r = subprocess.run([BASH, str(SCRIPT), "--bogus"], capture_output=True, text=True,
                           env={"PATH": os.environ["PATH"], "HOME": str(self.home)})
        self.assertEqual(r.returncode, 2)
        self.assertIn("Unknown argument", r.stderr)

    def test_help_exits_zero(self):
        r = subprocess.run([BASH, str(SCRIPT), "--help"], capture_output=True, text=True,
                           env={"PATH": os.environ["PATH"], "HOME": str(self.home)})
        self.assertEqual(r.returncode, 0)
        self.assertIn("--allow-unpinned", r.stdout)

    def test_refuses_world_writable_helper_library(self):
        tree = self.root / "tree"
        (tree / "OSINT" / "Playbook").mkdir(parents=True)
        (tree / "Scripts" / "lib").mkdir(parents=True)
        shutil.copy(SCRIPT, tree / "OSINT" / "Playbook" / "install_dependencies.sh")
        lib = tree / "Scripts" / "lib" / "safe_install.sh"
        shutil.copy(REPO / "Scripts" / "lib" / "safe_install.sh", lib)
        lib.chmod(0o666)
        r = subprocess.run([BASH, str(tree / "OSINT" / "Playbook" / "install_dependencies.sh"), "--help"],
                           capture_output=True, text=True, env={"PATH": os.environ["PATH"], "HOME": str(self.home)})
        self.assertEqual(r.returncode, 1)
        self.assertIn("refusing to continue", r.stderr)


class StaticGuards(unittest.TestCase):
    def code(self):
        return "\n".join(l for l in SCRIPT.read_text().splitlines() if not l.lstrip().startswith("#"))

    def test_no_unsafe_patterns(self):
        code = self.code()
        self.assertNotIn("--break-system-packages", code)
        self.assertNotRegex(code, r"curl[^\n]*\|\s*(ba)?sh")
        self.assertNotIn("@latest", code)
        # The wrapper's `#!/usr/bin/env bash` shebang is the only allowed /usr/bin reference.
        self.assertNotIn("/usr/bin/", code.replace("/usr/bin/env bash", ""))
        self.assertNotIn("/usr/local/bin", code)
        self.assertNotIn("pacman -Sy ", code)
        # No direct network commands: all downloads go through the verified helpers.
        self.assertNotRegex(code, r"(?m)^\s*(curl|wget)\s")
        self.assertNotRegex(code, r"\$\(\s*(curl|wget)\s")
        self.assertNotIn("| tee", code)

    def test_no_dangling_set_e_arithmetic(self):
        code = self.code()
        # `(( n++ ))` and `$((n++))` style post-increments return status 1 when n is 0.
        self.assertNotRegex(code, r"\(\(\s*\w+\+\+")
        self.assertNotRegex(code, r"\+\+\s*\)\)")
        self.assertIn("missing=$((missing + 1))", code)

    def test_both_package_names_use_sherlock_project(self):
        self.assertEqual(SCRIPT.read_text().count("sherlock-project"), 2)  # comment + venv_tool call


if __name__ == "__main__":
    unittest.main()
