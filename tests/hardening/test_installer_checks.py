"""Behavioural tests for Scripts/pnwc_install_tools.sh pinning/verification logic.

The script is sourced (its main() is guarded), with LOGFILE, INSTALL_DIR and the
pins file redirected to a temporary directory. `go` and the venv python are PATH
shims that only record their arguments, so nothing is installed or downloaded.
"""
import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "Scripts" / "pnwc_install_tools.sh"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class InstallerBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.install_dir = self.root / "opt"
        (self.install_dir / "venv" / "bin").mkdir(parents=True)
        self.pins = self.root / "pins.conf"
        self.pins.write_text("")
        self.bin = self.root / "shims"
        self.bin.mkdir()
        self.calls = self.root / "calls.log"
        self.calls.write_text("")
        # `go` shim: records its argv and succeeds.
        self.shim("go", f'echo "go $*" >> "{self.calls}"\n')
        # venv python shim: records `-m pip install ...`.
        py = self.install_dir / "venv" / "bin" / "python"
        py.write_text(f'#!/bin/sh\necho "python $*" >> "{self.calls}"\n')
        py.chmod(0o755)

    def shim(self, name, body):
        p = self.bin / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(0o755)

    def run_script(self, snippet, env=None):
        full_env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.root),
        }
        full_env.update(env or {})
        prelude = (
            f'source "{SCRIPT}"\n'
            "set +e\n"
            f'LOGFILE=/dev/null; INSTALL_DIR="{self.install_dir}"; PINS_FILE="{self.pins}"\n'
        )
        return subprocess.run(["bash", "-c", prelude + snippet],
                              capture_output=True, text=True, env=full_env)

    def calls_text(self):
        return self.calls.read_text()


class GoInstallTests(InstallerBase):
    def test_unpinned_is_skipped_and_go_never_runs(self):
        r = self.run_script('go_install "github.com/x/y/cmd/z"; echo "SKIPPED=${SKIPPED_TOOLS[*]}"')
        self.assertIn("SKIPPED=go:github.com/x/y/cmd/z (no pin)", r.stdout)
        self.assertNotIn("go install", self.calls_text())

    def test_pinned_version_is_used_even_if_caller_passes_latest(self):
        self.pins.write_text("go:github.com/x/y/cmd/z=v1.2.3\n")
        self.run_script('go_install "github.com/x/y/cmd/z@latest"')
        self.assertIn("go install github.com/x/y/cmd/z@v1.2.3", self.calls_text())
        self.assertNotIn("@latest", self.calls_text())

    def test_allow_unpinned_installs_latest_and_records_it(self):
        r = self.run_script('go_install "github.com/x/y/cmd/z"; echo "U=${UNPINNED_USED[*]}"',
                            env={"PNWC_ALLOW_UNPINNED": "1"})
        self.assertIn("go install github.com/x/y/cmd/z@latest", self.calls_text())
        self.assertIn("U=go:github.com/x/y/cmd/z", r.stdout)

    def test_invalid_pin_fails_and_does_not_fall_back_to_latest(self):
        self.pins.write_text("go:github.com/x/y/cmd/z=latest\n")
        r = self.run_script('go_install "github.com/x/y/cmd/z"; echo "F=${FAILED_TOOLS[*]}"',
                            env={"PNWC_ALLOW_UNPINNED": "1"})
        self.assertIn("F=go:github.com/x/y/cmd/z (invalid pin)", r.stdout)
        self.assertNotIn("go install", self.calls_text())

    def test_gosumdb_off_is_refused(self):
        self.pins.write_text("go:github.com/x/y/cmd/z=v1.0.0\n")
        r = self.run_script('go_install "github.com/x/y/cmd/z"; echo "F=${FAILED_TOOLS[*]}"',
                            env={"GOSUMDB": "off"})
        self.assertIn("GOSUMDB=off", r.stdout)
        self.assertNotIn("go install", self.calls_text())


class PipTests(InstallerBase):
    def test_pinned_pip_uses_exact_version(self):
        self.pins.write_text("pip:requests=2.34.2\n")
        self.run_script("pip_install requests")
        self.assertIn("pip install --quiet requests==2.34.2", self.calls_text())

    def test_unpinned_pip_skipped(self):
        r = self.run_script('pip_install somepkg; echo "S=${SKIPPED_TOOLS[*]}"')
        self.assertIn("S=pip:somepkg (no pin)", r.stdout)
        self.assertNotIn("somepkg", self.calls_text())

    def test_invalid_pin_is_failure_not_unpinned(self):
        self.pins.write_text("pip:somepkg=latest\n")
        r = self.run_script('pip_install somepkg; echo "F=${FAILED_TOOLS[*]}"',
                            env={"PNWC_ALLOW_UNPINNED": "1"})
        self.assertIn("F=pip:somepkg (invalid pin)", r.stdout)
        self.assertNotIn("somepkg", self.calls_text())

    def test_package_name_with_url_or_spaces_rejected(self):
        for bad in ("git+https://evil/x.git", "a b", "x;y", "../x"):
            r = self.run_script(f'pip_install "{bad}"; echo "F=${{FAILED_TOOLS[*]}}"')
            self.assertNotIn("python -m pip", self.calls_text(), bad)

    def test_shipped_pins_cover_every_pip_package_the_script_installs(self):
        shipped = (REPO / "Scripts" / "tool_pins.conf").read_text()
        for pkg in ("pip", "setuptools", "wheel", "pipx", "shodan", "censys", "holehe",
                    "h8mail", "maigret", "osrframework", "volatility3", "impacket", "scapy"):
            self.assertRegex(shipped, rf"(?m)^pip:{pkg}=\S+$", pkg)


class GitCloneTests(InstallerBase):
    def make_repo(self, name):
        d = self.install_dir / name
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        (d / "f").write_text("x")
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        subprocess.run(["git", "-C", str(d), "add", "f"], check=True, env=env)
        subprocess.run(["git", "-C", str(d), "commit", "-q", "-m", "c"], check=True, env=env)
        return subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()

    def test_non_https_url_refused(self):
        r = self.run_script('git_clone_tool tool "http://example.invalid/t.git"; echo "F=${FAILED_TOOLS[*]}"')
        self.assertIn("F=git:tool (non-https url)", r.stdout)
        self.assertFalse((self.install_dir / "tool").exists())

    def test_bad_tool_name_refused(self):
        self.run_script('git_clone_tool "../evil" "https://example.invalid/t.git"')
        self.assertFalse((self.root / "evil").exists())

    def test_unpinned_is_skipped(self):
        r = self.run_script('git_clone_tool tool "https://example.invalid/t.git"; echo "S=${SKIPPED_TOOLS[*]}"')
        self.assertIn("S=git:tool (no pin)", r.stdout)
        self.assertFalse((self.install_dir / "tool").exists())

    def test_invalid_pin_fails(self):
        self.pins.write_text("git:tool=main\n")
        r = self.run_script('git_clone_tool tool "https://example.invalid/t.git"; echo "F=${FAILED_TOOLS[*]}"',
                            env={"PNWC_ALLOW_UNPINNED": "1"})
        self.assertIn("F=git:tool (invalid pin)", r.stdout)

    def test_existing_checkout_at_pin_is_accepted_without_network(self):
        commit = self.make_repo("tool")
        self.pins.write_text(f"git:tool={commit}\n")
        r = self.run_script('git_clone_tool tool "https://example.invalid/t.git"; echo "F=${FAILED_TOOLS[*]:-none}"')
        self.assertIn("already at pinned commit", r.stdout)
        self.assertIn("F=none", r.stdout)

    def test_existing_checkout_not_at_pin_is_left_untouched_and_reported(self):
        self.make_repo("tool")
        self.pins.write_text("git:tool=" + "b" * 40 + "\n")
        r = self.run_script('git_clone_tool tool "https://example.invalid/t.git"; echo "F=${FAILED_TOOLS[*]}"')
        self.assertIn("existing checkout differs from pin", r.stdout)
        self.assertTrue((self.install_dir / "tool" / "f").exists())

    def test_existing_unpinned_checkout_is_not_pulled(self):
        self.make_repo("tool")
        self.shim("git", f'echo "git $*" >> "{self.calls}"; exit 1\n')
        r = self.run_script('git_clone_tool tool "https://example.invalid/t.git"')
        self.assertNotIn("pull", self.calls_text())
        self.assertIn("not updating", r.stdout)


class FetchPinnedTests(InstallerBase):
    ENV = {"SAFE_ALLOW_FILE_URLS": "1"}

    def setUp(self):
        super().setUp()
        self.src = self.root / "src.bin"
        self.src.write_bytes(b"payload")
        self.dest = self.root / "dest.bin"

    def fetch(self, snippet_args=None):
        return self.run_script(
            f'fetch_pinned tool any "{self.src.as_uri()}" "{self.dest}"; echo "rc=$? '
            f'S=${{SKIPPED_TOOLS[*]}} F=${{FAILED_TOOLS[*]}}"', env=self.ENV)

    def test_no_pin_means_no_download_and_allow_unpinned_does_not_bypass(self):
        for env in (self.ENV, dict(self.ENV, PNWC_ALLOW_UNPINNED="1")):
            self.dest.unlink(missing_ok=True)
            r = self.run_script(
                f'fetch_pinned tool any "{self.src.as_uri()}" "{self.dest}"; echo "rc=$?"', env=env)
            self.assertIn("rc=10", r.stdout)
            self.assertFalse(self.dest.exists())

    def test_matching_pin_downloads(self):
        self.pins.write_text(f"dl:tool:sha256:any={sha256(b'payload')}\n")
        r = self.fetch()
        self.assertIn("rc=0", r.stdout)
        self.assertEqual(self.dest.read_bytes(), b"payload")

    def test_mismatch_is_failure_and_leaves_nothing(self):
        self.pins.write_text(f"dl:tool:sha256:any={sha256(b'other')}\n")
        r = self.fetch()
        self.assertIn("rc=3", r.stdout)
        self.assertIn("checksum mismatch", r.stdout)
        self.assertFalse(self.dest.exists())

    def test_malformed_pin_is_treated_as_absent(self):
        self.pins.write_text("dl:tool:sha256:any=not-hex\n")
        r = self.fetch()
        self.assertIn("rc=2", r.stdout)
        self.assertFalse(self.dest.exists())


class ReleasePrereqTests(InstallerBase):
    def test_missing_version_skips(self):
        r = self.run_script('release_prereqs jadx any; echo "rc=$? S=${SKIPPED_TOOLS[*]}"')
        self.assertIn("rc=1", r.stdout)
        self.assertIn("no pinned version", r.stdout)

    def test_unsupported_architecture_skips(self):
        self.pins.write_text("dl:tool:version=v1.0.0\n")
        r = self.run_script('release_prereqs tool; echo "rc=$? S=${SKIPPED_TOOLS[*]}"',
                            env={"SAFE_UNAME_M": "armv7l"})
        self.assertIn("rc=1", r.stdout)
        self.assertIn("unsupported architecture armv7l", r.stdout)

    def test_supported_architecture_and_version(self):
        self.pins.write_text("dl:tool:version=v1.0.0\n")
        r = self.run_script('release_prereqs tool; echo "rc=$? V=$REL_VER A=$REL_ARCH"',
                            env={"SAFE_UNAME_M": "aarch64"})
        self.assertIn("rc=0 V=v1.0.0 A=arm64", r.stdout)

    def test_arch_independent_artifact_ignores_architecture(self):
        self.pins.write_text("dl:tool:version=v1.0.0\n")
        r = self.run_script('release_prereqs tool any; echo "rc=$? A=$REL_ARCH"',
                            env={"SAFE_UNAME_M": "armv7l"})
        self.assertIn("rc=0 A=any", r.stdout)

    def test_commit_pin_is_accepted_and_malformed_commit_is_not(self):
        good = "a" * 40
        self.pins.write_text(f"dl:tool:commit={good}\n")
        r = self.run_script('release_prereqs tool any; echo "rc=$? V=$REL_VER"')
        self.assertIn(f"rc=0 V={good}", r.stdout)
        self.pins.write_text("dl:tool:commit=master\n")
        r = self.run_script('release_prereqs tool any; echo "rc=$? V=[$REL_VER]"')
        self.assertIn("rc=1 V=[]", r.stdout)


class SummaryAndTrustTests(InstallerBase):
    def test_summary_does_not_claim_success_when_installs_failed(self):
        r = self.run_script('FAILED_TOOLS=("x"); print_summary')
        self.assertIn("FINISHED WITH 1 FAILURE", r.stdout)
        self.assertNotIn("INSTALLATION COMPLETE", r.stdout)

    def test_summary_without_failures(self):
        r = self.run_script("print_summary")
        self.assertIn("INSTALLATION FINISHED", r.stdout)
        self.assertNotIn("FAILURE", r.stdout)

    def test_trusted_file_rules(self):
        f = self.root / "f"
        f.write_text("x")
        f.chmod(0o644)
        self.assertEqual(self.run_script(f'trusted_file "{f}"; echo $?').stdout.strip(), "0")
        f.chmod(0o664)
        self.assertEqual(self.run_script(f'trusted_file "{f}"; echo $?').stdout.strip(), "1")
        f.chmod(0o646)
        self.assertEqual(self.run_script(f'trusted_file "{f}"; echo $?').stdout.strip(), "1")
        f.chmod(0o644)
        link = self.root / "l"
        link.symlink_to(f)
        self.assertEqual(self.run_script(f'trusted_file "{link}"; echo $?').stdout.strip(), "1")

    def test_script_refuses_to_run_with_world_writable_lib(self):
        tree = self.root / "tree" / "Scripts"
        (tree / "lib").mkdir(parents=True)
        shutil.copy(SCRIPT, tree / "pnwc_install_tools.sh")
        shutil.copy(REPO / "Scripts" / "lib" / "safe_install.sh", tree / "lib" / "safe_install.sh")
        (tree / "lib" / "safe_install.sh").chmod(0o666)
        r = subprocess.run(["bash", str(tree / "pnwc_install_tools.sh"), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("refusing to continue", r.stderr)

    def test_print_proposed_pins_for_go_and_pip(self):
        self.shim("go", 'printf "/opt/go/bin/z: go1.22\\n\\tpath\\tx/y/cmd/z\\n\\tmod\\tx/y\\tv9.9.9\\th1:abc\\n"\n')
        py = self.install_dir / "venv" / "bin" / "python"
        py.write_text('#!/bin/sh\necho "Name: p"; echo "Version: 3.4.5"\n')
        py.chmod(0o755)
        r = self.run_script('UNPINNED_USED=("go:x/y/cmd/z" "pip:p"); print_proposed_pins')
        self.assertIn("go:x/y/cmd/z=v9.9.9", r.stdout)
        self.assertIn("pip:p=3.4.5", r.stdout)


class NoRawDownloadTests(unittest.TestCase):
    """Static guards so unsafe patterns cannot creep back in."""

    def test_no_predictable_tmp_paths_or_latest_lookups(self):
        text = SCRIPT.read_text()
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotIn("/tmp/", code)
        self.assertNotIn("releases/latest", code)
        self.assertNotIn("api.github.com", code)
        self.assertNotRegex(code, r"curl[^\n]*\|\s*(ba)?sh")
        self.assertNotIn(" pull -q", code)

    def test_every_go_install_call_site_omits_a_version(self):
        for line in SCRIPT.read_text().splitlines():
            if line.strip().startswith("go_install \""):
                self.assertNotIn("@", line, line)


if __name__ == "__main__":
    unittest.main()
