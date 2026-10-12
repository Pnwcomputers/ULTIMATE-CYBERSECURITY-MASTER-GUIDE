"""R8: domain_monitor must not report a failed collection as 'no records' or 'clean'."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "OSINT" / "Playbook" / "scripts" / "domain_monitor.sh"
BASH = shutil.which("bash")


class MonitorBase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.shims = self.root / "shims"
        self.shims.mkdir()
        self.mon = self.home / ".config" / "osint-investigator" / "monitor" / "example.org"

    def tearDown(self):
        self._t.cleanup()

    def shim(self, name, body):
        p = self.shims / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(0o755)

    def good_tools(self, a="1.2.3.4"):
        # dig fails (rc 9, stderr message) when DIG_FAIL=1, otherwise answers
        self.shim("dig", f'if [ -n "$DIG_FAIL" ]; then echo ";; no servers could be reached" >&2; exit 9; fi\necho {a}\n')
        self.shim("whois", 'echo "Registrar: Example Registrar"\n')
        self.shim("openssl", 'if [ "$1" = s_client ]; then echo CERT; else echo "subject=CN=example.org"; fi\n')
        self.shim("curl", 'for a in "$@"; do case "$a" in *crt.sh*) echo "[{},{}]"; exit 0;; esac; done\n'
                         'echo "HTTP/2 200"; echo "server: nginx"; echo "HTTP_CODE=200"\n')

    def run_mon(self, *args, env=None):
        e = {"PATH": f"{self.shims}:{os.environ['PATH']}", "HOME": str(self.home), "TERM": "dumb", "LC_ALL": "C.UTF-8"}
        e.update(env or {})
        return subprocess.run([BASH, str(SCRIPT), *args], capture_output=True, text=True, errors="replace", env=e)


class FailureHandling(MonitorBase):
    def test_complete_baseline_then_clean_check(self):
        self.good_tools()
        r = self.run_mon("--init", "example.org")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.mon / "baseline" / "dns_a.txt").read_text().strip(), "1.2.3.4")
        self.assertFalse((self.mon / "baseline_incomplete.txt").exists())
        r = self.run_mon("--check", "example.org")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("[CLEAN]", r.stdout)

    def test_failed_dig_during_init_is_reported_not_ok(self):
        self.good_tools()
        r = self.run_mon("--init", "example.org", env={"DIG_FAIL": "1"})
        self.assertNotEqual(r.returncode, 0)
        out = r.stdout
        self.assertIn("[FAILED]", out)
        self.assertNotIn("[OK]  DNS A record", out)
        self.assertIn("INCOMPLETE", out)
        self.assertIn("no servers could be reached", (self.mon / "baseline" / "dns_a.txt.err").read_text())
        self.assertEqual((self.mon / "baseline" / "dns_a.txt.rc").read_text().strip(), "9")

    def test_failed_dig_during_check_is_not_a_clean_result(self):
        self.good_tools()
        self.run_mon("--init", "example.org")
        r = self.run_mon("--check", "example.org", env={"DIG_FAIL": "1"})
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertNotIn("[CLEAN]", r.stdout)
        self.assertIn("could not be verified", r.stdout)
        self.assertTrue(list(self.mon.glob("changes_*.log")))
        errs = list(self.mon.glob("check_errors_*.log"))
        self.assertTrue(errs and "no servers could be reached" in errs[0].read_text())

    def test_real_change_is_still_detected(self):
        self.good_tools("1.2.3.4")
        self.run_mon("--init", "example.org")
        self.good_tools("5.6.7.8")
        r = self.run_mon("--check", "example.org")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("CHANGE DETECTED", r.stdout)
        self.assertIn("5.6.7.8", next(self.mon.glob("changes_*.log")).read_text())

    def test_failed_baseline_item_is_not_diffed_as_empty(self):
        self.good_tools()
        self.run_mon("--init", "example.org", env={"DIG_FAIL": "1"})
        r = self.run_mon("--check", "example.org")   # now DNS works, baseline for DNS is missing data
        self.assertNotIn("CHANGE: DNS A Record", r.stdout)
        self.assertIn("UNVERIFIED: DNS A Record", r.stdout)
        self.assertNotIn("[CLEAN]", r.stdout)

    def test_unparsable_crtsh_reply_is_failure_not_zero(self):
        self.good_tools()
        self.shim("curl", 'for a in "$@"; do case "$a" in *crt.sh*) echo "<html>rate limited</html>"; exit 0;; esac; done\n'
                          'echo "HTTP/2 200"; echo "HTTP_CODE=200"\n')
        r = self.run_mon("--init", "example.org")
        self.assertRegex(r.stdout, r"\[FAILED\].*crt\.sh certificate count")
        self.assertNotIn("CERT_COUNT=0", (self.mon / "baseline" / "crtsh.txt").read_text())

    def test_missing_tool_is_reported_as_skipped_and_incomplete(self):
        self.good_tools()
        (self.shims / "whois").unlink()
        # keep PATH to shims + essentials only, without whois
        r = self.run_mon("--init", "example.org", env={"PATH": f"{self.shims}:/usr/bin:/bin"})
        if shutil.which("whois", path="/usr/bin:/bin"):
            self.skipTest("system whois present")
        self.assertIn("[SKIP]", r.stdout)
        self.assertNotEqual(r.returncode, 0)

    def test_no_stderr_suppression_left_on_collectors(self):
        code = SCRIPT.read_text()
        for tool in ("dig", "whois", "openssl", "curl"):
            for ln in code.splitlines():
                if ln.strip().startswith(("#", "echo", "warn")):
                    continue
                if f" {tool} " in f" {ln} " and "2>/dev/null" in ln and "command -v" not in ln:
                    self.fail(f"stderr discarded: {ln.strip()}")


if __name__ == "__main__":
    unittest.main()
