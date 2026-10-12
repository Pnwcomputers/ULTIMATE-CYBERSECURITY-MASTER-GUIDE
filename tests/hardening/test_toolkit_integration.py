"""R8: toolkit_integration.sh wrapper functions must not report success when the
underlying script fails. Several run_* functions used to run the real tool and then
print success() unconditionally, discarding its exit status."""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "OSINT" / "Playbook" / "toolkit_integration.sh"
TEXT = SCRIPT.read_text()
BASH = shutil.which("bash")


def func(name):
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", TEXT, re.S | re.M)
    assert m, name
    return m.group(0)


CASES = [
    # (function, var pointing at the tool, extra args, exit-phrase)
    ("run_threat_feed_check", "THREAT_FEED_SCRIPT", ["1.2.3.4", "{out}"], "Threat feed check FAILED"),
    ("run_crypto_audit", "CRYPTO_AUDIT_SCRIPT", ["1Addr", "{out}"], "Crypto audit FAILED"),
    ("run_domain_monitor_init", "DOMAIN_MONITOR_SCRIPT", ["example.test"], "Domain monitor baseline init FAILED"),
    ("run_username_audit", "USERNAME_AUDIT_SCRIPT", ["someuser", "{out}"], "Username audit FAILED"),
    ("run_ssl_cert_audit", "SSL_CERT_SCRIPT", ["example.test", "{out}"], "SSL cert audit FAILED"),
    ("run_whois_bulk", "WHOIS_BULK_SCRIPT", ["{out}/list.txt", "{out}"], "Bulk WHOIS FAILED"),
    ("run_metadata_strip", "METADATA_STRIP_SCRIPT", ["{out}/f.txt", "{out}"], "Metadata strip FAILED"),
    ("run_screenshot_archive", "SCREENSHOT_SCRIPT", ["https://example.test", "{out}"], "Screenshot archive FAILED"),
]


class ToolkitIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)
        self.out = self.root / "out"
        self.out.mkdir()
        (self.out / "f.txt").write_text("x")
        (self.out / "list.txt").write_text("example.test\n")

    def tearDown(self):
        self._t.cleanup()

    def make_fake_script(self, rc):
        p = self.root / "fake_tool.sh"
        p.write_text(f"#!/bin/bash\necho fake output\nexit {rc}\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
        return p

    def run_case(self, fn_name, script_var, args, rc):
        fake = self.make_fake_script(rc)
        resolved_args = [a.format(out=str(self.out)) for a in args]
        code = (f'info(){{ :; }}; success(){{ echo "SUCCESS: $1"; }}; error(){{ echo "ERROR: $1"; }}; '
                f'{script_var}="{fake}"\n' + func(fn_name)
                + f'\n{fn_name} ' + " ".join(f'"{a}"' for a in resolved_args) + '; echo "ret=$?"')
        return subprocess.run([BASH, "-c", code], capture_output=True, text=True)

    def test_failure_is_reported_as_error_not_success(self):
        for fn_name, script_var, args, phrase in CASES:
            with self.subTest(fn=fn_name):
                r = self.run_case(fn_name, script_var, args, rc=3)
                self.assertNotIn("SUCCESS:", r.stdout, (fn_name, r.stdout, r.stderr))
                self.assertIn("ERROR:", r.stdout, (fn_name, r.stdout, r.stderr))
                self.assertIn(phrase, r.stdout)
                self.assertNotIn("ret=0", r.stdout)

    def test_success_is_still_reported_on_success(self):
        for fn_name, script_var, args, _ in CASES:
            with self.subTest(fn=fn_name):
                r = self.run_case(fn_name, script_var, args, rc=0)
                self.assertIn("SUCCESS:", r.stdout, (fn_name, r.stdout, r.stderr))
                self.assertIn("ret=0", r.stdout)

    def test_theharvester_failure_is_reported(self):
        fake = self.make_fake_script(5)
        code = ('info(){ :; }; success(){ echo "SUCCESS: $1"; }; error(){ echo "ERROR: $1"; }; '
                f'THEHARVESTER_PATH="{fake}"\n' + func("run_theharvester")
                + f'\nrun_theharvester example.test "{self.out}" 50; echo "ret=$?"')
        r = subprocess.run([BASH, "-c", code], capture_output=True, text=True)
        self.assertNotIn("SUCCESS:", r.stdout)
        self.assertNotIn("ret=0", r.stdout)

    def test_case_report_failure_is_reported(self):
        fake = self.make_fake_script(2)
        code = ('info(){ :; }; success(){ echo "SUCCESS: $1"; }; error(){ echo "ERROR: $1"; }; '
                f'CASE_REPORT_SCRIPT="{fake}"\n' + func("run_case_report")
                + '\nrun_case_report CASE-1 false; echo "ret=$?"')
        r = subprocess.run([BASH, "-c", code], capture_output=True, text=True)
        self.assertNotIn("SUCCESS:", r.stdout)
        self.assertIn("Case report generation FAILED", r.stdout)
        self.assertNotIn("ret=0", r.stdout)


if __name__ == "__main__":
    unittest.main()
