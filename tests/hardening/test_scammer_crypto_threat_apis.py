"""R8: curl|pretty_json API calls in scammer_audit.sh must not read a failed/empty fetch as
'nothing found', and the http_code checks in crypto_audit.sh / threat_feed_check.sh must not
choke on an empty code from a hard transport failure."""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "OSINT" / "Playbook" / "scripts"
BASH = shutil.which("bash")


def func(path, name):
    text = (SCRIPTS / path).read_text()
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.S | re.M)
    assert m, (path, name)
    return m.group(0)


class ScammerAuditApiTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.out = self.root / "out.json"

    def tearDown(self):
        self._t.cleanup()

    def stub_curl(self, body):
        p = self.bin / "curl"
        p.write_text("#!/bin/bash\n" + body + "\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)

    def run_query_api(self, *args):
        code = ('log(){ printf "%s\\n" "$1"; }; YELLOW=; NC=; '
                + func("scammer_audit.sh", "pretty_json") + func("scammer_audit.sh", "query_api")
                + '\nquery_api "' + str(self.out) + '" TestAPI ' + " ".join(f'"{a}"' for a in args)
                + '; echo "ret=$?"')
        env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "HOME": str(self.root)}
        return subprocess.run([BASH, "-c", code], capture_output=True, text=True, env=env)

    def test_network_failure_leaves_output_empty_and_warns(self):
        self.stub_curl('echo "connection refused" >&2; exit 7')
        r = self.run_query_api("https://example.test/x")
        self.assertIn("ret=1", r.stdout)
        self.assertIn("FAILED", r.stdout)
        self.assertIn("UNVERIFIED", r.stdout)
        self.assertEqual(self.out.read_text(), "")
        self.assertIn("connection refused", Path(f"{self.out}.err").read_text())

    def test_success_is_saved(self):
        self.stub_curl('printf \'{"total": 3}\'')
        r = self.run_query_api("https://example.test/x")
        self.assertIn("ret=0", r.stdout)
        self.assertIn('"total": 3', self.out.read_text())

    def test_no_bare_pretty_json_pipes_remain_outside_helper(self):
        text = (SCRIPTS / "scammer_audit.sh").read_text()
        live = [ln for ln in text.splitlines() if "| pretty_json" in ln and not ln.lstrip().startswith("#")]
        self.assertEqual(len(live), 1, live)  # only inside query_api itself


class HttpCodeSafetyTests(unittest.TestCase):
    """An unreachable host can leave $http_code empty; '-eq 200' on '' is a bash error,
    not a clean 'not 200' — crypto_audit.sh / threat_feed_check.sh must compare safely."""

    def test_no_unguarded_eq_200_comparisons(self):
        for name in ("crypto_audit.sh", "threat_feed_check.sh"):
            text = (SCRIPTS / name).read_text()
            self.assertNotIn('-eq 200', text, name)
            self.assertIn('${http_code:-000}" == "200"', text, name)

    def test_curl_calls_have_a_timeout(self):
        for name in ("crypto_audit.sh", "threat_feed_check.sh"):
            text = (SCRIPTS / name).read_text()
            for line in text.splitlines():
                if 'curl -s -o "$' in line and 'http_code' in text:
                    self.assertIn("--max-time", line, line)

    def test_empty_http_code_is_treated_as_failure_not_crash(self):
        code = 'http_code=""; if [[ "${http_code:-000}" == "200" ]]; then echo YES; else echo NO; fi'
        r = subprocess.run([BASH, "-c", code], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "NO")
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
