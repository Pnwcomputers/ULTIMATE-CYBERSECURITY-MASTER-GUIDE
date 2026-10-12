"""R8: phone_audit.sh API lookups must not read a failed/empty curl as 'no record found'."""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "OSINT" / "Playbook" / "scripts" / "phone_audit.sh"
TEXT = SCRIPT.read_text()
BASH = shutil.which("bash")


def func(name):
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", TEXT, re.S | re.M)
    assert m, name
    return m.group(0)


class PhoneAuditTests(unittest.TestCase):
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
        code = ('log(){ printf "%s\\n" "$1"; }; YELLOW=; NC=; ' + func("pretty_json") + func("query_api")
                + '\nquery_api "' + str(self.out) + '" TestAPI ' + " ".join(f'"{a}"' for a in args)
                + '; echo "ret=$?"')
        env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "HOME": str(self.root)}
        return subprocess.run([BASH, "-c", code], capture_output=True, text=True, env=env)

    def test_curl_failure_leaves_output_empty_and_warns(self):
        self.stub_curl('echo "could not resolve host" >&2; exit 6')
        r = self.run_query_api("https://example.test/x")
        self.assertIn("ret=1", r.stdout)
        self.assertIn("FAILED", r.stdout + r.stderr)
        self.assertIn("UNVERIFIED", r.stdout + r.stderr)
        self.assertEqual(self.out.read_text(), "")
        self.assertIn("could not resolve host", Path(f"{self.out}.err").read_text())

    def test_empty_body_is_also_unverified_not_silently_empty_success(self):
        self.stub_curl('exit 0')  # returns empty stdout, rc 0 (e.g. a 204)
        r = self.run_query_api("https://example.test/x")
        self.assertIn("ret=1", r.stdout)
        self.assertIn("empty response", r.stdout + r.stderr)

    def test_successful_response_is_saved(self):
        self.stub_curl('printf \'{"ok": true}\'')
        r = self.run_query_api("https://example.test/x")
        self.assertIn("ret=0", r.stdout)
        self.assertIn('"ok": true', self.out.read_text())

    def test_no_live_pretty_json_pipes_remain(self):
        live = [ln for ln in TEXT.splitlines() if "| pretty_json" in ln and not ln.lstrip().startswith("#")]
        self.assertEqual(len(live), 1, live)  # only the one inside query_api itself

    def test_intelx_search_failure_is_unverified(self):
        self.stub_curl('echo "timed out" >&2; exit 28')
        code = ('log(){ printf "%s\\n" "$1"; }; YELLOW=; GREEN=; NC=; INTELX_KEY=x; normalize_phone(){ echo "$1"; }; '
                + func("pretty_json") + func("query_api") + func("query_intelx")
                + f'\nquery_intelx +15555550100 "{self.out}"')
        env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "HOME": str(self.root)}
        r = subprocess.run([BASH, "-c", code], capture_output=True, text=True, env=env)
        self.assertIn("UNVERIFIED", r.stdout + r.stderr)
        self.assertEqual(self.out.read_text(), "")


if __name__ == "__main__":
    unittest.main()
