"""R8: failed DNS/API collectors in email_audit.sh and username_audit.sh must not read as "not found"."""
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


def extract(path, name):
    text = (SCRIPTS / path).read_text()
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.S | re.M)
    assert m, name
    return m.group(0)


class CollectorFailureTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.out = self.root / "out"
        self.out.mkdir()

    def tearDown(self):
        self._t.cleanup()

    def stub(self, name, body):
        p = self.bin / name
        p.write_text("#!/bin/bash\n" + body + "\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)

    def run_bash(self, code):
        env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "HOME": str(self.root), "LC_ALL": "C.UTF-8"}
        return subprocess.run([BASH, "-c", code], capture_output=True, text=True, env=env)

    # ---- email_audit DNS
    def dns(self, dig_body):
        self.stub("dig", dig_body)
        code = ('log(){ :; }; GREEN=; NC=; '
                + extract("email_audit.sh", "check_domain_dns")
                + f'\ncheck_domain_dns example.test "{self.out}/dns.txt"')
        r = self.run_bash(code)
        self.assertEqual(r.returncode, 0, r.stderr)
        return (self.out / "dns.txt").read_text()

    def test_dns_failure_is_unverified_not_no_record(self):
        txt = self.dns('echo "connection timed out; no servers could be reached" >&2; exit 9')
        self.assertEqual(txt.count("LOOKUP FAILED (dig exit 9)"), 4, txt)
        self.assertIn("UNVERIFIED", txt)
        self.assertNotIn("No MX records", txt)

    def test_dns_empty_success_is_distinguished(self):
        txt = self.dns("exit 0")
        self.assertIn("None found (query succeeded, empty answer)", txt)
        self.assertNotIn("LOOKUP FAILED", txt)

    def test_dns_records_and_spf_filter(self):
        txt = self.dns('''case "$*" in *MX*) echo "10 mx.example.test.";; *_dmarc*) echo '"v=DMARC1; p=none"';; *TXT*) printf '"v=spf1 -all"\\n"other"\\n';; *) echo 192.0.2.1;; esac''')
        self.assertIn("10 mx.example.test.", txt)
        self.assertIn("v=spf1 -all", txt)
        self.assertNotIn("other", txt)
        self.assertIn("192.0.2.1", txt)

    # ---- username_audit API checks
    def api(self, curl_body, fn="check_github", args="octo"):
        self.stub("curl", curl_body)
        code = ('log(){ :; }; warn(){ echo "WARN: $*"; }; GREEN=; NC=; YELLOW=; '
                + extract("username_audit.sh", "api_fetch")
                + extract("username_audit.sh", fn)
                + f'\n{fn} {args} "{self.out}"')
        return self.run_bash(code)

    def found(self):
        f = self.out / "api_found.txt"
        return f.read_text() if f.exists() else ""

    def test_rate_limited_api_is_unverified(self):
        r = self.api('for a in "$@"; do [ "$prev" = -o ] && echo "{}" > "$a"; prev=$a; done; printf 403')
        self.assertIn("UNVERIFIED", r.stdout + r.stderr)
        self.assertIn("lookup FAILED", (self.out / "api_errors.txt").read_text())
        self.assertEqual(self.found(), "")

    def test_network_failure_is_unverified(self):
        r = self.api('echo "curl: (6) Could not resolve host" >&2; exit 6')
        self.assertIn("UNVERIFIED", r.stdout + r.stderr)
        self.assertIn("curl exit 6", (self.out / "api_errors.txt").read_text())

    def test_success_is_recorded(self):
        r = self.api('for a in "$@"; do [ "$prev" = -o ] && echo \'{"login": "octo"}\' > "$a"; prev=$a; done; printf 200')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("https://github.com/octo|api_direct", self.found())

    def test_404_is_a_genuine_not_found(self):
        r = self.api('for a in "$@"; do [ "$prev" = -o ] && echo \'{"message":"Not Found"}\' > "$a"; prev=$a; done; printf 404')
        self.assertNotIn("UNVERIFIED", r.stdout + r.stderr)
        self.assertEqual(self.found(), "")


if __name__ == "__main__":
    unittest.main()
