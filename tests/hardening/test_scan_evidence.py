"""R8: scammer_audit.sh run_scan keeps stdout/stderr/rc and flags failures; port state is never guessed."""
import re, subprocess, tempfile, unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "OSINT" / "Playbook" / "scripts" / "scammer_audit.sh"
TEXT = SCRIPT.read_text()


def func(name):
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", TEXT, re.S | re.M)
    assert m
    return m.group(0)


class RunScanTests(unittest.TestCase):
    def run_scan(self, cmd):
        with tempfile.TemporaryDirectory() as d:
            code = 'RED=; GREEN=; NC=; log(){ echo "$1"; }\n' + func("run_scan") + f'\nrun_scan Label "{d}/x" {cmd}; echo "ret=$?"'
            r = subprocess.run(["bash", "-c", code], capture_output=True, text=True)
            files = {n: (Path(d) / n).read_text() for n in ("x.stdout", "x.err", "x.rc")}
            return r.stdout, files

    def test_success_keeps_output_and_rc_zero(self):
        out, f = self.run_scan("sh -c 'echo hi; echo warn >&2'")
        self.assertIn("ret=0", out)
        self.assertEqual((f["x.stdout"], f["x.err"], f["x.rc"].strip()), ("hi\n", "warn\n", "0"))

    def test_failure_is_flagged_with_stderr_kept(self):
        out, f = self.run_scan("sh -c 'echo boom >&2; exit 3'")
        self.assertIn("FAILED (exit 3)", out)
        self.assertIn("ret=3", out)
        self.assertEqual(f["x.err"], "boom\n")
        self.assertEqual(f["x.rc"].strip(), "3")

    def test_script_gates_web_recon_on_scan_success(self):
        self.assertIn('[ "$NMAP_BASIC_OK" = true ]', TEXT)
        self.assertIn("UNVERIFIED (not 'closed')", TEXT)
        self.assertNotIn('-oX "$IP_DIR/nmap_basic.xml" > /dev/null 2>&1', TEXT)


if __name__ == "__main__":
    unittest.main()
