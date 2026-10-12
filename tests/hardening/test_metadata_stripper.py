"""R8: metadata_stripper.sh must not report a failed or unverifiable strip as clean."""
import os, re, shutil, stat, subprocess, tempfile, unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "OSINT" / "Playbook" / "scripts" / "metadata_stripper.sh"


def func(name):
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", SCRIPT.read_text(), re.S | re.M)
    assert m
    return m.group(0)


class StripTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)
        (self.root / "bin").mkdir()
        self.out = self.root / "out"
        self.out.mkdir()
        self.src = self.root / "a.jpg"
        self.src.write_bytes(b"x")

    def tearDown(self):
        self._t.cleanup()

    def exiftool(self, body):
        p = self.root / "bin" / "exiftool"
        p.write_text("#!/bin/bash\n" + body + "\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)

    def run_strip(self):
        code = (f'set -o pipefail; RED=; GREEN=; YELLOW=; NC=; OUTPUT_DIR="{self.out}"; LOG_FILE="{self.out}/log"; '
                f'REPORT_FILE="{self.out}/report"; log(){{ echo "$1"; }}\n' + func("strip_metadata")
                + f'\nstrip_metadata "{self.src}"')
        env = {"PATH": f"{self.root/'bin'}:{os.environ['PATH']}", "HOME": str(self.root)}
        r = subprocess.run(["bash", "-c", code], capture_output=True, text=True, env=env)
        return r.stdout + r.stderr, (self.out / "report").read_text()

    def test_failed_strip_is_reported_failed(self):
        self.exiftool('echo "Error: corrupt" >&2; : > "$3" 2>/dev/null; exit 2')
        out, rep = self.run_strip()
        self.assertIn("STRIP FAILED (exiftool exit 2)", rep)
        self.assertNotIn("[STRIPPED]", out)
        self.assertFalse((self.out / "stripped" / "a.jpg").exists())
        self.assertTrue((self.out / "stripped" / "a.jpg.INCOMPLETE").exists())

    def test_unreadable_result_is_unverified_not_clean(self):
        self.exiftool('if [ "$1" = "-all=" ]; then echo data > "$3"; exit 0; fi; echo "cannot read" >&2; exit 1')
        out, rep = self.run_strip()
        self.assertIn("STRIP UNVERIFIED", rep)
        self.assertNotIn("[STRIPPED]", out)

    def test_clean_strip_reported_stripped(self):
        self.exiftool('if [ "$1" = "-all=" ]; then echo data > "$3"; exit 0; fi; echo "File Name : a.jpg"')
        out, rep = self.run_strip()
        self.assertIn("[STRIPPED]", out)
        self.assertIn("STRIPPED:", rep)

    def test_remaining_fields_flagged_partial(self):
        self.exiftool('if [ "$1" = "-all=" ]; then echo data > "$3"; exit 0; fi; echo "Owner Name : Jane"')
        out, _ = self.run_strip()
        self.assertIn("[PARTIAL STRIP]", out)


if __name__ == "__main__":
    unittest.main()
