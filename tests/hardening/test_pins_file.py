"""The shipped pins file must be well-formed and cover what the installers request."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PINS = ROOT / "Scripts" / "tool_pins.conf"
LINE = re.compile(r"^[A-Za-z0-9:_./@+-]+=[A-Za-z0-9._/+-]*$")
UNPINNED_ON_PURPOSE = {"ULTIMATE-CYBERSECURITY-MASTER-GUIDE", "exploitdb"}


def pins():
    out = {}
    for ln in PINS.read_text().splitlines():
        if ln.strip() and not ln.lstrip().startswith("#") and LINE.match(ln):
            k, v = ln.split("=", 1)
            assert k not in out, f"duplicate pin {k}"
            out[k] = v
    return out


class PinsFile(unittest.TestCase):
    def test_every_pin_is_well_formed(self):
        for k, v in pins().items():
            kind = k.split(":", 1)[0]
            if kind == "git":
                self.assertRegex(v, r"^[0-9a-f]{40}$", k)
            elif k.startswith("dl:") and ":sha256:" in k:
                self.assertRegex(v, r"^[0-9a-f]{64}$", k)
                self.assertRegex(k, r":sha256:(amd64|arm64|any)$")
            elif k.startswith("dl:") and k.endswith(":commit"):
                self.assertRegex(v, r"^[0-9a-f]{40}$", k)
            elif kind in ("pip", "go", "cargo", "gem") or k.endswith(":version"):
                self.assertTrue(v and v != "latest", k)
            else:
                self.fail(f"unknown pin kind: {k}")

    def test_no_garbage_lines_are_silently_ignored(self):
        for n, ln in enumerate(PINS.read_text().splitlines(), 1):
            s = ln.strip()
            if s and not s.startswith("#"):
                self.assertRegex(ln, LINE, f"line {n} would be ignored by the parser")

    def test_every_git_clone_and_go_install_has_a_pin_or_documented_exception(self):
        p = pins()
        src = (ROOT / "Scripts/pnwc_install_tools.sh").read_text() + (ROOT / "OSINT/Playbook/install_dependencies.sh").read_text()
        missing = []
        for m in re.finditer(r'git_clone_tool\s+"([^"$]+)"', src):
            if f"git:{m.group(1)}" not in p and m.group(1) not in UNPINNED_ON_PURPOSE:
                missing.append(f"git:{m.group(1)}")
        for m in re.finditer(r'^\s*go_install\s+"?(github\.com/[^\s"]+)', src, re.M):
            if f"go:{m.group(1)}" not in p:
                missing.append(f"go:{m.group(1)}")
        self.assertEqual(sorted(set(missing)), [])

    def test_downloads_pin_only_verified_artifact_hashes(self):
        p = pins()
        # These values come from GitHub's SHA-256 release-asset digest metadata.
        # An absent, unverifiable digest is safer than a fabricated one.
        for arch in ("amd64", "arm64"):
            self.assertRegex(p.get(f"dl:feroxbuster:sha256:{arch}", ""),
                             r"^[0-9a-f]{64}$")
        for tool in ("jadx", "apktool", "ghidra"):
            self.assertRegex(p.get(f"dl:{tool}:sha256:any", ""),
                             r"^[0-9a-f]{64}$", tool)
        for tool in ("phoneinfoga", "feroxbuster", "jadx", "dex2jar", "apktool"):
            self.assertIn(f"dl:{tool}:version", p)
        for tool in ("msfinstall", "asn"):
            self.assertRegex(p.get(f"dl:{tool}:commit", ""),
                             r"^[0-9a-f]{40}$")
        # No SHA for some legacy assets is available from verified release data.
        # Missing digests are acceptable only because fetch_pinned fails closed.
        # See test_installer_checks.FetchPinnedTests for executable regressions.

        # moving-branch URLs must not come back
        src = (ROOT / "OSINT/Playbook/install_dependencies.sh").read_text() + (ROOT / "Scripts/pnwc_install_tools.sh").read_text()
        self.assertNotRegex(src, r"raw\.githubusercontent\.com/[^\s\"]+/(master|main)/")


if __name__ == "__main__":
    unittest.main()
