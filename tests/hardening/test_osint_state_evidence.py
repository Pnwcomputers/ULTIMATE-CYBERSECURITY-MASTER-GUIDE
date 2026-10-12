"""R5 (case state) and R8 (evidence preservation) regression tests."""
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parents[2] / "OSINT" / "Playbook" / "lib"
STATE = LIB / "case_state.py"
EVID = LIB / "collect_evidence.py"


def run(script, *args, stdin=b"", cwd=None):
    return subprocess.run([sys.executable, "-I", str(script), *args], input=stdin,
                          capture_output=True, cwd=cwd)


def records(*pairs):
    return b"".join(k.encode() + b"\0" + v.encode() + b"\0" for k, v in pairs)


class CaseStateTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.dir = Path(self._t.name) / "case"
        self.dir.mkdir(mode=0o700)

    def tearDown(self):
        self._t.cleanup()

    def save(self, *pairs):
        return run(STATE, "save", str(self.dir), stdin=records(("CASE_ID", "C-1"), *pairs))

    def test_round_trip_preserves_hostile_values_as_data(self):
        evil = '$(touch pwned) `touch pwned2` "; touch pwned3 #'
        r = self.save(("EMAILS", "a@example.com"), ("EMAILS", evil), ("COMPANY_NAME_TARGET", evil))
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(STATE, "load", str(self.dir))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(evil.encode(), r.stdout)
        data = json.loads((self.dir / ".case_state.json").read_text())
        self.assertEqual(data["EMAILS"], ["a@example.com", evil])
        self.assertEqual(data["schema_version"], 1)
        for m in ("pwned", "pwned2", "pwned3"):
            self.assertFalse((self.dir / m).exists())

    def test_state_file_is_private_and_atomic(self):
        self.assertEqual(self.save().returncode, 0)
        p = self.dir / ".case_state.json"
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual([x.name for x in self.dir.iterdir()], [".case_state.json"])

    def test_rejects_control_characters_and_unknown_keys(self):
        self.assertNotEqual(self.save(("EMAILS", "a\nCASE_ID=evil")).returncode, 0)
        self.assertNotEqual(self.save(("EMAILS", "a\x1b[31m")).returncode, 0)
        self.assertNotEqual(self.save(("PATH", "/tmp")).returncode, 0)
        self.assertNotEqual(self.save(("EMAILS", "x" * 5000)).returncode, 0)
        self.assertFalse((self.dir / ".case_state.json").exists())

    def test_rejects_bad_case_ids(self):
        for bad in ("", "../x", "a b", "a/b", "x" * 65, "a;b", "$(id)"):
            r = run(STATE, "save", str(self.dir), stdin=records(("CASE_ID", bad)))
            self.assertNotEqual(r.returncode, 0, bad)
            self.assertNotEqual(run(STATE, "check-id", bad).returncode, 0, bad)
        self.assertEqual(run(STATE, "check-id", "2026-10_A").returncode, 0)

    def test_load_rejects_tampered_state(self):
        self.save()
        p = self.dir / ".case_state.json"
        for payload in ('{"schema_version": 1, "CASE_ID": "C-1", "EMAILS": "notalist"}',
                        '{"schema_version": 2, "CASE_ID": "C-1"}',
                        '{"schema_version": 1, "CASE_ID": "C-1", "evil": 1}',
                        '[1,2]', 'CASE_ID="x"; touch pwned', '{'):
            p.write_text(payload)
            p.chmod(0o600)
            r = run(STATE, "load", str(self.dir))
            self.assertNotEqual(r.returncode, 0, payload)
            self.assertEqual(r.stdout, b"")
        self.assertFalse((self.dir / "pwned").exists())

    def test_load_refuses_symlink_and_unsafe_permissions(self):
        self.save()
        p = self.dir / ".case_state.json"
        p.chmod(0o666)
        self.assertNotEqual(run(STATE, "load", str(self.dir)).returncode, 0)
        p.chmod(0o600)
        target = Path(self._t.name) / "elsewhere.json"
        target.write_text(p.read_text())
        p.unlink()
        p.symlink_to(target)
        self.assertNotEqual(run(STATE, "load", str(self.dir)).returncode, 0)

    def test_refuses_world_writable_or_symlinked_case_dir(self):
        self.dir.chmod(0o777)
        self.assertNotEqual(self.save().returncode, 0)
        self.dir.chmod(0o700)
        link = Path(self._t.name) / "link"
        link.symlink_to(self.dir)
        r = run(STATE, "save", str(link), stdin=records(("CASE_ID", "C-1")))
        self.assertNotEqual(r.returncode, 0)

    def test_legacy_shell_state_is_never_evaluated(self):
        (self.dir / ".case_state").write_text('CASE_ID="x"\ntouch pwned_legacy\n')
        self.assertNotEqual(run(STATE, "load", str(self.dir)).returncode, 0)
        self.assertFalse((self.dir / "pwned_legacy").exists())


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.dir = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def collect(self, *cmd, base="ev", extra=()):
        return run(EVID, "--out", str(self.dir / base), *extra, "--", *cmd)

    def meta(self, base="ev"):
        return json.loads((self.dir / f"{base}.meta.json").read_text())

    def test_complete_run_keeps_full_output_and_hashes(self):
        big = "line\n" * 200000  # far beyond the old `head -50`
        r = self.collect(sys.executable, "-c", "import sys;sys.stdout.write('line\\n'*200000);sys.stderr.write('warn\\n')")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = (self.dir / "ev.stdout").read_bytes()
        self.assertEqual(out.decode(), big)
        self.assertEqual((self.dir / "ev.stderr").read_text(), "warn\n")
        m = self.meta()
        self.assertEqual(m["status"], "complete")
        self.assertEqual(m["returncode"], 0)
        self.assertEqual(m["stdout"]["sha256"], hashlib.sha256(out).hexdigest())
        self.assertEqual(m["stderr"]["sha256"], hashlib.sha256(b"warn\n").hexdigest())
        for ext in (".stdout", ".stderr", ".meta.json"):
            self.assertEqual(stat.S_IMODE((self.dir / f"ev{ext}").stat().st_mode), 0o600)

    def test_failure_is_marked_partial_with_stderr_preserved(self):
        r = self.collect(sys.executable, "-c", "import sys;print('some');sys.stderr.write('boom');sys.exit(7)")
        self.assertEqual(r.returncode, 3)
        m = self.meta()
        self.assertEqual((m["status"], m["returncode"]), ("partial", 7))
        self.assertEqual((self.dir / "ev.stderr").read_text(), "boom")

    def test_timeout_is_partial_and_recorded(self):
        r = self.collect(sys.executable, "-c", "import time;print('x',flush=True);time.sleep(30)",
                         extra=("--timeout", "1"))
        self.assertEqual(r.returncode, 3)
        m = self.meta()
        self.assertTrue(m["timed_out"])
        self.assertEqual(m["status"], "partial")
        self.assertEqual((self.dir / "ev.stdout").read_text(), "x\n")

    def test_size_cap_marks_truncation(self):
        r = self.collect(sys.executable, "-c", "print('a'*5000)", extra=("--max-bytes", "100"))
        self.assertEqual(r.returncode, 3)
        m = self.meta()
        self.assertTrue(m["stdout"]["truncated"])
        self.assertEqual(m["stdout"]["bytes"], 100)

    def test_missing_tool_is_not_run_not_success(self):
        r = self.collect("definitely-not-a-real-tool-xyz")
        self.assertEqual(r.returncode, 4)
        m = self.meta()
        self.assertEqual(m["status"], "not_run")
        self.assertIn("error", m)

    def test_never_overwrites_existing_evidence(self):
        self.assertEqual(self.collect(sys.executable, "-c", "print(1)").returncode, 0)
        before = (self.dir / "ev.stdout").read_bytes()
        r = self.collect(sys.executable, "-c", "print(2)")
        self.assertEqual(r.returncode, 1)
        self.assertEqual((self.dir / "ev.stdout").read_bytes(), before)

    def test_arguments_are_not_shell_interpreted(self):
        evil = "$(touch pwned); `touch pwned2`"
        r = self.collect(sys.executable, "-c", "import sys;print(sys.argv[1])", evil)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.dir / "ev.stdout").read_text().strip(), evil)
        self.assertFalse((self.dir / "pwned").exists())

    def test_log_row_is_appended_and_escaped(self):
        log = self.dir / "evidence_log.md"
        log.write_text("| h |\n")
        self.collect(sys.executable, "-c", "print(1)", extra=("--log", str(log), "--label", "a|b\nc"))
        text = log.read_text()
        self.assertTrue(text.startswith("| h |\n"))
        row = text.splitlines()[1]
        self.assertIn("a\\|b c", row)
        self.assertIn("complete (rc=0)", row)

    def test_no_command_is_usage_error(self):
        self.assertEqual(run(EVID, "--out", str(self.dir / "x")).returncode, 2)


if __name__ == "__main__":
    unittest.main()
