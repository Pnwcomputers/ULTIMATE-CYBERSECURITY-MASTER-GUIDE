"""R5/R8 integration: osint_investigator.sh uses validated JSON state and preserves evidence."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "OSINT" / "Playbook" / "osint_investigator.sh"
BASH = shutil.which("bash")


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.shims = self.root / "shims"
        self.shims.mkdir()
        self.cwd = self.root / "cwd"
        self.cwd.mkdir()

    def tearDown(self):
        self._t.cleanup()

    def shim(self, name, body):
        p = self.shims / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(0o755)

    def sh(self, snippet, env=None):
        e = {"PATH": f"{self.shims}:{os.environ['PATH']}", "HOME": str(self.home), "TERM": "dumb"}
        e.update(env or {})
        return subprocess.run([BASH, "-c", f'source "{SCRIPT}"\nset +e\n{snippet}'],
                              capture_output=True, text=True, env=e, cwd=self.cwd)


class CaseStateIntegration(Base):
    def test_hostile_state_values_round_trip_without_execution(self):
        evil = '"; touch "$HOME/pwned_a"; echo "'
        evil2 = "$(touch $HOME/pwned_b)"
        r = self.sh(f'''
            CASE_ID=T1; create_new_case_dir() {{ :; }}
            CASE_BASE_DIR="$HOME/OSINT_Cases"
            mkdir -p "$CASE_BASE_DIR/T1"; CASE_DIR="$CASE_BASE_DIR/T1"
            EMAILS=('a@example.com' '{evil}'); COMPANY_NAME_TARGET='{evil2}'
            save_case_state || echo SAVE_FAILED
            EMAILS=(); COMPANY_NAME_TARGET=""
            load_case T1 || echo LOAD_FAILED
            printf 'N=%s\\n' "${{#EMAILS[@]}}"
            printf 'E1=%s\\n' "${{EMAILS[1]}}"
            printf 'C=%s\\n' "$COMPANY_NAME_TARGET"
        ''')
        self.assertNotIn("FAILED", r.stdout + r.stderr, r.stderr)
        self.assertIn("N=2", r.stdout)
        self.assertIn(f"E1={evil}", r.stdout)
        self.assertIn(f"C={evil2}", r.stdout)
        self.assertFalse((self.home / "pwned_a").exists())
        self.assertFalse((self.home / "pwned_b").exists())

    def test_tampered_or_legacy_state_is_not_executed(self):
        case = self.home / "OSINT_Cases" / "T2"
        case.mkdir(parents=True)
        (case / ".case_state").write_text('CASE_ID="T2"\ntouch "$HOME/pwned_legacy"\n')
        r = self.sh('CASE_BASE_DIR="$HOME/OSINT_Cases"; load_case T2; echo "rc=$?"')
        self.assertFalse((self.home / "pwned_legacy").exists())
        self.assertIn("legacy", (r.stdout + r.stderr).lower())

        (case / ".case_state.json").write_text('{"schema_version":1,"CASE_ID":"T2","EMAILS":"x"}')
        (case / ".case_state.json").chmod(0o600)
        r = self.sh('CASE_BASE_DIR="$HOME/OSINT_Cases"; load_case T2 && echo LOADED || echo REFUSED')
        self.assertIn("REFUSED", r.stdout)
        self.assertNotIn("LOADED", r.stdout)

    def test_state_for_other_case_is_refused(self):
        a = self.home / "OSINT_Cases" / "A"
        b = self.home / "OSINT_Cases" / "B"
        a.mkdir(parents=True, mode=0o700)
        b.mkdir(parents=True, mode=0o700)
        self.sh('CASE_BASE_DIR="$HOME/OSINT_Cases"; CASE_ID=A; CASE_DIR="$CASE_BASE_DIR/A"; save_case_state')
        shutil.copy(a / ".case_state.json", b / ".case_state.json")
        (b / ".case_state.json").chmod(0o600)
        r = self.sh('CASE_BASE_DIR="$HOME/OSINT_Cases"; load_case B && echo LOADED || echo REFUSED')
        self.assertIn("REFUSED", r.stdout)

    def test_case_id_traversal_is_rejected(self):
        for bad in ("../../etc", "a/b", "$(id)", ""):
            r = self.sh(f'set_case_id_from_input {bad!r} && echo "ID=$CASE_ID" || echo REJECTED')
            out = r.stdout
            self.assertTrue("REJECTED" in out or re.search(r"ID=[A-Za-z0-9_-]+$", out.strip()), out)
            self.assertNotIn("/", out.replace("ID=", ""))
            self.assertNotIn("..", out)

    def test_new_case_info_json_is_valid_with_quotes_in_name(self):
        r = self.sh('''
            CASE_BASE_DIR="$HOME/OSINT_Cases"; INVESTIGATOR_NAME='Eve "the" \\ Tester'
            prompt() { printf -v "$1" '%s' "NEW-1"; }
            create_new_case >/dev/null 2>&1; echo "rc=$?"
        ''')
        info = self.home / "OSINT_Cases" / "NEW-1" / "case_info.json"
        self.assertTrue(info.exists(), r.stdout + r.stderr)
        self.assertEqual(json.loads(info.read_text())["investigator"], 'Eve "the" \\ Tester')
        self.assertTrue((self.home / "OSINT_Cases" / "NEW-1" / ".case_state.json").exists())


class EvidenceIntegration(Base):
    def prepare_case(self):
        return ('CASE_BASE_DIR="$HOME/OSINT_Cases"; mkdir -p "$CASE_BASE_DIR/E1"; '
                'CASE_ID=E1; CASE_DIR="$CASE_BASE_DIR/E1"; RAW_DIR="$CASE_DIR/raw_data"; '
                'printf "| t |\\n" > "$CASE_DIR/evidence_log.md"; ')

    def test_failure_and_stderr_are_preserved_and_flagged(self):
        self.shim("whois", 'echo "partial record"; echo "whois: connection refused" >&2; exit 5\n')
        self.shim("dig", 'echo "1.2.3.4"\n')
        r = self.sh(self.prepare_case() + 'investigate_domain example.org')
        self.assertEqual(r.returncode, 0, r.stderr)
        d = self.home / "OSINT_Cases" / "E1" / "raw_data" / "domain"
        report = next(d.glob("*.md")).read_text()
        self.assertIn("**whois**: PARTIAL", report)
        self.assertIn("**dig A**: complete", report)
        self.assertEqual(next(d.glob("*.whois.stderr")).read_text(), "whois: connection refused\n")
        meta = json.loads(next(d.glob("*.whois.meta.json")).read_text())
        self.assertEqual((meta["returncode"], meta["status"]), (5, "partial"))
        log = (self.home / "OSINT_Cases" / "E1" / "evidence_log.md").read_text()
        self.assertIn("partial (rc=5)", log)

    def test_output_is_not_truncated(self):
        self.shim("whois", 'i=0; while [ $i -lt 500 ]; do echo "line $i"; i=$((i+1)); done\n')
        self.shim("dig", "true\n")
        self.sh(self.prepare_case() + 'investigate_domain example.org')
        d = self.home / "OSINT_Cases" / "E1" / "raw_data" / "domain"
        self.assertEqual(len(next(d.glob("*.whois.stdout")).read_text().splitlines()), 500)

    def test_missing_tool_is_reported_not_silent(self):
        self.shim("holehe", "true\n")
        (self.shims / "holehe").unlink()
        r = self.sh(self.prepare_case() + 'investigate_email a@example.org',
                    env={"PATH": f"{self.shims}:/usr/bin:/bin"})
        d = self.home / "OSINT_Cases" / "E1" / "raw_data" / "email"
        report = next(d.glob("*.md")).read_text()
        self.assertIn("skipped (not installed)", report, r.stderr)

    def test_hostile_target_is_one_argument_and_safe_filename(self):
        self.shim("whois", 'printf "%s\\n" "$@" > "$HOME/whois_args"\n')
        self.shim("dig", "true\n")
        target = "x.org;touch $HOME/pwned_t `touch $HOME/pwned_u`"
        self.sh(self.prepare_case() + f'investigate_domain {target!r}')
        self.assertFalse((self.home / "pwned_t").exists())
        self.assertFalse((self.home / "pwned_u").exists())
        self.assertEqual((self.home / "whois_args").read_text().strip(), target)
        d = self.home / "OSINT_Cases" / "E1" / "raw_data" / "domain"
        for f in d.iterdir():
            self.assertRegex(f.name, r"^[A-Za-z0-9._-]+$")


class ConfigAndStaticChecks(Base):
    def test_group_writable_api_config_is_not_sourced(self):
        cfg = self.home / ".config" / "osint-investigator"
        cfg.mkdir(parents=True)
        f = cfg / "api_keys.conf"
        f.write_text('touch "$HOME/pwned_cfg"\nexport SHODAN_API_KEY="k"\n')
        f.chmod(0o666)
        r = self.sh('init_config; echo "key=[${SHODAN_API_KEY:-}]"')
        self.assertFalse((self.home / "pwned_cfg").exists())
        self.assertIn("key=[]", r.stdout)

    def test_private_api_config_is_loaded(self):
        cfg = self.home / ".config" / "osint-investigator"
        cfg.mkdir(parents=True)
        f = cfg / "api_keys.conf"
        f.write_text('export SHODAN_API_KEY="abc12345"\n')
        f.chmod(0o600)
        r = self.sh('init_config; echo "key=[$SHODAN_API_KEY]"')
        self.assertIn("key=[abc12345]", r.stdout)

    def test_api_key_with_shell_metacharacters_is_rejected(self):
        cfg = self.home / ".config" / "osint-investigator"
        cfg.mkdir(parents=True)
        f = cfg / "api_keys.conf"
        f.write_text('export SHODAN_API_KEY=""\n')
        f.chmod(0o600)
        evil = 'abcdefgh"; touch $HOME/pwned_k; echo "'
        # The hostile key arrives on stdin (as typed input), never inside the harness's own command line.
        subprocess.run([BASH, "-c", f'source "{SCRIPT}"; set +e; configure_apis >/dev/null 2>&1'],
                       input=evil + "\n", env={"PATH": os.environ["PATH"], "HOME": str(self.home), "TERM": "dumb"},
                       capture_output=True, text=True)
        self.assertFalse((self.home / "pwned_k").exists())
        self.assertNotIn("pwned_k", f.read_text())

    def test_static_guards(self):
        code = SCRIPT.read_text()
        self.assertNotRegex(code, r"(?m)^\s*sudo\b", "installer must not be run through sudo")
        self.assertNotIn("--break-system-packages", code)
        self.assertNotRegex(code, r"pip3? install")
        self.assertNotRegex(code, r'source\s+"\$\{?CASE_DIR\}?/\.case_state')
        self.assertNotRegex(code, r"(?m)^\s*(holehe|h8mail|whois|dig|subfinder|maigret|sherlock|phoneinfoga)\b.*2>/dev/null")
        self.assertNotRegex(code, r"\|\s*head\s+-\d+")
        self.assertTrue(code.rstrip().endswith("fi"), "main must be guarded")


if __name__ == "__main__":
    unittest.main()
