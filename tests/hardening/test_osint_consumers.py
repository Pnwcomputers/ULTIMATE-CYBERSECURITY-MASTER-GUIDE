"""R5 follow-up: every consumer of case state / config uses the validated, non-executing loaders."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PLAYBOOK = Path(__file__).resolve().parents[2] / "OSINT" / "Playbook"
BASH = shutil.which("bash")
PY = PLAYBOOK / "lib" / "case_state.py"


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.home = Path(self._t.name) / "home"
        self.home.mkdir()
        self.base = self.home / "OSINT_Cases"
        self.case = self.base / "C1"
        self.case.mkdir(parents=True, mode=0o700)

    def tearDown(self):
        self._t.cleanup()

    def sh(self, script, snippet):
        env = {"PATH": os.environ["PATH"], "HOME": str(self.home), "TERM": "dumb"}
        return subprocess.run([BASH, "-c", f'source "{PLAYBOOK / script}"\nset +e\n{snippet}'],
                              capture_output=True, text=True, env=env)

    def write_state(self, domains):
        recs = b"CASE_ID\0C1\0" + b"".join(b"DOMAINS\0" + d.encode() + b"\0" for d in domains)
        r = subprocess.run(["python3", "-I", str(PY), "save", str(self.case)], input=recs, capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class ConsumerTests(Base):
    def test_abuse_generator_reads_json_and_keeps_hostile_values_as_data(self):
        evil = "a.example;touch $HOME/pwned_abuse"
        self.write_state([evil, "b.example"])
        r = self.sh("abuse_report_generator.sh", f'''
            CASE_BASE_DIR="{self.base}"
            generate_domain_registrar_report() {{ echo "DOM=$1"; }}
            generate_hosting_provider_report() {{ :; }}; generate_isp_report() {{ :; }}
            generate_all_reports "{self.case}" >/dev/null 2>&1
            case_state_load "{self.case}"; printf 'D=%s\\n' "${{DOMAINS[@]}}"
        ''')
        self.assertIn(f"D={evil}", r.stdout)
        self.assertFalse((self.home / "pwned_abuse").exists())

    def test_legacy_case_state_is_never_executed_by_any_consumer(self):
        (self.case / ".case_state").write_text('DOMAINS=(x)\ntouch "$HOME/pwned_legacy"\n')
        r1 = self.sh("abuse_report_generator.sh", f'CASE_BASE_DIR="{self.base}"; generate_all_reports "{self.case}" >/dev/null 2>&1')
        r2 = self.sh("toolkit_integration.sh", f'CASE_BASE_DIR="{self.base}"; run_integrated_investigation "{self.case}"; echo "rc=$?"')
        self.assertFalse((self.home / "pwned_legacy").exists())
        self.assertIn("rc=1", r2.stdout)
        self.assertIn("legacy", (r1.stderr + r2.stderr + r2.stdout).lower())

    def test_toolkit_refuses_tampered_json(self):
        self.write_state(["x.example"])
        p = self.case / ".case_state.json"
        p.write_text('{"schema_version":1,"CASE_ID":"C1","DOMAINS":"not-a-list"}')
        p.chmod(0o600)
        r = self.sh("toolkit_integration.sh", f'CASE_BASE_DIR="{self.base}"; run_integrated_investigation "{self.case}"; echo "rc=$?"')
        self.assertIn("rc=1", r.stdout)


class TrustedConfigTests(Base):
    def conf(self, name="api_keys.conf", mode=0o600):
        d = self.home / ".config" / "osint-investigator"
        d.mkdir(parents=True, exist_ok=True)
        f = d / name
        f.write_text('touch "$HOME/pwned_conf"\nexport ABUSEIPDB_API_KEY=k1\n')
        f.chmod(mode)
        return f

    def test_source_trusted_refuses_writable_and_symlinked_files(self):
        f = self.conf(mode=0o666)
        r = self.sh("lib/trusted_conf.sh", f'source_trusted "{f}"; echo "rc=$?"')
        self.assertIn("rc=1", r.stdout)
        self.assertFalse((self.home / "pwned_conf").exists())
        f.chmod(0o600)
        link = f.parent / "link.conf"
        link.symlink_to(f)
        r = self.sh("lib/trusted_conf.sh", f'source_trusted "{link}"; echo "rc=$?"')
        self.assertIn("rc=1", r.stdout)

    def test_source_trusted_loads_private_file(self):
        f = self.conf()
        f.write_text("export ABUSEIPDB_API_KEY=k1\n")
        r = self.sh("lib/trusted_conf.sh", f'source_trusted "{f}"; echo "k=$ABUSEIPDB_API_KEY"')
        self.assertIn("k=k1", r.stdout)

    def test_no_script_sources_untrusted_files_directly(self):
        offenders = []
        for f in list(PLAYBOOK.glob("*.sh")) + list((PLAYBOOK / "scripts").glob("*.sh")):
            if f.name in ("osint_investigator.sh", "install_dependencies.sh"):
                continue
            for n, line in enumerate(f.read_text().splitlines(), 1):
                if re.match(r"^\s*(source|\.)\s+[\"$]", line) and "source_trusted" not in line \
                        and "_PNWC_LIB" not in line and "_PNWC_TK_DIR" not in line:
                    offenders.append(f"{f.name}:{n}: {line.strip()}")
        self.assertEqual(offenders, [])
        for f in PLAYBOOK.rglob("*.sh"):
            self.assertNotRegex(f.read_text(), r"source\s+\"?\$\{?case_dir\}?/\.case_state\b(?!\.json)", f.name)


if __name__ == "__main__":
    unittest.main()
