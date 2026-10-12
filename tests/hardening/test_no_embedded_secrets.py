"""R2/R9: the files remediated for hard-coded credentials must not regress.

Reports file:line and the rule only; matched text is never printed so a real
secret would not be copied into CI logs.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGETS = [
    "IncidentResponse/SIEM/elk_stack.md",
    "IncidentResponse/SIEM/graylog.md",
    "IncidentResponse/SIEM/splunk.md",
    "ENHANCED_MASTER_GUIDE.md",
    "OSINT/Playbook/osint_investigator.sh",
    "OSINT/Playbook/install_dependencies.sh",
    "Scripts/pnwc_install_tools.sh",
    "Scripts/lib/safe_install.sh",
]
RULES = {
    "sample password literal": re.compile(r"YourStrongPassword|YourKibanaPassword|AnalystPassword|Password123!?"),
    "insecure ${VAR:-default} secret": re.compile(r"\$\{(?:[A-Z_]*(?:PASSWORD|KEY|SECRET|TOKEN)[A-Z_]*):-[^}]+\}"),
    "literal password in curl -u": re.compile(r"-u\s+[A-Za-z_]+:(?![\"'$]|\$)[^\s\\\"']+"),
    "literal openssl pass:": re.compile(r"-pass(?:word|out|in)\s+pass:\S+"),
    "published sample hash of a weak password": re.compile(r"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"),
    "literal password in config": re.compile(r"""(?i)\bpassword\s*(?:=>|:)\s*["']changeme["']"""),
    "literal KEY=value secret assignment": re.compile(
        r"^\s*(?:export\s+)?[A-Z_]*(?:PASSWORD|SECRET|TOKEN|ENCRYPTION_KEY)\s*=\s*(?![\"']?[\"']?\s*(?:#.*)?$)(?![\"']?[$<])[^\s#]{6,}",
        re.M),
}


class NoEmbeddedSecrets(unittest.TestCase):
    def test_remediated_files_have_no_credential_literals(self):
        hits = []
        for rel in TARGETS:
            for n, line in enumerate((ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
                for name, rx in RULES.items():
                    if rx.search(line):
                        hits.append(f"{rel}:{n}: {name}")
        self.assertEqual(hits, [], "\n".join(hits))

    def test_elk_compose_requires_secrets(self):
        text = (ROOT / "IncidentResponse/SIEM/elk_stack.md").read_text(encoding="utf-8")
        for var in ("ELASTIC_PASSWORD", "KIBANA_PASSWORD", "LOGSTASH_WRITER_PASSWORD", "ENCRYPTION_KEY"):
            self.assertIn("${%s:?" % var, text, var)
        self.assertIn("O_EXCL", text)
        self.assertIn("0o600", text)


if __name__ == "__main__":
    unittest.main()
