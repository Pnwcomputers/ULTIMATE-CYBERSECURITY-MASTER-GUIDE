"""Offline regression tests for HTTP and Markdown candidate classifications."""
import json
from pathlib import Path
import tempfile
import unittest

from tools.maintenance_candidate_triage import (
    classify_http, scan_root, table_has_empty_cell, render_markdown
)


class CandidateTriageTests(unittest.TestCase):
    def test_http_classification(self):
        cases = {
            "http://localhost:9000": "loopback",
            "http://127.0.0.1:8080": "loopback",
            "http://192.168.1.50:9000": "private-lab-address",
            "http://169.254.169.254/latest": "link-local-metadata-or-lab",
            "http://198.51.100.42": "documentation-address",
            "http://opensearch:9200": "private-service-or-test",
            "http://myhiddenservice.onion": "onion-reference-review",
            "http://target.com/page": "illustrative-placeholder",
            "http://<YOUR_SERVER_IP>:9000": "illustrative-placeholder",
            "http://vendor.example.net/download": "illustrative-placeholder",
            "http://testmynids.org/uid/index.html": "external-public-http-needs-review",
            "http://": "scheme-only-mention",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(classify_http(url), expected)

    def test_markdown_empty_cells(self):
        self.assertTrue(table_has_empty_cell("| Owner |  | Status |"))
        self.assertFalse(table_has_empty_cell("| Owner | Not recorded | Status |"))
        self.assertFalse(table_has_empty_cell("| Text | " + chr(96) + "cmd | sed" + chr(96) + " | Status |"))
        self.assertFalse(table_has_empty_cell("| A \\| B | C | D |"))
        self.assertFalse(table_has_empty_cell("|---|---|---|"))
        self.assertFalse(table_has_empty_cell("Not a | table | at all"))

    def test_scan_preserves_code_http_but_ignores_code_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            doc = root / "form-template.md"
            doc.write_text(
                "## Review\n"
                "| Case |  | Reviewer |\n"
                "~~~bash\n"
                "echo '| A |  | B |'\n"
                "curl http://127.0.0.1:8080\n"
                "~~~\n"
                "See http://official.example.org/docs\n"
                "And http://testmynids.org/uid/index.html\n",
                encoding="utf-8",
            )
            records = scan_root(root)
            self.assertEqual(len([r for r in records if r["kind"] == "empty-table-cell"]), 1)
            self.assertEqual(len([r for r in records if r["kind"] == "http-reference"]), 3)
            self.assertIn("template-candidate-review",
                          [r["classification"] for r in records])
            summary = render_markdown(records, 2)
            self.assertIn("additional records", summary)
            self.assertIn("127.0.0.1", json.dumps(records))


if __name__ == "__main__":
    unittest.main()
