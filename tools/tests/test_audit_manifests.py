"""Regression checks for dated review artifacts; no live network or hardware access."""
import json
from collections import Counter
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "Documentation"


class AuditManifestTests(unittest.TestCase):
    def test_complete_baseline_markdown_disposition(self):
        data = json.loads((DOCS / "MARKDOWN-EMPTY-CELL-REVIEW-2026-11-11.json").read_text())
        entries = data["entries"]
        self.assertEqual(len(entries), 167)
        self.assertEqual(
            dict(Counter(x["classification"] for x in entries)),
            {"intentional-operator-input": 116, "documentation-defect-corrected": 51},
        )
        for item in entries:
            with self.subTest(path=item["path"], line=item["baseline_line"]):
                self.assertTrue((ROOT / item["path"]).is_file())
                self.assertGreater(item["baseline_line"], 0)
                self.assertTrue(item["rationale"].strip())
                self.assertTrue(item["resolution"].strip())

    def test_all_external_failures_preserved_and_unknowns_not_certified(self):
        data = json.loads((DOCS / "EXTERNAL-LINK-AUDIT-2026-11-11.json").read_text())
        entries = data["records"]
        self.assertEqual(len(entries), 205)
        self.assertEqual(data["occurrences"], 205)
        self.assertEqual(data["distinct_failed_urls"], 148)
        statuses = Counter(x["response"] for x in entries)
        self.assertEqual(statuses["404"], 17)
        self.assertEqual(statuses["403"], 126)
        self.assertEqual(statuses["429"], 32)
        for item in entries:
            with self.subTest(path=item["path"], line=item["baseline_line"]):
                self.assertTrue((ROOT / item["path"]).is_file())
                self.assertGreater(item["baseline_line"], 0)
                self.assertTrue(item["url"].startswith(("http://", "https://")))
                if item["response"] in {"401", "403", "429", "502", "503", "521", "TIMEOUT"}:
                    self.assertEqual(item["assessment"], "unconfirmed_bot_or_host_restriction")
        self.assertEqual(len([x for x in entries if x["response"] == "404" and
                              x["assessment"] == "replacement_or_retirement_committed_in_pr_195"]), 17)


if __name__ == "__main__":
    unittest.main()
