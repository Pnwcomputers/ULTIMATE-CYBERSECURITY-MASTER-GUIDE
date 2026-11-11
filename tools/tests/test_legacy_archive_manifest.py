"""Manifest coverage and Python 3 parser-only status; archived code is NEVER run."""
import ast
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "Scripts" / "GO"
MANIFEST = ARCHIVE / "archive_manifest.json"


class LegacyArchiveManifestTests(unittest.TestCase):
    def test_all_python_archive_paths_accounted_for(self):
        inventory = json.loads(MANIFEST.read_text(encoding="utf-8"))
        records = inventory["entries"]
        expected = {p.relative_to(ARCHIVE).as_posix() for p in ARCHIVE.rglob("*.py")}
        actual = {record["path"] for record in records}
        self.assertEqual(len(records), 39, "Update the inventory for archive changes")
        self.assertEqual(len(actual), len(records), "Duplicate manifest record")
        self.assertEqual(actual, expected)

    def test_static_parser_findings_match_manifest(self):
        records = json.loads(MANIFEST.read_text(encoding="utf-8"))["entries"]
        failures = 0
        for record in records:
            path = ARCHIVE / record["path"]
            with self.subTest(path=record["path"]):
                try:
                    ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
                    status = "no-legacy-syntax-finding"
                except SyntaxError:
                    status = "fails-legacy-syntax"
                    failures += 1
                self.assertEqual(status, record["python3_ast"])
                self.assertIn(record["disposition"], {
                    "historical-only", "modernize-only-with-fixtures",
                    "retire-from-active-index"})
                self.assertEqual(record["validation"],
                                 "not-executed; third-party dependencies and permissions not verified")
        self.assertEqual(failures, 21)


if __name__ == "__main__":
    unittest.main()
