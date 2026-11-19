"""Fixture tests for repository-wide JSON/XML and historical-code syntax census."""
from pathlib import Path
import tempfile
import unittest
from importlib.util import module_from_spec, spec_from_file_location

PATH = Path(__file__).resolve().parents[1] / "audit_source_formats.py"
spec = spec_from_file_location("format_audit", PATH)
formats = module_from_spec(spec)
spec.loader.exec_module(formats)


class FormatAuditTests(unittest.TestCase):
    def test_valid_and_invalid_structured_data(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "valid.json").write_text('{"one": 1}', encoding="utf-8")
            (root / "bad.json").write_text('{"one": ', encoding="utf-8")
            (root / "valid.xml").write_text('<root><a /></root>', encoding="utf-8")
            (root / "bad.xml").write_text('<root>&bogus;</root>', encoding="utf-8")
            report = formats.inspect(root)
            self.assertEqual(report["by_extension"][".json"], 2)
            self.assertEqual(report["by_extension"][".xml"], 2)
            self.assertEqual(len(report["maintained_errors"]), 2)
            self.assertEqual(report["outcomes"]["parsed OK (maintained)"], 2)

    def test_archives_and_unparsed_specialized_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "Scripts/GO").mkdir(parents=True)
            (root / "Scripts/GO/archive.json").write_text('{"archive": true}', encoding="utf-8")
            (root / "Scripts/GO/example.c").write_text('int main() {', encoding="utf-8")
            report = formats.inspect(root)
            self.assertEqual(report["outcomes"]["parsed OK (archived)"], 1)
            self.assertEqual(len(report["not_parsed"]), 1)
            self.assertEqual(len(report["maintained_errors"]), 0)


if __name__ == "__main__":
    unittest.main()
