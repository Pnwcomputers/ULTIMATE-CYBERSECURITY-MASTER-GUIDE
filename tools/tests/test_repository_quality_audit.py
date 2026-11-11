"""Unit fixtures for the offline repository QA review queue."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "repository_quality_audit.py"
spec = importlib.util.spec_from_file_location("repository_quality_audit", SOURCE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class QualityInventoryTests(unittest.TestCase):
    def test_markers_outside_fences_are_review_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(
                "# Example\nTODO: finish\n~~~bash\n# TODO intentional fixture\n~~~\n| A |  |\n",
                encoding="utf-8"
            )
            (root / "good.py").write_text("print('ok')\n")
            counts, errors, candidates = audit.inspect(root)
            self.assertEqual(counts["markdown"], 1)
            self.assertEqual(counts["python"], 1)
            self.assertEqual(errors, [])
            self.assertEqual(sum(c[2] == "incomplete-marker" for c in candidates), 1)
            self.assertEqual(sum(c[2] == "empty-table-cell" for c in candidates), 1)

    def test_bad_python_is_reported_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.py").write_text("if False\n  pass\n")
            _, errors, _ = audit.inspect(root)
            self.assertTrue(any("python syntax" in message for _, message in errors))

    @unittest.skipUnless(shutil.which("bash"), "Bash unavailable")
    def test_bad_shell_is_reported_without_executing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.sh").write_text("if true; then\n  echo unexpected\n")
            _, errors, _ = audit.inspect(root)
            self.assertTrue(any("bash syntax" in message for _, message in errors))


if __name__ == "__main__":
    unittest.main()
