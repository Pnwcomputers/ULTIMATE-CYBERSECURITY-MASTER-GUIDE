"""Offline integration and malformed-baseline checks."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import evidence_manifest as generator
import verify_manifest as verifier


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.folder = self.base / "evidence"
        self.folder.mkdir()
        (self.folder / "original.txt").write_bytes(b"abc")
        self.saved = self.base / "manifest.json"
        self.manifest = generator.write_manifest(self.folder, self.saved)

    def run_cli(self):
        return subprocess.run([sys.executable, str(TOOLS / "verify_manifest.py"),
                               "--input", str(self.folder), "--manifest", str(self.saved)],
                              capture_output=True, text=True)

    def test_round_trip_and_cli_match(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["matches"])
        self.assertEqual(json.loads(self.saved.read_text()), self.manifest)

    def test_added_missing_and_same_size_changed(self):
        (self.folder / "original.txt").write_bytes(b"xyz")
        (self.folder / "new.txt").write_bytes(b"new")
        result = verifier.verify_manifest(self.folder, self.saved)
        self.assertEqual(result["changed"], ["original.txt"])
        self.assertEqual(result["added"], ["new.txt"])
        self.assertEqual(self.run_cli().returncode, 1)
        (self.folder / "original.txt").unlink()
        self.assertEqual(verifier.verify_manifest(self.folder, self.saved)["missing"], ["original.txt"])

    def test_empty_and_nested_unicode_inventory(self):
        (self.folder / "original.txt").unlink()
        self.assertEqual(generator.build_manifest(self.folder)["file_count"], 0)
        nested = self.folder / "nested"
        nested.mkdir()
        (nested / "café.txt").write_bytes(b"")
        baseline = self.base / "nested.json"
        generator.write_manifest(self.folder, baseline)
        self.assertTrue(verifier.verify_manifest(self.folder, baseline)["matches"])

    def test_reject_unsafe_duplicate_and_invalid_records(self):
        mutations = []
        for path in ["../outside", "/absolute", "C:/outside", "a\\b", "./a", "a//b", "."]:
            value = copy.deepcopy(self.manifest)
            value["files"][0]["relative_path"] = path
            mutations.append(value)
        for key, value in [("size_bytes", True), ("size_bytes", -1), ("sha256", "bad")]:
            mutated = copy.deepcopy(self.manifest)
            mutated["files"][0][key] = value
            mutations.append(mutated)
        duplicate = copy.deepcopy(self.manifest)
        duplicate["files"] *= 2
        duplicate["file_count"] = 2
        mutations.extend([duplicate, {}, [], dict(self.manifest, file_count=True),
                          dict(self.manifest, file_count=2), dict(self.manifest, format="unknown")])
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                verifier.validate_manifest(value)

    def test_invalid_json_and_missing_input_exit_two(self):
        self.saved.write_text("{")
        self.assertEqual(self.run_cli().returncode, 2)
        self.saved.unlink()
        self.assertEqual(self.run_cli().returncode, 2)

    def test_baseline_inside_input_rejected(self):
        inside = self.folder / "manifest.json"
        inside.write_text(json.dumps(self.manifest))
        with self.assertRaises(ValueError):
            verifier.verify_manifest(self.folder, inside)

    def test_walk_failure_aborts_without_output(self):
        def failing_walk(root, **kwargs):
            kwargs["onerror"](PermissionError("unreadable subtree"))
            return iter(())
        output = self.base / "partial.json"
        with patch.object(generator.os, "walk", side_effect=failing_walk):
            with self.assertRaises(PermissionError):
                generator.write_manifest(self.folder, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
