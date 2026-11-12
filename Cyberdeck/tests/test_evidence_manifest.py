"""Offline unit checks for the public manifest helper."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "evidence_manifest.py"
spec = importlib.util.spec_from_file_location("evidence_manifest", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ManifestTests(unittest.TestCase):
    def test_sha256_and_relative_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            inp = base / "in"
            inp.mkdir()
            (inp / "sample.txt").write_bytes(b"abc")
            manifest = module.build_manifest(inp)
            self.assertEqual(manifest["file_count"], 1)
            self.assertEqual(manifest["files"][0]["relative_path"], "sample.txt")
            self.assertEqual(manifest["files"][0]["sha256"],
                             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_reject_output_inside_source(self):
        with tempfile.TemporaryDirectory() as temp:
            inp = Path(temp) / "data"
            inp.mkdir()
            with self.assertRaises(ValueError):
                module.write_manifest(inp, inp / "manifest.json")

    def test_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            inp = base / "data"
            inp.mkdir()
            out = base / "manifest.json"
            out.write_text("old")
            with self.assertRaises(FileExistsError):
                module.write_manifest(inp, out)
            self.assertEqual(out.read_text(), "old")

    def test_valid_json_write(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            inp = base / "data"
            inp.mkdir()
            (inp / "example").write_text("synthetic")
            out = base / "manifest.json"
            module.write_manifest(inp, out)
            data = json.loads(out.read_text())
            self.assertEqual(data["file_count"], 1)
            self.assertEqual(data["files"][0]["relative_path"], "example")

    def test_symlink_is_skipped_if_supported(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            inp = base / "data"
            inp.mkdir()
            outside = base / "outside.txt"
            outside.write_text("private")
            try:
                (inp / "outside-link").symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation unavailable")
            self.assertEqual(module.build_manifest(inp)["file_count"], 0)


if __name__ == "__main__":
    unittest.main()
