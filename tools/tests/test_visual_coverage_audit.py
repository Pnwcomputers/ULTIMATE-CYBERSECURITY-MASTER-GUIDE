"""Offline coverage-test fixtures for the repository-wide visual auditor."""
from pathlib import Path
import tempfile
import unittest
from importlib.util import module_from_spec, spec_from_file_location

AUDIT_PATH = Path(__file__).resolve().parents[1] / "audit_visual_coverage.py"
spec = spec_from_file_location("visual_audit", AUDIT_PATH)
audit = module_from_spec(spec)
spec.loader.exec_module(audit)


GOOD_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc">
<title id="title">Safe architecture</title>
<desc id="desc">A static conceptual workflow</desc>
<rect width="10" height="10"/>
</svg>'''


class VisualCoverageAuditTests(unittest.TestCase):
    def test_full_fixture_tree_count_and_placement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Docs").mkdir()
            (root / "assets/diagrams").mkdir(parents=True)
            (root / "assets/diagrams/safe.svg").write_text(GOOD_SVG, encoding="utf-8")
            (root / "assets/diagrams/unplaced.svg").write_text(GOOD_SVG, encoding="utf-8")
            (root / "Docs/readme.md").write_text(
                "![Safe diagram](../assets/diagrams/safe.svg)\n", encoding="utf-8"
            )
            r = audit.visual_audit(root)
            self.assertEqual(r["counts"]["markdown"], 1)
            self.assertEqual(r["counts"]["svg"], 2)
            self.assertEqual(r["counts"]["svg_embedded"], 1)
            self.assertEqual(r["counts"]["svg_neither_linked_nor_embedded"], 1)
            self.assertEqual(r["counts"]["svg_missing_accessibility_metadata"], 0)
            self.assertEqual(r["counts"]["svg_invalid_or_unsafe"], 0)

    def test_embedded_asset_still_requires_an_index_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "assets/diagrams").mkdir(parents=True)
            diagram = "assets/diagrams/example.svg"
            (root / diagram).write_text(GOOD_SVG, encoding="utf-8")
            (root / "guide.md").write_text(f"![Example]({diagram})", encoding="utf-8")

            before = audit.visual_audit(root)
            self.assertEqual(before["counts"]["svg_embedded"], 1)
            self.assertEqual(before["unindexed_asset_svgs"], [diagram])

            (root / "assets/README.md").write_text(
                "[Example](./diagrams/example.svg)", encoding="utf-8"
            )
            after = audit.visual_audit(root)
            self.assertEqual(after["counts"]["asset_svg_missing_from_index"], 0)

    def test_broken_asset_and_active_svg_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "assets/diagrams").mkdir(parents=True)
            (root / "guide.md").write_text("![Missing](assets/nope.svg)\n", encoding="utf-8")
            (root / "assets/diagrams/bad.svg").write_text(
                GOOD_SVG.replace("<rect", '<script>alert(1)</script><rect'),
                encoding="utf-8")
            r = audit.visual_audit(root)
            self.assertEqual(r["counts"]["broken_local_image_embeds"], 1)
            self.assertGreater(r["counts"]["svg_invalid_or_unsafe"], 0)

    def test_svg_reference_link_is_not_a_figure_embed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "assets/diagrams").mkdir(parents=True)
            (root / "assets/diagrams/reference.svg").write_text(GOOD_SVG, encoding="utf-8")
            (root / "readme.md").write_text(
                "[Diagram](assets/diagrams/reference.svg)", encoding="utf-8")
            r = audit.visual_audit(root)
            self.assertEqual(r["counts"]["svg_linked_without_embedding"], 1)
            self.assertEqual(r["counts"]["svg_embedded"], 0)
            self.assertEqual(r["counts"]["svg_neither_linked_nor_embedded"], 0)


if __name__ == "__main__":
    unittest.main()
