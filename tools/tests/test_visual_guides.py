"""Offline checks for the intentionally scoped conceptual SVG diagram batch.

No live sensor, SIEM, EDR, or hardware tests are attempted by this suite.
"""
from pathlib import Path
import unittest
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]

DIAGRAM_GUIDES = {
    "assets/diagrams/purple-team-emulation-detection-loop.svg": (
        "PlayBooks/purple-team-detection-validation.md",
        "PlayBooks/PurpleTeam_Detailed.md",
    ),
    "assets/diagrams/detection-evidence-verification-gates.svg": (
        "IncidentResponse/SIEM/detection-content-validation.md",
        "Documentation/CANARY-DETECTION-VALIDATOR.md",
    ),
    "assets/diagrams/cyberdeck-policy-zones.svg": (
        "Cyberdeck/docs/ARCHITECTURE.md",
    ),
    "assets/diagrams/wireshark-capture-display-boundaries.svg": (
        "Documentation/wireshark.md",
    ),
    "assets/diagrams/ai-soc-trust-and-approval-boundaries.svg": (
        "AI/ai-security-operations-workflows.md",
    ),
    "assets/diagrams/cti-to-approved-emulation-gates.svg": (
        "PlayBooks/PurpleTeam_Detailed.md",
    ),
}


class VisualGuideTests(unittest.TestCase):
    def test_conceptual_svgs_are_well_formed_and_accessible(self):
        for path in DIAGRAM_GUIDES:
            with self.subTest(asset=path):
                asset = ROOT / path
                self.assertTrue(asset.is_file(), path)
                svg = ET.parse(asset).getroot()
                ns = "{http://www.w3.org/2000/svg}"
                self.assertEqual(svg.tag, ns + "svg")
                self.assertEqual(svg.get("role"), "img")
                self.assertEqual(svg.get("aria-labelledby"), "title desc")
                self.assertTrue((svg.find(ns + "title").text or "").strip())
                self.assertTrue((svg.find(ns + "desc").text or "").strip())
                text = asset.read_text(encoding="utf-8")
                self.assertNotIn("<script", text.lower())
                self.assertNotIn("<image", text.lower())

    def test_each_svg_is_embedded_in_expected_guide_and_index(self):
        index = (ROOT / "assets/README.md").read_text(encoding="utf-8")
        for path, guides in DIAGRAM_GUIDES.items():
            filename = Path(path).name
            with self.subTest(asset=path):
                self.assertIn(filename, index)
                for guide in guides:
                    md = (ROOT / guide).read_text(encoding="utf-8")
                    rel = __import__("os").path.relpath(ROOT / path, (ROOT / guide).parent)
                    self.assertIn("](" + rel.replace("\\", "/") + ")", md)
                    self.assertIn("![" , md)


if __name__ == "__main__":
    unittest.main()
