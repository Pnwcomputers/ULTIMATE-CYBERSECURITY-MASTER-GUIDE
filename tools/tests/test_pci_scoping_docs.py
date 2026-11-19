"""Offline checks for PCI DSS scoping documentation and linked conceptual visual.

Tests assert Markdown/asset structure, not PCI DSS compliance or live network results.
"""
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]

class PciScopingDocumentTests(unittest.TestCase):
    def test_scoping_guide_and_template_are_linked(self):
        guide = (ROOT / "Compliance/pci-dss-scoping.md").read_text(encoding="utf-8")
        template = (ROOT / "Compliance/pci-scope-review-template.md").read_text(encoding="utf-8")
        for section in ("## Terminology", "## Classify", "## Segmentation",
                        "## Merchant Checkout", "## Service Providers",
                        "## Required Scope Review Cadence"):
            self.assertIn(section, guide)
        for control in ("12.5.1", "12.5.2", "12.5.2.1", "11.4.5",
                        "11.4.6", "FAQ 1604", "FAQ 1588"):
            self.assertIn(control, guide)
        self.assertIn("no actual CHD/SAD", guide)
        self.assertIn("**Blank template only.**", template)
        for path in ("Compliance/README.md", "Compliance/frameworks.md", "README.md"):
            self.assertIn("pci-dss-scoping.md", (ROOT / path).read_text(encoding="utf-8"))

    def test_diagram_is_well_formed_accessible_and_embedded(self):
        diagram = ROOT / "assets/diagrams/pci-dss-scoping-boundaries.svg"
        ns = "{http://www.w3.org/2000/svg}"
        root = ET.parse(diagram).getroot()
        self.assertEqual(root.tag, ns + "svg")
        self.assertEqual(root.attrib.get("role"), "img")
        self.assertEqual(root.attrib.get("aria-labelledby"), "title desc")
        self.assertTrue((root.find(ns + "title").text or "").strip())
        self.assertTrue((root.find(ns + "desc").text or "").strip())
        self.assertIn("![" , (ROOT / "Compliance/pci-dss-scoping.md").read_text(encoding="utf-8"))
        self.assertIn("pci-dss-scoping-boundaries.svg", (ROOT / "assets/README.md").read_text(encoding="utf-8"))
        self.assertNotIn("<script", diagram.read_text(encoding="utf-8").lower())

if __name__ == "__main__":
    unittest.main()
