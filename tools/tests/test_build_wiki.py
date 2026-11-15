"""Local fixtures only: builds a wiki from a temporary fake repository."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_wiki", ROOT / "tools/build_wiki.py")
build_wiki = importlib.util.module_from_spec(spec)
sys.modules["build_wiki"] = build_wiki
spec.loader.exec_module(build_wiki)

WIKI = "https://github.com/o/r/wiki/"
FILES = {
    "README.md": "# Root\n",
    "LEGAL.md": "# Legal Terms\n",
    "CHANGELOG.md": "# Changelog\n",
    "assets/cybersecurityguide.png": "",
    "OSINT/README.md": "# OSINT Hub\n\nSee [tools](tools.md) and [home](../README.md).\n",
    "OSINT/tools.md": (
        '<a id="top"></a>\n\n# 🔍 OSINT Tools\n\n'
        "Back to [hub](./README.md#top), [legal](/LEGAL.md), [script](run.sh), [folder](./sub/).\n"
        '![diagram](../assets/cybersecurityguide.png) <img src="../assets/cybersecurityguide.png">\n'
        "`[not a link](tools.md)`\n\n```\n[inside code](tools.md)\n```\n\n[ref]: ./tools.md\n"
    ),
    "OSINT/run.sh": "",
    "OSINT/sub/x.txt": "",
    "SDR/nanovna/01-setup.md": "# 🔧 01 — Setup\n",
}


class BuildWikiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        for name, text in FILES.items():
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(text, encoding="utf-8")
        self.out = Path(self.tmp.name) / "wiki"
        self.out.mkdir()
        (self.out / "Stale.md").write_text(build_wiki.MARKER + "\nold\n", encoding="utf-8")
        (self.out / "Hand-Written.md").write_text("keep me\n", encoding="utf-8")
        self.pages = build_wiki.build(self.out, "o/r", root=self.repo, tracked=list(FILES))

    def tearDown(self):
        self.tmp.cleanup()

    def read(self, slug):
        return (self.out / f"{slug}.md").read_text(encoding="utf-8")

    def test_every_guide_gets_its_own_page_and_maintenance_files_are_skipped(self):
        for slug in ["Home", "_Sidebar", "_Footer", "Browse-by-Topic", "OSINT-Tools",
                     "Open-Source-Intelligence-OSINT", "Legal-Terms", "nanovna-01-Setup"]:
            self.assertTrue((self.out / f"{slug}.md").exists(), slug)
        self.assertNotIn("Changelog", self.pages)
        self.assertFalse((self.out / "Stale.md").exists())
        self.assertTrue((self.out / "Hand-Written.md").exists())

    def test_links_are_rewritten_for_the_wiki(self):
        page = self.read("OSINT-Tools")
        self.assertNotIn("# 🔍 OSINT Tools", page)
        self.assertIn(f"[hub]({WIKI}Open-Source-Intelligence-OSINT#top)", page)
        self.assertIn(f"[legal]({WIKI}Legal-Terms)", page)
        self.assertIn("[script](https://github.com/o/r/blob/main/OSINT/run.sh)", page)
        self.assertIn("[folder](https://github.com/o/r/tree/main/OSINT/sub)", page)
        raw = "https://raw.githubusercontent.com/o/r/main/assets/cybersecurityguide.png"
        self.assertIn(f"![diagram]({raw})", page)
        self.assertIn(f'<img src="{raw}">', page)
        self.assertIn("`[not a link](tools.md)`", page)
        self.assertIn("[inside code](tools.md)", page)
        self.assertIn(f"[ref]: {WIKI}OSINT-Tools", page)
        self.assertIn(f"[home]({WIKI}Home)", self.read("Open-Source-Intelligence-OSINT"))

    def test_home_follows_the_wiki_layout(self):
        home = self.read("Home")
        for text in ["***Disclaimer:***", "## Introduction", "## 🧭 Start Here",
                     "## 🛡️ Defense & Investigations", "## 🌐 Join the Community", "cybersecurityguide.png"]:
            self.assertIn(text, home)
        self.assertIn(f"{WIKI}Home", self.read("_Footer"))


if __name__ == "__main__":
    unittest.main()
