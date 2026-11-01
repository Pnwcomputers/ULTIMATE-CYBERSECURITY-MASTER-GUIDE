#!/usr/bin/env python3
"""Offline honeypot unit checks: no network outside localhost."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
import xml.etree.ElementTree as ET
from http.server import ThreadingHTTPServer
from urllib.request import urlopen, Request
from urllib.error import HTTPError

from diy_http_decoy import EventWriter, build_handler
from esp32_serial_bridge import parse_line


HERE = Path(__file__).parent


class HoneypotTests(unittest.TestCase):
    def test_metadata_redaction_and_json(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "decoy.jsonl"
            writer = EventWriter(path, "lab-sensor")
            writer.record("GET", "/admin?password=should-not-appear", "127.0.0.1",
                          50000, "tester\nfake-header: secret")
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(record["honeypot"]["path"], "/admin")
            self.assertNotIn("should-not-appear", path.read_text(encoding="utf-8"))
            self.assertNotIn("\n", record["honeypot"]["user_agent"])

    def test_http_get_and_post_no_echo(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "requests.jsonl"
            server = ThreadingHTTPServer(("127.0.0.1", 0),
                                         build_handler(EventWriter(path, "sensor-1")))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}/path?token=hidden"
                for method in ("GET", "POST"):
                    request = Request(url, method=method)
                    with self.assertRaises(HTTPError) as err:
                        urlopen(request, timeout=5)
                    self.assertEqual(err.exception.code, 404)
                lines = [json.loads(x) for x in path.read_text().splitlines()]
                self.assertEqual([x["honeypot"]["method"] for x in lines], ["GET", "POST"])
                self.assertTrue(all(x["honeypot"]["path"] == "/path" for x in lines))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_xml_unique_ids_and_valid_synthetic(self):
        root = ET.parse(HERE / "honeypot_rules.xml").getroot()
        ids = [int(rule.attrib["id"]) for rule in root.findall("rule")]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(100400 <= x < 100430 for x in ids))
        records = [json.loads(line) for line in
                   (HERE / "synthetic-events.jsonl").read_text().splitlines()]
        self.assertEqual(len(records), 4)
        self.assertIn("node_id", records[1])
        self.assertEqual(records[2]["eventid"], "cowrie.session.connect")

    def test_custom_esp32_serial_contract(self):
        example = 'HONEYPOT_JSON:{"event":"tcp_connection","src_ip":"192.0.2.30","port":23}'
        normalized = parse_line(example, "s3-decoy")
        self.assertEqual(normalized["honeypot"]["integration"], "esp32_serial")
        self.assertEqual(normalized["honeypot"]["src_ip"], "192.0.2.30")
        self.assertEqual(normalized["honeypot"]["dst_port"], 23)
        self.assertIsNone(parse_line('HONEYPOT_JSON:{"event":"cmd","src_ip":"192.0.2.30","port":23}', "s3"))
        self.assertIsNone(parse_line('HONEYPOT_JSON:{"event":"tcp_connection","src_ip":"bad","port":23}', "s3"))
        self.assertIsNone(parse_line("unrelated serial banner", "s3"))


if __name__ == "__main__":
    unittest.main()
