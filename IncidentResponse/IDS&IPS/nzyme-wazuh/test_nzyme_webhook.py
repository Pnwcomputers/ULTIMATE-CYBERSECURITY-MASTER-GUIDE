#!/usr/bin/env python3
"""Offline unit checks + local HTTP-only webhook receiver integration tests."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

from nzyme_webhook_bridge import build_handler, names, normalize
from http.server import HTTPServer

HERE = Path(__file__).parent


def sample():
    return {
        "event_type": "MONITOR_TRIGGERED",
        "event_type_subsystem": "GENERIC",
        "event_type_human_readable": "Monitor triggered",
        "details": "Synthetic unit test only",
        "event_supertype": "detection",
        "timestamp": "2026-10-31T20:06:00-07:00",
    }


class NormalizationTests(unittest.TestCase):
    def test_generic_event_is_not_auto_deauth(self):
        data = normalize(sample(), "nzyme-test")
        self.assertEqual(data["wids"]["integration"], "nzyme")
        self.assertEqual(data["wids"]["category"], "unclassified_detection")
        self.assertNotIn("bssid", data["wids"])
        self.assertEqual(data["wids"]["observed_at"], "2026-11-01T03:06:00+00:00")

    def test_explicit_event_allowlist(self):
        kind = "SYNTHETIC_WIDS_DISCONNECT_ANOMALY"
        item = sample()
        item["event_type"] = kind
        record = normalize(item, "test", names(kind))
        self.assertEqual(record["wids"]["category"], "disconnect_anomaly")
        self.assertEqual(record["wids"]["event"], kind)

    def test_system_event_stays_system(self):
        item = sample()
        item["event_supertype"] = "system"
        item["event_type"] = "SOME_SYSTEM_EVENT"
        out = normalize(item, "test", names("SOME_SYSTEM_EVENT"))
        self.assertEqual(out["wids"]["category"], "system_event")

    def test_invalid_payloads(self):
        for item in ({}, {"event_type": "X", "event_supertype": "detection",
                          "timestamp": "2026-10-31T22:00:00"}, []):
            with self.subTest(item=item):
                with self.assertRaises(ValueError):
                    normalize(item, "test")

    def test_rule_ids_unique_and_well_formed(self):
        root = ET.parse(HERE / "nzyme_wids_rules.xml").getroot()
        ids = [x.attrib["id"] for x in root.findall("rule")]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("100352", ids)
        self.assertEqual(root.tag, "group")

    def test_synthetic_fixtures_valid(self):
        with (HERE / "synthetic-events.jsonl").open(encoding="utf-8") as f:
            events = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event_type"], "MONITOR_TRIGGERED")


class LocalWebhookTests(unittest.TestCase):
    def test_bearer_auth_and_persistent_jsonl(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / "events.jsonl"
            key = "local-test-secret-" + ("x" * 32)
            handler = build_handler(key, "nzyme-test", output, frozenset(), frozenset())
            server = HTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%s/nzyme" % server.server_port
                payload = json.dumps(sample()).encode("utf-8")
                request = Request(
                    url, data=payload, method="POST",
                    headers={"Content-Type": "application/json",
                             "Authorization": "Bearer wrong-token"})
                with self.assertRaises(HTTPError) as err:
                    urlopen(request, timeout=5)
                self.assertEqual(err.exception.code, 401)
                self.assertFalse(output.exists())
                request = Request(
                    url, data=payload, method="POST",
                    headers={"Content-Type": "application/json",
                             "Authorization": "Bearer " + key})
                with urlopen(request, timeout=5) as response:
                    self.assertEqual(response.status, 204)
                result = json.loads(output.read_text(encoding="utf-8").strip())
                self.assertEqual(result["wids"]["integration"], "nzyme")
                self.assertEqual(result["wids"]["sensor"], "nzyme-test")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
