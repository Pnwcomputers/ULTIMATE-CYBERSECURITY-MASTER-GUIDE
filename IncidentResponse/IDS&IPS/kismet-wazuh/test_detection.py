#!/usr/bin/env python3
"""Offline unit checks. Run: python3 -m unittest discover -s kismet-wazuh -p 'test_*.py' -v"""
import json
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from tempfile import TemporaryDirectory
from correlate_offline import correlate, read_events
from kismet_alert_bridge import field, normalize
from pcap_burst_detector import classify_rows, tier

HERE = Path(__file__).parent


class KismetNormalizeTests(unittest.TestCase):
    def test_flattened_kismet_fields(self):
        alert = {
            "kismet.alert.timestamp": 1800000000,
            "kismet.alert.utimestamp": 750000,
            "kismet.alert.header": "DEAUTHFLOOD",
            "kismet.alert.bssid": "02:11:22:33:44:55",
            "kismet.alert.text": "example lab event",
        }
        event, timestamp, checksum = normalize(alert, "sensor-a")
        self.assertEqual(event["wids"]["event"], "DEAUTHFLOOD")
        self.assertAlmostEqual(timestamp, 1800000000.75)
        self.assertEqual(event["wids"]["bssid"], "02:11:22:33:44:55")
        self.assertEqual(len(checksum), 64)

    def test_nested_field(self):
        self.assertEqual(field({"kismet": {"alert": {"header": "APSPOOF"}}},
                               "kismet.alert.header"), "APSPOOF")

    def test_missing_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            normalize({"kismet.alert.header": "DEAUTHFLOOD"}, "sensor-a")


class BurstTests(unittest.TestCase):
    def test_tiers(self):
        self.assertEqual(tier(11), "")
        self.assertEqual(tier(12), "medium")
        self.assertEqual(tier(40), "high")
        self.assertEqual(tier(100), "critical")

    def test_frame_counted_per_bssid_window(self):
        one = "02:11:22:33:44:55"
        two = "02:11:22:33:44:66"
        rows = [f"1800000000.{i:03d}\t{one}\t0x0c\t02:aa:aa:aa:aa:aa\t{one}" for i in range(12)]
        rows += [f"1800000000.123\t{two}\t0x0a\t02:bb:bb:bb:bb:bb\t{two}"]
        out = list(classify_rows(rows, "sensor-a"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["wids"]["tier"], "medium")
        self.assertEqual(out[0]["wids"]["deauth_count"], 12)
        self.assertEqual(out[0]["wids"]["disassoc_count"], 0)

    def test_invalid_thresholds(self):
        with self.assertRaises(ValueError):
            list(classify_rows([], "sensor-a", low=40, high=12))

    def test_xml_syntax_and_unique_ids(self):
        root = ET.parse(HERE / "kismet_wids_rules.xml").getroot()
        ids = [r.attrib["id"] for r in root.findall("rule")]
        self.assertEqual(len(ids), len(set(ids)))


class CorrelationTests(unittest.TestCase):
    def test_signals_require_a_matching_known_sensor(self):
        base = {"sensor": "lab-one", "bssid": "02:11:22:33:44:55", "observed_at": "2026-11-22T00:00:00Z"}
        kismet = dict(base, event="DEAUTHFLOOD")
        pcap = dict(base, event="DISCONNECT_BURST")
        self.assertEqual(len(list(correlate([(kismet, 0)], [(pcap, 60)]))), 1)
        self.assertEqual(list(correlate([(kismet, 0)], [(dict(pcap, sensor="lab-two"), 60)])), [])
        self.assertEqual(list(correlate([(dict(kismet, sensor="unknown"), 0)],
                                         [(dict(pcap, sensor="unknown"), 60)])), [])

    def test_input_alias_cannot_overwrite_evidence(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "kismet.jsonl"
            capture = Path(folder) / "pcap.jsonl"
            content = json.dumps({"wids": {"sensor": "lab", "bssid": "02:11:22:33:44:55",
                                           "observed_at": "2026-11-22T00:00:00Z"}}) + "\n"
            source.write_text(content, encoding="utf-8")
            capture.write_text("", encoding="utf-8")
            process = subprocess.run([sys.executable, str(HERE / "correlate_offline.py"), "--kismet",
                                      str(source), "--pcap-events", str(capture), "--output", str(source)],
                                     capture_output=True, text=True, timeout=5)
            self.assertEqual(process.returncode, 1)
            self.assertIn("Could not correlate events", process.stderr)
            self.assertEqual(source.read_text(encoding="utf-8"), content)

    def test_bad_input_names_the_line(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            path.write_text("\n[]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"events\.jsonl:2:"):
                list(read_events(path))


if __name__ == "__main__":
    unittest.main()
