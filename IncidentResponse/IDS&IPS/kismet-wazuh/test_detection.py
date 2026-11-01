#!/usr/bin/env python3
"""Offline unit checks. Run: python3 -m unittest discover -s kismet-wazuh -p 'test_*.py' -v"""
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
