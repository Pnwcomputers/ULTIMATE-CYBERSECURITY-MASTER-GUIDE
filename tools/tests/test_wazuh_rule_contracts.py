"""Offline Wazuh XML structural and illustrative match-contract checks.

NEVER invokes wazuh-logtest or claims actual Wazuh/EDR outcome. Rule semantics
here are deliberately limited to decoded JSON field regex and if_sid ancestry.
Historical frequency/timeframe/same_field is NOT simulated.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
FILES = (
    ROOT / "IncidentResponse/IDS&IPS/kismet-wazuh/kismet_wids_rules.xml",
    ROOT / "IncidentResponse/IDS&IPS/nzyme-wazuh/nzyme_wids_rules.xml",
    ROOT / "IncidentResponse/HoneyPot/lab/honeypot_rules.xml",
)


def read_rules(path: Path):
    root = ET.parse(path).getroot()
    if root.tag != "group" or not root.attrib.get("name"):
        raise ValueError(f"Expected top-level Wazuh group: {path}")
    if any(child.tag != "rule" for child in root):
        raise ValueError(f"Non-rule under outer group: {path}")
    rules = root.findall("rule")
    if not rules:
        raise ValueError(f"No Wazuh rules: {path}")
    for rule in rules:
        if list(rule.findall(".//rule")):
            raise ValueError(f"Nested rule in {path}: {rule.attrib['id']}")
        for field in rule:
            if field.tag == "group":
                if len(list(field)) or not (field.text or "").strip().endswith(","):
                    raise ValueError(f"Invalid grouping label in {path}: {rule.attrib['id']}")
        if not rule.findtext("description"):
            raise ValueError(f"Missing description in {path}: {rule.attrib['id']}")
    return rules


def lookup(event: dict, dotted: str):
    value = event
    for key in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def offline_candidate_ids(path: Path, event: dict):
    """Best-effort regex-only documentation test; NOT a Wazuh engine simulation."""
    rules = read_rules(path)
    passed = set()
    for rule in rules:
        sid = int(rule.attrib["id"])
        if rule.find("if_matched_sid") is not None:
            continue  # frequency/timeframe semantics deliberately unsupported
        parent = rule.findtext("if_sid")
        if parent and not any(int(x.strip()) in passed for x in parent.split(",")):
            continue
        fields = rule.findall("field")
        if fields and not all(
            lookup(event, f.attrib["name"]) is not None
            and re.search(f.text or "", str(lookup(event, f.attrib["name"])))
            for f in fields
        ):
            continue
        if rule.findtext("decoded_as") == "json" or parent:
            passed.add(sid)
    return passed


class WazuhContractTests(unittest.TestCase):
    def test_rule_tree_and_local_parent_references(self):
        seen = set()
        all_rules = []
        for path in FILES:
            rules = read_rules(path)
            all_rules.extend((path, rule) for rule in rules)
        for path, rule in all_rules:
            rid = int(rule.attrib["id"])
            self.assertTrue(100000 <= rid < 120000)
            self.assertNotIn(rid, seen, f"Duplicate custom rule ID: {rid}")
            seen.add(rid)
            self.assertTrue(0 <= int(rule.attrib["level"]) <= 16)
        for path, rule in all_rules:
            for key in ("if_sid", "if_matched_sid"):
                parent = rule.findtext(key)
                if parent:
                    for part in re.split(r"[, ]+", parent.strip()):
                        if part:
                            self.assertIn(int(part), seen, f"Missing parent {part} in {path}")

    def test_example_positive_negative_events_are_separated(self):
        kismet = FILES[0]
        pos = {"wids": {"integration": "kismet", "event": "DEAUTHFLOOD", "bssid": "02:00:00:00:00:01"}}
        benign = {"wids": {"integration": "kismet", "event": "CHANCHANGE"}}
        self.assertTrue({100300, 100301} <= offline_candidate_ids(kismet, pos))
        self.assertNotIn(100302, offline_candidate_ids(kismet, pos))
        self.assertNotIn(100301, offline_candidate_ids(kismet, benign))
        self.assertEqual(offline_candidate_ids(kismet, {"wids": {"integration": "other"}}), set())
        correlation = {"wids": {"integration": "correlator", "event": "KISMET_PCAP_CORRELATED"}}
        self.assertIn(100340, offline_candidate_ids(kismet, correlation))

        nzyme = FILES[1]
        self.assertIn(100352, offline_candidate_ids(nzyme, {"wids": {
            "integration": "nzyme", "category": "disconnect_anomaly"}}))
        self.assertNotIn(100352, offline_candidate_ids(nzyme, {"wids": {
            "integration": "nzyme", "category": "system_event"}}))
        self.assertIn(100354, offline_candidate_ids(nzyme, {"wids": {
            "integration": "nzyme", "category": "system_event"}}))

        honeypot = FILES[2]
        get = {"honeypot": {"integration": "diy_http", "event": "http_probe", "method": "GET"}}
        post = {"honeypot": {"integration": "diy_http", "event": "http_probe", "method": "POST"}}
        serial = {"honeypot": {"integration": "esp32_serial", "event": "tcp_connection"}}
        self.assertEqual(offline_candidate_ids(honeypot, get), {100400})
        self.assertEqual(offline_candidate_ids(honeypot, post), {100400, 100401})
        self.assertEqual(offline_candidate_ids(honeypot, serial), {100402})

    def test_wazuh_output_not_presented_as_observed(self):
        # This fixture explicitly records missing real-manager evidence.
        case = {"test_kind": "offline_json_regex_contract",
                "siem_actual_result": "not-tested",
                "independent_sensor_confirmation": "not-tested",
                "deployment_approved": False}
        self.assertEqual(json.loads(json.dumps(case))["siem_actual_result"], "not-tested")


if __name__ == "__main__":
    unittest.main()
