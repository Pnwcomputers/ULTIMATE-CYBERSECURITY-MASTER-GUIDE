"""Isolated canary-evaluator regression tests; no outside services."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "tools/lab_detection_validator.py"
spec = spec_from_file_location("lab_validator", PATH)
mod = module_from_spec(spec)
spec.loader.exec_module(mod)


def cases():
    return [
        {"test_id": "positive-1", "source": "mock-wazuh", "event_time": "2026-11-11T16:00:00Z",
         "expected_alert": True, "expected_rule_ids": ["100301"]},
        {"test_id": "negative-1", "source": "mock-wazuh", "event_time": "2026-11-11T16:00:00Z",
         "expected_alert": False, "expected_rule_ids": []},
    ]


def observation(key, kind, offset, rule=None):
    record = {"test_id": key, "source": "mock-wazuh", "kind": kind,
              "timestamp": f"2026-11-11T16:00:{offset:02d}Z"}
    if rule:
        record["rule_id"] = rule
    return record


def baseline():
    return [observation("positive-1", "telemetry", 1),
            observation("positive-1", "alert", 2, "100301"),
            observation("negative-1", "telemetry", 1)]


class LabEvaluatorTests(unittest.TestCase):
    def test_paired_controls(self):
        r = mod.evaluate(cases(), baseline(), max_latency=5)
        self.assertEqual(r["counts"], {"true-negative": 1, "true-positive": 1})
        self.assertFalse(r["real_siem_validated"])
        self.assertEqual(r["evidence_origin"], "fixture")

    def test_false_positive_and_false_negative(self):
        events = [observation("positive-1", "telemetry", 1),
                  observation("negative-1", "telemetry", 1),
                  observation("negative-1", "alert", 2, "unapproved-rule")]
        r = mod.evaluate(cases(), events)
        self.assertEqual(r["counts"], {"false-negative": 1, "false-positive": 1})

    def test_latency_and_duplicates_fail(self):
        events = baseline() + [observation("positive-1", "alert", 7, "100301")]
        r = mod.evaluate(cases(), events, max_latency=5)
        self.assertEqual(r["counts"].get("false-negative"), 1)

    def test_missing_telemetry_is_unassessable(self):
        r = mod.evaluate(cases(), [observation("positive-1", "alert", 2, "100301"),
                                    observation("negative-1", "telemetry", 1)])
        self.assertEqual(r["counts"], {"true-negative": 1, "unassessable": 1})

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(ValueError):
            mod.evaluate(cases()[:1], baseline())
        with self.assertRaises(ValueError):
            mod.evaluate(cases(), baseline() + [observation("foreign", "telemetry", 1)])
        with self.assertRaises(ValueError):
            mod.evaluate(cases(), [dict(baseline()[0], timestamp="2026-11-11T16:00:01")])
        with self.assertRaises(ValueError):
            mod.evaluate(cases(), baseline(), evidence_origin="certified")

    def test_cli_can_run_with_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "cases.jsonl", Path(d) / "observations.jsonl"
            a.write_text("\n".join(json.dumps(x) for x in cases()) + "\n")
            b.write_text("\n".join(json.dumps(x) for x in baseline()) + "\n")
            run = subprocess.run([sys.executable, str(PATH), "--cases", str(a),
                                  "--observations", str(b)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["counts"]["true-positive"], 1)


if __name__ == "__main__":
    unittest.main()
