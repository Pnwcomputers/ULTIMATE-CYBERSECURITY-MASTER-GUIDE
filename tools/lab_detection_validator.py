#!/usr/bin/env python3
"""Evaluate supplied synthetic canary telemetry against alert expectations.

Offline only: does NOT contact a SIEM, EDR, target, or network. The evaluator
reports consistency of supplied evidence, NOT whether any real sensor worked.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("ISO-8601 timestamp required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as err:
        raise ValueError(f"invalid timestamp: {value}") from err
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def read_jsonl(path):
    result = []
    with Path(path).open(encoding="utf-8") as handle:
        for n, line in enumerate(handle, 1):
            if line.strip():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as err:
                    raise ValueError(f"{path}:{n}: invalid JSON") from err
                if not isinstance(item, dict):
                    raise ValueError(f"{path}:{n}: expected object")
                result.append(item)
    return result


def evaluate(cases, observations, evidence_origin="fixture", max_latency=120):
    if evidence_origin not in ("fixture", "imported-unverified") or max_latency < 0:
        raise ValueError("invalid origin or latency limit")
    defined = {}
    for case in cases:
        key = case.get("test_id")
        if not isinstance(key, str) or not key or key in defined:
            raise ValueError("unique nonempty test_id required")
        if not isinstance(case.get("source"), str) or not case["source"]:
            raise ValueError(f"{key}: nonempty source required")
        expected = case.get("expected_alert")
        rules = case.get("expected_rule_ids")
        if not isinstance(expected, bool) or not isinstance(rules, list):
            raise ValueError(f"{key}: expected_alert boolean and expected_rule_ids list required")
        if not all(isinstance(v, str) and v for v in rules) or bool(rules) != expected:
            raise ValueError(f"{key}: rule IDs must be strings for positive cases only")
        timestamp(case.get("event_time"))
        defined[key] = case
    if not any(c["expected_alert"] for c in cases) or not any(not c["expected_alert"] for c in cases):
        raise ValueError("at least one positive and one negative control required")

    grouped = defaultdict(list)
    for event in observations:
        key = event.get("test_id")
        if key not in defined:
            raise ValueError(f"unknown test_id: {key}")
        if event.get("source") != defined[key]["source"]:
            raise ValueError(f"{key}: mismatched source")
        if event.get("kind") not in ("telemetry", "alert"):
            raise ValueError(f"{key}: invalid kind")
        timestamp(event.get("timestamp"))
        if event["kind"] == "alert" and not isinstance(event.get("rule_id"), str):
            raise ValueError(f"{key}: alert must include rule_id")
        grouped[key].append(event)

    outcomes = []
    counts = Counter()
    for key, case in defined.items():
        observations_here = grouped[key]
        telemetry = [x for x in observations_here if x["kind"] == "telemetry"]
        alerts = [x for x in observations_here if x["kind"] == "alert"]
        correct = [x for x in alerts if x["rule_id"] in case["expected_rule_ids"]]
        event_time = timestamp(case["event_time"])
        latencies = [(timestamp(x["timestamp"]) - event_time).total_seconds() for x in correct]
        # A missing/doubled telemetry event is a visibility problem, not evidence of a negative result.
        telemetry_ok = len(telemetry) == 1 and timestamp(telemetry[0]["timestamp"]) >= event_time
        if not telemetry_ok:
            verdict = "unassessable"
        elif case["expected_alert"]:
            verdict = "true-positive" if len(correct) == 1 and len(alerts) == 1 and all(0 <= t <= max_latency for t in latencies) else "false-negative"
        else:
            verdict = "false-positive" if alerts else "true-negative"
        counts[verdict] += 1
        outcomes.append({"test_id": key, "source": case["source"], "verdict": verdict,
                         "telemetry_count": len(telemetry), "alert_count": len(alerts),
                         "matching_rule_count": len(correct),
                         "matching_alert_latency_seconds": latencies})
    return {"evidence_origin": evidence_origin, "real_siem_validated": False,
            "counts": dict(sorted(counts.items())), "cases": outcomes,
            "notice": "Input evidence is user-supplied. Verify exporter, source timestamps, versions and chain of custody independently."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--evidence-origin", choices=("fixture", "imported-unverified"), default="fixture")
    parser.add_argument("--max-latency", type=float, default=120)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = evaluate(read_jsonl(args.cases), read_jsonl(args.observations),
                          args.evidence_origin, args.max_latency)
    except (ValueError, OSError) as err:
        parser.error(str(err))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
