#!/usr/bin/env python3
"""Evaluate supplied synthetic canary telemetry against alert expectations.

Offline only: does NOT contact a SIEM, EDR, target, or network. The evaluator
reports consistency of supplied evidence, NOT whether any real sensor worked.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import math
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


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def read_jsonl(path):
    result = []
    with Path(path).open(encoding="utf-8") as handle:
        for n, line in enumerate(handle, 1):
            if line.strip():
                try:
                    item = json.loads(line, object_pairs_hook=unique_json_object)
                except json.JSONDecodeError as err:
                    raise ValueError(f"{path}:{n}: invalid JSON") from err
                except ValueError as err:
                    raise ValueError(f"{path}:{n}: {err}") from err
                if not isinstance(item, dict):
                    raise ValueError(f"{path}:{n}: expected object")
                result.append(item)
    return result


def evaluate(cases, observations, evidence_origin="fixture", max_latency=120):
    if (evidence_origin not in ("fixture", "imported-unverified")
            or isinstance(max_latency, bool)
            or not isinstance(max_latency, (int, float))
            or not math.isfinite(max_latency)
            or max_latency < 0):
        raise ValueError("invalid origin or finite, nonnegative latency limit")
    defined = {}
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each test case must be an object")
        key = case.get("test_id")
        if not isinstance(key, str) or not key or key in defined:
            raise ValueError("unique nonempty test_id required")
        if not isinstance(case.get("source"), str) or not case["source"]:
            raise ValueError(f"{key}: nonempty source required")
        expected = case.get("expected_alert")
        rules = case.get("expected_rule_ids")
        if not isinstance(expected, bool) or not isinstance(rules, list):
            raise ValueError(f"{key}: expected_alert boolean and expected_rule_ids list required")
        if (not all(isinstance(v, str) and v.strip() for v in rules)
                or len(set(rules)) != len(rules)
                or bool(rules) != expected):
            raise ValueError(f"{key}: unique nonempty rule IDs required for positive cases only")
        timestamp(case.get("event_time"))
        defined[key] = case
    if not any(c["expected_alert"] for c in cases) or not any(not c["expected_alert"] for c in cases):
        raise ValueError("at least one positive and one negative control required")

    grouped = defaultdict(list)
    for event in observations:
        if not isinstance(event, dict):
            raise ValueError("each observation must be an object")
        key = event.get("test_id")
        if not isinstance(key, str) or not key:
            raise ValueError("observation requires a nonempty string test_id")
        if key not in defined:
            raise ValueError(f"unknown test_id: {key}")
        if event.get("source") != defined[key]["source"]:
            raise ValueError(f"{key}: mismatched source")
        if event.get("kind") not in ("telemetry", "alert"):
            raise ValueError(f"{key}: invalid kind")
        timestamp(event.get("timestamp"))
        if event["kind"] == "alert" and (
                not isinstance(event.get("rule_id"), str)
                or not event["rule_id"].strip()):
            raise ValueError(f"{key}: alert must include nonempty rule_id")
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
        # Missing, duplicate, early or stale telemetry cannot validate either control.
        # max_latency bounds observed telemetry as well as the expected alert.
        telemetry_latency = (
            (timestamp(telemetry[0]["timestamp"]) - event_time).total_seconds()
            if len(telemetry) == 1 else None
        )
        telemetry_ok = (
            telemetry_latency is not None
            and 0 <= telemetry_latency <= max_latency
        )
        if not telemetry_ok:
            verdict = "unassessable"
        elif case["expected_alert"]:
            verdict = "true-positive" if len(correct) == 1 and len(alerts) == 1 and all(0 <= t <= max_latency for t in latencies) else "false-negative"
        else:
            verdict = "false-positive" if alerts else "true-negative"
        counts[verdict] += 1
        outcomes.append({"test_id": key, "source": case["source"], "verdict": verdict,
                         "telemetry_count": len(telemetry), "alert_count": len(alerts),
                         "telemetry_latency_seconds": telemetry_latency,
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
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(rendered)
        except FileExistsError:
            parser.error("report output already exists; choose a new path")
        except OSError as err:
            parser.error(f"cannot write report: {err}")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
