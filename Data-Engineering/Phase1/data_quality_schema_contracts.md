# ✅ Data Quality & Schema Contracts

<div align="center">

**Validation, nulls, duplicates, schema evolution, compatibility gates, quarantine, and producer/consumer expectations**

*Declared contracts • Record and batch checks • Null rates • Breaking-change detection • Reject handling*

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md)*

![Foundations](https://img.shields.io/badge/Level-Foundations-blue?style=for-the-badge)
![Quality](https://img.shields.io/badge/Focus-Data_Quality-darkgreen?style=for-the-badge)
![Contracts](https://img.shields.io/badge/Design-Schema_Contracts-purple?style=for-the-badge)
![Lab](https://img.shields.io/badge/Lab-Python_Stdlib-orange?style=for-the-badge)

</div>

---

_Last reviewed: 2026-09-11. The validator and compatibility checker were executed against the fixtures; all counts shown are actual output. See the [Verification Record](#verification-record)._

**Prerequisites:** [Data Engineering Fundamentals](./data_engineering_fundamentals.md) for quarantine and identity, and [ETL & ELT Pipeline Design](./etl_elt_pipeline_design.md) for where validation sits in a load.

## 🎯 Purpose

Replace the implicit assumptions inside a loader with an explicit, versioned contract — a file that states what a valid record is, what the batch as a whole must look like, and which changes to that definition are allowed to ship without coordination.

## ⚙️ Function

Define the six dimensions of data quality; separate record-level from batch-level checks; handle nulls and duplicates deliberately; build a contract-driven validator that quarantines rejects with reasons and enforces batch expectations; build a compatibility checker that classifies schema changes as compatible or breaking and fails a build on the latter; and set out the obligations a producer and a consumer owe each other.

## 🏆 Goal

Enable a practitioner to point at a file and say "this is what valid means", have a failing batch stop before it reaches consumers with a named reason, and have a breaking schema change rejected in review rather than discovered by a downstream outage.

## 📋 When to Use

- Adding validation to any pipeline built in this section.
- Diagnosing a consumer complaint about missing, duplicated, or nonsensical data.
- Planning a schema change to a dataset other teams already read.
- Establishing what a data producer is accountable for.
- Deciding whether a bad batch should fail the run or be quarantined.

## 🧰 Audience & Prerequisites

**Audience:** Practitioners responsible for a dataset that someone else depends on.

**Prerequisites:** Python 3.10 or later. The lab uses only `json`, `re`, `datetime`, `collections`, and `logging`, so it runs anywhere without installation. Production alternatives such as JSON Schema, Pydantic, Avro, Great Expectations, and dbt tests are referenced but not required.

> [!NOTE]
> The contract format used here is deliberately minimal so the validation logic is fully visible. In production, prefer an established specification — the concepts transfer directly, and a standard format brings tooling and a registry with it.

---

<a id="table-of-contents"></a>

## 📋 Table of Contents

- [📐 1. The Six Dimensions of Quality](#1-the-six-dimensions-of-quality)
- [📜 2. What a Contract Contains](#2-what-a-contract-contains)
- [🔎 3. Record-Level Validation](#3-record-level-validation)
- [📊 4. Batch-Level Expectations](#4-batch-level-expectations)
- [🕳️ 5. Nulls](#5-nulls)
- [👯 6. Duplicates](#6-duplicates)
- [🧪 7. Lab: The Contract Validator](#7-lab-the-contract-validator)
- [🔀 8. Schema Evolution and Compatibility](#8-schema-evolution-and-compatibility)
- [🚧 9. Quarantine and Reject Handling](#9-quarantine-and-reject-handling)
- [🤝 10. Producer and Consumer Obligations](#10-producer-and-consumer-obligations)
- [🎓 11. Self-Check](#11-self-check)
- [✅ Verification Record](#verification-record)
- [🤝 Contributing](#contributing)
- [📚 Resources](#resources)
- [🔗 Quick Links & Related Guides](#see-also)
- [📊 Guide Details](#guide-details)

---

<a id="1-the-six-dimensions-of-quality"></a>

## 📐 1. The Six Dimensions of Quality

"Bad data" is not a diagnosis. These six dimensions turn it into one, and each maps to a check that can be automated.

| Dimension | Question | Automated check |
| --- | --- | --- |
| **Completeness** | Is every expected value and record present? | Null rates; source-versus-destination counts |
| **Validity** | Does each value conform to its declared type and domain? | Type, enum, pattern, range checks |
| **Uniqueness** | Does each real-world entity appear once? | Distinct primary key count versus row count |
| **Consistency** | Do related values agree with each other? | Cross-field rules; referential integrity |
| **Timeliness** | Is the data recent enough to be useful? | Freshness and lag measurement |
| **Accuracy** | Do the values match reality? | Reconciliation against an authoritative source |

Accuracy is the only dimension a pipeline cannot verify on its own — it requires a second source of truth. The other five are entirely mechanizable, which is why they are where the effort belongs.

> [!TIP]
> When a consumer reports "the data is wrong", ask which dimension. Roughly half of such reports resolve to timeliness (the data is correct but stale) or to a definitional disagreement about completeness — neither of which is fixed by changing the transformation.

---

<a id="2-what-a-contract-contains"></a>

## 📜 2. What a Contract Contains

A schema says what the fields are. A **contract** adds the promises around them and the rules for changing them.

| Element | Purpose |
| --- | --- |
| **Name and version** | Identify the dataset and the contract revision |
| **Field specifications** | Type, required, nullable, and value constraints |
| **Primary key** | Which fields define record identity, and therefore the grain |
| **Batch expectations** | Thresholds the batch as a whole must satisfy |
| **Compatibility policy** | Which changes may ship without consumer coordination |
| **Ownership** | Who is accountable, and how they are contacted |
| **Freshness commitment** | How current consumers may assume the data is |

The contract used in the lab:

```json
{
  "name": "asset_checkin",
  "version": 1,
  "primary_key": ["serial", "checked_at"],
  "fields": {
    "serial":     {"type": "string",  "required": true,  "nullable": false, "pattern": "^SN-[0-9]{4}$"},
    "hostname":   {"type": "string",  "required": true,  "nullable": false, "max_length": 63},
    "site":       {"type": "string",  "required": true,  "nullable": false, "enum": ["vancouver","portland","seattle"]},
    "checked_at": {"type": "timestamp", "required": true, "nullable": false},
    "cpu_pct":    {"type": "number",  "required": true,  "nullable": true,  "min": 0, "max": 100},
    "status":     {"type": "string",  "required": true,  "nullable": false, "enum": ["ok","warn","fail"]}
  },
  "expectations": {
    "max_null_rate": {"cpu_pct": 0.25},
    "max_duplicate_rate": 0.0,
    "max_reject_rate": 0.20
  }
}
```

### 📘 Required and nullable are different properties

This distinction causes more contract disputes than any other:

| `required` | `nullable` | Meaning |
| --- | --- | --- |
| `true` | `false` | The key must be present and hold a real value |
| `true` | `true` | The key must be present; `null` is a valid, meaningful value |
| `false` | `true` | The key may be absent entirely |
| `false` | `false` | If present, it must hold a real value |

`cpu_pct` is `required: true, nullable: true` — the agent must always report the field, but `null` is the legitimate way to say "I could not measure this". That is deliberately different from omitting the field, which would mean the agent is an older version that does not know about it.

### 📘 Keep the contract next to the code

The contract belongs in version control, in the same repository as the pipeline, reviewed through the same process. A contract maintained in a wiki drifts from the code within weeks and then actively misleads. See the Git workflow section of [data_pipelines.md](../data_pipelines.md#5-manage-code-and-configuration-with-git).

---

<a id="3-record-level-validation"></a>

## 🔎 3. Record-Level Validation

Record-level checks examine one record in isolation and answer: is this record admissible?

| Check | Catches |
| --- | --- |
| **Presence** | A required key absent from the record |
| **Nullability** | `null` where a real value is mandatory |
| **Type** | A string where a number is declared |
| **Enum** | A status value the consumer has no branch for |
| **Pattern** | A malformed identifier that would break joins |
| **Range** | A percentage of 150 |
| **Length** | A hostname exceeding the destination column |
| **Timestamp** | A time with no timezone offset (see [Python for Data Processing](./python_data_processing.md#6-timestamps-done-correctly)) |
| **Unknown fields** | A producer-side addition the contract has not agreed to |

### 📘 Collect every error, not the first

```python
def validate_record(contract: dict, record: dict) -> list[str]:
    errors = [e for n, s in contract["fields"].items()
              if (e := validate_field(n, s, record))]
    unknown = set(record) - set(contract["fields"])
    if unknown:
        errors.append(f"unknown fields present: {sorted(unknown)}")
    return errors
```

Returning a list rather than raising on the first problem matters operationally: a producer fixing rejects wants the complete defect list for a record, not to rediscover a new problem on each iteration.

### 📘 Handling unknown fields

Three defensible policies, and the contract must state which applies:

| Policy | Behavior | Use when |
| --- | --- | --- |
| **Strict** | Reject records with unrecognized fields | The contract is authoritative and producers are coordinated |
| **Ignore** | Drop unknown fields silently | Wide, evolving sources; consumers take only declared fields |
| **Capture** | Store unknown fields in a catch-all column | Raw retention matters and the producer iterates fast |

The lab uses **strict**, which surfaces producer-side changes immediately. For a high-churn telemetry source, **capture** is usually better: the data is preserved, and a review of the catch-all column shows what the producer started sending.

---

<a id="4-batch-level-expectations"></a>

## 📊 4. Batch-Level Expectations

Some failures are invisible at record level. Every record can be individually valid while the batch as a whole is clearly wrong.

| Expectation | Detects |
| --- | --- |
| **Max reject rate** | A producer-side format change or a broken upstream job |
| **Max duplicate rate** | A double delivery or a failed deduplication |
| **Max null rate per field** | A sensor or agent that stopped reporting a value |
| **Min/max row count** | An empty extract or a runaway duplication |
| **Freshness** | A source that has stopped producing |
| **Distribution shift** | A category that vanished or a mean that moved sharply |

### 📘 Why rates rather than counts

A threshold of "fewer than 50 rejects" fails differently on a 100-row batch than on a 10-million-row batch. Rates are stable across volume. Keep absolute floors only where they genuinely apply — for example, a minimum expected row count that catches an empty extract.

### 📘 Where the threshold comes from

Do not invent thresholds. Measure the pipeline for a period, observe the normal rate, and set the limit above the observed range with margin. A threshold set below normal variation generates alerts that get muted, which is worse than having no threshold at all.

> [!WARNING]
> A batch expectation that fails must actually stop something. A check that logs a warning into a stream nobody reads is decorative. Decide per expectation: does a breach halt the load, quarantine the batch for review, or page someone? Write that decision into the contract.

---

<a id="5-nulls"></a>

## 🕳️ 5. Nulls

`null` is a legitimate value meaning *unknown*. The failure is never that nulls exist — it is that they are undifferentiated.

Three distinct situations are routinely collapsed into one `null`:

| Situation | Meaning | Should be distinguishable |
| --- | --- | --- |
| Not measured | The agent could not read the value | Yes — a rising rate is an incident |
| Not applicable | The field has no meaning for this record type | Yes — never a defect |
| Lost in the pipeline | A join missed or a parse failed | Yes — always a defect |

The third is the dangerous one, because it looks exactly like the first two. Two practices separate them:

1. **Never substitute a default that is indistinguishable from a real value.** Writing `0` for an unmeasured CPU percentage corrupts every average computed afterwards, permanently and unrecoverably.
2. **Record the reason alongside the value where it matters.** A `cpu_pct_status` column holding `measured` / `unavailable` / `not_applicable` costs one column and eliminates an entire class of ambiguity.

### 📘 Monitor the rate, not the presence

```sql
SELECT COUNT(*) AS rows,
       COUNT(cpu_pct) AS with_value,
       ROUND(1.0 * (COUNT(*) - COUNT(cpu_pct)) / COUNT(*), 3) AS null_rate
FROM dw_checkins
WHERE checked_at >= date('now', '-1 day');
```

A null rate that moves from 2% to 40% overnight is a real incident that no record-level check fires on — every one of those nulls is contractually valid. This is exactly what batch expectations exist to catch.

---

<a id="6-duplicates"></a>

## 👯 6. Duplicates

A duplicate is defined relative to the primary key in the contract. Until the key is declared, "duplicate" has no meaning.

| Type | Definition | Usual cause |
| --- | --- | --- |
| **Exact** | Every field identical | Retry, double delivery, overlap window |
| **Key** | Same primary key, different attributes | A restatement, or a genuine key collision |
| **Near** | Same entity, different representation | Casing, whitespace, or formatting differences |

### 📘 Normalize before comparing

Near-duplicates are defeated at the transformation step, not the deduplication step. `"SN-1001"`, `"sn-1001 "`, and `"SN‑1001"` (with a non-breaking hyphen) are three distinct strings and one physical asset. Apply Unicode normalization, trimming, and case folding before the key is computed — the `normkey()` pattern from [Python for Data Processing](./python_data_processing.md#2-text-bytes-and-encoding).

### 📘 Where to enforce uniqueness

| Location | Mechanism | Strength |
| --- | --- | --- |
| Validator | In-memory set of seen keys per batch | Within a batch only |
| Destination | `UNIQUE` constraint plus upsert | Across all batches, always |
| Consumer | `SELECT DISTINCT` or window deduplication | Fragile; every consumer must remember |

The destination constraint is the only one that holds unconditionally. The batch check is still worth having because it attributes the duplicate to a specific batch and line, which the constraint cannot do.

> [!NOTE]
> Key duplicates within a single batch are ambiguous by nature: two records claim the same identity with different attributes, and nothing in the data says which is correct. The defensible options are to reject both and alert, or to apply a documented tiebreaker such as "highest source timestamp wins". Silently keeping whichever arrived last is the option to avoid.

---

<a id="7-lab-the-contract-validator"></a>

## 🧪 7. Lab: The Contract Validator

### 🧪 Step 1: The batch

Save the contract from §2 as `contract_v1.json`, then create `batch.jsonl` with ten records containing a representative spread of defects:

```json
{"serial":"SN-1001","hostname":"ws-acct-01","site":"vancouver","checked_at":"2026-09-10T14:00:00+00:00","cpu_pct":12.5,"status":"ok"}
{"serial":"SN-1002","hostname":"ws-acct-02","site":"vancouver","checked_at":"2026-09-10T14:05:00+00:00","cpu_pct":null,"status":"ok"}
{"serial":"SN-1003","hostname":"srv-file-01","site":"portland","checked_at":"2026-09-10T14:07:00+00:00","cpu_pct":38.4,"status":"ok"}
{"serial":"SN-1001","hostname":"ws-acct-01","site":"vancouver","checked_at":"2026-09-10T14:00:00+00:00","cpu_pct":12.5,"status":"ok"}
{"serial":"1004","hostname":"ws-ops-07","site":"portland","checked_at":"2026-09-10T14:09:00+00:00","cpu_pct":22.0,"status":"ok"}
{"serial":"SN-1005","hostname":"ws-ship-03","site":"spokane","checked_at":"2026-09-10T14:11:00+00:00","cpu_pct":81.0,"status":"warn"}
{"serial":"SN-1006","hostname":"ws-spare-01","site":"seattle","checked_at":"2026-09-10 14:13:00","cpu_pct":5.0,"status":"ok"}
{"serial":"SN-1007","hostname":"ws-lab-02","site":"seattle","checked_at":"2026-09-10T14:15:00+00:00","cpu_pct":150,"status":"ok"}
{"serial":"SN-1008","hostname":"ws-lab-03","site":"seattle","checked_at":"2026-09-10T14:17:00+00:00","cpu_pct":44.0,"status":"degraded"}
{"serial":"SN-1009","hostname":"ws-lab-04","site":"portland","checked_at":"2026-09-10T14:19:00+00:00","status":"ok"}
```

Each defect is deliberate: a duplicate key, a serial failing the pattern, a site outside the enum, a timestamp without an offset, a CPU above the maximum, an unknown status, and a missing required field.

### 🧪 Step 2: The validator

`validate.py`:

```python
#!/usr/bin/env python3
"""Validate a JSON Lines batch against a declared data contract."""
from __future__ import annotations
import datetime as dt, json, logging, pathlib, re, sys
from collections import Counter

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
log = logging.getLogger("validate")

CHECKERS = {
    "string":  lambda v: isinstance(v, str),
    "number":  lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
}


def check_timestamp(value) -> str | None:
    if not isinstance(value, str):
        return "expected timestamp string"
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return f"unparseable timestamp: {value!r}"
    if parsed.tzinfo is None:
        return f"timestamp lacks timezone offset: {value!r}"
    return None


def validate_field(name: str, spec: dict, record: dict) -> str | None:
    present = name in record
    if not present:
        return None if not spec.get("required", False) else f"{name}: required field absent"
    value = record[name]
    if value is None:
        return None if spec.get("nullable", False) else f"{name}: null not permitted"

    ftype = spec["type"]
    if ftype == "timestamp":
        return (lambda e: f"{name}: {e}" if e else None)(check_timestamp(value))
    if not CHECKERS[ftype](value):
        return f"{name}: expected {ftype}, got {type(value).__name__}"
    if "enum" in spec and value not in spec["enum"]:
        return f"{name}: {value!r} not in allowed values {spec['enum']}"
    if "pattern" in spec and not re.fullmatch(spec["pattern"], value):
        return f"{name}: {value!r} does not match {spec['pattern']}"
    if "max_length" in spec and len(value) > spec["max_length"]:
        return f"{name}: length {len(value)} exceeds {spec['max_length']}"
    if "min" in spec and value < spec["min"]:
        return f"{name}: {value} below minimum {spec['min']}"
    if "max" in spec and value > spec["max"]:
        return f"{name}: {value} above maximum {spec['max']}"
    return None


def validate_record(contract: dict, record: dict) -> list[str]:
    errors = [e for n, s in contract["fields"].items()
              if (e := validate_field(n, s, record))]
    unknown = set(record) - set(contract["fields"])
    if unknown:
        errors.append(f"unknown fields present: {sorted(unknown)}")
    return errors


def main(contract_path: str, batch_path: str) -> int:
    contract = json.loads(pathlib.Path(contract_path).read_text())
    exp = contract.get("expectations", {})
    pk = contract["primary_key"]

    accepted, rejected = [], []
    seen, dup_keys = set(), Counter()
    null_counts, reason_counts = Counter(), Counter()
    total = 0

    with open(batch_path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            total += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                rejected.append({"line": line_no, "errors": [f"malformed json: {exc}"],
                                 "raw": line[:200]})
                reason_counts["malformed json"] += 1
                continue

            errors = validate_record(contract, record)
            if errors:
                rejected.append({"line": line_no, "errors": errors, "raw": record})
                for e in errors:
                    reason_counts[e.split(":")[0] if ":" in e else e] += 1
                continue

            key = tuple(record.get(k) for k in pk)
            if key in seen:
                dup_keys[key] += 1
                rejected.append({"line": line_no, "errors": ["duplicate primary key"],
                                 "raw": record})
                reason_counts["duplicate primary key"] += 1
                continue
            seen.add(key)

            for name in contract["fields"]:
                if record.get(name) is None:
                    null_counts[name] += 1
            accepted.append(record)

    pathlib.Path("accepted.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in accepted))
    pathlib.Path("quarantine.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in rejected))

    n_acc = len(accepted)
    reject_rate = len(rejected) / total if total else 0.0
    dup_rate = sum(dup_keys.values()) / total if total else 0.0

    log.info("records=%d accepted=%d rejected=%d reject_rate=%.2f duplicate_rate=%.2f",
             total, n_acc, len(rejected), reject_rate, dup_rate)
    for reason, count in reason_counts.most_common():
        log.info("  reason %-28s %d", reason, count)

    breaches = []
    if reject_rate > exp.get("max_reject_rate", 1.0):
        breaches.append(f"reject_rate {reject_rate:.2f} > {exp['max_reject_rate']}")
    if dup_rate > exp.get("max_duplicate_rate", 1.0):
        breaches.append(f"duplicate_rate {dup_rate:.2f} > {exp['max_duplicate_rate']}")
    for field, limit in exp.get("max_null_rate", {}).items():
        rate = null_counts[field] / n_acc if n_acc else 0.0
        log.info("  null_rate %-28s %.2f (limit %.2f)", field, rate, limit)
        if rate > limit:
            breaches.append(f"null_rate[{field}] {rate:.2f} > {limit}")

    if breaches:
        for b in breaches:
            log.error("EXPECTATION BREACH: %s", b)
        return 1
    log.info("all batch expectations met")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
```

### 🧪 Step 3: Run it

```bash
python3 validate.py contract_v1.json batch.jsonl; echo "exit=$?"
```

Actual output:

```text
INFO validate records=10 accepted=3 rejected=7 reject_rate=0.70 duplicate_rate=0.10
INFO validate   reason cpu_pct                      2
INFO validate   reason duplicate primary key        1
INFO validate   reason serial                       1
INFO validate   reason site                         1
INFO validate   reason checked_at                   1
INFO validate   reason status                       1
INFO validate   null_rate cpu_pct                      0.33 (limit 0.25)
ERROR validate EXPECTATION BREACH: reject_rate 0.70 > 0.2
ERROR validate EXPECTATION BREACH: duplicate_rate 0.10 > 0.0
ERROR validate EXPECTATION BREACH: null_rate[cpu_pct] 0.33 > 0.25
exit=1
```

Three things are worth reading closely:

- **`cpu_pct` appears twice** in the reason counts — once for the value of 150 exceeding the maximum, once for the field being absent on the final record. Grouping by field name shows a producer which field to investigate.
- **The null-rate breach is the subtle one.** One of the three accepted records has `cpu_pct: null`, which is contractually valid per-record. Only the batch-level view reveals that a third of accepted records carry no CPU reading.
- **The exit status is 1.** This is what makes the validator usable as a gate in an orchestrated pipeline rather than an advisory script.

Inspect the rejects — each carries its line number, every failing rule, and the original record:

```bash
python3 -c "
import json
for l in open('quarantine.jsonl'):
    r = json.loads(l); print(r['line'], r['errors'])"
```

---

<a id="8-schema-evolution-and-compatibility"></a>

## 🔀 8. Schema Evolution and Compatibility

Schemas change. The question is whether a given change breaks the consumers that already exist.

| Mode | Definition | Enables |
| --- | --- | --- |
| **Backward compatible** | New readers can read old data | Upgrade consumers before producers |
| **Forward compatible** | Old readers can read new data | Upgrade producers before consumers |
| **Full** | Both | Upgrade in any order |
| **Breaking** | Neither | Requires coordinated deployment |

### 📘 Classifying a change

| Change | Classification | Reason |
| --- | --- | --- |
| Add an optional/nullable field | Compatible | Old readers ignore it |
| Add a required non-nullable field | **Breaking** | Old producers emit records that now fail validation |
| Remove a field | **Breaking** | Consumers referencing it break |
| Widen a type (`integer` → `number`) | Compatible | Old values remain valid |
| Narrow a type (`number` → `integer`) | **Breaking** | Existing values may not fit |
| Add an enum value | Compatible for producers, **breaking for strict consumers** | A consumer with an exhaustive branch has no case for it |
| Remove an enum value | **Breaking** | Existing data becomes invalid |
| Loosen a range | Compatible | Previously valid values stay valid |
| Tighten a range | **Breaking** | Existing data may now fail |
| Make an optional field required | **Breaking** | Old records lack it |
| Make a nullable field non-nullable | **Breaking** | Existing nulls become invalid |
| Change the primary key | **Breaking** | Redefines identity and the grain |
| Rename a field | **Breaking** | Equivalent to remove plus add |

> [!CAUTION]
> Adding an enum value is the change most often misfiled as safe. It is safe for anything storing the value as text, and breaking for any consumer with an exhaustive `match`, a `CHECK` constraint, or a lookup table. Classify it by what consumers actually do, not by the storage type — and tell consumers before shipping it.

### 📘 The compatibility checker

`compat.py`:

```python
#!/usr/bin/env python3
"""Classify the difference between two contract versions as compatible or breaking."""
from __future__ import annotations
import json, pathlib, sys

def classify(old: dict, new: dict) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    of, nf = old["fields"], new["fields"]

    for name in nf.keys() - of.keys():
        spec = nf[name]
        if spec.get("required") and not spec.get("nullable"):
            findings.append(("BREAKING", f"added required non-nullable field '{name}'"))
        else:
            findings.append(("COMPATIBLE", f"added optional field '{name}'"))

    for name in of.keys() - nf.keys():
        findings.append(("BREAKING", f"removed field '{name}'"))

    for name in of.keys() & nf.keys():
        o, n = of[name], nf[name]
        if o["type"] != n["type"]:
            findings.append(("BREAKING", f"'{name}' type changed {o['type']} -> {n['type']}"))
        if not o.get("required") and n.get("required"):
            findings.append(("BREAKING", f"'{name}' became required"))
        if o.get("nullable") and not n.get("nullable"):
            findings.append(("BREAKING", f"'{name}' no longer nullable"))
        if "enum" in o and "enum" in n:
            removed = set(o["enum"]) - set(n["enum"])
            added = set(n["enum"]) - set(o["enum"])
            if removed:
                findings.append(("BREAKING", f"'{name}' enum values removed: {sorted(removed)}"))
            if added:
                findings.append(("COMPATIBLE", f"'{name}' enum values added: {sorted(added)}"))
        for bound, worse in (("min", lambda a, b: b > a), ("max", lambda a, b: b < a)):
            if bound in o and bound in n and worse(o[bound], n[bound]):
                findings.append(("BREAKING", f"'{name}' {bound} tightened {o[bound]} -> {n[bound]}"))
    if old.get("primary_key") != new.get("primary_key"):
        findings.append(("BREAKING",
                         f"primary key changed {old.get('primary_key')} -> {new.get('primary_key')}"))
    return findings

def main(old_path: str, new_path: str) -> int:
    old = json.loads(pathlib.Path(old_path).read_text())
    new = json.loads(pathlib.Path(new_path).read_text())
    print(f"{old['name']} v{old['version']} -> v{new['version']}")
    findings = classify(old, new)
    for level, msg in sorted(findings):
        print(f"  [{level:11}] {msg}")
    breaking = [f for f in findings if f[0] == "BREAKING"]
    print(f"\n{len(findings)} change(s), {len(breaking)} breaking")
    return 1 if breaking else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
```

Create `contract_v2.json` as a copy of v1 adding `spokane` to the site enum, an optional `agent_ver` field, and a **required non-nullable** `mem_pct`:

```bash
python3 compat.py contract_v1.json contract_v2.json; echo "exit=$?"
```

```text
asset_checkin v1 -> v2
  [BREAKING   ] added required non-nullable field 'mem_pct'
  [COMPATIBLE ] 'site' enum values added: ['spokane']
  [COMPATIBLE ] added optional field 'agent_ver'

3 change(s), 1 breaking
exit=1
```

The gate fails. Make `mem_pct` optional and nullable in `contract_v3.json` — a two-phase rollout where the field is added optionally first, populated by producers, and only then made required:

```bash
python3 compat.py contract_v1.json contract_v3.json; echo "exit=$?"
```

```text
asset_checkin v1 -> v3
  [COMPATIBLE ] 'site' enum values added: ['spokane']
  [COMPATIBLE ] added optional field 'agent_ver'
  [COMPATIBLE ] added optional field 'mem_pct'

3 change(s), 0 breaking
exit=0
```

Revalidating the same batch against v3 shows the effect of widening the enum — `SN-1005` at the `spokane` site is now accepted:

```text
INFO validate records=10 accepted=4 rejected=6 reject_rate=0.60 duplicate_rate=0.10
```

> [!TIP]
> Run `compat.py` in continuous integration on every pull request that touches a contract file, comparing the committed version against the previous one. A non-zero exit forces a human decision about coordination rather than allowing a breaking change to merge unnoticed.

### 📘 The two-phase pattern for required fields

Adding a genuinely required field without an outage always takes two releases:

1. **Add it as optional.** Deploy consumers that tolerate its absence. Deploy producers that populate it. Wait until the null rate reaches zero and stays there.
2. **Make it required.** Now no existing record violates the constraint.

Attempting both in one step guarantees a window where valid production data fails validation.

---

<a id="9-quarantine-and-reject-handling"></a>

## 🚧 9. Quarantine and Reject Handling

A rejected record is evidence, not garbage. Quarantine gives it somewhere durable to live.

### 📘 What a quarantine record must contain

| Field | Why |
| --- | --- |
| The original record, unmodified | The producer needs to see exactly what was sent |
| Every failing rule | Fixing one defect at a time wastes cycles |
| Source file and line or offset | Locating the record upstream |
| Batch identifier | Correlating with the run log |
| Contract version | The same record may be valid under a different version |
| Quarantine timestamp | Ageing and retention |

### 📘 The lifecycle

```text
reject ──► quarantine ──► triage ──► ┌─ fix upstream ──► replay ──► accepted
                                     ├─ amend contract ──► replay ──► accepted
                                     └─ confirmed invalid ──► expire per retention
```

A quarantine that is written and never read is a disk-usage problem rather than a quality control. Three practices prevent that:

- **Alert on rate, not on presence.** A steady 0.1% reject rate may be normal; a jump to 15% is an incident.
- **Give it an owner and a review cadence.** Unreviewed quarantine grows until someone deletes the directory.
- **Set a retention period.** Quarantined records frequently contain the malformed personal or sensitive data that failed validation in the first place, and they inherit the same handling obligations as the source.

### 📘 Reject versus fail the run

| Choose | When |
| --- | --- |
| **Quarantine and continue** | Machine-generated sources where individual defects are expected |
| **Fail the entire batch** | Small curated inputs, financial data, or a reject rate above the contract's threshold |

The lab implements both: individual records are quarantined, and the run still exits non-zero when the aggregate breaches an expectation. That combination — granular tolerance with an aggregate limit — is the pattern worth copying.

> [!CAUTION]
> Never write quarantined records to a location with broader access than the source data. A reject file assembled from security logs or customer records carries the same classification as the original, and the fact that a record is malformed does not make it non-sensitive.

---

<a id="10-producer-and-consumer-obligations"></a>

## 🤝 10. Producer and Consumer Obligations

A contract is between parties. Most data quality incidents are a failure of one of these obligations rather than a coding error.

### 📘 The producer owes

| Obligation | Practical meaning |
| --- | --- |
| **Conformance** | Emitted records satisfy the declared contract |
| **Advance notice** | Breaking changes are announced before deployment, with a migration window |
| **Version identification** | Records or the batch carry the contract version |
| **Stable semantics** | A field's meaning does not change while its name and type stay the same |
| **Freshness** | Data arrives within the committed window, and failures are communicated |
| **Documented identity** | The primary key is stated and does not change silently |

The fourth obligation is the one most often broken and hardest to detect: repurposing an existing field passes every type, enum, and range check while making every historical value wrong. No automated check catches it. Only communication does.

### 📘 The consumer owes

| Obligation | Practical meaning |
| --- | --- |
| **Use declared fields only** | Do not depend on undocumented columns or on row ordering |
| **Tolerate compatible changes** | New optional fields must not break a reader |
| **Handle nulls per contract** | Where nullable is declared, handle it |
| **Report defects with evidence** | Cite the record, the field, and the expectation breached |
| **Stay current** | Migrate within the announced window |
| **Do not silently repair** | Fixing bad data locally hides a producer defect from everyone else |

That last obligation matters more than it appears. When each consumer patches around the same upstream defect in its own way, the producer never learns it exists, and the consumers quietly diverge in what they report.

### 📘 Minimal contract header

```json
{
  "name": "asset_checkin",
  "version": 3,
  "owner": "platform-team",
  "contact": "platform@example.internal",
  "freshness_sla_minutes": 30,
  "compatibility": "backward",
  "consumers": ["inventory-report", "detection-rules"]
}
```

Listing consumers is the highest-value line in the file. It converts "who will this break?" from an unanswerable question into a list of people to notify.

---

<a id="11-self-check"></a>

## 🎓 11. Self-Check

1. Which of the six quality dimensions cannot be verified without a second source, and why?
2. Explain the difference between `required` and `nullable`, and give a case where `required: true, nullable: true` is correct.
3. The batch had three accepted records and still failed. Which expectation failed and why is it invisible at record level?
4. Why does `validate_record` return a list of errors instead of raising on the first?
5. Name the three situations that a single `null` can conflate, and the practice that separates them.
6. Why is adding an enum value ambiguous rather than simply compatible?
7. Describe the two-phase rollout for adding a required field, and what breaks if it is done in one step.
8. Why is the validator's exit status significant?
9. What must a quarantine record contain beyond the original data, and why each element?
10. Which producer obligation cannot be enforced by any automated check?

---

<a id="verification-record"></a>

## ✅ Verification Record

| Area | Verification performed | Limitation |
| --- | --- | --- |
| Contract fixtures | `contract_v1.json`, `contract_v2.json`, and `contract_v3.json` created and parsed | Custom minimal format, not JSON Schema or Avro |
| Record validation | Executed against the 10-record batch; all seven intended defects rejected with named reasons | Cross-field consistency rules not implemented |
| Batch expectations | Executed; `reject_rate=0.70`, `duplicate_rate=0.10`, `null_rate[cpu_pct]=0.33` all breached; exit status 1 | Distribution-shift and row-count checks described, not implemented |
| Duplicate detection | Confirmed the repeated `(SN-1001, 2026-09-10T14:00:00+00:00)` key rejected as a duplicate | In-batch only; cross-batch uniqueness relies on a destination constraint |
| Null accounting | Confirmed 1 of 3 accepted records null for `cpu_pct`, rate 0.33 against a 0.25 limit | Small sample; rates are volatile at this size |
| Quarantine output | Confirmed `quarantine.jsonl` holds all seven rejects with line, errors, and original record | Contract version and batch id are described as requirements but not emitted by the lab script |
| Compatibility checker | Executed v1→v2: 1 breaking, 2 compatible, exit 1. Executed v1→v3: 0 breaking, exit 0 | Classification covers the rules in §8; does not evaluate consumer-side exhaustiveness |
| Enum widening effect | Revalidated the same batch against v3; accepted rose from 3 to 4 as `spokane` became valid | — |

Local checks used Python 3.12.3 on Ubuntu with standard-library modules only. These identify the verification environment and are not a version recommendation.

---

<a id="contributing"></a>

## 🤝 Contributing

**Submission Guidelines:**

1. State the contract a check enforces; a check without a declared expectation is an opinion.
2. Include a fixture that fails, alongside one that passes.
3. Classify any proposed schema change using the table in §8 and justify the classification.
4. Keep validation logic free of destination access so it can be unit tested.
5. Report the actual output observed, including exit statuses.
6. Update the [section index](../README.md) when adding a guide.

---

<a id="resources"></a>

## 📚 Resources

| Area | Official References |
| --- | --- |
| 📜 Schema specifications | [JSON Schema](https://json-schema.org/) · [Apache Avro specification](https://avro.apache.org/docs/current/specification/) · [Protocol Buffers](https://protobuf.dev/programming-guides/proto3/) |
| 🔀 Compatibility | [Avro schema resolution](https://avro.apache.org/docs/current/specification/#schema-resolution) · [Protobuf update rules](https://protobuf.dev/programming-guides/proto3/#updating) |
| ✅ Validation tooling | [Great Expectations](https://docs.greatexpectations.io/) · [Pydantic](https://docs.pydantic.dev/) · [dbt tests](https://docs.getdbt.com/docs/build/data-tests) |
| 🐍 Python | [json](https://docs.python.org/3/library/json.html) · [re](https://docs.python.org/3/library/re.html) · [collections.Counter](https://docs.python.org/3/library/collections.html#collections.Counter) |
| 📄 Formats | [JSON Lines](https://jsonlines.org/) · [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) |

---

<a id="see-also"></a>

## 🔗 Quick Links & Related Guides

- [🗄️ Data Engineering Section Index](../README.md)
- [🧱 Data Engineering Fundamentals](./data_engineering_fundamentals.md)
- [🐍 Python for Data Processing](./python_data_processing.md)
- [🗃️ SQL & Data Modeling](./sql_data_modeling.md)
- [🔄 ETL & ELT Pipeline Design](./etl_elt_pipeline_design.md)
- [🛡️ Secure Data Pipelines](../data_pipelines.md)
- [📊 Log Aggregation & Visibility](../../IncidentResponse/log_agg.md)
- [📖 Repository Glossary](../../GLOSSARY.md)

---

<a id="guide-details"></a>

## 📊 Guide Details

| Item | Details |
| --- | --- |
| 🎯 Focus | Declared contracts, automated validation, and safe schema evolution |
| 🧰 Core Technologies | Python standard library; JSON contract files |
| 📘 Format | Reference guide with an executed validator and compatibility gate |
| 🧪 Validation Status | Both lab tools executed; outputs and limitations documented above |
| 📁 Location | `Data-Engineering/Phase1/data_quality_schema_contracts.md` |
| 🔄 Content Review Date | September 11, 2026 |

---

<div align="center">

**✅ Declare the Contract. Quarantine the Rest. Gate the Change.**

*Data quality is not a dashboard — it is a written expectation, an automated check, and a build that fails when either is violated.*

**Repository:** [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Pacific Northwest Computers:** [PNWC on GitHub](https://github.com/Pnwcomputers)

[🏠 Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [📋 Table of Contents](#table-of-contents) | [📜 Legal Notice](../../LEGAL.md)

⭐ **Star the repository if you find it useful!** ⭐

</div>
