# 🐍 Python for Data Processing

<div align="center">

**Bounded memory, correct encoding, honest timestamps, and testable pipeline code**

*CSV • JSON Lines • Iterators • Encoding • datetime • logging • Packaging • unittest*

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md)*

![Foundations](https://img.shields.io/badge/Level-Foundations-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Language-Python_3.10%2B-darkgreen?style=for-the-badge)
![Memory](https://img.shields.io/badge/Design-Bounded_Memory-purple?style=for-the-badge)
![Stdlib](https://img.shields.io/badge/Dependencies-Standard_Library-orange?style=for-the-badge)

</div>

---

_Last reviewed: 2026-09-11. Examples executed locally on the versions listed in the [Verification Record](#verification-record)._

**Prerequisites:** [Data Engineering Fundamentals](./data_engineering_fundamentals.md) for lifecycle vocabulary, record identity, and quarantine concepts.

## 🎯 Purpose

Teach the Python patterns that make data processing code correct under real conditions: files larger than memory, mixed encodings, ambiguous timestamps, partial failures, and code that must be changed six months later without breaking.

## ⚙️ Function

Cover streaming iteration, encoding handling, the sharp edges of the `csv` module, JSON versus JSON Lines, timezone-correct timestamp conversion, structured logging, project layout and packaging, and unit tests built on small fixtures — then assemble them into an installable package with a passing test suite.

## 🏆 Goal

Enable a practitioner to write a processing script that handles a multi-gigabyte input in constant memory, fails loudly on ambiguous data, logs enough to diagnose a production incident, and is covered by tests that run in under a second.

## 📋 When to Use

- Writing or reviewing any Python script that reads data files and produces output.
- Diagnosing a job that works on a sample and fails on the full dataset.
- Investigating mojibake, `UnicodeDecodeError`, or timestamps that are off by hours.
- Converting a single ad-hoc script into a maintainable, tested module.
- Preparing the transformation layer described in [ETL & ELT Pipeline Design](./etl_elt_pipeline_design.md).

## 🧰 Audience & Prerequisites

**Audience:** Practitioners who can write basic Python and now need it to be reliable under production data conditions.

**Prerequisites:** Python 3.10 or later (3.11+ recommended for the `fromisoformat` improvements noted in §6). Familiarity with functions, dictionaries, and the terminal. No third-party packages are required; `pytest` is mentioned as an option but every runnable test here uses the standard-library `unittest`.

> [!NOTE]
> All examples use synthetic data and run locally. The packaging section builds a local editable install only; nothing is published to an index.

---

<a id="table-of-contents"></a>

## 📋 Table of Contents

- [🌊 1. Stream, Do Not Load](#1-stream-do-not-load)
- [🔤 2. Text, Bytes, and Encoding](#2-text-bytes-and-encoding)
- [📄 3. CSV and Its Sharp Edges](#3-csv-and-its-sharp-edges)
- [🧾 4. JSON and JSON Lines](#4-json-and-json-lines)
- [🔁 5. Generator Pipelines](#5-generator-pipelines)
- [🕐 6. Timestamps Done Correctly](#6-timestamps-done-correctly)
- [📋 7. Logging for Pipelines](#7-logging-for-pipelines)
- [📦 8. Project Layout and Packaging](#8-project-layout-and-packaging)
- [🧪 9. Testing with Fixtures](#9-testing-with-fixtures)
- [🚀 10. Lab: Build the Package](#10-lab-build-the-package)
- [🎓 11. Self-Check](#11-self-check)
- [✅ Verification Record](#verification-record)
- [🤝 Contributing](#contributing)
- [📚 Resources](#resources)
- [🔗 Quick Links & Related Guides](#see-also)
- [📊 Guide Details](#guide-details)

---

<a id="1-stream-do-not-load"></a>

## 🌊 1. Stream, Do Not Load

The single most common cause of a pipeline that "worked in testing" is reading an entire file into memory.

```python
# Unbounded — memory grows with file size
rows = open("events.csv").readlines()          # entire file in RAM
data = json.load(open("events.json"))          # entire structure in RAM
results = [transform(r) for r in rows]         # a second full copy

# Bounded — memory stays roughly constant
with open("events.csv", encoding="utf-8") as fh:
    for line in fh:                            # one line at a time
        handle(transform(line))
```

A file object is already an iterator over lines. A generator function lets each stage of processing consume the previous one lazily, so only one record is in flight at any moment regardless of whether the file holds a thousand rows or a hundred million.

| Pattern | Peak memory | Use when |
| --- | --- | --- |
| `fh.read()` / `json.load()` | Size of file | Small config files of known bounded size |
| `for line in fh` | One line | Line-delimited text of any size |
| Generator chain | One record | Multi-stage transformation of any size |
| `list(...)` anywhere in the chain | Entire result | Only when the result is deliberately small (lookups, aggregates) |

> [!WARNING]
> Sorting, grouping, and deduplication are inherently unbounded operations — they must hold state. When the state is the problem, push it into a database (see [SQL & Data Modeling](./sql_data_modeling.md)) rather than a Python dictionary. A `set` of every seen identifier will exhaust memory on a large enough input; a `UNIQUE` index will not.

---

<a id="2-text-bytes-and-encoding"></a>

## 🔤 2. Text, Bytes, and Encoding

Every file on disk is bytes. Text only exists after a decoding decision. When that decision is left implicit, Python uses a platform default that differs between machines — the classic cause of a script that works on one host and raises `UnicodeDecodeError` on another.

**Always state the encoding explicitly.**

```python
# Implicit: behavior depends on the platform's locale
with open(path) as fh: ...

# Explicit: behavior is identical everywhere
with open(path, encoding="utf-8", newline="") as fh: ...
```

### 📘 Handling sources that are not clean UTF-8

Real exports from legacy systems contain bytes that are not valid UTF-8. Three strategies, in order of preference:

```python
# 1. Correct: decode with the encoding the source actually uses
open(path, encoding="cp1252")        # common for Windows-generated exports

# 2. Lossless round-trip: preserve undecodable bytes so they survive re-encoding
open(path, encoding="utf-8", errors="surrogateescape")

# 3. Last resort: substitute, and COUNT the substitutions
open(path, encoding="utf-8", errors="replace")
```

Option 3 destroys information. If it is used, the number of affected records must be logged and monitored — a rising count means the upstream encoding changed.

> [!TIP]
> A byte order mark (BOM) at the start of a UTF-8 file becomes a literal `\ufeff` in the first field name, which makes `row["serial"]` raise `KeyError` while the header looks correct in an editor. Use `encoding="utf-8-sig"` when reading files produced by Excel or PowerShell's `Export-Csv`; it strips the BOM if present and behaves like `utf-8` if not.

### 📘 Normalizing text for comparison

Two visually identical strings can hold different code points. Normalize before using text as a key:

```python
import unicodedata

def normkey(value: str) -> str:
    """Normalize text used for identity comparison."""
    return unicodedata.normalize("NFKC", value).strip().casefold()
```

Use `casefold()` rather than `lower()` — it handles cases that `lower()` does not, such as the German ß.

---

<a id="3-csv-and-its-sharp-edges"></a>

## 📄 3. CSV and Its Sharp Edges

CSV looks simple and is not. Never parse it by splitting on commas; quoted fields legitimately contain commas and newlines.

```python
import csv

with open(path, newline="", encoding="utf-8-sig") as fh:
    for row in csv.DictReader(fh):
        ...
```

### 📘 The four rules

| Rule | Reason |
| --- | --- |
| Pass `newline=""` to `open()` | The `csv` module handles line endings itself; omitting this corrupts quoted fields containing newlines |
| Never use `str.split(",")` | Breaks on any quoted comma — silently, producing shifted columns |
| Treat every value as a string | The reader does no type conversion; `"007"`, `"1e5"`, and `""` all arrive as `str` |
| Distinguish empty from missing | `""` is a present empty value; `None` from `DictReader` means the row had fewer fields than the header |

### 📘 Detecting structural problems

`DictReader` does not raise when a row's field count differs from the header. It silently produces `None` for missing fields and collects extras under a `restkey`. Make that explicit:

```python
import csv

def read_csv_strict(path, expected: tuple[str, ...]):
    """Yield (line_number, row) and raise on structural problems."""
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh, restkey="__extra__", restval=None)
        if tuple(reader.fieldnames or ()) != expected:
            raise ValueError(
                f"header mismatch: expected {expected}, got {tuple(reader.fieldnames or ())}"
            )
        for row in reader:
            if row.get("__extra__") is not None:
                raise ValueError(f"line {reader.line_num}: too many fields")
            if any(row[f] is None for f in expected):
                raise ValueError(f"line {reader.line_num}: too few fields")
            yield reader.line_num, row
```

Note `reader.line_num` rather than a manual counter: it reports the physical line in the file, which stays accurate when a quoted field spans multiple lines — the number a human needs to find the bad record.

### 📘 Writing CSV safely

```python
with open(out_path, "w", newline="", encoding="utf-8") as fh:
    writer = csv.DictWriter(fh, fieldnames=["serial", "hostname", "site"])
    writer.writeheader()
    writer.writerows(rows)
```

> [!CAUTION]
> A CSV field beginning with `=`, `+`, `-`, or `@` is interpreted as a formula when the file is opened in a spreadsheet application. If the data originates from user or untrusted input and the output will be opened in Excel, this is a live code-execution path (CSV injection). Prefix such values with a single quote, or deliver the data in a format that is not spreadsheet-executable.

---

<a id="4-json-and-json-lines"></a>

## 🧾 4. JSON and JSON Lines

A single JSON document must be parsed in full before any element is available — unbounded memory and unusable for large data. **JSON Lines** (one complete JSON object per line) fixes this and is the default interchange format for pipeline records.

```python
import json

# Reading: bounded memory, and one bad line does not lose the file
def read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except json.JSONDecodeError as exc:
                yield line_no, {"__error__": str(exc), "__raw__": line[:500]}

# Writing: append-friendly, streamable
def write_jsonl(path, records):
    with open(path, "a", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
```

| Choice | Why |
| --- | --- |
| `ensure_ascii=False` | Keeps non-ASCII text readable instead of `\uXXXX` escapes; the file is already UTF-8 |
| `sort_keys=True` | Deterministic output, so diffs and content hashes are stable |
| Truncate `__raw__` | A malformed line can be enormous; bounded capture prevents a log-flooding failure |
| One object per line, no trailing commas | Any line can be processed independently and appended to safely |

> [!NOTE]
> JSON numbers do not preserve integer precision beyond 2^53 in many consumers, and `json` will happily emit `NaN` and `Infinity`, which are not valid JSON and are rejected by strict parsers. Pass `allow_nan=False` when the output crosses a system boundary, and serialize large identifiers as strings.

---

<a id="5-generator-pipelines"></a>

## 🔁 5. Generator Pipelines

Compose processing as a chain of generators. Each stage does one thing, is testable in isolation, and holds one record at a time.

```python
import itertools

def parse(lines):
    for line_no, line in lines:
        yield line_no, line.rstrip("\n")

def validate(records, required):
    for line_no, record in records:
        missing = [f for f in required if not record.get(f)]
        if missing:
            yield line_no, None, f"missing: {','.join(missing)}"
        else:
            yield line_no, record, None

def enrich(records, sites):
    for line_no, record, error in records:
        if error is None:
            record["region"] = sites.get(record["site"], "unknown")
        yield line_no, record, error
```

Each stage is called with the previous one's output; nothing executes until the final loop pulls records through.

### 📘 Useful `itertools` for bounded work

```python
from itertools import islice, groupby

def batched(iterable, size):
    """Yield lists of at most `size` items. Use for chunked database writes."""
    iterator = iter(iterable)
    while chunk := list(islice(iterator, size)):
        yield chunk
```

Batching database writes is the usual fix for a loader that is correct but slow: one transaction per 1,000 records instead of one per record typically improves throughput by an order of magnitude, with the trade-off that a failure loses the current batch rather than a single row.

> [!TIP]
> Python 3.12 provides `itertools.batched` directly. The implementation above is included because much operational tooling still runs on 3.10 and 3.11; prefer the standard-library version when the minimum target allows it.

> [!WARNING]
> `itertools.groupby` only groups *consecutive* equal keys. It does not sort. Applying it to unsorted input produces multiple groups for the same key and is a frequent source of undercounted aggregates. Either sort first — which is unbounded — or aggregate in SQL.

---

<a id="6-timestamps-done-correctly"></a>

## 🕐 6. Timestamps Done Correctly

Timestamps cause more silent data corruption than any other field type.

### 📘 The three rules

1. **Store UTC.** Convert at the edge, store one representation, format for display only at presentation time.
2. **Reject naive timestamps from external sources.** A timestamp without an offset has no defined meaning. Guessing its zone is a decision to be wrong twice a year.
3. **Separate event time from ingest time.** Event time is when the thing happened; ingest time is when the pipeline saw it. Recording both is what makes lateness measurable.

```python
import datetime as dt

def to_utc(value: str) -> str:
    """Parse an ISO-8601 timestamp and normalize to UTC. Raise if naive."""
    parsed = dt.datetime.fromisoformat(value.strip())
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp lacks timezone offset: {value!r}")
    return parsed.astimezone(dt.timezone.utc).isoformat()

def now_utc() -> str:
    """Ingest timestamp. Never use datetime.utcnow()."""
    return dt.datetime.now(dt.timezone.utc).isoformat()
```

> [!CAUTION]
> `datetime.utcnow()` returns a **naive** datetime holding UTC values. Comparing it to an aware datetime raises `TypeError`; passing it to `.astimezone()` silently reinterprets it as local time, shifting every record by the machine's offset. It is deprecated as of Python 3.12. Use `datetime.now(dt.timezone.utc)`.

### 📘 Epoch and non-ISO formats

```python
import datetime as dt
from zoneinfo import ZoneInfo

# Epoch seconds — ALWAYS pass tz, never rely on local interpretation
dt.datetime.fromtimestamp(1757606400, tz=dt.timezone.utc)

# Epoch milliseconds (common in JavaScript and many APIs)
dt.datetime.fromtimestamp(1757606400000 / 1000, tz=dt.timezone.utc)

# Known-zone local time from a source that documents its zone
naive = dt.datetime.strptime("2026-09-11 14:30:00", "%Y-%m-%d %H:%M:%S")
aware = naive.replace(tzinfo=ZoneInfo("America/Los_Angeles"))
utc = aware.astimezone(dt.timezone.utc)
```

Use `zoneinfo` (standard library since 3.9) rather than fixed offsets: `ZoneInfo("America/Los_Angeles")` accounts for daylight saving transitions, whereas a hardcoded `-08:00` is wrong for eight months of the year.

> [!NOTE]
> Before Python 3.11, `fromisoformat` parsed only the exact format produced by `isoformat()` and rejected a trailing `Z`. On 3.11 and later it accepts the full common ISO-8601 range including `Z`. If code must run on 3.10, normalize first: `value.replace("Z", "+00:00")`.

### 📘 Ambiguity that no library resolves

During a daylight-saving fall-back, a local wall-clock time occurs twice. `ZoneInfo` defaults to the first occurrence via the `fold` attribute. If the source does not record an offset, that hour is genuinely ambiguous and roughly one hour of data per year is unorderable. The only real fix is upstream: require offsets in the contract. See [Data Quality & Schema Contracts](./data_quality_schema_contracts.md).

---

<a id="7-logging-for-pipelines"></a>

## 📋 7. Logging for Pipelines

`print()` cannot be filtered, routed, timestamped, or turned off. Use `logging` from the first version of the script.

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger(__name__)
```

### 📘 What each level means in a pipeline

| Level | Meaning | Example |
| --- | --- | --- |
| `DEBUG` | Per-record detail, off in normal operation | Field values after transformation |
| `INFO` | Run boundaries and counts | `read=7 accepted=4 quarantined=3` |
| `WARNING` | Handled problem, run continues | A record was quarantined |
| `ERROR` | The run failed or produced incomplete output | Destination unreachable |
| `CRITICAL` | Data integrity is at risk | Reconciliation mismatch after commit |

### 📘 Three habits that matter in production

```python
# 1. Lazy formatting — the string is only built if the level is enabled
log.info("processed %d records from %s", count, path)   # correct
log.info(f"processed {count} records from {path}")      # builds the string always

# 2. Log exceptions with the traceback attached
try:
    load(path)
except Exception:
    log.exception("load failed for %s", path)           # includes traceback

# 3. Emit one machine-readable summary per run
log.info("run_summary %s", json.dumps({
    "source": str(path), "read": read, "accepted": accepted,
    "quarantined": quarantined, "duration_s": round(elapsed, 2),
}, sort_keys=True))
```

That final summary line is what makes a pipeline observable without extra infrastructure: it can be grepped, shipped to a log aggregator, or parsed into freshness and error-rate metrics. See [Log Aggregation & Visibility](../../IncidentResponse/log_agg.md) for the collection side.

> [!CAUTION]
> Never log credentials, tokens, session identifiers, or unredacted personal data. Logs are frequently retained longer and read more widely than the data itself. When a record must be logged for diagnosis, log its identifier rather than its contents.

---

<a id="8-project-layout-and-packaging"></a>

## 📦 8. Project Layout and Packaging

A single script becomes unmaintainable at roughly the point where it needs tests. This layout scales from a hundred lines to a real project and is directly installable.

```text
assetpipe/
├── pyproject.toml
├── README.md
├── src/
│   └── assetpipe/
│       ├── __init__.py
│       ├── config.py        # paths and settings, no logic
│       ├── readers.py       # source input, one function per format
│       ├── transform.py     # pure functions: value in, value out
│       ├── sinks.py         # destination writes
│       └── cli.py           # argument parsing and wiring only
└── tests/
    ├── fixtures/
    │   └── assets_small.csv
    └── test_transform.py
```

### 📘 Why `src/`

Without it, `import assetpipe` may resolve to the working-directory copy rather than the installed package, so tests can pass against code that would fail once installed. The `src` layout makes that impossible.

### 📘 Minimal `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "assetpipe"
version = "0.1.0"
description = "Asset inventory ingestion pipeline"
requires-python = ">=3.10"
dependencies = []

[project.scripts]
assetpipe = "assetpipe.cli:main"

[tool.setuptools.packages.find]
where = ["src"]
```

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
assetpipe --help
```

The editable install (`-e`) points at the source tree, so edits take effect without reinstalling. The `[project.scripts]` entry creates the `assetpipe` command.

### 📘 The separation that makes testing possible

Keep `transform.py` free of file and database access. Pure functions — value in, value out — need no fixtures, no temporary directories, and no mocks. Push all input/output to the edges in `readers.py`, `sinks.py`, and `cli.py`. This single rule is the difference between a test suite that runs in milliseconds and one nobody runs.

---

<a id="9-testing-with-fixtures"></a>

## 🧪 9. Testing with Fixtures

Test the cases that actually break pipelines, not the happy path that already works.

| Category | Test |
| --- | --- |
| **Boundary** | Empty file, header only, single record, final line without newline |
| **Encoding** | UTF-8 with BOM, non-ASCII names, undecodable byte |
| **Structure** | Too few fields, too many fields, reordered header |
| **Values** | Empty string versus absent key, leading zeros, whitespace padding |
| **Time** | Naive timestamp, `Z` suffix, non-UTC offset, epoch seconds |
| **Idempotence** | Same input twice produces the same destination state |

```python
import datetime as dt
import unittest

from assetpipe.transform import to_utc, normalize_serial


class TestTimestamps(unittest.TestCase):
    def test_offset_is_converted_to_utc(self):
        self.assertEqual(
            to_utc("2026-09-11T07:00:00-07:00"),
            "2026-09-11T14:00:00+00:00",
        )

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaises(ValueError):
            to_utc("2026-09-11T14:00:00")

    def test_already_utc_is_unchanged(self):
        self.assertEqual(
            to_utc("2026-09-11T14:00:00+00:00"),
            "2026-09-11T14:00:00+00:00",
        )


class TestSerials(unittest.TestCase):
    def test_case_and_whitespace_normalized(self):
        self.assertEqual(normalize_serial("  sn-1001 "), "SN-1001")

    def test_empty_serial_rejected(self):
        with self.assertRaises(ValueError):
            normalize_serial("   ")


if __name__ == "__main__":
    unittest.main()
```

```bash
python3 -m unittest discover -s tests -v
```

> [!TIP]
> Keep fixture files tiny — five to ten rows containing every defect you care about. A fixture that must be scrolled is a fixture nobody reads, and a test suite that takes minutes is one that gets skipped before a deadline. `pytest` offers a more concise syntax and is worth adopting, but `unittest` requires no dependency, which matters for tooling that must run on locked-down hosts.

---

<a id="10-lab-build-the-package"></a>

## 🚀 10. Lab: Build the Package

Assemble the pieces into a working, installable, tested package.

### 🧪 Step 1: Scaffold

```bash
mkdir -p ~/assetpipe/src/assetpipe ~/assetpipe/tests/fixtures
cd ~/assetpipe
```

### 🧪 Step 2: `src/assetpipe/transform.py`

```python
"""Pure transformation functions. No file or database access belongs here."""
from __future__ import annotations

import datetime as dt
import hashlib
import unicodedata

REQUIRED_FIELDS = ("serial", "hostname", "site", "os", "last_seen")


def normkey(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().casefold()


def normalize_serial(value: str) -> str:
    cleaned = unicodedata.normalize("NFKC", value or "").strip().upper()
    if not cleaned:
        raise ValueError("serial is empty")
    return cleaned


def to_utc(value: str) -> str:
    parsed = dt.datetime.fromisoformat((value or "").strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp lacks timezone offset: {value!r}")
    return parsed.astimezone(dt.timezone.utc).isoformat()


def asset_id(serial: str) -> str:
    return hashlib.sha256(normkey(serial).encode("utf-8")).hexdigest()[:32]


def transform_row(row: dict[str, str]) -> dict[str, str]:
    """Return a normalized record or raise ValueError describing the problem."""
    for field in REQUIRED_FIELDS:
        if not (row.get(field) or "").strip():
            raise ValueError(f"missing required field: {field}")
    serial = normalize_serial(row["serial"])
    return {
        "asset_id": asset_id(serial),
        "serial": serial,
        "hostname": row["hostname"].strip().lower(),
        "site": row["site"].strip().lower(),
        "os": row["os"].strip(),
        "last_seen": to_utc(row["last_seen"]),
    }
```

### 🧪 Step 3: `src/assetpipe/readers.py`

```python
"""Source input. Bounded memory, explicit encoding, structural checks."""
from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

from .transform import REQUIRED_FIELDS


def read_assets_csv(path: Path) -> Iterator[tuple[int, dict[str, str]]]:
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh, restkey="__extra__", restval=None)
        header = tuple(reader.fieldnames or ())
        if header != REQUIRED_FIELDS:
            raise ValueError(f"header mismatch: expected {REQUIRED_FIELDS}, got {header}")
        for row in reader:
            if row.get("__extra__") is not None:
                raise ValueError(f"line {reader.line_num}: too many fields")
            if any(row.get(f) is None for f in REQUIRED_FIELDS):
                raise ValueError(f"line {reader.line_num}: too few fields")
            yield reader.line_num, row
```

### 🧪 Step 4: `src/assetpipe/cli.py`

```python
"""Argument parsing and wiring. No business logic belongs here."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .readers import read_assets_csv
from .transform import transform_row

log = logging.getLogger("assetpipe")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="assetpipe", description="Normalize an asset CSV export")
    parser.add_argument("source", type=Path, help="input CSV path")
    parser.add_argument("--out", type=Path, required=True, help="accepted JSON Lines output")
    parser.add_argument("--quarantine", type=Path, required=True, help="rejected JSON Lines output")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    read = accepted = quarantined = 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.quarantine.parent.mkdir(parents=True, exist_ok=True)

    try:
        with args.out.open("w", encoding="utf-8") as out, \
             args.quarantine.open("w", encoding="utf-8") as bad:
            for line_no, row in read_assets_csv(args.source):
                read += 1
                try:
                    record = transform_row(row)
                except ValueError as exc:
                    quarantined += 1
                    log.warning("line %d quarantined: %s", line_no, exc)
                    bad.write(json.dumps(
                        {"line": line_no, "reason": str(exc), "raw": row},
                        sort_keys=True, ensure_ascii=False) + "\n")
                    continue
                accepted += 1
                out.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    except (OSError, ValueError):
        log.exception("run failed for %s", args.source)
        return 1

    log.info("run_summary %s", json.dumps(
        {"source": str(args.source), "read": read,
         "accepted": accepted, "quarantined": quarantined}, sort_keys=True))
    return 0 if read == accepted + quarantined else 1


if __name__ == "__main__":
    sys.exit(main())
```

Create an empty `src/assetpipe/__init__.py`, then add the `pyproject.toml` from §8.

### 🧪 Step 5: Fixture and tests

`tests/fixtures/assets_small.csv`:

```text
serial,hostname,site,os,last_seen
SN-1001,ws-acct-01,vancouver,Windows 11,2026-09-10T07:03:00-07:00
sn-1002, WS-ACCT-02 ,Vancouver,Windows 11,2026-09-10T14:05:00Z
SN-1003,,portland,Ubuntu 24.04,2026-09-10T14:07:00+00:00
SN-1004,ws-ops-07,seattle,Windows 11,2026-09-10 14:11:00
```

Use the test module from §9, extended for the fixture, then run:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python3 -m unittest discover -s tests -v
assetpipe tests/fixtures/assets_small.csv --out /tmp/ok.jsonl --quarantine /tmp/bad.jsonl
```

Expected summary:

```text
INFO assetpipe run_summary {"accepted": 2, "quarantined": 2, "read": 4, "source": "tests/fixtures/assets_small.csv"}
```

Two records are accepted with `sn-1002` normalized to `SN-1002` and its `Z` suffix converted to `+00:00`; two are quarantined — one for the missing hostname and one for the timestamp with no offset. Inspect both output files to confirm.

---

<a id="11-self-check"></a>

## 🎓 11. Self-Check

1. Why does `newline=""` matter when opening a CSV file, and what breaks without it?
2. What is the difference between `encoding="utf-8"` and `encoding="utf-8-sig"`, and which source produces the difference?
3. Why is `datetime.utcnow()` unsafe, and what replaces it?
4. When does `itertools.groupby` produce wrong aggregates?
5. Why does `log.info("count %d", n)` differ from `log.info(f"count {n}")` in a hot loop?
6. What does the `src/` layout prevent that a flat layout does not?
7. A record has `"last_seen": "2026-09-11T14:00:00"`. Why is quarantining it better than assuming UTC?
8. Which functions in the lab package can be tested with no filesystem access, and why is that the design goal?

---

<a id="verification-record"></a>

## ✅ Verification Record

| Area | Verification performed | Limitation |
| --- | --- | --- |
| `to_utc()` | Executed; `2026-09-11T07:00:00-07:00` → `2026-09-11T14:00:00+00:00`; naive input raised `ValueError`; `Z` suffix accepted | Does not cover leap seconds or pre-1970 dates |
| `normalize_serial()` / `asset_id()` | Executed; whitespace and case normalization confirmed; identifier stable across runs | 32-character truncation is for readability, not a cryptographic commitment |
| `read_assets_csv()` | Executed against the fixture; header mismatch, too-few-fields, and too-many-fields paths each raised as documented | UTF-8/BOM inputs tested; other encodings not exercised |
| `assetpipe` CLI | Executed against the fixture; observed `read=4 accepted=2 quarantined=2` and inspected both output files | Run on the fixture only |
| Package install | `pip install -e .` completed in a virtual environment and the `assetpipe` console script resolved | setuptools backend only; no wheel publication tested |
| Test suite | `python3 -m unittest discover -s tests -v` passed | `pytest` alternative mentioned but not executed |
| `batched()` | Executed on a range input; final short chunk returned correctly | Python 3.12 `itertools.batched` not used in the shown implementation |

Local checks used Python 3.12.3 on Ubuntu with setuptools from the active virtual environment. These identify the verification environment and are not a recommendation to pin to those versions.

---

<a id="contributing"></a>

## 🤝 Contributing

**Submission Guidelines:**

1. Prefer standard-library examples; state and justify any added dependency.
2. Include a failing case alongside each new pattern — the defect it prevents.
3. State the minimum supported Python version for any version-dependent behavior.
4. Keep transformation examples free of file and database access.
5. Report what you executed and the exact output observed.
6. Update the [section index](../README.md) when adding a guide.

---

<a id="resources"></a>

## 📚 Resources

| Area | Official References |
| --- | --- |
| 📄 CSV | [csv module](https://docs.python.org/3/library/csv.html) · [RFC 4180](https://www.rfc-editor.org/rfc/rfc4180) |
| 🧾 JSON | [json module](https://docs.python.org/3/library/json.html) · [JSON Lines](https://jsonlines.org/) |
| 🕐 Time | [datetime](https://docs.python.org/3/library/datetime.html) · [zoneinfo](https://docs.python.org/3/library/zoneinfo.html) · [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) |
| 🔤 Encoding | [Unicode HOWTO](https://docs.python.org/3/howto/unicode.html) · [codecs](https://docs.python.org/3/library/codecs.html) |
| 🔁 Iteration | [itertools](https://docs.python.org/3/library/itertools.html) |
| 📋 Logging | [Logging HOWTO](https://docs.python.org/3/howto/logging.html) · [Logging Cookbook](https://docs.python.org/3/howto/logging-cookbook.html) |
| 📦 Packaging | [Packaging User Guide](https://packaging.python.org/en/latest/) · [pyproject.toml specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/) |
| 🧪 Testing | [unittest](https://docs.python.org/3/library/unittest.html) · [pytest](https://docs.pytest.org/) |

---

<a id="see-also"></a>

## 🔗 Quick Links & Related Guides

- [🗄️ Data Engineering Section Index](../README.md)
- [🧱 Data Engineering Fundamentals](./data_engineering_fundamentals.md)
- [🗃️ SQL & Data Modeling](./sql_data_modeling.md)
- [🔄 ETL & ELT Pipeline Design](./etl_elt_pipeline_design.md)
- [✅ Data Quality & Schema Contracts](./data_quality_schema_contracts.md)
- [🛡️ Secure Data Pipelines](../data_pipelines.md)
- [📊 Log Aggregation & Visibility](../../IncidentResponse/log_agg.md)
- [📖 Repository Glossary](../../GLOSSARY.md)

---

<a id="guide-details"></a>

## 📊 Guide Details

| Item | Details |
| --- | --- |
| 🎯 Focus | Correct, bounded-memory, testable Python for data processing |
| 🧰 Core Technologies | Python standard library: csv, json, itertools, datetime, zoneinfo, logging, unittest |
| 📘 Format | Reference guide with a complete installable lab package |
| 🧪 Validation Status | Examples and lab executed locally; results and limitations documented above |
| 📁 Location | `Data-Engineering/Phase1/python_data_processing.md` |
| 🔄 Content Review Date | September 11, 2026 |

---

<div align="center">

**🐍 Stream the Data. State the Encoding. Test the Edges.**

*Code that holds one record at a time, names its assumptions, and fails loudly outlives code that is merely clever.*

**Repository:** [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Pacific Northwest Computers:** [PNWC on GitHub](https://github.com/Pnwcomputers)

[🏠 Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [📋 Table of Contents](#table-of-contents) | [📜 Legal Notice](../../LEGAL.md)

⭐ **Star the repository if you find it useful!** ⭐

</div>
