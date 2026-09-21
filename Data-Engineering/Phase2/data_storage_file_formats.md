# 🗄️ Data Storage & File Formats

<div align="center">

**Choose storage by access pattern, preserve meaning across formats, and publish complete datasets**

*Relational • Object • Analytical • CSV • JSON Lines • Parquet • Retention*

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md)*

![Phase](https://img.shields.io/badge/Phase_2-Storage_%26_Integration-blue?style=for-the-badge)
![Level](https://img.shields.io/badge/Level-Intermediate-darkgreen?style=for-the-badge)
![Lab](https://img.shields.io/badge/Core_Lab-Python_Standard_Library-purple?style=for-the-badge)

**[Phase 2 Index](README.md) · [Data Engineering Overview](../README.md)**

</div>

---

_Reviewed: 2026-09-11. The local lab was executed with Python 3.12.14 and SQLite 3.53.1. External systems and optional integrations were not exercised; see the Verification Record._


---

<a id="purpose"></a>

## 🎯 Purpose, Function & Goal

**Purpose:** Explain how to choose the storage system and representation that fit a dataset's consumers, update patterns, and recovery needs.

**Function:** Compare relational, object, and analytical storage; describe CSV, JSON Lines, and Parquet; design partitions, compression, publication, and retention; then demonstrate a local round trip with integrity checks.

**Goal:** Be able to justify where a dataset lives, what its bytes mean, how readers discover a complete version, and how it can be restored or rebuilt.

**When to use:** Designing a landing zone, replacing spreadsheet exports, preparing telemetry for analytics, investigating small-file overhead, or defining data retention.

**Prerequisites:** [Fundamentals](../Phase1/data_engineering_fundamentals.md), [SQL & Data Modeling](../Phase1/sql_data_modeling.md), and [Data Quality & Schema Contracts](../Phase1/data_quality_schema_contracts.md).

---

<a id="contents"></a>

## 📋 Table of Contents

- [🧭 1. Choose Storage by the Workload](#storage)
- [📄 2. CSV, JSON Lines & Parquet](#formats)
- [🗂️ 3. Partitioning & Compression](#layout)
- [📦 4. Publish Complete Versions](#publication)
- [🗓️ 5. Retention, Recovery & Access](#retention)
- [🧪 6. Lab: Round Trips, Partitions & Integrity](#lab)
- [🧩 7. Optional Parquet Extension — Not Executed](#parquet)
- [💥 8. Failure Drills & Self-Check](#failures)
- [✅ Verification Record](#verification)
- [Contributing & Related Guides](#related)

---

<a id="storage"></a>

## 🧭 1. Choose Storage by the Workload

A storage service, file format, query engine, and table format are different decisions. Parquet is a file format; object storage stores those files; an analytical engine queries them. A table format can coordinate versions and metadata across many files. A folder full of Parquet files does not automatically provide transactional table updates.

| Storage pattern | Fits well | Design questions | Common mistake |
| --- | --- | --- | --- |
| **Relational database** | Keyed lookups, updates, joins, integrity constraints, transactions | How many writers? Which indexes? What isolation and backup procedure? | Treating a database dump as a live database |
| **Object storage** | Large immutable objects, raw history, exports, dataset files | How are versions published, authorized, discovered, and expired? | Assuming directory-style rename or multi-object transactions |
| **Analytical warehouse or engine** | Scans, aggregates, reporting over many rows | Which queries prune data? What does compute cost? How are models refreshed? | Optimizing only ingest speed while ignoring query cost |
| **Local files or SQLite** | Small, understandable labs and single-host workloads | Who owns writes? How do backups remain consistent? | Assuming local behavior proves distributed behavior |

These categories overlap: a relational database can serve analytics, and an analytical platform may store its tables in object storage. Begin with the access pattern, then select a system.

For an asset inventory, use keyed transactional state for the current device record, retain source exports for reconstruction where policy permits, and publish a separate analytical dataset for historical reports. Avoid forcing one representation to satisfy all three roles.

Record the expected data volume, ingest frequency, query filters, concurrent writers, required recovery point, and acceptable restore time. Benchmark a representative workload before making a scale or cost claim.

---

<a id="formats"></a>

## 📄 2. CSV, JSON Lines & Parquet

| Format | Strengths | Limitations | Contract decisions |
| --- | --- | --- | --- |
| **CSV** | Easy exchange with existing tools; readable; incremental parsing | Weak typing; dialect differences; quoted newlines; ambiguous nulls | Encoding, delimiter, header, quote rules, null sentinel, decimal and timestamp conventions |
| **JSON Lines** | One JSON value per line; useful for record-oriented ingestion; nested values | Repeated field names; inconsistent record shapes; no enforced dataset schema | Require an object per line, UTF-8, explicit timestamp strings, schema version, null versus absent field |
| **Parquet** | Typed columnar representation for analytical access | Binary; requires a reader; file compatibility must be tested across engines | Column types, timestamp units/timezone semantics, decimal precision, nullability, writer compatibility |

Parquet organizes data by columns and supports encodings and compression; it is designed for bulk data access. It is not a row-by-row update protocol. Verify that the readers used by your consumers support the writer's chosen features. [Apache Parquet overview](https://parquet.apache.org/docs/overview/)

### CSV needs a declared null policy

The Python CSV writer turns `None` into an empty field. Without an additional convention, an empty string and a missing value can become indistinguishable. The lab explicitly interprets an empty CPU field as null; that convention is valid for this numeric field, not a universal rule for every CSV column. Use `newline=""` with Python's CSV reader/writer and let the parser handle quoting. [Python CSV documentation](https://docs.python.org/3/library/csv.html)

### JSON Lines is not a JSON array

Read one complete line, parse its JSON value, validate it, and continue. A newline embedded inside a string must be escaped in serialized JSON. A top-level `[{...}, {...}]` document requires an array-aware parser instead. Python accepts some nonstandard numeric values unless configured otherwise; this lab uses `allow_nan=False` when writing.

### Preserve business meaning across formats

Use integer minor units or declared decimals for exact monetary values. Preserve identifiers such as `00123` as strings. Distinguish zero, null, empty, and unknown. Normalize timestamps under an explicit policy while preserving source metadata when it matters. Test a round trip that includes boundary values rather than only ordinary rows.

---

<a id="layout"></a>

## 🗂️ 3. Partitioning & Compression

Partitioning places subsets of data into separate physical groups so suitable queries can skip unrelated data. Choose fields commonly used as filters and stable enough for the intended write pattern.

| Candidate | Useful when | Tradeoff |
| --- | --- | --- |
| Event date | Reports usually filter by occurrence date | Late events require revisiting older partitions |
| Ingest date | Operations and replay follow arrival batches | Event-date queries may scan several ingest dates |
| Region or site plus date | Queries repeatedly select these fields | More directories/files; watch uneven distribution |
| Device ID or request ID | Rarely a good first partition choice | High cardinality can create excessive tiny files |

Example object key: `telemetry/schema_v1/event_date=2026-09-10/part-000.parquet`. A naming convention alone does not make a query engine prune partitions; its reader must recognize the layout and receive appropriate predicates.

Choose file and row-group sizes from measurements: query latency, file count, metadata overhead, compression ratio, and writer memory. Compact small files into new dataset versions. Do not compact by overwriting files that active readers are using.

Compression exchanges CPU work for reduced bytes. Gzip is convenient for sequential text scans, but do not assume an ordinary `.gz` text file can be split or randomly accessed efficiently. Parquet compresses within its columnar structure; choose a supported internal codec rather than wrapping the whole file in gzip. Test the actual reader and codec combination. [Arrow Parquet guide](https://arrow.apache.org/docs/python/parquet.html)

Partitioning and sorting solve different problems. A date partition limits candidate files; sorting within those files can help supported readers skip smaller regions. Neither replaces an index for every workload.

---

<a id="publication"></a>

## 📦 4. Publish Complete Versions

A reader must be able to distinguish a completed dataset from a partially written one.

1. Assign a dataset version or batch identity.
2. Write files to a new location owned by that version.
3. Validate row counts, schema, and file integrity.
4. Write a manifest listing the exact files, schema version, counts, checksums, and creation metadata.
5. Publish a pointer to that completed version using the storage system's documented atomic or conditional operation.
6. Keep the previous version until readers and rollback policy permit removal.

For one local writer, writing a temporary manifest and replacing its name on the same filesystem is a useful visibility boundary. It does not prove crash durability without appropriate syncing, and it is not a multi-file transaction. For object storage, use immutable versioned keys and conditional pointer updates or a supported table/catalog transaction; do not translate local rename assumptions directly.

Use a cryptographic digest to compare exact bytes. A checksum detects corruption relative to a trusted manifest; it does not authenticate an untrusted manifest. Compression metadata can change byte hashes even when logical rows are equal, so distinguish file integrity from semantic equality. Do not assume an object-store ETag is universally an MD5 content hash.

The lab writes one local version and reads only the files its manifest names. It deliberately corrupts a file after successful reading and checks that its recorded hash no longer matches.

---

<a id="retention"></a>

## 🗓️ 5. Retention, Recovery & Access

Define retention separately for raw inputs, rejected records, transformed datasets, logs, temporary files, and backups. A derived table may be rebuildable only while its source inputs and transformation version remain available.

| Policy field | Example question to answer |
| --- | --- |
| Owner and consumers | Who decides whether this dataset is still needed? |
| Retention trigger | Is age measured from arrival, event time, completion, or supersession? |
| Replay horizon | How far back must an operator be able to reconstruct results? |
| Recovery objectives | How much data loss and downtime are acceptable? |
| Deletion exceptions | Are there holds or other obligations that prevent ordinary expiry? |
| Copies | Do replicas, exports, caches, and backups follow the policy? |

Keep retention decisions explicit; this guide supplies no universal day count. Test restoration, including permissions, schema, and transformation code. Encryption keys must remain available for the lifetime of retained encrypted data. Access should distinguish producers, readers, and retention administrators.

Make the first retention job a report of proposed deletions. Verify it against manifests and active references before implementing deletion. A database or file being old does not prove that it is unused, and an object lifecycle rule is not a substitute for a backup strategy.

---

<a id="lab"></a>

## 🧪 6. Lab: Round Trips, Partitions & Integrity

This lab writes four synthetic records as CSV and partitioned gzip JSON Lines, restores their types, loads SQLite, and checks counts, null handling, an aggregate, and corruption detection.

**Requirements:** Python 3.10+ with `sqlite3` available for the database labs. Only Python 3.12.14 was executed for this revision. No credentials, server, network requests, or third-party packages are used.

Save the following as `storage_lab.py` in a practice directory. It creates a temporary workspace and removes that workspace on completion. Run without Python's `-O` flag so assertions remain enabled.

```python
"""Synthetic local storage lab. Output stays inside a temporary directory."""
import csv
import gzip
import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def run(root):
    rows = [
        {'id': 1, 'day': '2026-09-09', 'site': 'VAN', 'cpu': 10.0},
        {'id': 2, 'day': '2026-09-09', 'site': 'PDX', 'cpu': None},
        {'id': 3, 'day': '2026-09-10', 'site': 'VAN', 'cpu': 30.0},
        {'id': 4, 'day': '2026-09-10', 'site': 'PDX', 'cpu': 50.0},
    ]
    csv_path = root / 'events.csv'
    with csv_path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with csv_path.open(encoding='utf-8', newline='') as f:
        restored_csv = [dict(id=int(r['id']), day=r['day'], site=r['site'],
                             cpu=None if r['cpu'] == '' else float(r['cpu']))
                        for r in csv.DictReader(f)]
    assert restored_csv == rows
    manifest = {'schema_version': 1, 'files': []}
    # Small fixture only: grouping all rows in memory is not a large-file design.
    for day in sorted({r['day'] for r in rows}):
        target = root / f'event_date={day}' / 'part-000.jsonl.gz'
        target.parent.mkdir()
        with gzip.open(target, 'wt', encoding='utf-8') as f:
            for row in rows:
                if row['day'] == day:
                    f.write(json.dumps(row, allow_nan=False) + '\n')
        manifest['files'].append({'path': str(target.relative_to(root)),
                                  'sha256': digest(target), 'rows': 2})
    # Publish the manifest only after every data file has been completed.
    temp = root / 'manifest.json.tmp'
    temp.write_text(json.dumps(manifest), encoding='utf-8')
    temp.replace(root / 'manifest.json')
    loaded = []
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    for item in manifest['files']:
        path = root / item['path']
        assert digest(path) == item['sha256']
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            batch = [json.loads(line) for line in f]
        assert len(batch) == item['rows']
        loaded.extend(batch)
    assert loaded == rows
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE events(id INTEGER PRIMARY KEY, day TEXT, site TEXT, cpu REAL)')
    with db:
        db.executemany('INSERT INTO events VALUES (:id,:day,:site,:cpu)', loaded)
    count, measured, avg = db.execute('SELECT COUNT(*), COUNT(cpu), AVG(cpu) FROM events').fetchone()
    assert (count, measured, avg) == (4, 3, 30.0)
    db.close()
    # A one-byte modification must invalidate the recorded checksum.
    first = root / manifest['files'][0]['path']
    with first.open('ab') as f:
        f.write(b'!')
    assert digest(first) != manifest['files'][0]['sha256']
    print('PASS: CSV and JSONL round trips; 2 partitions; 4 rows; 3 measured; mean 30.0; corruption detected')


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='phase2-storage-') as folder:
        run(Path(folder))
```

Run:

```bash
python3 storage_lab.py
```

On Windows, use `py -3 storage_lab.py` if that is how Python is installed. The Windows launcher was not tested here.

**Actual output from this revision:**

```text
PASS: CSV and JSONL round trips; 2 partitions; 4 rows; 3 measured; mean 30.0; corruption detected
```

---

<a id="parquet"></a>

## 🧩 7. Optional Parquet Extension — Not Executed

The core lab intentionally needs no third-party package. The following extension is separate and **was not executed in this revision** because PyArrow was not installed in the test environment.

In an isolated Python environment, install a compatible PyArrow release using `python -m pip install pyarrow`; record and pin the resolved version in your own project after testing. Save this as `parquet_demo.py` and run it with that environment's Python:

```python
from pathlib import Path
from tempfile import TemporaryDirectory
import pyarrow as pa
import pyarrow.parquet as pq

schema = pa.schema([('id', pa.int64()), ('cpu', pa.float64())])
table = pa.Table.from_pylist([
    {'id': 1, 'cpu': 10.0}, {'id': 2, 'cpu': None}
], schema=schema)
with TemporaryDirectory() as folder:
    path = Path(folder) / 'events.parquet'
    pq.write_table(table, path, compression='snappy')
    restored = pq.read_table(path)
    assert restored.equals(table)
    assert pq.read_table(path, columns=['id']).column_names == ['id']
    print('Parquet round trip and projection passed')
```

The example demonstrates explicit schema, a null value, and column projection using Arrow's documented Parquet API. It does not test partition discovery, predicate pruning, multi-engine interoperability, encryption, or performance. [Arrow Parquet reading and writing](https://arrow.apache.org/docs/python/parquet.html)

---

<a id="failures"></a>

## 💥 8. Failure Drills & Self-Check

| Symptom | Investigate | Useful proof |
| --- | --- | --- |
| Row count agrees but totals differ | Type conversion, null handling, rounding | Boundary-value round trip and aggregate comparison |
| Queries open thousands of objects | Excessive partition cardinality or small files | File count and representative query profile |
| Readers see incomplete data | Publication occurs before completion | Readers use only committed manifests |
| Historical replay fails | Expired raw data, missing code version, missing keys | Restore a selected historical batch |
| Two writers lose an update | Shared output names or pointer overwrite | Conditional publication conflict handling |

**Self-check:** Why is a manifest useful? Why is a checksum not an authenticity guarantee? Which partition would a late record update? How does your null policy survive a CSV round trip? Can your largest consumer read the exact Parquet schema you publish?

---

<a id="verification"></a>

## ✅ Verification Record

| Check | Result |
| --- | --- |
| CSV round trip with explicit numeric-null policy | Passed |
| Gzip JSON Lines round trip across two partitions | Passed |
| SQLite row count, non-null count, and mean | Passed: 4, 3, 30.0 |
| Mutation changes the recorded file hash | Passed |
| PyArrow, cloud storage, multi-writer publication, performance | Not executed |
| Power-loss durability and retention deletion | Not tested or implemented |

The fixture is deliberately small and uses in-memory lists. It is a correctness exercise, not a scalable partition writer or benchmark.

---

<a id="related"></a>

## 🤝 Contributing & Related Guides

For a correction, include the section, a synthetic reproducer, your runtime versions, expected behavior, and observed output. Update the Verification Record only for checks you actually perform. Keep credentials and customer records out of examples.

- [📥 API & File Ingestion](./api_file_ingestion.md)
- [⚙️ Workflow Orchestration](./workflow_orchestration.md)
- [🌊 Streaming & Change Data Capture](./streaming_cdc.md)
- [Phase 2 Index](README.md)
- [Phase 1 Fundamentals](../Phase1/data_engineering_fundamentals.md)
- [Data Engineering Overview](../README.md)
- [Repository Home](../../README.md)

**[⬆ Back to Contents](#contents)**
