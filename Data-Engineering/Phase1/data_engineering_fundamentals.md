
# 🧱 Data Engineering Fundamentals

<div align="center">

**Lifecycle, requirements, latency decisions, and source-to-destination design**

*Terminology • Requirements • Batch vs Streaming • Contracts • A file-to-database project*

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Foundations](https://img.shields.io/badge/Level-Foundations-blue?style=for-the-badge)
![Data Engineering](https://img.shields.io/badge/Discipline-Data_Engineering-darkgreen?style=for-the-badge)
![Lab](https://img.shields.io/badge/Lab-Python_%7C_SQLite-purple?style=for-the-badge)
![Stdlib](https://img.shields.io/badge/Dependencies-Standard_Library-orange?style=for-the-badge)

</div>

---

_Last reviewed: 2026-09-11. Local lab verified on the versions listed in the [Verification Record](#verification-record); adapt before using in your own environment._

## 🎯 Purpose

Establish the vocabulary, design questions, and failure assumptions that every later data engineering document in this section depends on. This guide answers *what a pipeline is, what it must promise, and how to decide its shape* before any tool is selected.

## ⚙️ Function

Walk through the data lifecycle from source to consumer, define the terms used across this section, provide a requirements template, compare batch and streaming trade-offs, and finish with a complete runnable file-to-database pipeline that demonstrates validation, quarantine, idempotence, and run logging in under 150 lines of standard-library Python.

## 🏆 Goal

Enable a practitioner to describe, for any pipeline they build or inherit: where the data came from, what shape it must have, how often it moves, what happens to bad records, what happens when the job runs twice, and how to prove the destination matches the source.

## 📋 When to Use

- Beginning data engineering study without prior pipeline experience.
- Scoping a new data movement task before choosing tools or platforms.
- Reviewing an inherited pipeline whose assumptions were never written down.
- Explaining to a stakeholder why a request implies batch, micro-batch, or streaming work.
- Preparing for the [SQL & Data Modeling](./sql_data_modeling.md) and [ETL & ELT Pipeline Design](./etl_elt_pipeline_design.md) guides.

## 🧰 Audience & Prerequisites

**Audience:** IT practitioners, security engineers, and analysts moving into data engineering work.

**Prerequisites:** Comfort with a terminal, file paths, and text editing. Python 3.10 or later. No database server, cloud account, or third-party package is required — the lab uses `csv`, `json`, `sqlite3`, `logging`, and `hashlib` from the standard library.

> [!NOTE]
> Every command in this guide runs locally against synthetic data. Nothing here contacts a network service, and no example requires elevated privileges.

---

<a id="table-of-contents"></a>

## 📋 Table of Contents

- [🧭 1. What Data Engineering Actually Delivers](#1-what-data-engineering-actually-delivers)
- [🔤 2. Core Terminology](#2-core-terminology)
- [♻️ 3. The Data Lifecycle](#3-the-data-lifecycle)
- [📝 4. Requirements Before Code](#4-requirements-before-code)
- [⏱️ 5. Batch, Micro-Batch, and Streaming](#5-batch-micro-batch-and-streaming)
- [🔗 6. Source-to-Destination Design](#6-source-to-destination-design)
- [🧪 7. Lab: File-to-Database Pipeline](#7-lab-file-to-database-pipeline)
- [💥 8. Failure Drills](#8-failure-drills)
- [🎓 9. Self-Check](#9-self-check)
- [✅ Verification Record](#verification-record)
- [🤝 Contributing](#contributing)
- [📚 Resources](#resources)
- [🔗 Quick Links & Related Guides](#see-also)
- [📊 Guide Details](#guide-details)

---

<a id="1-what-data-engineering-actually-delivers"></a>

## 🧭 1. What Data Engineering Actually Delivers

A pipeline is not judged by how much data it moves. It is judged by whether a consumer can trust what arrives. Four promises define the work:

| Promise | Question it answers | How it fails quietly |
| --- | --- | --- |
| **Completeness** | Did every source record reach the destination? | A paginated API stops at page 1 and the job still exits zero. |
| **Correctness** | Do the values still mean what they meant at the source? | A timestamp without a timezone is stored as if it were UTC. |
| **Timeliness** | Is the data recent enough for the decision being made? | A job succeeds nightly but the source stopped producing a week ago. |
| **Traceability** | Can a single row be explained back to its origin? | Records are merged from three files with no column recording which. |

Notice that each failure mode produces a *successful-looking job*. Most of the engineering effort in this section exists to make those four promises observable rather than assumed.

> [!TIP]
> When reviewing any pipeline — yours or one you inherited — ask which of the four promises it can currently prove with a query, and which it only asserts in a README.

### 📘 Where this sits next to related disciplines

| Discipline | Owns | Boundary |
| --- | --- | --- |
| **Data engineering** | Movement, shape, reliability, and delivery of data | Stops at the prepared dataset |
| **Analytics** | Interpretation of prepared data | Depends on the engineer's contract holding |
| **Detection engineering** | Which telemetry patterns warrant investigation | Consumes structured events; see [Incident Response](../IncidentResponse/README.md) |
| **Platform / infrastructure** | The servers, containers, and networks underneath | Deploys the pipeline; does not define its schema |

---

<a id="2-core-terminology"></a>

## 🔤 2. Core Terminology

These terms recur in every other guide in this section. Definitions here are operational rather than academic.

| Term | Working definition |
| --- | --- |
| **Source** | The system of record where data originates. A file drop, API, database, agent, or device. |
| **Sink / destination** | Where processed data lands for consumption. A table, object store prefix, index, or topic. |
| **Record / event** | One unit of meaning. A row, a log line, a JSON object, a message. |
| **Schema** | The declared field names, types, and required-ness of a record. |
| **Contract** | The schema *plus* the promises around it: identity, nullability, timezone, compatibility, and who is allowed to change what. |
| **Batch** | A bounded set of records processed together with a defined start and end. |
| **Stream** | An unbounded sequence of records processed continuously as they arrive. |
| **Watermark / high-water mark** | The stored marker of how far a source has been consumed, used to resume without reprocessing everything. |
| **Checkpoint** | A durable record of pipeline progress, written so a restart resumes rather than restarts. |
| **Idempotence** | Running the same job twice with the same input produces the same destination state as running it once. |
| **Natural key** | A field combination that uniquely identifies a record in the real world (for example, an asset serial number). |
| **Surrogate key** | A system-generated identifier used internally when the natural key is unstable or wide. |
| **Event ID** | A deterministic hash of identifying fields, used to detect duplicates across retries. |
| **Quarantine** | A durable holding location for records that failed validation, kept for inspection rather than discarded. |
| **Backfill** | A deliberate reprocessing of a historical range, usually after a bug fix or a new field. |
| **Lineage** | The recorded path from a destination row back through transformations to its source. |
| **Freshness** | The age of the newest record in the destination, measured against expectation. |
| **Lag** | The delay between an event occurring and it becoming queryable. |
| **Reconciliation** | Comparing source and destination counts or checksums to prove completeness. |

> [!NOTE]
> Two terms are routinely confused. *Deployment automation* configures the machines that run a pipeline (see the Ansible section of [data_pipelines.md](./data_pipelines.md#9-automate-deployments-with-ansible)). *Workflow orchestration* schedules and sequences the data jobs themselves. A configured server does not imply a scheduled, retried, dependency-aware job.

Acronyms used across this section are defined on first use and collected in the repository [glossary](../GLOSSARY.md).

---

<a id="3-the-data-lifecycle"></a>

## ♻️ 3. The Data Lifecycle

Every pipeline, regardless of scale, passes through the same seven stages. Small pipelines collapse several stages into one script; large ones assign each to a separate service. The stages do not disappear — they only become less visible.

| Stage | What happens | Primary risk | Minimum control |
| --- | --- | --- | --- |
| **1. Generation** | The source system produces a record | Silent producer outage | Expected-arrival monitoring |
| **2. Ingestion** | The record is collected and staged | Partial reads, lost pages | Checkpoints and raw retention |
| **3. Validation** | Shape and values are checked | Bad data accepted as good | Explicit schema and quarantine |
| **4. Transformation** | Values are normalized, enriched, derived | Meaning changes silently | Unit tests on fixtures |
| **5. Storage** | Data is written to the destination | Duplicates or partial writes | Idempotent writes in a transaction |
| **6. Serving** | Consumers query or subscribe | Reading half-written state | Atomic publication, documented freshness |
| **7. Retention** | Data is archived or deleted | Unbounded growth, policy breach | Documented retention rules |

### 📘 Retain the raw layer

A recurring beginner mistake is transforming during ingestion and keeping only the result. When the transformation is later found to be wrong, the original is gone and the error is permanent.

Keep an immutable raw landing area — even a dated directory of the original files is enough at small scale. Transformation should read *from* raw, never overwrite it. This single habit makes backfills possible and is the practical foundation of the ELT patterns discussed in [ETL & ELT Pipeline Design](./etl_elt_pipeline_design.md).

```text
data/
├── raw/2026-09-11/assets_export.csv     # never modified after landing
├── quarantine/2026-09-11/rejects.jsonl  # failed validation, kept for review
└── warehouse/assets.db                  # derived, rebuildable from raw
```

> [!CAUTION]
> Raw retention is a data-protection decision as well as an engineering one. Raw security logs and customer exports frequently contain sensitive fields. Define access boundaries and a deletion schedule for the raw layer at the same time you create it, and never commit it to Git.

---

<a id="4-requirements-before-code"></a>

## 📝 4. Requirements Before Code

Most pipeline rework traces back to a question that was never asked. The following template takes fifteen minutes and prevents the majority of it. Fill it in before opening an editor.

```markdown
## Pipeline: <name>

**Owner:**              <person or team responsible when it breaks>
**Consumer:**           <who reads the output and for what decision>

### Source
- System:               <file share / API / database / agent>
- Access method:        <credential type, network path>
- Format & encoding:    <CSV UTF-8 / JSON Lines / Parquet>
- Volume:               <records per run, bytes per run, growth rate>
- Availability window:  <when the source is complete and safe to read>

### Destination
- System:               <table / object prefix / topic / index>
- Write mode:           <append / upsert / replace-partition>
- Retention:            <how long, and what deletes it>

### Contract
- Record identity:      <fields that make a record unique>
- Required fields:      <fields that may never be null>
- Timestamp semantics:  <event time or ingest time; timezone; format>
- Bad-record policy:    <quarantine / fail the run / drop with count>

### Operations
- Schedule:             <cron, event-driven, continuous>
- Acceptable delay:     <maximum age of data the consumer tolerates>
- Rerun behavior:       <is a second run of the same input safe?>
- Failure notification: <who is told, by what channel>
- Sensitivity:          <classification; fields needing masking>
```

### 📘 The two questions that change the architecture

**"What is the acceptable delay?"** This single answer determines batch versus streaming more than data volume does. A daily report tolerating 24 hours does not justify a broker.

**"What happens if this runs twice?"** If the honest answer is *"we get duplicates"*, the design is not finished. Idempotence is cheaper to build in at the start than to retrofit after a duplicated month of data.

---

<a id="5-batch-micro-batch-and-streaming"></a>

## ⏱️ 5. Batch, Micro-Batch, and Streaming

| Dimension | Batch | Micro-batch | Streaming |
| --- | --- | --- | --- |
| **Typical delay** | Minutes to a day | Seconds to minutes | Sub-second to seconds |
| **Unit of work** | Whole bounded set | Small time or size window | Individual record |
| **Restart model** | Rerun the window | Rerun the window | Resume from offset |
| **Failure blast radius** | One run | One window | Consumer lag grows |
| **Operational cost** | Lowest | Moderate | Highest |
| **Typical use** | Reports, exports, reconciliation | Dashboards, near-real-time metrics | Alerting, fraud, live detection |

### 📘 Choosing honestly

Start with batch. Move up only when a specific consumer requirement — not a preference — cannot be met.

**Batch is sufficient when:**
- The consumer acts on the data on a schedule, not continuously.
- The source itself only publishes periodically (a nightly export cannot be streamed).
- Reprocessing an entire window is cheap.

**Micro-batch earns its cost when:**
- A dashboard is checked throughout the day and hourly staleness is visible.
- Volume per window is large enough that per-record overhead matters.

**Streaming is justified when:**
- A delayed decision loses value — blocking an active session, paging an on-call responder.
- The source is genuinely continuous and unbounded.
- The team can operate brokers, consumer groups, and lag monitoring. See the Kafka material in [data_pipelines.md](./data_pipelines.md#8-stream-and-centralize-events-with-kafka) and the Phase 2 streaming guide when published.

> [!WARNING]
> Streaming does not remove batch work; it adds to it. Streamed data still requires periodic reconciliation, backfills after logic changes, and historical reprocessing. Teams that adopt streaming without keeping a batch correction path end up unable to fix past data.

### 📘 The sizing question people skip

Estimate before you architect:

```text
records_per_day  ×  average_bytes_per_record  =  raw daily volume
raw daily volume ×  retention_days            =  storage footprint
records_per_day  ÷  86400                     =  average records/second
peak_multiplier  ×  average records/second    =  design target
```

A source producing 5 million records per day averages roughly 58 records per second. With a peak multiplier of 10, the design target is under 600 per second — a load a single well-written process and an indexed database handle comfortably. Many distributed architectures are built for volumes that were never calculated.

---

<a id="6-source-to-destination-design"></a>

## 🔗 6. Source-to-Destination Design

With requirements written, design the path in five decisions.

### 📘 Decision 1: How is new data identified?

| Source capability | Extraction strategy | Watermark stored |
| --- | --- | --- |
| Immutable dated files | Process unseen filenames | Set of processed filenames |
| Append-only table with sequence | `WHERE id > :last_id` | Highest id |
| Table with reliable `updated_at` | `WHERE updated_at > :last_ts` | Highest timestamp, with overlap |
| API with cursor | Follow cursor until exhausted | Last cursor token |
| No change indicator at all | Full extract and compare | Content hash per record |

> [!TIP]
> When using an `updated_at` watermark, re-read a small overlap window (for example, the last 5 minutes) on each run. Clock skew and transactions committing after their timestamp was assigned are common causes of permanently skipped records. The overlap is only safe because writes are idempotent — which is Decision 3.

### 📘 Decision 2: What identifies a record?

Choose the field combination that makes a record unique *in the real world*, then derive a stable event identifier from it. A deterministic hash makes duplicate detection possible even across systems that never coordinate:

```python
import hashlib

def event_id(*parts: str) -> str:
    """Stable identifier derived from the fields that define record identity."""
    joined = "\x1f".join(p.strip().lower() for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32]
```

The separator matters. Concatenating `"ab" + "c"` and `"a" + "bc"` without one produces the same hash for different records. The unit separator (`\x1f`) is used because it does not appear in ordinary field values.

### 📘 Decision 3: How are writes made repeatable?

| Write mode | Mechanism | Use when |
| --- | --- | --- |
| **Append-only** | Insert, tolerate duplicates downstream | Rarely acceptable; only for immutable event logs with dedup at read |
| **Upsert** | `INSERT ... ON CONFLICT DO UPDATE` on the key | Records can be corrected or restated |
| **Insert-or-ignore** | `INSERT OR IGNORE` on the key | Records are immutable once seen |
| **Replace-partition** | Delete the window, insert the window, in one transaction | Whole-day or whole-file reloads |

All four are compatible with reruns. Plain `INSERT` without a key constraint is not.

### 📘 Decision 4: What happens to bad records?

Three options, chosen per-pipeline and written into the contract:

1. **Fail the run.** Correct for small, critical, human-curated inputs where any error means the file is wrong.
2. **Quarantine and continue.** Correct for most telemetry and machine-generated sources. Rejected records are written with their reason and original content to a durable location.
3. **Drop with a counter.** Only acceptable when the record is genuinely worthless *and* the count is monitored, because a rising drop rate is a real incident.

Silent dropping is never one of the options.

### 📘 Decision 5: How is success proven?

Define, before building, the query that demonstrates the run worked:

- Source record count versus accepted plus quarantined count.
- Newest destination timestamp versus expected freshness.
- Distinct key count versus row count, proving no duplicates.

If no such query exists, the pipeline has no definition of success — only an absence of exceptions.

---

<a id="7-lab-file-to-database-pipeline"></a>

## 🧪 7. Lab: File-to-Database Pipeline

This lab implements every decision above in a complete, runnable pipeline: synthetic CSV assets are validated, quarantined on failure, upserted idempotently into SQLite, and reconciled with a run log. It uses only the standard library.

### 🧪 Step 1: Create the working directory and synthetic source

```bash
mkdir -p ~/de-lab/data/raw ~/de-lab/data/quarantine ~/de-lab/data/warehouse
cd ~/de-lab
```

Create `make_sample.py`:

```python
#!/usr/bin/env python3
"""Generate a synthetic asset inventory export with deliberate data problems."""
import csv
import pathlib

ROWS = [
    # serial,       hostname,   site,       os,           last_seen
    ("SN-1001", "ws-acct-01", "vancouver", "Windows 11", "2026-09-10T14:03:00+00:00"),
    ("SN-1002", "ws-acct-02", "vancouver", "Windows 11", "2026-09-10T14:05:00+00:00"),
    ("SN-1003", "srv-file-01", "portland", "Ubuntu 24.04", "2026-09-10T14:07:00+00:00"),
    ("SN-1002", "ws-acct-02", "vancouver", "Windows 11", "2026-09-10T14:05:00+00:00"),  # exact duplicate
    ("SN-1004", "", "portland", "Windows 11", "2026-09-10T14:09:00+00:00"),             # missing hostname
    ("SN-1005", "ws-ops-07", "seattle", "Windows 11", "10/09/2026 14:11"),              # unparseable timestamp
    ("", "ws-ghost-01", "vancouver", "Windows 10", "2026-09-10T14:13:00+00:00"),        # missing natural key
]

def main() -> None:
    out = pathlib.Path("data/raw/2026-09-11/assets_export.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["serial", "hostname", "site", "os", "last_seen"])
        writer.writerows(ROWS)
    print(f"wrote {out} ({len(ROWS)} data rows)")

if __name__ == "__main__":
    main()
```

```bash
python3 make_sample.py
```

Expected output:

```text
wrote data/raw/2026-09-11/assets_export.csv (7 data rows)
```

Seven rows containing four distinct problems: one exact duplicate, one missing required field, one unparseable timestamp, and one missing natural key. A pipeline that reports "7 rows loaded" has failed.

### 🧪 Step 2: The loader

Create `load_assets.py`:

```python
#!/usr/bin/env python3
"""Load a synthetic asset CSV into SQLite with validation, quarantine, and idempotent writes."""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import logging
import pathlib
import sqlite3
import sys

RAW_DIR = pathlib.Path("data/raw")
QUARANTINE_DIR = pathlib.Path("data/quarantine")
DB_PATH = pathlib.Path("data/warehouse/assets.db")

REQUIRED = ("serial", "hostname", "site", "os", "last_seen")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("load_assets")


def event_id(*parts: str) -> str:
    joined = "\x1f".join(p.strip().lower() for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32]


def parse_ts(value: str) -> str:
    """Return a normalized UTC ISO-8601 string or raise ValueError."""
    parsed = dt.datetime.fromisoformat(value.strip())
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone offset")
    return parsed.astimezone(dt.timezone.utc).isoformat()


def schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS assets (
            asset_id     TEXT PRIMARY KEY,
            serial       TEXT NOT NULL UNIQUE,
            hostname     TEXT NOT NULL,
            site         TEXT NOT NULL,
            os           TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            source_file  TEXT NOT NULL,
            loaded_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS load_runs (
            run_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file  TEXT NOT NULL,
            started_at   TEXT NOT NULL,
            read_rows    INTEGER NOT NULL,
            accepted     INTEGER NOT NULL,
            quarantined  INTEGER NOT NULL,
            inserted     INTEGER NOT NULL,
            updated      INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_assets_site ON assets(site);
        """
    )


def validate(row: dict[str, str]) -> tuple[dict[str, str] | None, str | None]:
    """Return (clean_row, None) or (None, reason)."""
    for field in REQUIRED:
        if not (row.get(field) or "").strip():
            return None, f"missing required field: {field}"
    try:
        last_seen = parse_ts(row["last_seen"])
    except ValueError as exc:
        return None, f"invalid last_seen: {exc}"
    return {
        "serial": row["serial"].strip().upper(),
        "hostname": row["hostname"].strip().lower(),
        "site": row["site"].strip().lower(),
        "os": row["os"].strip(),
        "last_seen": last_seen,
    }, None


def load(csv_path: pathlib.Path) -> int:
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    quarantine_path = QUARANTINE_DIR / csv_path.parent.name / "rejects.jsonl"
    quarantine_path.parent.mkdir(parents=True, exist_ok=True)

    read_rows = accepted = quarantined = inserted = updated = 0

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    schema(conn)

    with csv_path.open(newline="", encoding="utf-8") as fh, \
         quarantine_path.open("a", encoding="utf-8") as rejects:
        reader = csv.DictReader(fh)
        try:
            with conn:  # single transaction: all or nothing
                for line_no, row in enumerate(reader, start=2):
                    read_rows += 1
                    clean, reason = validate(row)
                    if reason is not None:
                        quarantined += 1
                        rejects.write(json.dumps({
                            "source_file": str(csv_path),
                            "line": line_no,
                            "reason": reason,
                            "raw": row,
                            "quarantined_at": started,
                        }) + "\n")
                        log.warning("quarantined line %d: %s", line_no, reason)
                        continue

                    accepted += 1
                    asset_id = event_id(clean["serial"])
                    existed = conn.execute(
                        "SELECT 1 FROM assets WHERE asset_id = ?", (asset_id,)
                    ).fetchone() is not None

                    conn.execute(
                        """
                        INSERT INTO assets
                            (asset_id, serial, hostname, site, os, last_seen,
                             source_file, loaded_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(asset_id) DO UPDATE SET
                            hostname    = excluded.hostname,
                            site        = excluded.site,
                            os          = excluded.os,
                            last_seen   = MAX(assets.last_seen, excluded.last_seen),
                            source_file = excluded.source_file,
                            loaded_at   = excluded.loaded_at
                        """,
                        (asset_id, clean["serial"], clean["hostname"], clean["site"],
                         clean["os"], clean["last_seen"], str(csv_path), started),
                    )
                    if existed:
                        updated += 1
                    else:
                        inserted += 1

                conn.execute(
                    """
                    INSERT INTO load_runs
                        (source_file, started_at, read_rows, accepted,
                         quarantined, inserted, updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (str(csv_path), started, read_rows, accepted,
                     quarantined, inserted, updated),
                )
        finally:
            conn.close()

    log.info(
        "read=%d accepted=%d quarantined=%d inserted=%d updated=%d",
        read_rows, accepted, quarantined, inserted, updated,
    )
    if read_rows != accepted + quarantined:
        log.error("reconciliation failed: rows unaccounted for")
        return 1
    return 0


if __name__ == "__main__":
    target = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else \
        RAW_DIR / "2026-09-11" / "assets_export.csv"
    sys.exit(load(target))
```

### 🧪 Step 3: Run it

```bash
python3 load_assets.py
```

Expected output (timestamps will differ):

```text
2026-09-11 21:40:02,113 WARNING load_assets quarantined line 6: missing required field: hostname
2026-09-11 21:40:02,113 WARNING load_assets quarantined line 7: invalid last_seen: Invalid isoformat string: '10/09/2026 14:11'
2026-09-11 21:40:02,113 WARNING load_assets quarantined line 8: missing required field: serial
2026-09-11 21:40:02,114 INFO load_assets read=7 accepted=4 quarantined=3 inserted=3 updated=1
```

Read the counts carefully. Seven rows produced **three** stored assets, not seven. The duplicate `SN-1002` was accepted as a valid record and then converged onto the existing row through the upsert — it shows as `updated=1`, not as a second asset.

### 🧪 Step 4: Verify with queries

```bash
sqlite3 data/warehouse/assets.db \
  "SELECT serial, hostname, site, last_seen FROM assets ORDER BY serial;"
sqlite3 data/warehouse/assets.db \
  "SELECT COUNT(*) AS rows, COUNT(DISTINCT serial) AS keys FROM assets;"
```

The row count and distinct-key count must be equal. That query is the completeness proof from Decision 5.

> [!TIP]
> If the `sqlite3` command-line tool is not installed, run the same queries through Python, which always has the driver available:
>
> ```bash
> python3 -c "import sqlite3; c=sqlite3.connect('data/warehouse/assets.db'); print(c.execute('SELECT COUNT(*), COUNT(DISTINCT serial) FROM assets').fetchone())"
> ```

Inspect what was rejected — the quarantine file preserves the original row and the reason:

```bash
python3 -c "import json,sys; [print(json.loads(l)['reason'], '|', json.loads(l)['raw']) for l in open('data/quarantine/2026-09-11/rejects.jsonl')]"
```

### 🧪 Step 5: Prove idempotence

```bash
python3 load_assets.py
sqlite3 data/warehouse/assets.db "SELECT COUNT(*) FROM assets;"
```

The asset count is unchanged after the second run: the second execution reports `inserted=0 updated=4`. This is the property that makes retries, overlapping watermarks, and backfills safe.

The run log records both executions:

```bash
sqlite3 -header -column data/warehouse/assets.db \
  "SELECT run_id, read_rows, accepted, quarantined, inserted, updated FROM load_runs;"
```

> [!NOTE]
> The quarantine file appends on every run, so a rerun duplicates reject entries. That is intentional here — it keeps a full audit of what each run saw. In production, either include the run identifier in the quarantine filename or add the same event-identifier deduplication used for accepted records.

---

<a id="8-failure-drills"></a>

## 💥 8. Failure Drills

A pipeline is only understood once its failures have been observed deliberately. Run each drill and record what the system actually did.

| Drill | How to induce it | What to confirm |
| --- | --- | --- |
| **Empty source** | `printf 'serial,hostname,site,os,last_seen\n' > data/raw/2026-09-11/empty.csv` then load it | Run succeeds with `read=0`; destination is unchanged; an empty result is distinguishable from a failure |
| **Malformed file** | Load a file with a missing column header | The error is explicit and no partial write is committed |
| **Interrupted run** | Press `Ctrl+C` mid-load on a large generated file | The transaction rolls back; no half-loaded state remains |
| **Duplicate delivery** | Copy the source file to a new name and load both | Asset count is unchanged; `updated` increments |
| **Restated record** | Edit one row's `os` value and reload | The upsert applies the correction; `last_seen` does not regress |
| **Disk full** | `ulimit -f 1` in a throwaway shell, then load | The failure surfaces rather than silently truncating |

> [!TIP]
> Record drill outcomes in the pipeline's requirements document. A drill that was performed once and written down is worth more than a monitoring dashboard nobody has tested.

---

<a id="9-self-check"></a>

## 🎓 9. Self-Check

Answer in your own words. If an answer requires reading the code, the concept is not yet internalized.

1. Why does a job that exits with status zero not prove completeness?
2. What is the difference between a schema and a contract?
3. When is `INSERT OR IGNORE` a better choice than `ON CONFLICT DO UPDATE`?
4. Why does the watermark strategy re-read an overlap window, and what property makes that safe?
5. Why is `\x1f` used as the separator in `event_id()` instead of a hyphen?
6. Which of the four promises does the quarantine file support, and which does the run log support?
7. A stakeholder requests "real-time" data for a report reviewed each Monday. What do you ask next?
8. The pipeline stored three assets from seven input rows. Explain each of the four rows that did not become a new asset.

### 📘 Suggested next steps

| Goal | Guide |
| --- | --- |
| Deepen the Python patterns used in the loader | [Python for Data Processing](./python_data_processing.md) |
| Design the destination properly instead of one flat table | [SQL & Data Modeling](./sql_data_modeling.md) |
| Add staging, incremental loads, and reconciliation | [ETL & ELT Pipeline Design](./etl_elt_pipeline_design.md) |
| Formalize validation and schema change rules | [Data Quality & Schema Contracts](./data_quality_schema_contracts.md) |
| Apply all of it to security telemetry | [Secure Data Pipelines](./data_pipelines.md) |

---

<a id="verification-record"></a>

## ✅ Verification Record

| Area | Verification performed | Limitation |
| --- | --- | --- |
| `make_sample.py` | Executed; produced the seven-row CSV with the four intended defects | Synthetic fixture only |
| `load_assets.py` | Executed; observed `read=7 accepted=4 quarantined=3 inserted=3 updated=1` | Single-file, single-process SQLite path |
| Idempotence | Reran the loader; asset count unchanged, second run reported `inserted=0 updated=4` | Concurrency and multi-writer behavior not exercised |
| Quarantine | Confirmed three JSON Lines records with reason and original row preserved | Quarantine records are appended, not deduplicated |
| Reconciliation query | Confirmed row count equals distinct serial count (3 and 3) | Run through the Python `sqlite3` module; the `sqlite3` CLI was unavailable in the verification environment, so the CLI invocations shown are untested syntax equivalents |
| Empty-source drill | Executed with a header-only file; run succeeded with `read=0` and no destination change | Other drills in §8 are described, not executed here |
| `event_id()` | Confirmed deterministic output across runs and separator behavior on adjacent-field collisions | Truncated to 32 hex characters; not a cryptographic commitment |

Local checks used Python 3.12.3 and SQLite 3.45.1 on Ubuntu. These identify the verification environment and are not a recommendation to pin to those versions. Revalidate on the releases you deploy.

---

<a id="contributing"></a>

## 🤝 Contributing

**Submission Guidelines:**

1. Use synthetic or thoroughly sanitized data in every example.
2. State the operating system, Python version, and any dependency added.
3. Describe what you executed, the output observed, and what remains unverified.
4. Prefer standard-library examples so readers can run them without setup.
5. Keep the distinction between runnable labs and configuration templates explicit.
6. Update the [section index](./README.md) and [master index](../README.md) when adding a guide.

---

<a id="resources"></a>

## 📚 Resources

| Area | Official References |
| --- | --- |
| 🐍 Python | [csv module](https://docs.python.org/3/library/csv.html) · [sqlite3 module](https://docs.python.org/3/library/sqlite3.html) · [logging HOWTO](https://docs.python.org/3/howto/logging.html) |
| 🗄️ SQLite | [UPSERT syntax](https://www.sqlite.org/lang_upsert.html) · [Transactions](https://www.sqlite.org/lang_transaction.html) |
| 🕐 Timestamps | [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) · [datetime.fromisoformat](https://docs.python.org/3/library/datetime.html#datetime.datetime.fromisoformat) |
| 📄 Formats | [JSON Lines](https://jsonlines.org/) · [RFC 4180 CSV](https://www.rfc-editor.org/rfc/rfc4180) |

---

<a id="see-also"></a>

## 🔗 Quick Links & Related Guides

- [🗄️ Data Engineering Section Index](./README.md)
- [🛡️ Secure Data Pipelines & Security Automation](./data_pipelines.md)
- [🐍 Python for Data Processing](./python_data_processing.md)
- [🗃️ SQL & Data Modeling](./sql_data_modeling.md)
- [🔄 ETL & ELT Pipeline Design](./etl_elt_pipeline_design.md)
- [✅ Data Quality & Schema Contracts](./data_quality_schema_contracts.md)
- [📖 Repository Glossary](../GLOSSARY.md)
- [📏 Repository Style Guide](../STYLE_GUIDE.md)

---

<a id="guide-details"></a>

## 📊 Guide Details

| Item | Details |
| --- | --- |
| 🎯 Focus | Lifecycle, terminology, requirements, and latency decisions |
| 🧰 Core Technologies | Python standard library, SQLite |
| 📘 Format | Reference guide with one complete runnable lab |
| 🧪 Validation Status | Lab executed locally; results and limitations documented above |
| 📁 Location | `Data-Engineering/data_engineering_fundamentals.md` |
| 🔄 Content Review Date | September 11, 2026 |

---

<div align="center">

**🧱 Define the Promise. Design the Path. Prove the Result.**

*Write the requirements before the code, and the query that proves success before the pipeline that claims it.*

**Repository:** [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Pacific Northwest Computers:** [PNWC on GitHub](https://github.com/Pnwcomputers)

[🏠 Master Index](../README.md) | [🎯 Role Navigation](../START_HERE.md) | [📋 Table of Contents](#table-of-contents) | [📜 Legal Notice](../LEGAL.md)

⭐ **Star the repository if you find it useful!** ⭐

</div>
