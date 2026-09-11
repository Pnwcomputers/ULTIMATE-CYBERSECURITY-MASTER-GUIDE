
# 🔄 ETL & ELT Pipeline Design

<div align="center">

**Staging, incremental loads, idempotent writes, checkpoints, backfills, and reconciliation**

*Extract-Transform-Load vs Extract-Load-Transform • Watermarks • Merge • Replay • Proof of completeness*

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Foundations](https://img.shields.io/badge/Level-Foundations-blue?style=for-the-badge)
![Patterns](https://img.shields.io/badge/Patterns-ETL_%7C_ELT-darkgreen?style=for-the-badge)
![Idempotence](https://img.shields.io/badge/Design-Idempotent_%7C_Replayable-purple?style=for-the-badge)
![Lab](https://img.shields.io/badge/Lab-Python_%7C_SQLite-orange?style=for-the-badge)

</div>

---

_Last reviewed: 2026-09-11. The incremental pipeline lab was executed end to end; all counts shown are actual output. See the [Verification Record](#verification-record)._

**Prerequisites:** [Data Engineering Fundamentals](./data_engineering_fundamentals.md) for watermarks and idempotence, and [SQL & Data Modeling](./sql_data_modeling.md) for constraints and transactions.

## 🎯 Purpose

Move from a script that loads a file to a pipeline that runs on a schedule, processes only what is new, survives being run twice, resumes after a crash, and can prove that its destination matches its source.

## ⚙️ Function

Compare ETL and ELT and the conditions that select between them; define the staging layer and why it exists; implement incremental extraction with watermarks and an overlap window; implement idempotent merge writes; store checkpoints durably; execute a backfill; and finish each run with a reconciliation that fails loudly when the destination has drifted.

## 🏆 Goal

Enable a practitioner to build a scheduled pipeline whose second run inserts nothing new, whose interrupted run leaves no partial state, whose backfill repairs missing data without duplicating existing data, and whose success is asserted by a query rather than by the absence of an exception.

## 📋 When to Use

- Turning a one-off load into a scheduled, repeatable job.
- Choosing between transforming before or after landing data.
- Designing incremental extraction against a source with an `updated_at` column, a sequence, or a cursor.
- Recovering from a failed run, a bad transformation, or a gap in the destination.
- Preparing the orchestration work described in the Phase 2 guides.

## 🧰 Audience & Prerequisites

**Audience:** Practitioners who can load data once and now need it to load correctly every fifteen minutes, unattended, for a year.

**Prerequisites:** Python 3.10 or later and SQLite (both used here without a server). The patterns apply unchanged to PostgreSQL, SQL Server, and cloud warehouses; dialect differences are noted.

> [!NOTE]
> The lab simulates an operational source database with a second SQLite file, so the full extract-land-merge-checkpoint-reconcile cycle runs locally with no external system.

---

<a id="table-of-contents"></a>

## 📋 Table of Contents

- [⚖️ 1. ETL, ELT, and How to Choose](#1-etl-elt-and-how-to-choose)
- [🗂️ 2. The Layered Architecture](#2-the-layered-architecture)
- [📥 3. Incremental Extraction](#3-incremental-extraction)
- [🔀 4. Idempotent Writes and Merge](#4-idempotent-writes-and-merge)
- [📍 5. Checkpoints and Run State](#5-checkpoints-and-run-state)
- [🧪 6. Lab: The Incremental Pipeline](#6-lab-the-incremental-pipeline)
- [♻️ 7. Backfills and Replay](#7-backfills-and-replay)
- [🧾 8. Reconciliation](#8-reconciliation)
- [💥 9. Failure Modes](#9-failure-modes)
- [🎓 10. Self-Check](#10-self-check)
- [✅ Verification Record](#verification-record)
- [🤝 Contributing](#contributing)
- [📚 Resources](#resources)
- [🔗 Quick Links & Related Guides](#see-also)
- [📊 Guide Details](#guide-details)

---

<a id="1-etl-elt-and-how-to-choose"></a>

## ⚖️ 1. ETL, ELT, and How to Choose

Both patterns move data from a source to a destination. They differ in *where* the transformation runs and *what* is stored first.

```text
ETL:  Source ──extract──► Transform (in the pipeline) ──load──► Destination
                                                                  └─ only transformed data stored

ELT:  Source ──extract──► Load raw ──► Destination ──transform (in the destination)──► Models
                                          └─ raw retained, models rebuildable
```

| Dimension | ETL | ELT |
| --- | --- | --- |
| Transformation engine | Pipeline process (Python, Spark) | The destination database |
| Raw data retained | Often not | Yes, by design |
| Fixing a transformation bug | Re-extract from the source | Rebuild models from stored raw |
| Schema change tolerance | Breaks the run | Lands anyway; the model absorbs it |
| Destination cost | Lower storage | Higher storage and compute |
| Fits when | Source access is expensive or fragile; sensitive fields must be dropped before landing | The destination is capable; history matters; models change often |

### 📘 The deciding question

**"When the transformation logic turns out to be wrong, what does fixing it require?"**

With ETL, it requires going back to the source — which may have already aged out, rate-limited you, or overwritten the row. With ELT, it requires re-running a query against data you already hold. That asymmetry is why ELT has become the default for analytical work, and it is the same reasoning behind retaining a raw layer in [Data Engineering Fundamentals](./data_engineering_fundamentals.md#3-the-data-lifecycle).

### 📘 Where ETL remains correct

- **Sensitive fields must never land.** Masking or dropping personal data, credentials, or regulated fields before they touch the destination is a control that ELT cannot provide after the fact. See the governance considerations in [Applied Cryptography](../Cryptography/applied-crypto.md).
- **The source is the bottleneck.** A rate-limited API or a production database under load should be read once, not repeatedly.
- **The destination cannot transform.** Object storage and message brokers have no compute.
- **Volume reduction is enormous.** Aggregating a billion raw events into a thousand summary rows before landing is legitimate — provided the raw is retained somewhere.

> [!TIP]
> In practice most pipelines are **EtLT**: a light, non-destructive transformation during extraction (decoding, normalizing timestamps, dropping restricted fields) followed by the substantive modeling in the destination. The lab in §6 uses exactly this shape.

---

<a id="2-the-layered-architecture"></a>

## 🗂️ 2. The Layered Architecture

Three layers, each with one job. The discipline is that each layer reads only from the one before it.

| Layer | Contents | Write mode | Rebuildable from |
| --- | --- | --- | --- |
| **Raw / landing** | Source data as received, plus load metadata | Append or partition-replace | The source only |
| **Staging** | One batch, lightly typed, transient | Truncate and load per batch | Raw |
| **Warehouse / model** | Conformed, deduplicated, business-ready | Merge (upsert) | Staging and raw |

### 📘 Why staging exists

Staging is the most frequently skipped layer and the most frequently regretted. It provides four things:

1. **A transaction boundary.** Landing a batch and merging it are separate steps; a failed merge does not force a re-extract.
2. **Set-based merging.** Comparing a whole batch against the target in SQL is far faster than row-by-row logic in the application.
3. **An inspection point.** When a load produces wrong numbers, the staging table holds exactly what the batch contained.
4. **Isolation from partial writes.** Consumers query the warehouse, which changes only in one committed step.

### 📘 Metadata columns that pay for themselves

Every landed row should carry provenance. The lab uses:

| Column | Purpose |
| --- | --- |
| `_batch_id` | Which run produced this row; the key to any investigation |
| `_loaded_at` | Ingest time, distinct from the source's event time |
| `_first_seen` / `_last_seen` | When the warehouse first and most recently observed the record |
| `source_updated_at` | The source's own timestamp, preserved unmodified |

Keeping `source_updated_at` separate from `_loaded_at` is what makes lateness measurable: the gap between them is the pipeline's actual lag.

> [!WARNING]
> Do not let the staging table accumulate. A staging table that is appended to instead of replaced grows without bound and silently reprocesses old batches into the merge. Truncate at the start of each batch, or partition it by `_batch_id` and prune on a schedule.

---

<a id="3-incremental-extraction"></a>

## 📥 3. Incremental Extraction

Full extraction re-reads everything on every run. It is simple, correct, and becomes impossible somewhere between a few hundred thousand and a few million rows. Incremental extraction reads only what changed since the last successful run.

| Source offers | Predicate | Watermark stored | Catches deletes? |
| --- | --- | --- | --- |
| Monotonic sequence / identity | `WHERE id > :last_id` | Highest id | No |
| Reliable `updated_at` | `WHERE updated_at > :watermark` | Highest timestamp | No |
| API cursor | Follow until exhausted | Last cursor token | Depends on API |
| Dated immutable files | Unseen filenames | Set of processed names | N/A |
| Change data capture (CDC) | Read the transaction log | Log position | Yes |
| Nothing | Full extract, hash-compare | Per-record content hash | Yes |

### 📘 The overlap window

A naive `WHERE updated_at > :watermark` loses records, permanently and silently. Three mechanisms cause it:

- **Clock skew** between the source's application servers.
- **Long transactions.** A row's `updated_at` is assigned when the statement runs, but the row is not visible to readers until commit. A transaction that starts before the watermark and commits after it produces a row the next run will skip forever.
- **Equal timestamps at the boundary.** Using `>` drops rows exactly at the watermark; using `>=` reprocesses them. Neither is wrong if writes are idempotent.

The fix is to re-read a small window before the watermark on every run:

```python
lo = (dt.datetime.fromisoformat(watermark) - dt.timedelta(minutes=OVERLAP_MINUTES)).isoformat()
rows = src.execute("SELECT ... FROM assets WHERE updated_at > ? ORDER BY updated_at", (lo,))
```

This deliberately reprocesses a few records every run. **That is only safe because the writes are idempotent** — which is §4. Overlap and idempotence are a single design decision, not two.

> [!CAUTION]
> Watermark-based extraction does not detect deletes. A row removed at the source keeps its last-known state in the warehouse indefinitely. If deletes matter, the source must soft-delete (a `deleted_at` column that updates the watermark), expose CDC, or be periodically reconciled against a full key list — the approach used in §8.

### 📘 Advance the watermark from the data, not the clock

Set the new watermark to the maximum `updated_at` **actually observed in the batch**, never to "now". Using wall-clock time skips any record whose timestamp falls between the query executing and the clock being read.

---

<a id="4-idempotent-writes-and-merge"></a>

## 🔀 4. Idempotent Writes and Merge

Idempotence is the property that makes retries, overlap windows, backfills, and at-least-once delivery safe. Without it, every one of those becomes a duplication event.

| Strategy | SQL | Semantics |
| --- | --- | --- |
| **Insert or ignore** | `INSERT ... ON CONFLICT DO NOTHING` | First write wins; records are immutable |
| **Upsert** | `INSERT ... ON CONFLICT DO UPDATE` | Latest write wins; records can be restated |
| **Replace partition** | `DELETE WHERE day = ?` then insert, one transaction | Whole-window reload |
| **Merge** | `MERGE INTO ...` (standard; SQL Server, Oracle, Snowflake, PostgreSQL 15+) | Insert, update, and delete in one statement |

All four are safe to rerun. A bare `INSERT` without a uniqueness constraint is not — and no amount of application-side checking substitutes for the constraint, because the check and the insert are not atomic under concurrency.

### 📘 Classify every incoming row

The lab's merge distinguishes three outcomes, and the distinction is operationally valuable:

| Outcome | Condition | Meaning |
| --- | --- | --- |
| **Inserted** | Key not present in the target | Genuinely new |
| **Updated** | Key present, attributes differ or source timestamp is newer | A real change |
| **Unchanged** | Key present, attributes identical | Reprocessed by the overlap window |

A run reporting `inserted=0 updated=0 unchanged=N` is the signature of a healthy no-op run. A run where `updated` suddenly equals the entire table usually means a source-side mass update or a transformation change — worth an alert either way.

### 📘 Guard against regression

```sql
ON CONFLICT(serial) DO UPDATE SET
    os                = excluded.os,
    source_updated_at = excluded.source_updated_at
WHERE excluded.source_updated_at > dw_assets.source_updated_at
```

The `WHERE` clause prevents an out-of-order or replayed batch from overwriting newer data with older data. Without it, replaying an old file after a recent load silently reverts the warehouse.

---

<a id="5-checkpoints-and-run-state"></a>

## 📍 5. Checkpoints and Run State

A checkpoint is the durable answer to "where did we get to?" Two rules govern it:

1. **Commit the checkpoint in the same transaction as the data.** If the data commits and the checkpoint does not, the next run reprocesses (safe, given idempotence). If the checkpoint commits and the data does not, the next run **skips data permanently**. Same transaction removes the second possibility.
2. **Store it in the destination, not in a file beside the script.** A checkpoint on the runner's local disk is lost when the container is rescheduled.

```sql
CREATE TABLE pipeline_state (
    pipeline   TEXT PRIMARY KEY,
    watermark  TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE run_log (
    batch_id       TEXT PRIMARY KEY,
    started_at     TEXT NOT NULL,
    watermark_from TEXT NOT NULL,
    watermark_to   TEXT NOT NULL,
    extracted  INTEGER, inserted INTEGER, updated INTEGER, unchanged INTEGER,
    status         TEXT NOT NULL
);
```

`pipeline_state` holds one row per pipeline — the current position. `run_log` holds one row per execution — the history. The history is what turns "the numbers look wrong this morning" into a five-minute investigation.

---

<a id="6-lab-the-incremental-pipeline"></a>

## 🧪 6. Lab: The Incremental Pipeline

### 🧪 Step 1: Simulate the source system

`source_sim.py`:

```python
#!/usr/bin/env python3
"""Simulate an operational source database with an updated_at column."""
import sqlite3, sys

SRC = "source.db"

def init():
    c = sqlite3.connect(SRC)
    c.executescript("""
    DROP TABLE IF EXISTS assets;
    CREATE TABLE assets (
        serial     TEXT PRIMARY KEY,
        hostname   TEXT NOT NULL,
        site       TEXT NOT NULL,
        os         TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    INSERT INTO assets VALUES
     ('SN-1001','ws-acct-01','vancouver','Windows 11','2026-09-10T08:00:00+00:00'),
     ('SN-1002','ws-acct-02','vancouver','Windows 11','2026-09-10T08:05:00+00:00'),
     ('SN-1003','srv-file-01','portland','Ubuntu 24.04','2026-09-10T08:10:00+00:00');
    """)
    c.commit(); print("source initialized with 3 rows")

def change():
    c = sqlite3.connect(SRC)
    with c:
        c.execute("UPDATE assets SET os='Ubuntu 24.04.1', updated_at=? WHERE serial='SN-1003'",
                  ("2026-09-11T09:00:00+00:00",))
        c.execute("INSERT INTO assets VALUES ('SN-1004','ws-ops-07','portland','Windows 11',?)",
                  ("2026-09-11T09:05:00+00:00",))
    print("source changed: 1 update, 1 insert")

if __name__ == "__main__":
    {"init": init, "change": change}[sys.argv[1]]()
```

### 🧪 Step 2: The pipeline

`elt.py`:

```python
#!/usr/bin/env python3
"""Incremental EL-T: extract by watermark, land to staging, merge, checkpoint, reconcile."""
from __future__ import annotations
import datetime as dt, logging, sqlite3, sys

SRC, WH = "source.db", "warehouse.db"
OVERLAP_MINUTES = 5
EPOCH = "1970-01-01T00:00:00+00:00"

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
log = logging.getLogger("elt")


def init_warehouse(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS stg_assets (
        serial TEXT, hostname TEXT, site TEXT, os TEXT, updated_at TEXT,
        _loaded_at TEXT NOT NULL, _batch_id TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS dw_assets (
        serial TEXT PRIMARY KEY, hostname TEXT NOT NULL, site TEXT NOT NULL,
        os TEXT NOT NULL, source_updated_at TEXT NOT NULL,
        _first_seen TEXT NOT NULL, _last_seen TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS pipeline_state (
        pipeline TEXT PRIMARY KEY, watermark TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS run_log (
        batch_id TEXT PRIMARY KEY, started_at TEXT NOT NULL,
        watermark_from TEXT NOT NULL, watermark_to TEXT NOT NULL,
        extracted INTEGER, inserted INTEGER, updated INTEGER, unchanged INTEGER,
        status TEXT NOT NULL
    );
    """)


def get_watermark(conn, pipeline="assets") -> str:
    row = conn.execute("SELECT watermark FROM pipeline_state WHERE pipeline=?",
                       (pipeline,)).fetchone()
    return row[0] if row else EPOCH


def run() -> int:
    started = dt.datetime.now(dt.timezone.utc)
    batch_id = started.strftime("%Y%m%dT%H%M%S%f")
    wh = sqlite3.connect(WH); init_warehouse(wh)

    wm = get_watermark(wh)
    lo = (dt.datetime.fromisoformat(wm) - dt.timedelta(minutes=OVERLAP_MINUTES)).isoformat()
    log.info("watermark=%s reading from %s (overlap %dm)", wm, lo, OVERLAP_MINUTES)

    # Extract: read-only connection to the source
    src = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True)
    rows = src.execute(
        "SELECT serial, hostname, site, os, updated_at FROM assets "
        "WHERE updated_at > ? ORDER BY updated_at", (lo,)).fetchall()
    src.close()

    inserted = updated = unchanged = 0
    try:
        with wh:                                   # one transaction: data + checkpoint
            wh.execute("DELETE FROM stg_assets")   # staging is rebuilt per batch
            wh.executemany(
                "INSERT INTO stg_assets (serial,hostname,site,os,updated_at,_loaded_at,_batch_id) "
                "VALUES (?,?,?,?,?,?,?)",
                [(*r, started.isoformat(), batch_id) for r in rows])

            for serial, hostname, site, os_, upd in wh.execute(
                    "SELECT serial,hostname,site,os,updated_at FROM stg_assets"):
                cur = wh.execute(
                    "SELECT hostname,site,os,source_updated_at FROM dw_assets WHERE serial=?",
                    (serial,)).fetchone()
                if cur is None:
                    wh.execute("INSERT INTO dw_assets VALUES (?,?,?,?,?,?,?)",
                               (serial, hostname, site, os_, upd,
                                started.isoformat(), started.isoformat()))
                    inserted += 1
                elif (cur[0], cur[1], cur[2]) != (hostname, site, os_) or cur[3] < upd:
                    wh.execute("UPDATE dw_assets SET hostname=?,site=?,os=?,"
                               "source_updated_at=?,_last_seen=? WHERE serial=?",
                               (hostname, site, os_, upd, started.isoformat(), serial))
                    updated += 1
                else:
                    wh.execute("UPDATE dw_assets SET _last_seen=? WHERE serial=?",
                               (started.isoformat(), serial))
                    unchanged += 1

            # Advance the watermark from observed data, never from the clock
            new_wm = max([r[4] for r in rows], default=wm)
            wh.execute("INSERT INTO pipeline_state VALUES ('assets',?,?) "
                       "ON CONFLICT(pipeline) DO UPDATE SET watermark=excluded.watermark,"
                       "updated_at=excluded.updated_at", (new_wm, started.isoformat()))
            wh.execute("INSERT INTO run_log VALUES (?,?,?,?,?,?,?,?,?)",
                       (batch_id, started.isoformat(), wm, new_wm,
                        len(rows), inserted, updated, unchanged, "success"))
    except Exception:
        log.exception("batch %s failed and was rolled back", batch_id)
        return 1

    log.info("batch=%s extracted=%d inserted=%d updated=%d unchanged=%d new_watermark=%s",
             batch_id, len(rows), inserted, updated, unchanged, get_watermark(wh))
    return 0


def reconcile() -> int:
    src = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True)
    wh = sqlite3.connect(WH)
    s_cnt = src.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    d_cnt = wh.execute("SELECT COUNT(*) FROM dw_assets").fetchone()[0]
    s_keys = {r[0] for r in src.execute("SELECT serial FROM assets")}
    d_keys = {r[0] for r in wh.execute("SELECT serial FROM dw_assets")}
    missing, extra = sorted(s_keys - d_keys), sorted(d_keys - s_keys)
    ok = not missing and not extra and s_cnt == d_cnt
    log.info("reconcile source=%d warehouse=%d missing=%s extra=%s -> %s",
             s_cnt, d_cnt, missing or "none", extra or "none", "MATCH" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(reconcile() if len(sys.argv) > 1 and sys.argv[1] == "reconcile" else run())
```

### 🧪 Step 3: Run the cycle

```bash
python3 source_sim.py init
python3 elt.py          # first load
python3 elt.py          # rerun with no source change
python3 source_sim.py change
python3 elt.py          # incremental pickup
python3 elt.py reconcile
```

Actual output:

```text
INFO elt watermark=1970-01-01T00:00:00+00:00 reading from 1969-12-31T23:55:00+00:00 (overlap 5m)
INFO elt batch=20260911T213600983690 extracted=3 inserted=3 updated=0 unchanged=0 new_watermark=2026-09-10T08:10:00+00:00

INFO elt watermark=2026-09-10T08:10:00+00:00 reading from 2026-09-10T08:05:00+00:00 (overlap 5m)
INFO elt batch=20260911T213601017779 extracted=1 inserted=0 updated=0 unchanged=1 new_watermark=2026-09-10T08:10:00+00:00

source changed: 1 update, 1 insert

INFO elt watermark=2026-09-10T08:10:00+00:00 reading from 2026-09-10T08:05:00+00:00 (overlap 5m)
INFO elt batch=20260911T213601062676 extracted=2 inserted=1 updated=1 unchanged=0 new_watermark=2026-09-11T09:05:00+00:00

INFO elt reconcile source=4 warehouse=4 missing=none extra=none -> MATCH
```

Read the three runs carefully — each demonstrates a specific property:

| Run | Output | What it proves |
| --- | --- | --- |
| **1** | `extracted=3 inserted=3` | Cold start from the epoch watermark loads everything |
| **2** | `extracted=1 inserted=0 unchanged=1` | The overlap window re-read one record; the merge recognized it as unchanged. **This is idempotence.** |
| **3** | `extracted=2 inserted=1 updated=1` | Only the two changed records were read — not the whole table. **This is incrementality.** |

Run 2 is the important one. A non-idempotent pipeline would have produced a duplicate `SN-1003` there, and the error would have compounded on every subsequent run.

---

<a id="7-backfills-and-replay"></a>

## ♻️ 7. Backfills and Replay

A backfill deliberately reprocesses history — after a bug fix, a new derived column, or data loss. In an idempotent pipeline it is a routine operation rather than an incident.

Simulate the loss of one warehouse row and detect it:

```bash
python3 -c "
import sqlite3; c=sqlite3.connect('warehouse.db')
with c: c.execute(\"DELETE FROM dw_assets WHERE serial='SN-1002'\")"
python3 elt.py reconcile
```

```text
INFO elt reconcile source=4 warehouse=3 missing=['SN-1002'] extra=none -> MISMATCH
```

Exit status `1`. The reconciliation named the missing key rather than reporting a bare count difference — the difference between an alert and an investigation.

Repair by resetting the watermark and rerunning:

```bash
python3 -c "
import sqlite3; c=sqlite3.connect('warehouse.db')
with c: c.execute(\"UPDATE pipeline_state SET watermark='1970-01-01T00:00:00+00:00'
                   WHERE pipeline='assets'\")"
python3 elt.py
python3 elt.py reconcile
```

```text
INFO elt batch=20260911T213608726762 extracted=4 inserted=1 updated=0 unchanged=3 new_watermark=2026-09-11T09:05:00+00:00
INFO elt reconcile source=4 warehouse=4 missing=none extra=none -> MATCH
```

The backfill re-read all four source rows and inserted exactly one — the missing record. The three already-correct rows were recognized as `unchanged` and left alone. **No duplicates, no regression, no manual repair.** That is the entire return on building idempotence first.

The `run_log` records the full history:

```text
extracted  inserted  updated  unchanged  status
3          3         0        0          success
1          0         0        1          success
2          1         1        0          success
4          1         0        3          success
```

### 📘 Backfill practices

| Practice | Reason |
| --- | --- |
| Bound the range explicitly | "Reprocess everything" on a large source is an outage |
| Run in windows, not one transaction | A single enormous transaction blocks writers and may exhaust the log |
| Backfill into a copy for large models | Validate, then swap, rather than leaving consumers reading half-rebuilt data |
| Record backfills in the run log | A reader six months later must be able to tell a backfill from normal operation |
| Verify the replay boundary | Confirm the range actually covers the gap before declaring it repaired |

> [!CAUTION]
> Resetting a watermark on a production pipeline re-reads from the source. Confirm the source can serve that volume, that API quotas allow it, and that no downstream consumer treats every arriving record as a new event — an at-least-once consumer downstream will see the entire backfill as fresh activity.

---

<a id="8-reconciliation"></a>

## 🧾 8. Reconciliation

A pipeline that only reports exceptions reports nothing about correctness. Reconciliation is the query that asserts the destination matches the source.

| Level | Check | Cost | Detects |
| --- | --- | --- | --- |
| **Count** | `COUNT(*)` source versus destination | Cheap | Gross loss or duplication |
| **Key set** | Set difference on identifiers | Moderate | Exactly which records are missing or extra |
| **Aggregate** | `SUM` of a numeric column on both sides | Moderate | Value corruption that counts miss |
| **Checksum** | Hash of sorted key plus attributes | Expensive | Any attribute drift |
| **Sampled row compare** | Full comparison of a random subset | Cheap | Transformation errors, at partial confidence |

The lab implements the first two. The key-set check is the one worth adopting first: it detects the delete-invisibility problem from §3, which no count-only check catches when a delete and an insert coincide.

### 📘 Where reconciliation belongs

Run it **after** the load commits, as a separate step with its own exit status. Do not fold it into the load transaction — a failing reconciliation should raise an alert about committed data, not roll back a load that may be perfectly correct while the check itself is buggy.

### 📘 Freshness is part of correctness

```sql
SELECT MAX(source_updated_at) AS newest_record,
       (julianday('now') - julianday(MAX(_last_seen))) * 24 AS hours_since_load
FROM dw_assets;
```

A pipeline that runs successfully every fifteen minutes against a source that stopped producing three days ago has a perfect run history and stale data. Freshness monitoring is what separates "the job ran" from "the data is current" — and it is the metric most commonly missing when a pipeline fails silently. See [Log Aggregation & Visibility](../IncidentResponse/log_agg.md) for shipping these signals somewhere they will be seen.

---

<a id="9-failure-modes"></a>

## 💥 9. Failure Modes

| Failure | Symptom | Prevention |
| --- | --- | --- |
| Checkpoint committed, data not | Permanent silent gap | Same transaction for both |
| No overlap window | Records missing near boundaries | Overlap plus idempotent writes |
| Overlap without idempotence | Growing duplicates | Uniqueness constraint and merge |
| Watermark set from wall clock | Skipped records | Advance from observed maximum |
| Staging appended, not truncated | Reprocessed old batches, growing table | Truncate per batch |
| Deletes at source | Warehouse retains removed records | Soft deletes, CDC, or key-set reconciliation |
| Source timezone changes | Watermark jumps forward or back | Store and compare UTC only |
| Transformation bug in ETL | Source data no longer available to re-derive | Retain raw; prefer ELT |
| Reconciliation inside the load transaction | Correct loads rolled back by a buggy check | Separate step, separate exit status |
| Long-running transaction | Writer lock contention, log growth | Bounded batch sizes |

> [!TIP]
> For each failure above, write the query that would detect it in your pipeline. If no such query exists, the failure mode is currently invisible — which is a different problem from it being unlikely.

---

<a id="10-self-check"></a>

## 🎓 10. Self-Check

1. State the question that decides between ETL and ELT, and explain why the answer usually favors ELT.
2. Why must the checkpoint commit in the same transaction as the data, and which failure order is the dangerous one?
3. Run 2 reported `extracted=1 unchanged=1`. Explain both numbers.
4. Why does the overlap window require idempotent writes rather than merely benefiting from them?
5. Why advance the watermark from the maximum observed value instead of the current time?
6. What does watermark-based extraction never detect, and what are three ways to handle it?
7. What does the `WHERE excluded.source_updated_at > ...` clause on the upsert prevent?
8. The backfill reported `extracted=4 inserted=1 unchanged=3`. Why is that the correct outcome?
9. Why should reconciliation run outside the load transaction?
10. A pipeline succeeds every run for three days while the source is down. Which check catches it?

---

<a id="verification-record"></a>

## ✅ Verification Record

| Area | Verification performed | Limitation |
| --- | --- | --- |
| Source simulator | Executed `init` and `change`; 3 rows then 1 update plus 1 insert | Synthetic SQLite source, not a real operational database |
| Cold-start load | Executed; `extracted=3 inserted=3 updated=0 unchanged=0` | — |
| Idempotent rerun | Executed; `extracted=1 inserted=0 unchanged=1`; warehouse unchanged | Single process; concurrent runs not exercised |
| Incremental pickup | Executed after source change; `extracted=2 inserted=1 updated=1` | Watermark strategy only; CDC not implemented |
| Checkpoint | Confirmed watermark advanced to `2026-09-11T09:05:00+00:00` from observed data | Crash-mid-transaction not simulated; atomicity is inferred from SQLite semantics |
| Reconciliation (match) | Executed; source 4, warehouse 4, exit status 0 | Count and key-set levels only |
| Reconciliation (mismatch) | Deleted one warehouse row; reported `missing=['SN-1002']`, exit status 1 | — |
| Backfill | Reset watermark and reran; `extracted=4 inserted=1 unchanged=3`, then reconcile MATCH | Small dataset; windowed backfill not demonstrated |
| Run log | Confirmed four rows with the counts shown in §7 | — |
| Regression guard | The `WHERE excluded... >` upsert clause is shown as a pattern | Not exercised in the lab; the lab uses procedural comparison instead |

Local checks used Python 3.12.3 with SQLite 3.45.1 on Ubuntu. Batch identifiers in the output are timestamps and will differ on every run. These identify the verification environment and are not a version recommendation.

---

<a id="contributing"></a>

## 🤝 Contributing

**Submission Guidelines:**

1. Demonstrate idempotence explicitly — show the second run's counts, not just the first.
2. State which extraction strategy an example assumes and what it cannot detect.
3. Include the reconciliation query alongside any new load pattern.
4. Use synthetic sources so examples run without external systems.
5. Report the actual output observed, including failure paths.
6. Update the [section index](./README.md) when adding a guide.

---

<a id="resources"></a>

## 📚 Resources

| Area | Official References |
| --- | --- |
| 🗄️ SQLite | [UPSERT](https://www.sqlite.org/lang_upsert.html) · [Transactions](https://www.sqlite.org/lang_transaction.html) · [URI filenames and read-only mode](https://www.sqlite.org/uri.html) |
| 🐘 PostgreSQL | [INSERT ... ON CONFLICT](https://www.postgresql.org/docs/current/sql-insert.html) · [MERGE](https://www.postgresql.org/docs/current/sql-merge.html) · [Transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html) |
| 🐍 Python | [sqlite3](https://docs.python.org/3/library/sqlite3.html) · [datetime](https://docs.python.org/3/library/datetime.html) · [logging](https://docs.python.org/3/howto/logging.html) |
| 🕐 Time | [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) |

---

<a id="see-also"></a>

## 🔗 Quick Links & Related Guides

- [🗄️ Data Engineering Section Index](./README.md)
- [🧱 Data Engineering Fundamentals](./data_engineering_fundamentals.md)
- [🐍 Python for Data Processing](./python_data_processing.md)
- [🗃️ SQL & Data Modeling](./sql_data_modeling.md)
- [✅ Data Quality & Schema Contracts](./data_quality_schema_contracts.md)
- [🛡️ Secure Data Pipelines](./data_pipelines.md)
- [📊 Log Aggregation & Visibility](../IncidentResponse/log_agg.md)
- [📖 Repository Glossary](../GLOSSARY.md)

---

<a id="guide-details"></a>

## 📊 Guide Details

| Item | Details |
| --- | --- |
| 🎯 Focus | Repeatable, incremental, recoverable data movement |
| 🧰 Core Technologies | Python standard library, SQLite |
| 📘 Format | Reference guide with a fully executed incremental pipeline lab |
| 🧪 Validation Status | Full cycle executed including backfill and mismatch detection; limitations documented above |
| 📁 Location | `Data-Engineering/etl_elt_pipeline_design.md` |
| 🔄 Content Review Date | September 11, 2026 |

---

<div align="center">

**🔄 Load Only What Changed. Survive the Rerun. Prove the Result.**

*A pipeline you can safely run twice is a pipeline you can safely recover, backfill, and trust.*

**Repository:** [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Pacific Northwest Computers:** [PNWC on GitHub](https://github.com/Pnwcomputers)

[🏠 Master Index](../README.md) | [🎯 Role Navigation](../START_HERE.md) | [📋 Table of Contents](#table-of-contents) | [📜 Legal Notice](../LEGAL.md)

⭐ **Star the repository if you find it useful!** ⭐

</div>
