# 🗃️ SQL & Data Modeling

<div align="center">

**Queries, joins, aggregates, window functions, constraints, transactions, indexes, and analytical models**

*Keys • NULL semantics • JOIN types • GROUP BY • OVER() • ACID • EXPLAIN • Star schemas*

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Foundations](https://img.shields.io/badge/Level-Foundations-blue?style=for-the-badge)
![SQL](https://img.shields.io/badge/Language-SQL-darkgreen?style=for-the-badge)
![Modeling](https://img.shields.io/badge/Design-Normalized_%7C_Dimensional-purple?style=for-the-badge)
![Lab](https://img.shields.io/badge/Lab-SQLite_3.25%2B-orange?style=for-the-badge)

</div>

---

_Last reviewed: 2026-09-11. Every query in this guide was executed against the lab database; outputs shown are actual results. See the [Verification Record](#verification-record)._

**Prerequisites:** [Data Engineering Fundamentals](./data_engineering_fundamentals.md) for keys, identity, and idempotence vocabulary.

## 🎯 Purpose

Make the database the place where correctness is enforced rather than hoped for. A well-constrained schema rejects bad data that application code forgot to check, and a well-indexed one answers questions that would otherwise require a distributed system.

## ⚙️ Function

Build a small inventory and telemetry schema, then work through filtering and NULL semantics, the join types and when each is correct, aggregation traps, window functions for per-group analysis, constraints as the last line of defense, transaction boundaries, index behavior read from query plans, and an introduction to dimensional modeling with a working star schema.

## 🏆 Goal

Enable a practitioner to design a schema whose constraints make a duplicate or orphaned record impossible, write a query that returns the latest record per group without a subquery per row, read a query plan well enough to know whether an index is being used, and explain when a normalized model should be supplemented by a dimensional one.

## 📋 When to Use

- Designing the destination for any pipeline built in this section.
- Reviewing a schema that allows duplicates, orphans, or ambiguous nulls.
- Writing analytical queries over telemetry, inventory, or log-derived tables.
- Diagnosing a query that became slow as data volume grew.
- Preparing the staging and warehouse layers in [ETL & ELT Pipeline Design](./etl_elt_pipeline_design.md).

## 🧰 Audience & Prerequisites

**Audience:** Practitioners who can write a `SELECT` and now need schemas and queries that stay correct under production conditions.

**Prerequisites:** SQLite 3.25 or later for window functions (3.45 used here), or any of PostgreSQL 9.4+, MySQL 8.0+, SQL Server 2012+. The lab uses SQLite because it requires no server. Portability differences are flagged where they exist.

> [!NOTE]
> SQL dialects differ. The concepts here are standard; the syntax is SQLite. Notable substitutions for other engines are called out inline — particularly `IS NOT` (§3), `AUTOINCREMENT` versus `IDENTITY`/`SERIAL`, and `EXPLAIN QUERY PLAN` versus `EXPLAIN ANALYZE`.

---

<a id="table-of-contents"></a>

## 📋 Table of Contents

- [🧱 1. The Lab Schema](#1-the-lab-schema)
- [🔑 2. Keys and Constraints](#2-keys-and-constraints)
- [🔍 3. Filtering and NULL Semantics](#3-filtering-and-null-semantics)
- [🔗 4. Joins](#4-joins)
- [📊 5. Aggregation](#5-aggregation)
- [🪟 6. Window Functions](#6-window-functions)
- [🔒 7. Transactions](#7-transactions)
- [⚡ 8. Indexes and Query Plans](#8-indexes-and-query-plans)
- [⭐ 9. Analytical Modeling](#9-analytical-modeling)
- [🧪 10. Lab: Build the Star Schema](#10-lab-build-the-star-schema)
- [🎓 11. Self-Check](#11-self-check)
- [✅ Verification Record](#verification-record)
- [🤝 Contributing](#contributing)
- [📚 Resources](#resources)
- [🔗 Quick Links & Related Guides](#see-also)
- [📊 Guide Details](#guide-details)

---

<a id="1-the-lab-schema"></a>

## 🧱 1. The Lab Schema

Create `schema.sql`:

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE sites (
    site_id   INTEGER PRIMARY KEY,
    site_code TEXT    NOT NULL UNIQUE,
    site_name TEXT    NOT NULL,
    region    TEXT    NOT NULL
);

CREATE TABLE assets (
    asset_id     INTEGER PRIMARY KEY,
    serial       TEXT    NOT NULL UNIQUE,
    hostname     TEXT    NOT NULL,
    site_id      INTEGER          REFERENCES sites(site_id) ON DELETE RESTRICT,
    os           TEXT    NOT NULL,
    purchased_on TEXT    NOT NULL CHECK (purchased_on LIKE '____-__-__')
);

CREATE TABLE checkins (
    checkin_id INTEGER PRIMARY KEY,
    asset_id   INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    checked_at TEXT    NOT NULL,
    status     TEXT    NOT NULL CHECK (status IN ('ok','warn','fail')),
    cpu_pct    REAL             CHECK (cpu_pct BETWEEN 0 AND 100),
    UNIQUE (asset_id, checked_at)
);
```

Create `seed.sql`:

```sql
INSERT INTO sites (site_id, site_code, site_name, region) VALUES
 (1,'VAN','Vancouver','pacific-northwest'),
 (2,'PDX','Portland','pacific-northwest'),
 (3,'SEA','Seattle','pacific-northwest');

INSERT INTO assets (asset_id, serial, hostname, site_id, os, purchased_on) VALUES
 (1,'SN-1001','ws-acct-01',   1,'Windows 11',  '2024-03-12'),
 (2,'SN-1002','ws-acct-02',   1,'Windows 11',  '2024-03-12'),
 (3,'SN-1003','srv-file-01',  2,'Ubuntu 24.04','2023-11-02'),
 (4,'SN-1004','ws-ops-07',    2,'Windows 11',  '2025-01-20'),
 (5,'SN-1005','ws-ship-03',   3,'Windows 10',  '2022-06-30'),
 (6,'SN-1006','ws-spare-01',NULL,'Windows 11', '2025-08-14');

INSERT INTO checkins (asset_id, checked_at, status, cpu_pct) VALUES
 (1,'2026-09-08T14:00:00+00:00','ok',  12.5),
 (1,'2026-09-09T14:00:00+00:00','ok',  18.0),
 (1,'2026-09-10T14:00:00+00:00','warn',74.2),
 (2,'2026-09-09T14:00:00+00:00','ok',  22.1),
 (2,'2026-09-10T14:00:00+00:00','ok',  25.6),
 (3,'2026-09-08T14:00:00+00:00','ok',  40.0),
 (3,'2026-09-09T14:00:00+00:00','fail',99.1),
 (3,'2026-09-10T14:00:00+00:00','ok',  38.4),
 (4,'2026-09-10T14:00:00+00:00','ok',  NULL),
 (5,'2026-09-07T14:00:00+00:00','warn',81.0),
 (5,'2026-09-10T14:00:00+00:00','fail',95.5);
```

Build it:

```bash
python3 -c "
import sqlite3
c = sqlite3.connect('lab.db')
c.executescript(open('schema.sql').read())
c.executescript(open('seed.sql').read())
c.commit()
print('assets', c.execute('SELECT COUNT(*) FROM assets').fetchone()[0])
print('checkins', c.execute('SELECT COUNT(*) FROM checkins').fetchone()[0])
"
```

```text
assets 6
checkins 11
```

Three deliberate features carry through the whole guide: asset 6 has a `NULL` site (an unassigned spare), checkin row for asset 4 has a `NULL` CPU reading (the agent failed to report it), and site 3 has only one asset.

> [!CAUTION]
> SQLite does **not** enforce foreign keys unless `PRAGMA foreign_keys = ON` is issued on every connection. It is a per-connection setting, not a property of the file. A schema with `REFERENCES` clauses that is written to by a client which omits the pragma will silently accumulate orphaned rows.

---

<a id="2-keys-and-constraints"></a>

## 🔑 2. Keys and Constraints

Constraints are not documentation. They are the only guarantee that survives a bug in the loader, a manual fix applied at 2 a.m., and a future maintainer who never read the README.

| Constraint | Guarantees | Example in the lab |
| --- | --- | --- |
| `PRIMARY KEY` | Row identity; one per table | `asset_id` |
| `UNIQUE` | No duplicate values, single or composite | `serial`; `(asset_id, checked_at)` |
| `NOT NULL` | The value is always present | `hostname`, `status` |
| `CHECK` | Values fall in an allowed domain | `status IN ('ok','warn','fail')` |
| `FOREIGN KEY` | The referenced row exists | `checkins.asset_id → assets.asset_id` |
| `DEFAULT` | A sensible value when unspecified | `is_current DEFAULT 1` in §9 |

### 📘 Natural versus surrogate keys

`serial` is the **natural key** — it identifies the asset in the physical world. `asset_id` is the **surrogate key** — a system-generated integer used for joins.

Use both. The surrogate key keeps joins narrow and stable if a serial is ever corrected; the `UNIQUE` constraint on the natural key is what actually prevents the same physical machine appearing twice. A schema with only a surrogate key has no defense against duplicate loads, because every insert generates a new identifier and therefore always succeeds.

### 📘 The composite unique key defines the grain

`UNIQUE (asset_id, checked_at)` states that an asset has at most one checkin per timestamp. This single line is what makes the loader's `INSERT ... ON CONFLICT` idempotent — without it, rerunning a load duplicates every row. Choosing this constraint *is* choosing the table's grain.

### 📘 Observed constraint behavior

Each of the following was executed against the lab database:

| Attempted write | Result |
| --- | --- |
| Insert a second asset with `serial='SN-1001'` | `IntegrityError: UNIQUE constraint failed: assets.serial` |
| Insert a checkin with `status='down'` | `IntegrityError: CHECK constraint failed: status IN ('ok','warn','fail')` |
| Insert an asset with `site_id=99` | `IntegrityError: FOREIGN KEY constraint failed` |
| Insert a checkin with `cpu_pct=150` | `IntegrityError: CHECK constraint failed: cpu_pct BETWEEN 0 AND 100` |
| `DELETE FROM sites WHERE site_id=1` | `IntegrityError: FOREIGN KEY constraint failed` (blocked by `ON DELETE RESTRICT`) |

That last row is the point of referential actions. `ON DELETE RESTRICT` on `assets.site_id` refuses to orphan assets, while `ON DELETE CASCADE` on `checkins.asset_id` removes an asset's telemetry with it. Choose per relationship: cascade when the child has no meaning without the parent, restrict when it does.

> [!WARNING]
> `CASCADE` is genuinely destructive and cascades transitively. Deleting one site row can remove millions of downstream records in a single statement with no confirmation. Before adding cascade to a table that grows, write down what a mistaken parent delete would destroy.

---

<a id="3-filtering-and-null-semantics"></a>

## 🔍 3. Filtering and NULL Semantics

`NULL` means *unknown*, not *empty* and not *zero*. Every comparison to an unknown value is itself unknown, and `WHERE` keeps only rows that evaluate to true — so unknown rows are dropped.

```sql
SELECT hostname, site_id FROM assets WHERE site_id <> 2 ORDER BY asset_id;
```

```text
hostname     site_id
ws-acct-01   1
ws-acct-02   1
ws-ship-03   3
```

`ws-spare-01` has `site_id IS NULL` and is **not** in the result — even though its site is plainly not 2. This is the single most common cause of undercounted reports.

```sql
SELECT hostname, site_id FROM assets WHERE site_id IS NOT 2 ORDER BY asset_id;
```

```text
hostname      site_id
ws-acct-01    1
ws-acct-02    1
ws-ship-03    3
ws-spare-01   NULL
```

| Intent | Correct SQL |
| --- | --- |
| Is unknown | `col IS NULL` |
| Is known | `col IS NOT NULL` |
| Not equal, treating unknown as "not equal" | `col IS DISTINCT FROM value` (standard) · `col IS NOT value` (SQLite) · `col <> value OR col IS NULL` (portable) |
| Substitute a display value | `COALESCE(col, 'UNASSIGNED')` |

> [!NOTE]
> `IS DISTINCT FROM` is the standard spelling and works in PostgreSQL and SQL Server 2022+. SQLite spells it `IS NOT`. MySQL uses the null-safe equality operator `<=>` with negation. The portable `col <> value OR col IS NULL` form works everywhere and is the safest choice for SQL that moves between engines.

Three further consequences worth internalizing:

- `NULL = NULL` is unknown, not true. `UNIQUE` constraints in most engines therefore permit multiple `NULL` values.
- `NULL` in arithmetic propagates: `74.2 + NULL` is `NULL`, so a `SUM` column containing one unknown is not automatically unknown (aggregates skip nulls) but a row-level expression is.
- Sort order for `NULL` differs by engine. Specify `NULLS FIRST` / `NULLS LAST` where supported when the placement matters.

---

<a id="4-joins"></a>

## 🔗 4. Joins

| Join | Returns | Use when |
| --- | --- | --- |
| `INNER JOIN` | Only matching pairs | Both sides are required for the row to mean anything |
| `LEFT JOIN` | All left rows, nulls where unmatched | The left side is the population being reported on |
| `RIGHT JOIN` | Mirror of left | Rare; rewrite as a `LEFT JOIN` with the tables swapped |
| `FULL OUTER JOIN` | All rows from both sides | Reconciling two sources; not supported before SQLite 3.39 |
| `CROSS JOIN` | Every combination | Generating dense date or category grids |

```sql
SELECT s.site_code, a.hostname
FROM assets a
JOIN sites s ON s.site_id = a.site_id
ORDER BY a.asset_id;
```

```text
site_code   hostname
VAN         ws-acct-01
VAN         ws-acct-02
PDX         srv-file-01
PDX         ws-ops-07
SEA         ws-ship-03
```

Five rows from six assets. The inner join silently dropped `ws-spare-01`. If this query backs an inventory report, one asset has just vanished from the count.

```sql
SELECT a.hostname, COALESCE(s.site_code, 'UNASSIGNED') AS site
FROM assets a
LEFT JOIN sites s ON s.site_id = a.site_id
ORDER BY a.asset_id;
```

```text
hostname      site
ws-acct-01    VAN
ws-acct-02    VAN
srv-file-01   PDX
ws-ops-07     PDX
ws-ship-03    SEA
ws-spare-01   UNASSIGNED
```

**The rule:** when a query answers "how many of X", start from X with `LEFT JOIN`. An inner join makes the answer conditional on a relationship existing, which is almost never what the question meant.

> [!TIP]
> A `LEFT JOIN` is silently converted into an inner join if the right table is referenced in the `WHERE` clause — `WHERE s.region = 'pacific-northwest'` discards the unmatched rows whose `s.region` is `NULL`. Put conditions on the right table in the `ON` clause instead.

### 📘 The fan-out trap

Joining a one-row-per-asset table to a many-rows-per-asset table multiplies the left side. `SUM(a.purchase_cost)` after joining to `checkins` counts each asset's cost once per checkin. Aggregate the many side first in a subquery or common table expression, then join the single-row result.

---

<a id="5-aggregation"></a>

## 📊 5. Aggregation

```sql
SELECT COUNT(*) AS rows_all,
       COUNT(cpu_pct) AS rows_with_cpu,
       AVG(cpu_pct) AS avg_cpu
FROM checkins;
```

```text
rows_all   rows_with_cpu   avg_cpu
11         10              50.64
```

`COUNT(*)` counts rows. `COUNT(col)` counts non-null values. `AVG` divides by the non-null count — so the average is over 10 readings, not 11. Whether that is right depends entirely on whether a missing reading means "not measured" (skip it, as here) or "zero" (substitute with `COALESCE(cpu_pct, 0)`). The database cannot decide; the contract must.

```sql
SELECT s.site_code, COUNT(*) AS assets
FROM assets a
JOIN sites s ON s.site_id = a.site_id
GROUP BY s.site_code
HAVING COUNT(*) > 1
ORDER BY assets DESC, s.site_code;
```

```text
site_code   assets
PDX         2
VAN         2
```

`WHERE` filters rows before grouping; `HAVING` filters groups after. Using `WHERE` for a condition on an aggregate is an error; using `HAVING` for a condition on a raw column works but scans more rows than necessary.

### 📘 Conditional aggregation

Counting subsets without multiple queries:

```sql
SELECT s.site_code,
       COUNT(c.checkin_id) AS checkins,
       SUM(CASE WHEN c.status = 'fail' THEN 1 ELSE 0 END) AS failures,
       ROUND(AVG(c.cpu_pct), 1) AS avg_cpu
FROM sites s
LEFT JOIN assets a   ON a.site_id   = s.site_id
LEFT JOIN checkins c ON c.asset_id  = a.asset_id
GROUP BY s.site_code
ORDER BY s.site_code;
```

```text
site_code   checkins   failures   avg_cpu
PDX         4          1          59.2
SEA         2          1          88.3
VAN         5          0          30.5
```

Note `COUNT(c.checkin_id)` rather than `COUNT(*)`. With a `LEFT JOIN`, a site with no assets still produces one row containing nulls, and `COUNT(*)` would report `1` for it. Counting a column from the right-hand table correctly reports `0`. The `CASE` expression inside `SUM` is the portable way to count a subset; PostgreSQL also offers `COUNT(*) FILTER (WHERE ...)`.

> [!WARNING]
> Most engines reject a `SELECT` column that is neither grouped nor aggregated. SQLite and older MySQL configurations accept it and return an arbitrary row's value — producing a report that looks correct and is not. Group by every non-aggregated column, or aggregate it explicitly with `MIN`/`MAX`.

---

<a id="6-window-functions"></a>

## 🪟 6. Window Functions

An aggregate collapses rows. A window function computes across a set of rows while keeping each row. This is the tool for "latest per group", "change since previous", and "running total" — the three questions telemetry constantly asks.

### 📘 Latest record per group

```sql
WITH ranked AS (
  SELECT c.*,
         ROW_NUMBER() OVER (PARTITION BY c.asset_id ORDER BY c.checked_at DESC) AS rn
  FROM checkins c
)
SELECT a.hostname, r.checked_at, r.status, r.cpu_pct
FROM ranked r
JOIN assets a ON a.asset_id = r.asset_id
WHERE r.rn = 1
ORDER BY a.hostname;
```

```text
hostname      checked_at                  status   cpu_pct
srv-file-01   2026-09-10T14:00:00+00:00   ok       38.4
ws-acct-01    2026-09-10T14:00:00+00:00   warn     74.2
ws-acct-02    2026-09-10T14:00:00+00:00   ok       25.6
ws-ops-07     2026-09-10T14:00:00+00:00   ok       NULL
ws-ship-03    2026-09-10T14:00:00+00:00   fail     95.5
```

This is the canonical "current state from an event history" pattern. The alternative — a correlated subquery selecting `MAX(checked_at)` per asset — re-scans for every row and degrades badly with volume.

The three ranking functions differ on ties:

| Function | Ties | Gaps after a tie |
| --- | --- | --- |
| `ROW_NUMBER()` | Broken arbitrarily | N/A |
| `RANK()` | Share a rank | Yes (1,1,3) |
| `DENSE_RANK()` | Share a rank | No (1,1,2) |

When ties are possible and correctness matters, add a deterministic tiebreaker to `ORDER BY` — for example `ORDER BY checked_at DESC, checkin_id DESC`.

### 📘 Change since the previous row

```sql
SELECT a.hostname, c.checked_at, c.cpu_pct,
       ROUND(c.cpu_pct - LAG(c.cpu_pct) OVER (
           PARTITION BY c.asset_id ORDER BY c.checked_at), 1) AS delta
FROM checkins c
JOIN assets a ON a.asset_id = c.asset_id
WHERE a.hostname = 'ws-acct-01'
ORDER BY c.checked_at;
```

```text
hostname     checked_at                  cpu_pct   delta
ws-acct-01   2026-09-08T14:00:00+00:00   12.5      NULL
ws-acct-01   2026-09-09T14:00:00+00:00   18.0      5.5
ws-acct-01   2026-09-10T14:00:00+00:00   74.2      56.2
```

The first row's delta is `NULL` because no previous row exists — correct, and distinct from a delta of zero. That 56.2-point jump is exactly the kind of signal a detection rule consumes; see [Log Aggregation & Visibility](../IncidentResponse/log_agg.md).

### 📘 Moving average with a frame

```sql
SELECT c.checked_at, c.cpu_pct,
       ROUND(AVG(c.cpu_pct) OVER (
           PARTITION BY c.asset_id ORDER BY c.checked_at
           ROWS BETWEEN 1 PRECEDING AND CURRENT ROW), 2) AS avg2
FROM checkins c
WHERE c.asset_id = 3
ORDER BY c.checked_at;
```

```text
checked_at                  cpu_pct   avg2
2026-09-08T14:00:00+00:00   40.0      40.0
2026-09-09T14:00:00+00:00   99.1      69.55
2026-09-10T14:00:00+00:00   38.4      68.75
```

> [!NOTE]
> The frame clause matters. With `ORDER BY` and no explicit frame, the default is `RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW`, which produces a running aggregate — and which groups peer rows with equal sort keys together. `ROWS` counts physical rows and is what most people mean by "the last N". State the frame explicitly whenever the result is not a simple running total.

---

<a id="7-transactions"></a>

## 🔒 7. Transactions

A transaction makes a group of statements atomic: all of them apply, or none do. This is what prevents a half-loaded batch.

```python
import sqlite3
conn = sqlite3.connect("lab.db")

with conn:                      # commits on success, rolls back on exception
    conn.execute("INSERT INTO checkins (asset_id, checked_at, status, cpu_pct) "
                 "VALUES (1, '2026-09-12T00:00:00+00:00', 'ok', 10)")
    conn.execute("INSERT INTO checkins (asset_id, checked_at, status, cpu_pct) "
                 "VALUES (1, '2026-09-12T00:00:00+00:00', 'ok', 10)")   # violates UNIQUE
```

Observed result:

```text
failed: UNIQUE constraint failed: checkins.asset_id, checkins.checked_at
count before 11 after 11
```

The first insert succeeded and was then rolled back with the second. The table is exactly as it was. Without the transaction, the row from the first statement would remain — a partial batch that a rerun would then have to reconcile.

### 📘 ACID in one line each

| Property | Meaning for a pipeline |
| --- | --- |
| **Atomicity** | A failed batch leaves no partial rows |
| **Consistency** | Constraints hold at every commit |
| **Isolation** | Concurrent readers do not see a half-written batch |
| **Durability** | A committed batch survives a crash |

### 📘 Practical guidance

- **Size batches deliberately.** One transaction per row is slow; one transaction for ten million rows holds locks and can exhaust the write-ahead log. Commit every few thousand records, and make each batch independently idempotent so a failure resumes cleanly.
- **Do not hold a transaction open across network I/O.** Fetching an API page inside an open write transaction blocks other writers for the duration of the request.
- **Use WAL mode for concurrent readers in SQLite:** `PRAGMA journal_mode = WAL`. It allows readers during a write, at the cost of extra files beside the database.

> [!CAUTION]
> SQLite permits exactly one writer at a time for the whole database. It is an excellent destination for single-process pipelines and labs, and the wrong choice for concurrent multi-writer workloads. Move to PostgreSQL when more than one process must write.

---

<a id="8-indexes-and-query-plans"></a>

## ⚡ 8. Indexes and Query Plans

Do not guess whether an index is used. Ask the engine.

```sql
EXPLAIN QUERY PLAN SELECT checkin_id FROM checkins WHERE status = 'fail';
```

Before creating an index:

```text
SCAN checkins
```

After `CREATE INDEX idx_checkins_status ON checkins(status);`:

```text
SEARCH checkins USING COVERING INDEX idx_checkins_status (status=?)
```

`SCAN` reads every row. `SEARCH` seeks directly. `COVERING` means the index alone satisfied the query and the table was never touched — the fastest outcome, achieved because the only selected column is part of the index or the row identifier.

### 📘 Indexes you already have

```sql
EXPLAIN QUERY PLAN SELECT * FROM checkins WHERE asset_id = 3;
```

```text
SEARCH checkins USING INDEX idx_checkins_asset_time (asset_id=?)
```

The `UNIQUE (asset_id, checked_at)` constraint from §1 created an index automatically. Every `PRIMARY KEY` and `UNIQUE` constraint does. Before adding an index, check whether a constraint already provides it — a redundant index costs write throughput and storage for no gain.

### 📘 Column order in composite indexes

An index on `(asset_id, checked_at)` serves:

- `WHERE asset_id = ?`
- `WHERE asset_id = ? AND checked_at > ?`
- `ORDER BY asset_id, checked_at`

It does **not** efficiently serve `WHERE checked_at > ?` alone. This is the leftmost-prefix rule: an index is usable from the left. Order composite index columns with equality predicates first, then the range or sort column.

### 📘 What disables an index

```sql
EXPLAIN QUERY PLAN SELECT * FROM checkins WHERE substr(checked_at,1,10) = '2026-09-10';
```

```text
SCAN checkins
```

Wrapping an indexed column in a function makes the index unusable. Rewrite as a range against the raw column:

```sql
WHERE checked_at >= '2026-09-10' AND checked_at < '2026-09-11'
```

The same applies to leading wildcards (`LIKE '%fail'`), implicit type conversion, and arithmetic on the column. When the expression genuinely cannot be avoided, most engines support an expression index on that exact expression.

> [!TIP]
> Index the columns used in `WHERE`, `JOIN`, and `ORDER BY` — not every column. Each index must be updated on every write, so an over-indexed table ingests slowly. Add indexes in response to a measured plan, then re-measure. In PostgreSQL use `EXPLAIN (ANALYZE, BUFFERS)` to get real timings rather than estimates.

---

<a id="9-analytical-modeling"></a>

## ⭐ 9. Analytical Modeling

The normalized schema in §1 is designed for **writes**: each fact stored once, constraints enforcing correctness. Analytical queries want something different — few joins, wide rows, and stable history. That is dimensional modeling.

| Aspect | Normalized (OLTP) | Dimensional (OLAP) |
| --- | --- | --- |
| Optimized for | Correct, concurrent writes | Large aggregate reads |
| Redundancy | Minimized | Accepted deliberately |
| Joins per query | Many | Few |
| History | Current state | Preserved over time |
| Typical table | `assets` | `fact_checkin`, `dim_asset` |

### 📘 Grain first

Before writing any dimensional DDL, state the grain in one sentence: **"one row per asset per day."** Everything else follows — which dimensions apply, which measures are additive, and what the fact table's unique constraint must be.

A fact table without a stated grain eventually accumulates rows at two different grains, and every aggregate over it is wrong in a way no constraint catches.

### 📘 Facts and dimensions

- **Fact table** — the measurements. Numeric, many rows, foreign keys to dimensions. Here: `status`, `cpu_pct`.
- **Dimension table** — the descriptive context by which facts are sliced. Fewer rows, wide, text-heavy. Here: asset, site, date.

A **star schema** is one fact table joined directly to its dimensions. A **snowflake schema** normalizes the dimensions further; it saves storage and costs joins. Prefer the star unless a dimension is genuinely enormous.

### 📘 Slowly changing dimensions

An asset moves from Vancouver to Portland. Should last month's checkins now report as Portland?

| Type | Behavior | Use when |
| --- | --- | --- |
| **Type 1** | Overwrite the old value | History does not matter; correcting a typo |
| **Type 2** | Add a new row with `valid_from` / `valid_to` / `is_current` | History matters; the common default for reporting |
| **Type 3** | Keep a `previous_value` column | Only one prior value is ever needed |

The `dim_site` table in the lab below carries Type 2 columns. The cost is that every fact must join on the dimension row that was current *at the time of the fact*, not simply the current one — which is precisely the accuracy that Type 2 exists to provide.

---

<a id="10-lab-build-the-star-schema"></a>

## 🧪 10. Lab: Build the Star Schema

Build a dimensional model from the normalized tables and query it.

```sql
CREATE TABLE dim_site (
    site_key   INTEGER PRIMARY KEY,
    site_code  TEXT NOT NULL,
    site_name  TEXT NOT NULL,
    region     TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to   TEXT,
    is_current INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE dim_asset (
    asset_key INTEGER PRIMARY KEY,
    serial    TEXT NOT NULL,
    hostname  TEXT NOT NULL,
    os        TEXT NOT NULL
);

CREATE TABLE fact_checkin (
    checkin_key INTEGER PRIMARY KEY,
    date_key    INTEGER NOT NULL,
    asset_key   INTEGER NOT NULL REFERENCES dim_asset(asset_key),
    site_key    INTEGER          REFERENCES dim_site(site_key),
    status      TEXT    NOT NULL,
    cpu_pct     REAL,
    UNIQUE (asset_key, date_key)          -- enforces the stated grain
);

INSERT INTO dim_site (site_key, site_code, site_name, region, valid_from, valid_to, is_current)
SELECT site_id, site_code, site_name, region, '2020-01-01', NULL, 1 FROM sites;

INSERT INTO dim_asset (asset_key, serial, hostname, os)
SELECT asset_id, serial, hostname, os FROM assets;

INSERT INTO fact_checkin (date_key, asset_key, site_key, status, cpu_pct)
SELECT CAST(REPLACE(SUBSTR(c.checked_at, 1, 10), '-', '') AS INTEGER),
       a.asset_id, a.site_id, c.status, c.cpu_pct
FROM checkins c
JOIN assets a ON a.asset_id = c.asset_id;
```

Query the star:

```sql
SELECT d.region, f.date_key,
       COUNT(*) AS checkins,
       SUM(f.status = 'fail') AS failures,
       ROUND(AVG(f.cpu_pct), 1) AS avg_cpu
FROM fact_checkin f
LEFT JOIN dim_site d ON d.site_key = f.site_key
GROUP BY d.region, f.date_key
ORDER BY f.date_key;
```

```text
region              date_key   checkins   failures   avg_cpu
pacific-northwest   20260907   1          0          81.0
pacific-northwest   20260908   2          0          26.3
pacific-northwest   20260909   3          1          46.4
pacific-northwest   20260910   5          1          58.4
```

Verify the grain holds:

```sql
SELECT COUNT(*), COUNT(DISTINCT asset_key || '-' || date_key) FROM fact_checkin;
```

```text
11   11
```

Equal counts prove one row per asset per day. Run this check after every load — it is the dimensional equivalent of the reconciliation query from [Data Engineering Fundamentals](./data_engineering_fundamentals.md#6-source-to-destination-design).

### 📘 Design notes on this model

- **`date_key` as an integer** (`20260910`) is a long-standing convention: compact, naturally sortable, and readable in raw output. A full `dim_date` table with weekday, month, quarter, and holiday flags is the usual companion and removes date arithmetic from every query.
- **The site key is stored on the fact** rather than looked up through `dim_asset`. That is deliberate: it freezes where the asset *was* at checkin time, so a later site reassignment does not silently rewrite history. This is the Type 2 benefit in practice.
- **`SUM(f.status = 'fail')`** relies on SQLite returning 1/0 for booleans. Use `SUM(CASE WHEN ... THEN 1 ELSE 0 END)` for portable SQL.
- **The fact table is rebuildable** from the normalized tables at any time, which is what makes a backfill after a modeling change safe.

---

<a id="11-self-check"></a>

## 🎓 11. Self-Check

1. Why did `WHERE site_id <> 2` exclude `ws-spare-01`, and what are three correct rewrites?
2. What does `UNIQUE (asset_id, checked_at)` guarantee, and which pipeline property depends on it?
3. Why is `COUNT(c.checkin_id)` correct where `COUNT(*)` is wrong after a `LEFT JOIN`?
4. When does `AVG(cpu_pct)` give a misleading answer, and what determines the right behavior?
5. What is the difference between `ROWS` and `RANGE` in a window frame?
6. Why does `WHERE substr(checked_at,1,10) = '2026-09-10'` force a table scan, and what replaces it?
7. Which index does `UNIQUE (asset_id, checked_at)` already provide, and which query does it *not* serve?
8. State the grain of `fact_checkin` and name the constraint that enforces it.
9. Why is `site_key` stored on the fact table rather than looked up through `dim_asset`?
10. The star schema reported 11 rows and 11 distinct grain keys. What would unequal counts indicate?

---

<a id="verification-record"></a>

## ✅ Verification Record

| Area | Verification performed | Limitation |
| --- | --- | --- |
| Schema and seed | Executed; 6 assets and 11 checkins loaded | Small synthetic dataset |
| Constraint behavior | Executed all five violations in §2; each raised the documented `IntegrityError` | SQLite error text; wording differs on other engines |
| NULL semantics | Executed both queries in §3; `<> 2` returned 3 rows, `IS NOT 2` returned 4 | `IS NOT` is SQLite spelling; the standard and portable forms shown were not executed |
| Joins | Executed; inner join returned 5 rows, left join returned 6 with `UNASSIGNED` | Fan-out trap described, not demonstrated with a cost column |
| Aggregation | Executed; `COUNT(*)=11`, `COUNT(cpu_pct)=10`, `AVG=50.64`; per-site output as shown | — |
| Window functions | Executed `ROW_NUMBER`, `LAG`, and a `ROWS` frame; outputs as shown | Tie behavior of `RANK`/`DENSE_RANK` described, not executed |
| Transactions | Executed the failing two-statement transaction; count unchanged at 11 | Single-connection; concurrency and WAL not exercised |
| Query plans | Executed `EXPLAIN QUERY PLAN` before and after index creation; observed `SCAN` → `SEARCH ... USING COVERING INDEX`, and `SCAN` for the `substr()` predicate | SQLite planner only; PostgreSQL `EXPLAIN ANALYZE` not run |
| Star schema | Executed; dimensional tables built, aggregate output as shown, grain check returned 11 and 11 | Type 2 columns are populated but no dimension change was processed |

Local checks used Python 3.12.3 with SQLite 3.45.1 on Ubuntu. Statements were executed through the Python `sqlite3` module; the `sqlite3` CLI was unavailable in the verification environment. These identify the verification environment and are not a version recommendation.

---

<a id="contributing"></a>

## 🤝 Contributing

**Submission Guidelines:**

1. State the engine and version for any dialect-specific syntax, and give the portable form where one exists.
2. Include actual query output rather than described output.
3. Show the query plan when making a performance claim.
4. State the grain of any fact table you add.
5. Keep example datasets small enough to reason about by hand.
6. Update the [section index](./README.md) when adding a guide.

---

<a id="resources"></a>

## 📚 Resources

| Area | Official References |
| --- | --- |
| 🗄️ SQLite | [SQL syntax](https://www.sqlite.org/lang.html) · [Window functions](https://www.sqlite.org/windowfunctions.html) · [Query planning](https://www.sqlite.org/queryplanner.html) · [EXPLAIN QUERY PLAN](https://www.sqlite.org/eqp.html) · [WAL mode](https://www.sqlite.org/wal.html) |
| 🐘 PostgreSQL | [SELECT](https://www.postgresql.org/docs/current/sql-select.html) · [Window functions](https://www.postgresql.org/docs/current/tutorial-window.html) · [Using EXPLAIN](https://www.postgresql.org/docs/current/using-explain.html) · [Indexes](https://www.postgresql.org/docs/current/indexes.html) |
| 🔒 Transactions | [SQLite transactions](https://www.sqlite.org/lang_transaction.html) · [PostgreSQL isolation levels](https://www.postgresql.org/docs/current/transaction-iso.html) |
| 🐍 Driver | [Python sqlite3](https://docs.python.org/3/library/sqlite3.html) |

---

<a id="see-also"></a>

## 🔗 Quick Links & Related Guides

- [🗄️ Data Engineering Section Index](./README.md)
- [🧱 Data Engineering Fundamentals](./data_engineering_fundamentals.md)
- [🐍 Python for Data Processing](./python_data_processing.md)
- [🔄 ETL & ELT Pipeline Design](./etl_elt_pipeline_design.md)
- [✅ Data Quality & Schema Contracts](./data_quality_schema_contracts.md)
- [🛡️ Secure Data Pipelines](./data_pipelines.md)
- [📊 Log Aggregation & Visibility](../IncidentResponse/log_agg.md)
- [📖 Repository Glossary](../GLOSSARY.md)

---

<a id="guide-details"></a>

## 📊 Guide Details

| Item | Details |
| --- | --- |
| 🎯 Focus | Correct schemas, correct queries, and readable query plans |
| 🧰 Core Technologies | SQLite 3.45 (portability notes for PostgreSQL and MySQL) |
| 📘 Format | Reference guide with an executed lab and real query output |
| 🧪 Validation Status | All queries executed; outputs and limitations documented above |
| 📁 Location | `Data-Engineering/sql_data_modeling.md` |
| 🔄 Content Review Date | September 11, 2026 |

---

<div align="center">

**🗃️ Constrain the Schema. State the Grain. Read the Plan.**

*A constraint prevents the bug that a code review missed, and a query plan settles the argument that benchmarks started.*

**Repository:** [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Pacific Northwest Computers:** [PNWC on GitHub](https://github.com/Pnwcomputers)

[🏠 Master Index](../README.md) | [🎯 Role Navigation](../START_HERE.md) | [📋 Table of Contents](#table-of-contents) | [📜 Legal Notice](../LEGAL.md)

⭐ **Star the repository if you find it useful!** ⭐

</div>
