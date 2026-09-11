# 🌊 Streaming & Change Data Capture

<div align="center">

**Apply changes predictably while handling snapshots, ordering, duplicates, late data, and replay**

*CDC • Snapshots • Event Time • Offsets • Deletes • Replay • Compatibility*

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md)*

![Phase](https://img.shields.io/badge/Phase_2-Storage_%26_Integration-blue?style=for-the-badge)
![Level](https://img.shields.io/badge/Level-Intermediate-darkgreen?style=for-the-badge)
![Lab](https://img.shields.io/badge/Core_Lab-Python_Standard_Library-purple?style=for-the-badge)

**[Phase 2 Index](./readme.md) · [Data Engineering Overview](../README.md)**

</div>

---

_Reviewed: 2026-09-11. The local lab was executed with Python 3.12.14 and SQLite 3.53.1. External systems and optional integrations were not exercised; see the Verification Record._


---

<a id="purpose"></a>

## 🎯 Purpose, Function & Goal

**Purpose:** Explain how to consume continuously arriving changes without silently corrupting current state or historical results.

**Function:** Compare polling, database CDC, and domain events; establish snapshot boundaries, ordering, delivery semantics, event-time policy, replay, and compatibility. Demonstrate a transactional one-partition consumer locally.

**Goal:** Explain what an offset proves, how replay affects a sink, why deletes need durable meaning, and where your ordering and exactly-once claims stop.

**When to use:** Replicating operational state, feeding near-real-time analytics, processing telemetry, or replacing full-table refreshes with changes.

**Prerequisites:** [ETL & ELT](../Phase1/etl_elt_pipeline_design.md), [Quality & Contracts](../Phase1/data_quality_schema_contracts.md), and [API & File Ingestion](./api_file_ingestion.md).

---

<a id="contents"></a>

## 📋 Table of Contents

- [📡 1. Streaming, CDC & Domain Events](#capture)
- [📸 2. Snapshots & the Transition to Changes](#snapshot)
- [✉️ 3. Event Identity, Keys & Ordering](#envelope)
- [📬 4. Delivery Semantics & Sink Commit](#delivery)
- [🗑️ 5. Deletes, Tombstones & Late Updates](#deletes)
- [⏱️ 6. Event Time, Watermarks & Late Records](#time)
- [♻️ 7. Replay & Consumer Compatibility](#replay)
- [🧪 8. Lab: Transactional CDC Consumer](#lab)
- [💥 9. Failure Drills & Monitoring](#operations)
- [✅ Verification Record](#verification)
- [Contributing & Related Guides](#related)

---

<a id="capture"></a>

## 📡 1. Streaming, CDC & Domain Events

Streaming describes ongoing processing. Change data capture describes obtaining changes to stored data. They overlap but are not interchangeable.

| Approach | What it captures | Key limitation |
| --- | --- | --- |
| Timestamp polling | Rows returned by a change query | Missed deletes or corrections unless explicitly represented |
| Log-based CDC | Database changes represented in a transaction log | Connector setup, log retention, source privileges, schema behavior |
| Application outbox | Intentional events committed with application data | Requires application design and relay ownership |
| Domain event stream | Business facts emitted under an event contract | Event meaning may differ from the current database row |

A row update says stored state changed. It does not necessarily explain the business reason. Keep that distinction when choosing between a CDC mirror and a domain-event-driven workflow.

Capture only intended tables and fields. Restrict source replication access, encrypt transport, and control access to raw events and rejects. CDC can expose fields that normal application APIs omit.

---

<a id="snapshot"></a>

## 📸 2. Snapshots & the Transition to Changes

A new consumer often needs an initial state plus every relevant change after it. Scanning a live table and then starting a change reader can leave a gap or apply stale snapshot rows over newer updates.

Define the consistency boundary using the chosen connector's documented snapshot/log-position protocol. Record snapshot completion, source positions, connector configuration, and schema history required for restart.

Debezium's PostgreSQL connector documents initial and incremental snapshot behavior, including coordination between snapshot reads and changes that arrive while a snapshot is running. Use its supported protocol instead of assembling an uncoordinated table dump plus log reader. Configuration and privileges depend on the connector and source version. [Debezium PostgreSQL connector](https://debezium.io/documentation/reference/stable/connectors/postgresql.html)

| Recovery situation | Decision to make |
| --- | --- |
| Connector restarts with a valid durable source position | Resume under the connector's recovery procedure |
| Required log history has expired | Resnapshot or restore a suitable archive; report the gap |
| A new table is added | Coordinate its initial state with ongoing changes |
| Snapshot overlaps live updates | Use connector-provided ordering/collision handling |
| Source is rebuilt or fails over | Verify source identity and position validity before resuming |

Monitor retained source logs and the age of the oldest needed position. A lagging replication reader can put pressure on source storage. Do not size retention only from average ingest delay; include outage detection and recovery time.

The local lab begins with a synthetic snapshot-read event. It does not implement a database snapshot or prove the correctness of a snapshot/log handoff.

---

<a id="envelope"></a>

## ✉️ 3. Event Identity, Keys & Ordering

Keep transport position, entity identity, and business time separate.

| Field | Purpose |
| --- | --- |
| Source identity | Distinguishes database, stream, and source generation |
| Entity key | Identifies the row or business entity being changed |
| Operation | Read/snapshot, create, update, delete, or a defined domain action |
| Source version/position | Supports ordering under a documented scope |
| Partition and offset | Identifies progress within a transport partition |
| Event time | When the source says the event occurred |
| Ingest time | When your system received it |
| Schema version | Identifies how to interpret the payload |

For a keyed state projection, route changes for the same key consistently and preserve their intended order. Ordering within a partition does not imply a total order across partitions. Cross-table transaction consistency requires an explicit strategy; seeing one row from a transaction does not establish that all its related rows have arrived.

The lab assumes a monotonic integer version per entity and a single ordered partition. Real CDC positions can be compound and source-specific; do not assume a source log position alone uniquely orders every row event. Define tie-breaking and reject equal-version conflicting payloads instead of choosing arbitrarily.

The lab also assumes contiguous fixture offsets. Real broker offsets can have gaps visible to a consumer, so a live adapter must track the broker-provided position correctly rather than requiring arithmetic contiguity as this simulator does.

---

<a id="delivery"></a>

## 📬 4. Delivery Semantics & Sink Commit

A duplicate message is often a normal recovery outcome. An unrepeatable side effect is a design decision that must be handled explicitly.

| Pattern | Failure consequence |
| --- | --- |
| Advance progress before committing the sink | Crash can skip effects that never committed |
| Commit sink, then advance independent progress | Crash can replay already-applied effects |
| Commit state and progress in one supported transaction | Removes that particular split-commit window |

Kafka's documented transactional guarantees can cover reads, writes, and offsets within supported Kafka processing. Effects in another system require that system's cooperation; a broker setting does not make an arbitrary external action exactly once. [Kafka delivery semantics](https://kafka.apache.org/41/design/design/)

For an external SQL sink, one option is to store its projection and source progress in the same SQL transaction, using that progress as the recovery authority. Another is an idempotent sink keyed by event identity with explicit handling of replay. Decide which state controls recovery before adding a second independently committed offset.

The lab stores projection state and next offset together in SQLite. A failure before commit rolls back both. Replayed old offsets produce no additional effect. This proves the local transaction behavior only; it is not a demonstration of a live broker transaction, distributed exactly-once processing, or exactly-once notifications.

---

<a id="deletes"></a>

## 🗑️ 5. Deletes, Tombstones & Late Updates

A delete is data with meaning. If a consumer simply removes the row and forgets its version, a later replay of an old update can recreate it.

Retain enough deletion state to reject stale events for the supported replay horizon. The lab keeps a versioned row with `deleted=1` and a null payload. Current-state queries filter deleted rows, while the version remains available for ordering checks.

Do not equate every null message with a row deletion. In some compacted-stream systems, a null-valued record is a transport tombstone with specific retention behavior. Interpret the connector envelope and broker semantics explicitly. A connector's delete event and a subsequent broker tombstone may serve different purposes.

Declare how long deletion markers, event deduplication state, and raw change history remain. Expiring a deletion marker while older events can still be replayed may permit resurrection. A current-state projection is not automatically a complete audit history; retain a separate immutable history when required.

---

<a id="time"></a>

## ⏱️ 6. Event Time, Watermarks & Late Records

Event time answers when a fact occurred. Processing time answers when a worker handled it. A delayed device can produce old event timestamps in newly arrived messages.

An event-time watermark is a policy estimate of progress through event time. It is not a guarantee that an older event will never arrive, and it is not the extraction checkpoint used in a batch importer.

| Late-record policy | Result | Required follow-up |
| --- | --- | --- |
| Update a still-open window | Results can change before closure | Define when consumers can treat them as final |
| Emit a correction | Previously published results are revised | Consumer must support revisions or retractions |
| Route to a late-data stream | Main window remains stable | Monitor and reconcile the late-data path |
| Drop after a documented threshold | Bounded state and predictable closure | Measure loss and justify the policy |

The lab's standalone time exercise tracks `max_seen_time - 10` and flags timestamps below the previous watermark. It finds one late arrival among `100, 120, 105, 118`. It does not aggregate windows or implement retractions.

Across multiple partitions, define how per-partition progress is combined and how idle partitions are treated. Advancing from only the fastest partition can close results before slower partitions contribute. Bound retained state with an explicit late-data policy rather than silently dropping inconvenient records.

---

<a id="replay"></a>

## ♻️ 7. Replay & Consumer Compatibility

Plan replay before an incident. Preserve the source range, contract version, transformation version, and destination semantics.

1. Identify the affected position or time range and confirm history remains available.
2. Select an isolated destination or coordinated recovery procedure.
3. Pin code, schema, and reference-data versions where possible.
4. Rebuild or repair with controlled throughput.
5. Reconcile keys, deletes, counts, and representative payloads.
6. Promote the rebuilt view or resume normal consumption after validation.

Running an old event through new enrichment data may produce a different answer. Decide whether replay reconstructs the original result or intentionally recalculates it under current logic.

For schema changes, test old consumer/new producer and new consumer/old retained event combinations separately. Adding an optional field can still break a consumer that rejects unknown fields. A rename, type change, changed key, or changed meaning can require coordinated migration even when the payload still parses. [Phase 1 Data Quality & Schema Contracts](../Phase1/data_quality_schema_contracts.md)

Choose a poison-event policy. The lab stops its partition on an unsupported schema and does not advance progress. A production quarantine-and-continue policy requires durable rejected content, error context, replay ownership, and an assessment of ordering effects. Skipping a bad update and applying its successor may not preserve intended state.

---

<a id="lab"></a>

## 🧪 8. Lab: Transactional CDC Consumer

The fixture includes a snapshot read, updates, a create, a delete, a stale update, a failed commit, restart, full replay, an offset gap, and an unsupported schema. A separate tiny event-time exercise identifies one late event.

**Requirements:** Python 3.10+ with `sqlite3` available for the database labs. Only Python 3.12.14 was executed for this revision. No credentials, server, network requests, or third-party packages are used.

Save the following as `streaming_lab.py` in a practice directory. It creates a temporary workspace and removes that workspace on completion. Run without Python's `-O` flag so assertions remain enabled.

```python
"""One-partition CDC simulation with transactional state and progress."""
import sqlite3
import tempfile
from pathlib import Path


def database(path):
    db = sqlite3.connect(path)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS state(
            id TEXT PRIMARY KEY, version INTEGER, name TEXT, deleted INTEGER);
        CREATE TABLE IF NOT EXISTS progress(
            partition_id INTEGER PRIMARY KEY, next_offset INTEGER);
        INSERT OR IGNORE INTO progress VALUES(0,0);
    ''')
    return db


def consume(db, event, fail=False):
    # Fixture contract: single partition, contiguous offsets, per-key monotonic versions.
    offset, key, version, op, name, schema = event
    expected = db.execute('SELECT next_offset FROM progress WHERE partition_id=0').fetchone()[0]
    if offset < expected:
        return 'duplicate'
    if offset != expected:
        raise ValueError('offset gap')
    if schema != 1 or op not in ('r', 'c', 'u', 'd'):
        raise ValueError('unsupported contract: partition stopped')
    with db:
        db.execute('''INSERT INTO state VALUES(?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET version=excluded.version,
              name=excluded.name, deleted=excluded.deleted
            WHERE excluded.version > state.version''',
            (key, version, None if op == 'd' else name, int(op == 'd')))
        if fail:
            raise RuntimeError('crash before commit')
        db.execute('UPDATE progress SET next_offset=? WHERE partition_id=0', (offset + 1,))
    return 'committed'


def run(root):
    events = [
        (0, 'A', 1, 'r', 'alpha', 1),  # snapshot read
        (1, 'A', 2, 'u', 'alpha-new', 1),
        (2, 'B', 1, 'c', 'beta', 1),
        (3, 'A', 3, 'd', None, 1),
        (4, 'A', 2, 'u', 'stale update', 1),
    ]
    db = database(root / 'consumer.db')
    consume(db, events[0])
    try:
        consume(db, events[1], fail=True)
    except RuntimeError:
        pass
    assert db.execute('SELECT version FROM state WHERE id="A"').fetchone()[0] == 1
    assert db.execute('SELECT next_offset FROM progress').fetchone()[0] == 1
    db.close()
    db = database(root / 'consumer.db')
    for event in events[1:]:
        consume(db, event)
    expected = [('A', 3, None, 1), ('B', 1, 'beta', 0)]
    assert db.execute('SELECT * FROM state ORDER BY id').fetchall() == expected
    assert all(consume(db, e) == 'duplicate' for e in events)
    for bad in [(6, 'C', 1, 'c', 'gap', 1), (5, 'C', 1, 'c', 'new schema', 2)]:
        try:
            consume(db, bad)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid event advanced progress')
    assert db.execute('SELECT next_offset FROM progress').fetchone()[0] == 5
    replay = database(root / 'replay.db')
    for event in events:
        consume(replay, event)
    assert replay.execute('SELECT * FROM state ORDER BY id').fetchall() == expected
    replay.close()
    db.close()
    # Separate event-time exercise: timestamps here are seconds on a synthetic clock.
    max_event_time = None
    late = 0
    for timestamp in (100, 120, 105, 118):
        watermark = float('-inf') if max_event_time is None else max_event_time - 10
        late += int(timestamp < watermark)
        max_event_time = timestamp if max_event_time is None else max(max_event_time, timestamp)
    assert late == 1
    print('PASS: rollback/restart; replay; duplicates; deletion retained; stale update ignored; gap/schema blocked; 1 late event')


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='phase2-streaming-') as folder:
        run(Path(folder))
```

Run:

```bash
python3 streaming_lab.py
```

On Windows, use `py -3 streaming_lab.py` if that is how Python is installed. The Windows launcher was not tested here.

**Actual output from this revision:**

```text
PASS: rollback/restart; replay; duplicates; deletion retained; stale update ignored; gap/schema blocked; 1 late event
```

---

<a id="operations"></a>

## 💥 9. Failure Drills & Monitoring

| Signal or drill | What it tells you |
| --- | --- |
| Source position and broker consumer lag | Where collection or consumption is falling behind |
| End-to-end event age | Whether consumers receive timely data |
| Restart immediately before/after sink commit | Whether replay can lose or duplicate effects |
| Delete followed by stale update | Whether old data can resurrect deleted state |
| Unknown schema | Whether progress stops or rejects are durably recoverable |
| Snapshot while writes continue | Whether the live connector preserves a consistent transition |
| Restore from oldest retained position | Whether the stated recovery horizon is realistic |

Track late records, rejected contracts, duplicate deliveries, stale updates, and source-log retention pressure separately. A growing duplicate counter can reflect retries; it does not by itself prove duplicate sink state.

**Self-check:** What is ordered globally, per partition, and per key? What proves a delete remains deleted after replay? Where are state and progress committed? How do you handle a schema you cannot decode? What happens when the source history expires?

---

<a id="verification"></a>

## ✅ Verification Record

| Check | Result |
| --- | --- |
| Failed state/progress transaction rolls back; database reopens | Passed |
| Duplicate offsets have no additional effect | Passed |
| Versioned delete survives a stale update | Passed |
| Independent replay reconstructs identical state | Passed |
| Gap and unsupported schema do not advance progress | Passed under fixture rules |
| Synthetic event-time example detects one late record | Passed |
| Kafka, Debezium, live source snapshot, replication configuration | Not executed |
| Multiple partitions, rebalances, source failover, window corrections | Not implemented or tested |

The simulator uses a deliberately simplified event tuple and monotonic per-key integer version. It is not a Debezium payload parser or Kafka client. Translate actual source and transport contracts before reusing its projection pattern.

---

<a id="related"></a>

## 🤝 Contributing & Related Guides

For a correction, include the section, a synthetic reproducer, your runtime versions, expected behavior, and observed output. Update the Verification Record only for checks you actually perform. Keep credentials and customer records out of examples.

- [🗄️ Data Storage & File Formats](./data_storage_file_formats.md)
- [📥 API & File Ingestion](./api_file_ingestion.md)
- [⚙️ Workflow Orchestration](./workflow_orchestration.md)
- [Phase 2 Index](./readme.md)
- [Phase 1 Fundamentals](../Phase1/data_engineering_fundamentals.md)
- [Data Engineering Overview](../README.md)
- [Repository Home](../../README.md)

**[⬆ Back to Contents](#contents)**
