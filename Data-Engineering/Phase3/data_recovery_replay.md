# ♻️ Backup, Replay & Disaster Recovery

<div align="center">

**Restore trusted state, replay within known boundaries, and prove the result before cutover**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md)*

![Phase](https://img.shields.io/badge/Phase_3-Operations_%26_Governance-blue?style=for-the-badge)
![Lab](https://img.shields.io/badge/Local_Lab-Verified-darkgreen?style=for-the-badge)

**[Phase 3 Index](README.md) · [Data Engineering Overview](../README.md)**

</div>

_Last reviewed: 2026-09-11. Local lab executed on Python 3.12.14 and SQLite 3.53.1 where used. The
Verification Record limits the claim to the checks performed._

Terms are defined at first use; see also the repository [Glossary](../../GLOSSARY.md).


---

<a id="purpose"></a>

## 🎯 Purpose, Function & Goal

**Purpose:** Make recovery an exercised procedure with an explicit data boundary, rather than a belief that
backups probably exist.

**Function:** Distinguish backups, replicas, snapshots, replay logs, and derived data. Set recovery
objectives, record recovery bundles, restore in isolation, replay safely, and validate before cutover.

**Goal:** Prove which state can be restored, which changes can be replayed, what loss remains, and how long a
realistic recovery takes.

**When to use:** Designing backup policy, recovering a failed pipeline, rebuilding corrupted outputs, or
preparing for source loss or a compromised environment.

**Prerequisites:** [Storage & File Formats](../Phase2/data_storage_file_formats.md), [Streaming &
CDC](../Phase2/streaming_cdc.md), and [Data Governance, Lineage & Access](./data_governance_lineage.md).

---

<a id="contents"></a>

## 📋 Table of Contents

- [🗄️ 1. Backup Is Not Replication](#copies)
- [🎯 2. Recovery Objectives & Measurement](#objectives)
- [📦 3. Define a Recovery Bundle](#bundle)
- [🧯 4. Restore in Isolation](#restore)
- [♻️ 5. Replay Boundaries & Deduplication](#replay)
- [🏗️ 6. Rebuild Derived Data](#derived)
- [🔀 7. Cutover, Failback & Drills](#cutover)
- [🧪 8. Lab: Backup, Restore & Replay](#lab)
- [✅ Verification Record & Self-Check](#verification)
- [Contributing & Related Guides](#related)

---

<a id="copies"></a>

## 🗄️ 1. Backup Is Not Replication

| Mechanism | Primary use | Recovery limitation |
| --- | --- | --- |
| Replica | Availability and read scaling | May promptly copy corruption or deletion |
| Backup | Recover a retained earlier state | Must be complete, readable, protected and restorable |
| Snapshot | Capture a storage state at a point | Application consistency and failure-domain independence vary |
| Change log | Replay changes after a known boundary | History can expire or have gaps |
| Derived output | Serve a transformed view | Rebuild depends on sources, code, schemas and reference data |

Choose copies in failure domains that match the threats. A backup beside the only live disk does not cover
that disk's failure. A copy controlled by the same compromised identity may not cover malicious deletion. Test
access from the recovery environment, not only from the production writer.

Versioned object storage or snapshots can contribute to recovery, but confirm retention, deletion permissions,
encryption keys, and restore behavior. A mechanism's name does not establish that it survives the incident
being planned for.

---

<a id="objectives"></a>

## 🎯 2. Recovery Objectives & Measurement

The **recovery point objective (RPO)** is the maximum acceptable loss expressed as a recovery-point gap, often
time. The **recovery time objective (RTO)** is the target time to restore an agreed usable service. Define
both with the consumer and operator.

| Objective field | Example decision |
| --- | --- |
| Recovery scope | One dataset, its dependencies, and its publication interface |
| RPO basis | Source commit time or another authoritative sequence/time mapping |
| RTO start | Incident declaration or another agreed trigger |
| RTO end | Verified consumer availability, not merely file-copy completion |
| Validation | Integrity, completeness, freshness and access checks |
| Degraded mode | Which partial service, if any, is acceptable? |

Do not infer achieved RPO solely from backup frequency. Failed backups, delayed log shipping, source gaps, or
missing keys can move the recoverable point backward. A recent snapshot with an inconsistent checkpoint may be
unusable.

Measure restore preparation, transfer, replay, reconciliation, permission checks, and cutover. A tiny local
lab runtime is not an RTO benchmark. Estimate capacity with representative data and the actual recovery
infrastructure, including the time required to obtain credentials and provision replacements.

For illustration only: a backup at 10:00 with verified changes through 10:12 can support a later point than
the backup alone. At a 10:15 failure, the recoverable gap may be three minutes if the journal is complete and
replay succeeds. Without that evidence, do not promise the three-minute result.

---

<a id="bundle"></a>

## 📦 3. Define a Recovery Bundle

A recovery bundle must include more than data bytes.

| Component | Why it is needed |
| --- | --- |
| Base snapshot or backup | Starting state |
| Consistent source/checkpoint position | Exact boundary between base and replay |
| Change history and continuity evidence | Changes required after the base |
| Schema and migration version | Correct interpretation and destination layout |
| Code and dependency identity | Repeatable transformation |
| Reference data | The lookup state that affected results |
| Encryption and access recovery path | Ability to read and operate recovered data |
| Manifest and trusted integrity evidence | Detect missing or modified components |
| Deletion/hold policy state | Prevent inappropriate reintroduction or removal |

Tie the checkpoint to the same committed state as the backup. Independently copying “latest data” and “latest
offset” can produce a gap even when each file looks valid.

For SQLite, use its supported backup mechanism rather than casually copying a live database file. The Online
Backup API copies a database into a destination connection while coordinating with the database engine. The
lab uses Python's `Connection.backup()` wrapper. [SQLite Online Backup
API](https://www.sqlite.org/backup.html), [Python SQLite
backup](https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup)

Other systems require their own documented consistent-backup procedure. Do not apply this SQLite example
directly to a running server database, a replicated log, or an object-store table.

---

<a id="restore"></a>

## 🧯 4. Restore in Isolation

1. Declare the recovery scope and prevent competing writers or publishers.
2. Preserve the failed state and relevant evidence where needed.
3. Select a trusted base and verify its manifest and required dependencies.
4. Restore into a new isolated destination with outbound side effects disabled.
5. Run storage-integrity and schema checks before application processing.
6. Confirm the stored checkpoint matches the base state.
7. Replay the required range under the pinned contract and code.
8. Reapply authorized deletion/access policy and reconcile the result.
9. Approve cutover under the operating procedure, then observe consumers.

For a compromise, the newest backup may already contain the unwanted change. Identify a trusted recovery point
and rotate affected credentials before reconnecting; blindly promoting the most recent bytes can restore the
incident.

Never test restore by overwriting the only good production copy. The lab preserves its live and backup files
and creates a separate restored database. Its checksum detects a byte change relative to the known digest, not
the trustworthiness of an attacker-controlled manifest.

---

<a id="replay"></a>

## ♻️ 5. Replay Boundaries & Deduplication

Replay requires an inclusive/exclusive boundary, a stable identity, and a known destination behavior.

| Question | Decision to document |
| --- | --- |
| Where does replay begin? | First event not included in the base checkpoint |
| Where does it stop? | A fixed cutover position or an agreed catch-up condition |
| Can events repeat? | Deduplication or idempotent application rule |
| Can they arrive out of order? | Partition/key ordering and source-version comparison |
| Are deletes retained? | Tombstone or equivalent state through the replay horizon |
| Can inputs expire? | Refuse an unsupported recovery claim if history is missing |

The lab uses one artificial contiguous sequence and a monotonic version per key. It skips already-applied
sequence numbers, commits state and sequence together, and refuses a missing next event. A retained deletion
version prevents a stale update from recreating a row.

Real systems can use noncontiguous offsets and source-specific positions. Translate their documented
continuity rules; do not reuse the fixture's integer adjacency test as a generic Kafka or database-log
validator.

If history is missing, stop and determine whether a new snapshot, another archive, or a documented partial
recovery is possible. Moving the checkpoint forward merely to make the error disappear destroys the claim of
completeness.

Disable or independently deduplicate external effects during replay. Rebuilding a table should not resend
every historical notification or repeat a billing action.

---

<a id="derived"></a>

## 🏗️ 6. Rebuild Derived Data

A dataset is rebuildable only if all required inputs and interpretation rules survive. Raw rows alone may be
insufficient when the result used changing lookup data, an external model, a manual correction, or a
historical contract.

Rebuild into a versioned destination. Verify counts, key sets, deletion semantics, and representative payloads
or aggregates against an independent expectation. Publish only after the validation gate passes.

| Desired recovery | Version choice |
| --- | --- |
| Reproduce the original report | Original code, schema and reference versions |
| Correct a known historical bug | Fixed version with an explicit correction scope |
| Produce a current reinterpretation | Current rules, labeled as recalculated output |

Do not call all three “the same replay.” Tell consumers when a corrected result changes a previous report.
Preserve lineage to the new output version and its source range.

The lab rebuilds a disposable SQL aggregate from recovered active rows and checks that its total is 15. This
simple aggregation has no external reference data. It does not prove that a larger business report is
reproducible.

---

<a id="cutover"></a>

## 🔀 7. Cutover, Failback & Drills

Cutover changes which system consumers trust. Prevent split ownership: fence old writers, coordinate
publication identity, and ensure new writes will not later be overwritten by an old process.

Validate permissions, secrets, scheduled jobs, monitoring, and downstream connections before declaring
recovery complete. Decide how writes that arrive during the transition are buffered or applied. Keep the
previous destination until rollback and evidence policies permit retirement.

Failback is another migration. Changes accepted by the recovery destination must be reconciled before
returning to the original system. Simply changing DNS or a connection string does not merge divergent
histories.

| Drill | Evidence to capture |
| --- | --- |
| Restore selected backup | Integrity, schema, key availability and elapsed stages |
| Replay after interruption | Checkpoint correctness and repeatable sink state |
| Missing history | Safe refusal and escalation path |
| Expired credentials | Recovery access procedure works independently |
| Deleted record in old backup | Suppression is reapplied before publication |
| Lost primary site | Provisioning, data transfer, monitoring and consumer recovery |

Track the actual recovery point and measured recovery time from representative exercises. Turn failed
assumptions into assigned fixes. Link operational triggers to [Pipeline Observability &
Reliability](./pipeline_observability.md).

---

<a id="lab"></a>

## 🧪 8. Lab: Backup, Restore & Replay

Create a consistent SQLite backup at sequence 2, apply additional live changes, restore to another file,
replay through sequence 5, preserve deletion state, rebuild an aggregate, and refuse a missing event or
changed backup bytes.

**Requirements:** Python 3.10+; the testing and recovery labs also use Python's `sqlite3` module. This
revision was executed on Python 3.12.14 and SQLite 3.53.1 only. All data is synthetic; no server, credentials,
network calls, or third-party dependencies are required.

Save as `recovery_lab.py` and run without Python's `-O` flag, because the standalone drills use assertions.
File-based fixtures use temporary directories that are removed on completion.

```python
"""SQLite backup, isolated restore, and deterministic event replay."""
import hashlib
import shutil
import sqlite3
import tempfile
from pathlib import Path


def connect(path):
    db = sqlite3.connect(path)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS state(id TEXT PRIMARY KEY, version INTEGER, value INTEGER, deleted INTEGER);
        CREATE TABLE IF NOT EXISTS progress(id INTEGER PRIMARY KEY, sequence INTEGER);
        INSERT OR IGNORE INTO progress VALUES(1,0);
    ''')
    return db


def apply(db, event):
    seq, key, version, value, deleted = event
    current = db.execute('SELECT sequence FROM progress WHERE id=1').fetchone()[0]
    if seq <= current:
        return
    if seq != current + 1:
        raise ValueError('missing event in retained journal')
    with db:
        db.execute('''INSERT INTO state VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET
            version=excluded.version,value=excluded.value,deleted=excluded.deleted
            WHERE excluded.version > state.version''', (key, version, value, deleted))
        db.execute('UPDATE progress SET sequence=? WHERE id=1', (seq,))


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def snapshot(db):
    return db.execute('SELECT * FROM state ORDER BY id').fetchall()


def run(root):
    journal = [(1, 'A', 1, 10, 0), (2, 'B', 1, 20, 0),
               (3, 'A', 2, 15, 0), (4, 'B', 2, None, 1),
               (5, 'B', 1, 20, 0)]  # stale update must not undo deletion
    live = connect(root / 'live.db')
    for e in journal[:2]:
        apply(live, e)
    backup_path = root / 'backup.db'
    backup = sqlite3.connect(backup_path)
    live.backup(backup)
    backup.close()
    expected_hash = digest(backup_path)
    for e in journal[2:]:
        apply(live, e)
    wanted = snapshot(live)
    live.close()
    # Recovery uses a new file; the source file is never overwritten.
    assert digest(backup_path) == expected_hash
    restored_path = root / 'restored.db'
    shutil.copyfile(backup_path, restored_path)
    restored = connect(restored_path)
    assert restored.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    assert restored.execute('SELECT sequence FROM progress').fetchone()[0] == 2
    for e in journal:
        apply(restored, e)
    assert snapshot(restored) == wanted == [('A', 2, 15, 0), ('B', 2, None, 1)]
    for e in journal:
        apply(restored, e)
    assert snapshot(restored) == wanted
    # Rebuild a disposable derived table from recovered authoritative state.
    with restored:
        restored.execute('CREATE TABLE derived AS SELECT SUM(value) AS total FROM state WHERE deleted=0')
    assert restored.execute('SELECT total FROM derived').fetchone()[0] == 15
    restored.close()
    gap_path = root / 'gap.db'
    shutil.copyfile(backup_path, gap_path)
    gap = connect(gap_path)
    try:
        apply(gap, journal[3])  # Deliberately omit event 3.
    except ValueError:
        pass
    else:
        raise AssertionError('missing history accepted')
    assert gap.execute('SELECT sequence FROM progress').fetchone()[0] == 2
    gap.close()
    damaged = root / 'damaged.db'
    shutil.copyfile(backup_path, damaged)
    with damaged.open('ab') as f:
        f.write(b'corruption')
    assert digest(damaged) != expected_hash
    print('PASS: online backup; isolated restore; integrity check; replay through seq=5; rerun unchanged; delete preserved; derived total=15; gap/corruption detected')


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='phase3-recovery-') as folder:
        run(Path(folder))
```

```bash
python3 recovery_lab.py
```

On Windows, `py -3 recovery_lab.py` may be the appropriate launcher. Windows execution was not tested here.

**Actual summary output:**

```text
PASS: online backup; isolated restore; integrity check; replay through seq=5; rerun unchanged; delete preserved; derived total=15; gap/corruption detected
```

---

<a id="verification"></a>

## ✅ Verification Record & Self-Check

| Check | Result |
| --- | --- |
| SQLite backup at committed sequence 2 | Passed |
| Isolated copy opens and integrity check returns `ok` | Passed |
| Replay through sequence 5 equals live expected state | Passed |
| Repeated replay changes nothing | Passed |
| Stale update does not undo deletion | Passed |
| Derived active-value total is 15 | Passed |
| Missing journal event and changed backup digest | Detected |
| Offsite recovery, power loss, concurrent backup writers, failover/failback | Not executed |
| Production RPO/RTO, restored privacy-deletion suppression | Not measured or implemented |

**Self-check:** Which failure destroys both your primary and its copy? Does the backup include a consistent
checkpoint? How far does verified replay history extend? Can an old backup reintroduce deleted data? What must
pass before cutover?

The journal is a fixed in-memory fixture supplied by the script. The lab does not demonstrate durable remote
log shipping or protection against loss of that history.

---

<a id="related"></a>

## 🤝 Contributing & Related Guides

For corrections, provide a synthetic reproducer, runtime versions, expected behavior, and actual results.
Update verification claims only for checks performed. Keep secrets and customer records out of examples.

- [📊 Pipeline Observability & Reliability](./pipeline_observability.md)
- [🧪 Pipeline Testing & CI/CD](./pipeline_testing_cicd.md)
- [🔐 Data Governance, Lineage & Access](./data_governance_lineage.md)
- [Phase 3 Index](README.md)
- [Phase 2 Storage & Integration](../Phase2/README.md)
- [Data Engineering Overview](../README.md)

---

[⬆ Back to Contents](#contents) | [⬅️ Master Index](../../README.md) | [🎯 Role
Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
