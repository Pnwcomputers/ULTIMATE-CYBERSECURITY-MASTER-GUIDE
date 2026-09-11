# 📥 API & File Ingestion

<div align="center">

**Collect complete, recoverable inputs without confusing a successful request with a successful load**

*Authentication • Pagination • Rate Limits • Retries • Watermarks • File Recovery*

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

**Purpose:** Make ingestion complete, restartable, and accountable when APIs and file producers fail or change.

**Function:** Define authentication boundaries, pagination, retry policy, incremental progress, changed-file detection, and incomplete-download handling. Exercise the recovery logic with a deterministic local simulator.

**Goal:** Recover from an interrupted collection without silently skipping records, advancing progress too early, or publishing incomplete files.

**When to use:** Importing SaaS records, receiving recurring exports, polling operational sources, or diagnosing intermittent data gaps.

**Prerequisites:** [Python Processing](../Phase1/python_data_processing.md), [ETL & ELT](../Phase1/etl_elt_pipeline_design.md), and [Storage & File Formats](./data_storage_file_formats.md).

---

<a id="contents"></a>

## 📋 Table of Contents

- [📋 1. Establish the Source Contract](#contract)
- [🔐 2. Authentication & Transport Boundaries](#auth)
- [📚 3. Pagination Without Silent Gaps](#pagination)
- [🔁 4. Rate Limits & Retry Policy](#retries)
- [📍 5. Watermarks & Commit Boundaries](#progress)
- [📁 6. Changed Files & Partial Downloads](#files)
- [🧪 7. Lab: Restartable Pages & File Recovery](#lab)
- [💥 8. Failure Drills & Operational Checks](#operations)
- [✅ Verification Record](#verification)
- [Contributing & Related Guides](#related)

---

<a id="contract"></a>

## 📋 1. Establish the Source Contract

Before writing a loop, identify the source's guarantees. A successful response says nothing about whether your extraction represents a complete snapshot.

| Question | Why it matters |
| --- | --- |
| Which records can the service identity see? | Limited permissions may look like missing data |
| Is there a stable record key and change version? | Required to distinguish updates from duplicates |
| Is pagination a snapshot or a changing live view? | Inserts and deletes can move records between pages |
| How are deletions reported? | Polling existing rows cannot discover every deletion |
| What counts as a completed export? | An upload in progress must not be treated as ready |
| How long do cursors, files, and change history survive? | Determines the safe outage and replay window |
| What are request, byte, and concurrency limits? | Determines collection pace and resource budgets |

Store extraction metadata: source identity, endpoint or export type, query parameters, schema version, start/end time, source version or cursor, input counts, byte counts, and destination batch identity. Redact secrets and sensitive query values from operational logs.

---

<a id="auth"></a>

## 🔐 2. Authentication & Transport Boundaries

Use a dedicated identity with only the read permissions required for the dataset. Obtain secrets through the execution environment's approved secret facility; avoid embedding credentials in source, examples, filenames, or command histories.

For a real HTTP adapter, require HTTPS, certificate validation, explicit timeouts, response-size limits, and an allowed destination origin. Handle token refresh through the provider's documented flow. Redact authorization headers, signed URLs, and response bodies that may contain private records.

Treat a supplied pagination URL as input, not automatic permission to send credentials elsewhere. Resolve it and verify its scheme and origin against the source contract. Some legitimate APIs use a separate download host; configure that allowed host explicitly and decide which credentials, if any, it should receive. Never blindly forward a bearer token across redirects.

Authentication failure should produce an actionable failed job. Repeating an unchanged invalid credential indefinitely consumes the rate limit and hides the actual problem. Refresh only when supported and bound the number of refresh attempts.

---

<a id="pagination"></a>

## 📚 3. Pagination Without Silent Gaps

| Pagination method | Typical state | Important limitation |
| --- | --- | --- |
| Offset/page number | Page index and page size | Concurrent writes can shift records across boundaries |
| Opaque cursor | Exact returned token and original query | Token may expire or be valid only for that query |
| Keyset | Last ordered key, often `(updated_at, id)` | Requires stable sort and matching comparison rules |
| Snapshot/export job | Export ID plus part list | Must wait for completion and reconcile all parts |

Follow the source's documented termination signal. An empty or short page is not universally the end. Detect repeated cursors and set limits on pages, total bytes, and elapsed time. Preserve the query and page size when required by the cursor contract.

For changing datasets, prefer a provider-supported snapshot or stable incremental cursor. A stable sort alone cannot compensate for a source that changes records behind the cursor. Where only timestamp polling exists, use an overlap window plus idempotent writes and periodic reconciliation; document what can still be missed.

The lab uses integer cursors `0`, `1`, and terminal `-1`. This is a simulation convention only. Its pages deliberately repeat one record with a newer version, demonstrating why destination identity differs from page identity.

---

<a id="retries"></a>

## 🔁 4. Rate Limits & Retry Policy

Separate failures you can retry from failures that require a change.

| Failure | Default action to consider |
| --- | --- |
| Timeout, reset, selected temporary server errors | Retry within an explicit attempt and elapsed-time budget |
| Rate-limit response | Honor source guidance and slow the shared source workload |
| Invalid authentication or permission | Stop or perform one documented refresh path |
| Invalid request or schema mismatch | Fail with context; repair request or contract |
| Corrupt or truncated response | Retry the safe read; never commit partial parsing as success |

HTTP `429` represents rate limiting and can include `Retry-After`. Providers can also publish their own limit headers and scopes; follow the source contract. [RFC 6585](https://www.rfc-editor.org/rfc/rfc6585#section-4)

Use bounded exponential backoff with jitter, for example a random delay between zero and `min(cap, base × 2^attempt)`. That spreads workers rather than making them all retry at the same instant. A source-specified wait is a minimum: wait at least that long, or defer/fail the job if it exceeds your budget. Do not cap it downward and immediately retry.

`Retry-After` may be a delay in seconds or an HTTP date. Account for clock skew when parsing dates. Retrying side-effecting requests requires the API's idempotency contract; a timeout does not establish that the server did nothing. [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html)

The lab exercises generic transient failures and full jitter with an injected wait function. It records intended waits without sleeping. It does **not** parse HTTP headers or implement OAuth, redirects, streaming response limits, or a live HTTP client.

Control the aggregate rate across workers. Ten individually polite workers can still overwhelm one account-level quota. Bound concurrency and track throttles, attempts, bytes, page count, and oldest uncollected data.

---

<a id="progress"></a>

## 📍 5. Watermarks & Commit Boundaries

An incremental extraction watermark means progress through a source. It is different from an event-time watermark used in streaming analytics.

For timestamp polling, use a stable tie-breaker such as `(updated_at, id)` when the source supports it. Declare timezone, precision, inclusive/exclusive boundaries, and behavior for corrections with unchanged timestamps. Capture an upper bound for each run when supported; otherwise the run may chase a moving target indefinitely.

**Advance progress only after the corresponding destination work is durable.** If records and progress share one transactional database, commit them together. If they live in different systems, design for replay: publish a complete batch, then advance the source checkpoint, and make reapplication safe. Do not claim atomicity across an object store and an unrelated SQL database.

The lab commits page rows and the next cursor in one SQLite transaction. A simulated failure after writes but before the checkpoint rolls the entire page back. After reopening the database, it resumes from the persisted cursor. Replaying both pages keeps three logical records because updates use stable keys and monotonic fixture versions.

Equal versions with different payloads should be treated as a contract violation in a production source. The lab assumes equal versions mean the same state. It does not implement deletes; use a deletion feed, explicit tombstones, or a complete snapshot comparison with a documented deletion policy.

---

<a id="files"></a>

## 📁 6. Changed Files & Partial Downloads

A filename alone is not a durable file identity. Prefer an immutable object version or producer manifest with a trusted checksum. Size and modification time are discovery hints; they can miss rewrites with the same size or timestamp resolution.

Track `(source, path, version or content digest)` and the destination batch that consumed it. Hash large files incrementally. If a producer changes a file during collection, either retrieve a pinned version or discard the attempt and restart from a stable export.

### Publication rule

Download into a job-owned `.part` file. Verify length, digest where supplied, parseability, and schema. Publish the final name only after those checks. Keep the old valid file until its replacement is complete. A changing file requires a new identity and replay policy, not just overwriting history.

### HTTP range recovery

Persist the validator and total size with the partial download. Resume only against that same representation. Use a byte range and a suitable `If-Range` validator; accept `206` only when `Content-Range` matches the requested start and expected representation. If the server returns `200`, replace the partial bytes instead of appending them. A `416` needs validation of the local size/version or a clean restart. Check the completed content before publication. [HTTP range and conditional request semantics](https://www.rfc-editor.org/rfc/rfc9110.html)

Keep content encoding stable for ranged bytes. Use safe generated local names rather than trusting remote paths. Limit both compressed and decompressed input size. The lab's byte-prefix comparison is **only a local simulation** of a version check; it is not an HTTP resume implementation and reads the small fixture into memory.

---

<a id="lab"></a>

## 🧪 7. Lab: Restartable Pages & File Recovery

The simulator combines two paginated responses, a transient failure, a transaction rollback, process-style database reopening, replay, partial bytes, a changed file, and a bad-checksum refusal. No remote system is contacted.

**Requirements:** Python 3.10+ with `sqlite3` available for the database labs. Only Python 3.12.14 was executed for this revision. No credentials, server, network requests, or third-party packages are used.

Save the following as `ingestion_lab.py` in a practice directory. It creates a temporary workspace and removes that workspace on completion. Run without Python's `-O` flag so assertions remain enabled.

```python
"""No HTTP requests: deterministic transport and partial-file simulation."""
import hashlib
import random
import sqlite3
import tempfile
from pathlib import Path


class Transient(Exception):
    pass


class Permanent(Exception):
    pass


def retry(call, wait, attempts=4, rng=None):
    rng = rng or random.Random()
    for attempt in range(attempts):
        try:
            return call()
        except Transient:
            if attempt == attempts - 1:
                raise
            wait(rng.uniform(0, min(8.0, 2.0 ** attempt)))


def database(path):
    db = sqlite3.connect(path)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY, version INTEGER, name TEXT);
        CREATE TABLE IF NOT EXISTS progress(singleton INTEGER PRIMARY KEY CHECK(singleton=1), cursor INTEGER);
        INSERT OR IGNORE INTO progress VALUES(1, 0);
    ''')
    return db


def ingest(db, fetch, wait, fail_page=None):
    cursor = db.execute('SELECT cursor FROM progress').fetchone()[0]
    seen = set()
    while cursor != -1:  # -1 is the simulator's terminal cursor, not an API convention.
        if cursor in seen:
            raise Permanent('pagination cycle')
        seen.add(cursor)
        page = retry(lambda: fetch(cursor), wait)
        nxt = page['next']
        if nxt != -1 and nxt in seen:
            raise Permanent('pagination cycle')
        with db:  # Rows and progress commit together in this single database.
            for row in page['rows']:
                db.execute('''INSERT INTO assets VALUES(?,?,?)
                    ON CONFLICT(id) DO UPDATE SET version=excluded.version, name=excluded.name
                    WHERE excluded.version > assets.version''', row)
            if cursor == fail_page:
                raise RuntimeError('simulated failure before checkpoint')
            db.execute('UPDATE progress SET cursor=? WHERE singleton=1', (nxt,))
        cursor = nxt


def publish_partial(part, final, remote, expected_hash):
    # A local stand-in for a validated range response; see the HTTP rules in the guide.
    # Production requires a pinned remote version, not a prefix comparison.
    if part.exists() and not remote.startswith(part.read_bytes()):
        part.unlink()  # Only this lab-owned incomplete file is discarded.
    offset = part.stat().st_size if part.exists() else 0
    with part.open('ab') as f:
        f.write(remote[offset:])
    if hashlib.sha256(part.read_bytes()).hexdigest() != expected_hash:
        raise ValueError('checksum mismatch: not published')
    part.replace(final)


def run(root):
    pages = {0: {'rows': [(1, 1, 'alpha'), (2, 1, 'beta')], 'next': 1},
             1: {'rows': [(2, 2, 'beta-new'), (3, 1, 'gamma')], 'next': -1}}
    calls, waits = [], []

    def fetch(cursor):
        calls.append(cursor)
        if len(calls) == 1:
            raise Transient('simulated 503')
        return pages[cursor]

    db = database(root / 'load.db')
    try:
        ingest(db, fetch, waits.append, fail_page=1)
    except RuntimeError:
        pass
    else:
        raise AssertionError('fault did not fire')
    assert db.execute('SELECT cursor FROM progress').fetchone()[0] == 1
    assert db.execute('SELECT version FROM assets WHERE id=2').fetchone()[0] == 1
    db.close()
    db = database(root / 'load.db')  # Restart using persisted progress.
    ingest(db, fetch, waits.append)
    assert db.execute('SELECT * FROM assets ORDER BY id').fetchall() == [
        (1, 1, 'alpha'), (2, 2, 'beta-new'), (3, 1, 'gamma')]
    with db:
        db.execute('UPDATE progress SET cursor=0')  # Explicit replay of the snapshot.
    ingest(db, fetch, waits.append)
    assert db.execute('SELECT COUNT(*) FROM assets').fetchone()[0] == 3
    assert len(waits) == 1 and 0 <= waits[0] <= 1
    db.close()
    failures = []

    def unavailable():
        failures.append(1)
        raise Transient('still unavailable')

    try:
        retry(unavailable, lambda delay: None)
    except Transient:
        pass
    assert len(failures) == 4
    permanent_calls = []

    def unauthorized():
        permanent_calls.append(1)
        raise Permanent('simulated 401')

    try:
        retry(unauthorized, lambda delay: None)
    except Permanent:
        pass
    assert len(permanent_calls) == 1
    part, final = root / 'data.part', root / 'data.jsonl'
    payload = b'{"id":1}\n{"id":2}\n'
    part.write_bytes(payload[:5])
    publish_partial(part, final, payload, hashlib.sha256(payload).hexdigest())
    assert final.read_bytes() == payload and not part.exists()
    original_hash = hashlib.sha256(final.read_bytes()).hexdigest()
    changed = payload + b'{"id":3}\n'
    assert hashlib.sha256(changed).hexdigest() != original_hash
    part.write_bytes(b'old version prefix')
    publish_partial(part, final, changed, hashlib.sha256(changed).hexdigest())
    assert final.read_bytes() == changed
    try:
        publish_partial(part, final, changed, 'incorrect checksum')
    except ValueError:
        pass
    else:
        raise AssertionError('bad checksum published')
    assert final.read_bytes() == changed
    print('PASS: bounded retry; permanent failure; rollback/restart; replay=3 rows; partial resume; changed file; checksum gate')


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='phase2-ingestion-') as folder:
        run(Path(folder))
```

Run:

```bash
python3 ingestion_lab.py
```

On Windows, use `py -3 ingestion_lab.py` if that is how Python is installed. The Windows launcher was not tested here.

**Actual output from this revision:**

```text
PASS: bounded retry; permanent failure; rollback/restart; replay=3 rows; partial resume; changed file; checksum gate
```

---

<a id="operations"></a>

## 💥 8. Failure Drills & Operational Checks

| Drill | Correct behavior |
| --- | --- |
| Fail after destination writes but before page commit | No partial page or advanced cursor remains |
| Replay a completed snapshot | No duplicated logical records |
| Return the same next cursor repeatedly | Stop with a pagination error |
| Keep returning a transient error | Exhaust the budget and report failure |
| Replace a remote object during download | Reject the version mismatch and restart safely |
| Lose access to part of the source | Flag completeness uncertainty; do not report an empty dataset as confirmed deletion |

Before declaring an integration ready, reconcile a known source export, test token expiry, observe actual rate-limit behavior, interrupt a real transfer, and confirm alerts reach the operator. Measure source-to-destination lag separately from job runtime.

**Self-check:** Why is a cursor not a record identity? What remains durable after a failed page? What happens when the source cursor expires? How do you know a file is complete? Can a same-sized file have changed?

---

<a id="verification"></a>

## ✅ Verification Record

| Check | Result |
| --- | --- |
| Transient retry plus permanent-error non-retry | Passed |
| Persistent failure exhausts four attempts | Passed |
| Failed second page rolls back; reopened database resumes | Passed |
| Full replay retains three current records | Passed |
| Partial content completion and changed-file replacement | Passed in local simulation |
| Bad digest prevents publication | Passed |
| Cursor-cycle guard | Implemented, not fault-injected in this revision |
| Live HTTP, authentication, headers, ranges, throttling, large files | Not executed |

This lab is a recovery-policy demonstration. Implement and verify the real transport adapter against the actual API before using it for live ingestion.

---

<a id="related"></a>

## 🤝 Contributing & Related Guides

For a correction, include the section, a synthetic reproducer, your runtime versions, expected behavior, and observed output. Update the Verification Record only for checks you actually perform. Keep credentials and customer records out of examples.

- [🗄️ Data Storage & File Formats](./data_storage_file_formats.md)
- [⚙️ Workflow Orchestration](./workflow_orchestration.md)
- [🌊 Streaming & Change Data Capture](./streaming_cdc.md)
- [Phase 2 Index](./readme.md)
- [Phase 1 Fundamentals](../Phase1/data_engineering_fundamentals.md)
- [Data Engineering Overview](../README.md)
- [Repository Home](../../README.md)

**[⬆ Back to Contents](#contents)**
