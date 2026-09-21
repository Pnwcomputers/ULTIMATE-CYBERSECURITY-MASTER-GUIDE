# 🧪 Pipeline Testing & CI/CD

<div align="center">

**Test data behavior, control changes, and promote reproducible releases with evidence**

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

**Purpose:** Make pipeline changes reviewable and repeatable without promoting an apparently successful test
into an unsupported production guarantee.

**Function:** Layer unit, integration, contract, and recovery tests; build useful synthetic fixtures; pin
dependencies; define review gates; and stage releases. Exercise a small loader with eight tests and a
deliberate faulty transformation.

**Goal:** Demonstrate that a proposed change preserves data meaning and failure behavior, then release the
tested artifact through controlled environments.

**When to use:** Refactoring a loader, changing a schema, upgrading a dependency, moving to another database,
or adding continuous integration and continuous delivery (CI/CD).

**Prerequisites:** [Python Processing](../Phase1/python_data_processing.md), [Quality &
Contracts](../Phase1/data_quality_schema_contracts.md), and [Workflow
Orchestration](../Phase2/workflow_orchestration.md).

---

<a id="contents"></a>

## 📋 Table of Contents

- [🧱 1. Test the Appropriate Boundary](#layers)
- [🧬 2. Synthetic Fixtures & Invariants](#fixtures)
- [📜 3. Schema & Compatibility Gates](#schemas)
- [📦 4. Dependency Pinning & Build Identity](#dependencies)
- [🚧 5. Review Gates & CI Trust Boundaries](#gates)
- [🚀 6. Staged Releases & Rollback](#release)
- [🧪 7. Lab: Unit Tests, Integration & Mutation](#lab)
- [⚙️ 8. Optional GitHub Actions Example — Not Run Remotely](#ci)
- [✅ Verification Record & Self-Check](#verification)
- [Contributing & Related Guides](#related)

---

<a id="layers"></a>

## 🧱 1. Test the Appropriate Boundary

| Layer | Example question | Environment |
| --- | --- | --- |
| Unit | Does normalization preserve `001` and zero? | Pure functions and tiny fixtures |
| Contract | Are required, nullable, extra, and changed fields handled correctly? | Versioned schemas and representative records |
| Integration | Do rows and progress commit or roll back together? | Real target engine or a clearly labeled substitute |
| End-to-end | Can the source-to-publication path produce the intended result? | Isolated connected services |
| Recovery | What happens after a crash, replay, or partial write? | Fault injection with disposable state |
| Performance | Does the workload fit latency and resource limits? | Representative volume and system configuration |

Mocking a database cursor can test control flow but cannot prove database transaction behavior. SQLite can
test a local transaction pattern; it cannot certify PostgreSQL isolation, cloud warehouse merges, or
distributed concurrency.

Keep tests tied to requirements and failure modes. A test that copies the implementation's formula may repeat
its mistake. Use independently known expected results, known invalid cases, and invariants such as unchanged
state after replay.

Python's `unittest` provides discovery, fixtures, assertions, and subtests without another dependency. The lab
uses those facilities for an executable baseline. [Python
unittest](https://docs.python.org/3/library/unittest.html)

---

<a id="fixtures"></a>

## 🧬 2. Synthetic Fixtures & Invariants

Design fixtures from the boundaries of the contract, not from the easiest data to generate.

| Fixture | Expected behavior to specify |
| --- | --- |
| Leading-zero identifier | Remains a string with identity preserved |
| Zero measurement | Remains a valid value; not treated as missing |
| Null or absent field | Handled according to distinct contract rules |
| Boolean in an integer field | Accepted or rejected explicitly; Python treats bool as an int subclass |
| Duplicate key | Rejected, merged, or quarantined under a declared policy |
| Empty batch | Records a legitimate empty outcome or fails an expected-arrival check |
| Reordered independent rows | Produces the same logical result |
| Interrupted write | Leaves no uncommitted partial state |

Use fixed timestamps, stable seeds, and temporary workspaces. Avoid reliance on today's date, row return order
without `ORDER BY`, or a public service that changes during a test.

Useful invariants include replay idempotence, conservation of classified input counts, referential integrity,
and deterministic outputs for pinned inputs. An invariant must match the design: sorting an event stream
arbitrarily is not valid if event order carries meaning.

Small synthetic fixtures are safe to publish and easy to understand, but they do not replace coverage of
production distributions. Derive edge cases from real incidents without copying customer payloads into source
control.

---

<a id="schemas"></a>

## 📜 3. Schema & Compatibility Gates

A schema check must validate values and semantics, not only whether JSON parses. Explicitly test field
presence, nullability, ranges, timestamp rules, identity, and unknown-field handling.

For a schema change, evaluate both old consumers with new data and new consumers with retained old data.
Adding an optional field can still break a strict consumer. A type-preserving change in units or meaning can
be more damaging than a parse error.

Keep contracts versioned with fixtures and an owner. A breaking change needs a migration plan, coordinated
rollout, and a retirement condition for the old representation. For shared databases, expand/contract
migration can preserve an overlap window: add the compatible representation, migrate readers/writers, then
remove the old form only after compatibility is established.

The lab uses an intentionally strict two-field record contract. It rejects unknown fields. It does not
implement a general schema registry or a compatibility checker; use the [Phase 1 contract
guide](../Phase1/data_quality_schema_contracts.md) for that broader pattern.

---

<a id="dependencies"></a>

## 📦 4. Dependency Pinning & Build Identity

Reproducibility depends on more than top-level package names. Record the Python version, transitive
dependencies, native libraries, base image or runner environment, build configuration, and source commit.

For a pip-based project, exact versions plus hashes can constrain what is installed. Hash-checking mode
requires pinned requirements and hashes for the requirements being installed; include transitive dependencies
and account for platform-specific wheels. Keep the lock generation and update process reviewed. [pip secure
installs](https://pip.pypa.io/en/stable/topics/secure-installs/)

```bash
python -m pip install --require-hashes -r requirements.lock
```

This command is a production-project pattern, **not a command required by the lab**. No `requirements.lock` is
supplied, because the lab has no third-party dependencies. Generate the lock from the actual project and
trusted package sources; do not invent hashes.

Pinning preserves a chosen dependency set; it does not make that set safe forever. Review updates, scan
dependencies where applicable, and retest meaningful behavior. Avoid mixing untrusted package indexes or
allowing the same internal package name to resolve unpredictably from public and private sources.

Give each release an immutable artifact identity or digest, source revision, contract version, and test
result. Promote that same artifact; rebuilding separately for production can introduce untested differences.

---

<a id="gates"></a>

## 🚧 5. Review Gates & CI Trust Boundaries

Define a gate by evidence, not by its name.

| Gate | Evidence before promotion |
| --- | --- |
| Source review | Logic, schema implications, permissions, and operational changes understood |
| Automated tests | Relevant units, contracts, integration and recovery checks passed |
| Build identity | Exact source and dependencies traceable to artifact |
| Staging validation | Target system behavior and representative data confirmed |
| Release readiness | Rollback/recovery procedure and owner identified |

Treat pull-request code as untrusted until reviewed. Use read-only repository permissions for ordinary tests,
keep production secrets out of those jobs, and avoid running untrusted contributions on a privileged
persistent runner. Pin reusable actions to reviewed immutable commits and keep workflow changes under review.
[GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)

Do not let a skipped or failed test job appear as a passed release gate. Confirm that required checks cover
the intended changes. Separate build/test credentials from deployment credentials, and make the promotion
environment enforce its own permissions.

A cache is an acceleration aid, not the authority for what dependencies should be installed. Partition cache
trust appropriately and verify the resolved environment. Never restore an untrusted executable cache into a
privileged release job without a defensible verification path.

---

<a id="release"></a>

## 🚀 6. Staged Releases & Rollback

A useful progression is: local fixture tests, isolated integration, staging or shadow output, constrained
production exposure, then broad promotion. Use the same artifact identity throughout.

Compare a candidate output with the existing version before redirecting consumers. For pipelines, a canary can
be a limited source partition or a shadow destination; publishing half a schema migration to a shared table is
not a safe canary by itself.

| Before release | During release | After release |
| --- | --- | --- |
| Pin inputs and artifact; record baseline | Observe rejects, lag, reconciliation, resource use | Confirm consumer results and retain rollback evidence |
| Define stop thresholds | Halt on integrity or compatibility failure | Retire old version after the agreed window |
| Rehearse recovery | Preserve source history and previous outputs | Update runbook and release record |

Rolling back code may not reverse data already written. If a new version changed schema, destroyed
information, or emitted external effects, recovery can require a compensating migration, restoring a previous
output version, or replay. Document this before deployment.

For backfills triggered by a release, state the historical range, input version, resource budget, and consumer
correction policy. See [Backup, Replay & Disaster Recovery](./data_recovery_replay.md).

---

<a id="lab"></a>

## 🧪 7. Lab: Unit Tests, Integration & Mutation

Eight tests cover identifier and zero preservation, contract rejects, persistence, replay, rollback, duplicate
input, ordering, and an empty batch. A separate deliberate mutation coerces an identifier to an integer and
confirms that the expected-result assertion detects it.

**Requirements:** Python 3.10+; the testing and recovery labs also use Python's `sqlite3` module. This
revision was executed on Python 3.12.14 and SQLite 3.53.1 only. All data is synthetic; no server, credentials,
network calls, or third-party dependencies are required.

Save as `testing_lab.py` and run without Python's `-O` flag, because the standalone drills use assertions.
File-based fixtures use temporary directories that are removed on completion.

```python
"""Unit and SQLite integration tests with a deliberate mutation check."""
import sqlite3
import tempfile
import unittest
from pathlib import Path


def normalize(row):
    if set(row) != {'id', 'value'}:
        raise ValueError('unexpected contract')
    if not isinstance(row['id'], str) or not row['id']:
        raise ValueError('id must be a nonempty string')
    # bool is a subclass of int; it is not a valid measurement in this contract.
    if type(row['value']) is not int or row['value'] < 0:
        raise ValueError('value must be a nonnegative integer')
    return row['id'], row['value']


def connect(path):
    db = sqlite3.connect(path)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS result(id TEXT PRIMARY KEY, value INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS runs(batch TEXT PRIMARY KEY, row_count INTEGER);
    ''')
    return db


def load(db, rows, batch, fail=False):
    # Snapshot-style upserts. No deletion inference; batch IDs are immutable by contract.
    parsed = [normalize(row) for row in rows]
    if len({key for key, _ in parsed}) != len(parsed):
        raise ValueError('duplicate key within batch')
    with db:
        db.executemany('''INSERT INTO result VALUES(?,?)
            ON CONFLICT(id) DO UPDATE SET value=excluded.value''', parsed)
        if fail:
            raise RuntimeError('injected failure')
        db.execute('INSERT OR REPLACE INTO runs VALUES(?,?)', (batch, len(parsed)))


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='phase3-tests-')
        self.path = Path(self.tmp.name) / 'test.db'
        self.db = connect(self.path)
        self.rows = [{'id': '001', 'value': 0}, {'id': '002', 'value': 8}]

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_zero_and_identifier(self):
        self.assertEqual(normalize(self.rows[0]), ('001', 0))

    def test_contract_rejections(self):
        for row in ({'id': 'x', 'value': True}, {'id': 'x', 'value': -1},
                    {'id': 'x', 'value': None}, {'id': '', 'value': 2},
                    {'id': 'x'}, {'id': 'x', 'value': 1, 'extra': 2}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                normalize(row)

    def test_commit_and_reopen(self):
        load(self.db, self.rows, 'b1')
        self.db.close()
        self.db = connect(self.path)
        self.assertEqual(self.db.execute('SELECT * FROM result ORDER BY id').fetchall(),
                         [('001', 0), ('002', 8)])

    def test_replay(self):
        load(self.db, self.rows, 'b1')
        load(self.db, self.rows, 'b1')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM result').fetchone()[0], 2)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM runs').fetchone()[0], 1)

    def test_rollback(self):
        with self.assertRaises(RuntimeError):
            load(self.db, self.rows, 'b1', fail=True)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM result').fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM runs').fetchone()[0], 0)

    def test_duplicate_refused(self):
        with self.assertRaises(ValueError):
            load(self.db, self.rows + self.rows, 'b1')

    def test_order_invariance(self):
        load(self.db, list(reversed(self.rows)), 'b1')
        self.assertEqual(self.db.execute('SELECT SUM(value) FROM result').fetchone()[0], 8)

    def test_empty_snapshot(self):
        load(self.db, [], 'empty')
        self.assertEqual(self.db.execute('SELECT row_count FROM runs').fetchone()[0], 0)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PipelineTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    # Deliberate faulty implementation: coercing identifiers loses leading zeros.
    def mutant(row):
        return str(int(row['id'])), row['value']
    try:
        unittest.TestCase().assertEqual(mutant({'id': '001', 'value': 0}), ('001', 0))
    except AssertionError:
        print('PASS: 8 tests; deliberate identifier mutation detected')
    else:
        raise SystemExit('FAIL: mutation survived')
```

```bash
python3 testing_lab.py
```

On Windows, `py -3 testing_lab.py` may be the appropriate launcher. Windows execution was not tested here.

**Actual summary output:**

```text
PASS: 8 tests; deliberate identifier mutation detected
```

---

<a id="ci"></a>

## ⚙️ 8. Optional GitHub Actions Example — Not Run Remotely

To use the lab as a CI exercise, save its complete Python block as `tests/test_pipeline.py` in a practice
repository. Its `PipelineTests` class is discoverable; its `__main__` mutation demonstration runs only when
executing the file directly.

Run these locally before configuring CI:

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
python tests/test_pipeline.py
```

The example below belongs at `.github/workflows/pipeline-tests.yml` in that practice repository. It is **an
optional configuration example**, not an installed workflow in this documentation package. It requires the
test file described above.

```yaml
name: Pipeline fixture tests
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065
        with:
          python-version: '3.12'
      - run: python -m unittest discover -s tests -p 'test_*.py' -v
      - run: python tests/test_pipeline.py
```

The commits were resolved from the `v4` checkout and `v5` setup-python tags on the review date: [checkout
commit](https://github.com/actions/checkout/commit/11d5960a326750d5838078e36cf38b85af677262), [setup-python
commit](https://github.com/actions/setup-python/commit/a26af69be951a213d495a4c3e4e4022e16d87065). Review
updates before changing those pins.

The hosted runner image and Python minor-version selector can still change. This example is suitable for
fixture CI, not a claim of a fully hermetic build. It performs no deployment and receives no explicitly
configured secrets. Repository rules and production approval gates must be configured separately.

---

<a id="verification"></a>

## ✅ Verification Record & Self-Check

| Check | Result |
| --- | --- |
| Eight unittest methods, including contract subtests | Passed |
| Local CI unittest discovery command | Passed: 8 tests |
| SQLite persistence, rollback and replay | Passed |
| Deliberate leading-zero mutation | Detected |
| Optional workflow action references | Resolved to commit IDs on the review date |
| GitHub Actions execution, deployment, required-check enforcement | Not executed |
| Another database, large workloads, package-lock installation | Not executed |

**Self-check:** Which failure would survive your tests? Does a mock prove real transaction behavior? Can a
dependency update alter data meaning? Can a release rollback undo its writes? Do pull-request tests have
access to production secrets?

The loader assumes immutable batch identities and fixed snapshots. It does not reject a reused batch ID with
different data, infer deletions, or resolve out-of-order updates. Production code must enforce its own batch
and version contracts.

---

<a id="related"></a>

## 🤝 Contributing & Related Guides

For corrections, provide a synthetic reproducer, runtime versions, expected behavior, and actual results.
Update verification claims only for checks performed. Keep secrets and customer records out of examples.

- [📊 Pipeline Observability & Reliability](./pipeline_observability.md)
- [🔐 Data Governance, Lineage & Access](./data_governance_lineage.md)
- [♻️ Backup, Replay & Disaster Recovery](./data_recovery_replay.md)
- [Phase 3 Index](README.md)
- [Phase 2 Storage & Integration](../Phase2/README.md)
- [Data Engineering Overview](../README.md)

---

[⬆ Back to Contents](#contents) | [⬅️ Master Index](../../README.md) | [🎯 Role
Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
