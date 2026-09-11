# 📊 Pipeline Observability & Reliability

<div align="center">

**Measure whether consumers receive complete, correct, timely data—and make failures actionable**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md)*

![Phase](https://img.shields.io/badge/Phase_3-Operations_%26_Governance-blue?style=for-the-badge)
![Lab](https://img.shields.io/badge/Local_Lab-Verified-darkgreen?style=for-the-badge)

**[Phase 3 Index](./readme.md) · [Data Engineering Overview](../README.md)**

</div>

_Last reviewed: 2026-09-11. Local lab executed on Python 3.12.14 and SQLite 3.53.1 where used. The
Verification Record limits the claim to the checks performed._

Terms are defined at first use; see also the repository [Glossary](../../GLOSSARY.md).


---

<a id="purpose"></a>

## 🎯 Purpose, Function & Goal

**Purpose:** Define reliability from the consumer's perspective and provide enough evidence to distinguish a
broken source, a delayed pipeline, an incorrect result, and a broken monitor.

**Function:** Specify freshness, throughput, lag, service level indicators, error budgets, alerts,
reconciliation, runbooks, and recovery drills. Calculate a small synthetic reliability report and exercise
failure detection.

**Goal:** Turn “the job ran” into an evidence-based answer about whether the right data arrived on time and
what to do if it did not.

**When to use:** Operating a recurring import, responding to stale reports, defining reliability targets, or
reducing noisy alerts.

**Prerequisites:** [ETL & ELT](../Phase1/etl_elt_pipeline_design.md), [Quality &
Contracts](../Phase1/data_quality_schema_contracts.md), and [Workflow
Orchestration](../Phase2/workflow_orchestration.md).

---

<a id="contents"></a>

## 📋 Table of Contents

- [📐 1. Define the Signals Before the Dashboard](#signals)
- [🎯 2. Service Levels & Error Budgets](#slo)
- [🛠️ 3. Instrument the Boundaries](#instrumentation)
- [🚨 4. Alert on Actionable Outcomes](#alerts)
- [🧾 5. Reconciliation Proves More Than Counts](#reconcile)
- [📘 6. Runbooks & Recovery Drills](#runbook)
- [🧪 7. Lab: Reliability Budget & Failure Detection](#lab)
- [✅ Verification Record & Self-Check](#verification)
- [Contributing & Related Guides](#related)

---

<a id="signals"></a>

## 📐 1. Define the Signals Before the Dashboard

| Signal | Example definition | What it does not prove |
| --- | --- | --- |
| **Freshness** | Evaluation time minus newest valid event time in the published dataset | That all older events are present |
| **Publication age** | Evaluation time minus last successful publication time | That the published source was current |
| **Ingestion lag** | Arrival time minus source event time | Time spent in later transformations |
| **End-to-end lag** | Queryable time minus source event time | Completeness of every source record |
| **Throughput** | Accepted records or bytes per elapsed second | Correctness or uniqueness |
| **Backlog** | Unprocessed records, partitions, or source positions | How quickly it will drain |
| **Reject rate** | Rejected input records divided by evaluated input records | Whether accepted records are accurate |

State which timestamp and unit each metric uses. A maximum timestamp can be distorted by a single future-dated
event; validate clock assumptions and report suspicious values rather than turning them into negative lag or
false health.

For a naturally quiet source, absence of new events may be expected. Separate an expected-arrival rule from
freshness. Use a source heartbeat or completed-export signal where appropriate, and keep synthetic heartbeats
distinguishable from real business data.

Example: a report published at 10:00 from a source frozen at 07:00 has a recent publication but old source
data. Monitor both. For multiple sources or partitions, avoid allowing one healthy contributor to hide another
stale one.

---

<a id="slo"></a>

## 🎯 2. Service Levels & Error Budgets

A **service level indicator (SLI)** measures a defined outcome. A **service level objective (SLO)** sets its
target over a declared window. A contractual service level agreement is a separate commitment; an internal SLO
is not automatically a customer promise.

For a batch dataset, define an eligible logical interval and call it good only if its publication is on time
and required quality checks pass. Count the interval once; retries are attempts, not extra opportunities to
inflate the denominator. Agree on ownership and consumer needs before choosing the target. [Google SRE:
Implementing SLOs](https://sre.google/workbook/implementing-slos/)

For an eligible count `N`, bad count `B`, and target fraction `T`:

```text
good fraction = (N - B) / N
allowed bad outcomes = N * (1 - T)
remaining budget = allowed bad outcomes - B
burn rate = (B / N) / (1 - T)
```

The lab uses 100 scheduled observations and a 99% target. Two are bad, including one missing observation. The
allowance is one, remaining budget is negative one, and burn rate is two. These are fictional teaching values,
not recommended production thresholds.

Declare the missing-data policy. This lab counts a missing expected observation as bad, while separately
marking current monitoring health unknown. Excluding missing samples from the denominator would make an
unavailable monitor improve the score. If there are zero eligible observations, report “not evaluated” rather
than 100% success.

Small denominators make percentages coarse. A monthly batch job has too few runs for a meaningful fine-grained
success percentage; a deadline-based objective or a longer observation window may communicate reliability more
clearly. Keep event-based and time-based objectives separate.

---

<a id="instrumentation"></a>

## 🛠️ 3. Instrument the Boundaries

Instrument source collection, validation, transformation, sink commit, and publication separately. Record how
much entered each stage and what left it. Export a last-success timestamp rather than a continually
incremented “seconds since success” value that can freeze if the job stops. Keep high-cardinality details such
as run IDs in logs or traces, not ordinary metric labels. [Prometheus instrumentation
guidance](https://prometheus.io/docs/practices/instrumentation/)

| Evidence | Useful fields |
| --- | --- |
| Run log | Job, logical interval, run/attempt ID, code version, source snapshot, outcome |
| Stage metrics | Input/output/reject counts, elapsed time, last completion, queue depth |
| Publication record | Dataset version, manifest identity, quality status, publication time |
| Trace or correlation record | Source request, batch, processing stages, sink commit |
| Monitor health | Last observation time, collection failures, rule evaluation status |

Avoid logging credentials or entire rejected records by default. Put sensitive diagnostic payloads in
restricted quarantine with a reference from the log. Redaction must cover exception text and request URLs as
well as normal messages.

Measure durations with a monotonic clock; use timezone-aware wall-clock timestamps for cross-system events and
investigation. Do not subtract unsynchronized clocks without understanding the resulting error.

For counter metrics, account for process resets in the monitoring system. A zero throughput value means
something different from a missing time series. A collector outage must not be interpreted as a confirmed idle
source.

---

<a id="alerts"></a>

## 🚨 4. Alert on Actionable Outcomes

A page should identify an urgent consumer impact and a response that someone can perform. A ticket can address
slower degradation. A dashboard can support investigation without notifying anyone.

| Condition | Possible response |
| --- | --- |
| Critical publication deadline missed | Page the dataset operator with interval and runbook |
| Sustained reject growth without immediate impact | Ticket the producer/contract owner |
| Monitor stops reporting | Alert on monitoring health; do not declare the pipeline healthy |
| Rapid budget consumption | Investigate active degradation and constrain risky changes |
| Forecast storage exhaustion | Capacity action before writes fail |

Burn-rate alerting relates observed bad outcomes to the permitted error rate. Combining longer and shorter
windows can identify sustained budget consumption while allowing alerts to resolve when the immediate problem
ends. Thresholds need to match the observation model and response time. [Google SRE: Alerting on
SLOs](https://sre.google/workbook/alerting-on-slos/)

The lab demonstrates only a two-number Boolean gate. It does not collect rolling windows, deduplicate alerts,
handle maintenance windows, or send a page. Its chosen threshold of four is illustrative.

Every operational alert should carry: dataset, environment, affected interval, observed value, threshold,
observation time, owner, runbook, and a link to restricted diagnostic evidence. Group downstream symptoms when
one upstream incident is the cause, without hiding distinct impacts.

Test the complete route from failed condition to notification delivery and acknowledgement. A correct rule
with a broken receiver is not an operational alert. Record legitimate quiet periods and maintenance exclusions
explicitly; do not retroactively exclude failures merely to improve the SLO.

---

<a id="reconcile"></a>

## 🧾 5. Reconciliation Proves More Than Counts

Compare like with like: the same source snapshot, filter, key, interval, transformation version, and deletion
rules. A moving source can make a correct sink look inconsistent.

| Check | Detects | Limitation |
| --- | --- | --- |
| Total count | Gross loss or excess | Different records can have equal counts |
| Key multiset | Missing, unexpected, or repeated identities | Payloads may still differ |
| Keyed payload comparison | Changed values | Requires compatible normalization |
| Aggregate comparison | Some calculation or mapping errors | Different errors may cancel |
| Trusted digest/manifest | Byte integrity or a defined canonical representation | Does not establish the truth of an untrusted source |

Account for all input outcomes: accepted, rejected, filtered, duplicate, and deferred. State whether counts
represent physical input events or current logical rows. Upserts and deletes mean a current-state row count
may legitimately differ from the number of consumed events.

The lab deliberately compares `[1, 2]` with `[1, 3]`. Counts agree; identities do not. Its `Counter`
comparison is suitable for a tiny fixture. For large datasets, use partitioned comparisons, anti-joins, or
hierarchical checks with explicit collision and normalization assumptions.

---

<a id="runbook"></a>

## 📘 6. Runbooks & Recovery Drills

A runbook should lead an operator from a symptom to a verified recovery boundary.

| Runbook field | What to record |
| --- | --- |
| Trigger and impact | Which consumer promise failed? |
| Scope | Environment, dataset, interval, source and output versions |
| First checks | Monitor health, source freshness, last successful commit, queue state |
| Containment | Pause publication or isolate a bad version when necessary |
| Recovery | Resume from a committed checkpoint, restore, or rebuild a stated range |
| Stop conditions | Missing history, unknown schema, conflicting writers, integrity failure |
| Verification | Reconciliation, freshness, access, and consumer readiness |
| Ownership | Operator, escalation owner, and communication responsibility |

Before re-running a job, inspect its last durable checkpoint and the destination. Preserve evidence of partial
outcomes. A retry is not a universal repair for a schema change, missing source history, or a corrupted
backup.

Run drills in an isolated environment: stop a producer, suppress an observation, inject a bad record,
interrupt a write, and restore a selected interval. Measure detection, acknowledgement, diagnosis, recovery,
and validation time separately. Turn gaps into assigned corrective work, then repeat the relevant drill. See
[Backup, Replay & Disaster Recovery](./data_recovery_replay.md).

---

<a id="lab"></a>

## 🧪 7. Lab: Reliability Budget & Failure Detection

Calculate a scheduled-observation budget, detect stale and unknown monitoring states, reject future
timestamps, and catch equal-count reconciliation errors.

**Requirements:** Python 3.10+; the testing and recovery labs also use Python's `sqlite3` module. This
revision was executed on Python 3.12.14 and SQLite 3.53.1 only. All data is synthetic; no server, credentials,
network calls, or third-party dependencies are required.

Save as `observability_lab.py` and run without Python's `-O` flag, because the standalone drills use
assertions. File-based fixtures use temporary directories that are removed on completion.

```python
"""Synthetic monitoring samples; no metrics server or notification traffic."""
from collections import Counter
from decimal import Decimal


def budget(expected_slots, samples, target):
    if not expected_slots or not Decimal('0') < target < Decimal('1'):
        raise ValueError('nonempty schedule and target between zero and one required')
    if len(set(expected_slots)) != len(expected_slots):
        raise ValueError('duplicate scheduled slot')
    # A missing expected sample is bad for this explicitly chosen SLI policy.
    good = sum(samples.get(slot) is True for slot in expected_slots)
    total = len(expected_slots)
    bad = total - good
    allowed = Decimal(total) * (1 - target)
    return {'total': total, 'bad': bad, 'allowed': allowed,
            'remaining': allowed - bad,
            'burn': (Decimal(bad) / total) / (1 - target)}


def health(now, latest_source, latest_published, observed_at, source_ids, sink_ids):
    if observed_at is None:
        return {'unknown': True, 'reasons': ['missing observation']}
    if observed_at > now or any(t is not None and t > now
                               for t in (latest_source, latest_published)):
        raise ValueError('future timestamp: investigate clocks or source contract')
    reasons = []
    if now - observed_at > 120:
        reasons.append('monitor stale')
    if latest_published is None or now - latest_published > 300:
        reasons.append('publication stale')
    if latest_source is not None and latest_published is not None:
        if latest_source - latest_published > 120:
            reasons.append('source-to-sink lag')
    # Fixture identities are authoritative and refer to the same closed snapshot.
    if Counter(source_ids) != Counter(sink_ids):
        reasons.append('reconciliation mismatch')
    return {'unknown': 'monitor stale' in reasons, 'reasons': reasons}


def run():
    expected = list(range(100))
    samples = {slot: True for slot in expected}
    samples[41] = False
    del samples[77]
    b = budget(expected, samples, Decimal('0.99'))
    assert b == {'total': 100, 'bad': 2, 'allowed': Decimal('1.00'),
                 'remaining': Decimal('-1.00'), 'burn': Decimal('2')}
    assert budget([1], {}, Decimal('0.99'))['bad'] == 1
    try:
        budget([], {}, Decimal('0.99'))
    except ValueError:
        pass
    else:
        raise AssertionError('empty denominator accepted')
    assert health(1000, 980, 980, 995, [1, 2], [1, 2])['reasons'] == []
    assert 'reconciliation mismatch' in health(
        1000, 980, 980, 995, [1, 2], [1, 3])['reasons']
    assert 'publication stale' in health(1400, 1380, 980, 1395, [1], [1])['reasons']
    assert 'source-to-sink lag' in health(1400, 1380, 980, 1395, [1], [1])['reasons']
    assert health(1000, 980, 980, None, [], [])['unknown']
    assert health(1000, 980, 980, 700, [], [])['unknown']
    try:
        health(1000, 1100, 980, 995, [], [])
    except ValueError:
        pass
    else:
        raise AssertionError('future timestamp accepted')
    # Illustrative two-window policy; thresholds are fixture choices, not defaults.
    def page(long_burn, short_burn):
        return long_burn >= 4 and short_burn >= 4
    assert page(5, 6) and not page(5, 1) and not page(1, 6)
    print('PASS: 100 slots; 2 bad including 1 missing; budget=1; burn=2; stale/unknown/future checks; equal-count mismatch; dual-window gate')


if __name__ == '__main__':
    run()
```

```bash
python3 observability_lab.py
```

On Windows, `py -3 observability_lab.py` may be the appropriate launcher. Windows execution was not tested here.

**Actual summary output:**

```text
PASS: 100 slots; 2 bad including 1 missing; budget=1; burn=2; stale/unknown/future checks; equal-count mismatch; dual-window gate
```

---

<a id="verification"></a>

## ✅ Verification Record & Self-Check

| Check | Result |
| --- | --- |
| Missing expected observation consumes budget | Passed |
| 100 observations, 2 bad, 1 allowed, burn rate 2 | Passed |
| Empty denominator refused | Passed |
| Healthy, stale, missing-monitor, and future-time cases | Passed |
| Equal-count key mismatch | Passed |
| Illustrative two-window gate | Passed |
| Metrics server, rolling windows, paging, real recovery timings | Not executed |

**Self-check:** What belongs in the denominator? Can one fresh record hide missing history? What does an
absent monitor mean? Can your alert identify an owner and a safe recovery action? What evidence lets you close
the incident?

The fixture compares source and published timestamps representing the same synthetic timeline. Real
multi-source lag needs source-specific semantics and clock validation.

---

<a id="related"></a>

## 🤝 Contributing & Related Guides

For corrections, provide a synthetic reproducer, runtime versions, expected behavior, and actual results.
Update verification claims only for checks performed. Keep secrets and customer records out of examples.

- [🧪 Pipeline Testing & CI/CD](./pipeline_testing_cicd.md)
- [🔐 Data Governance, Lineage & Access](./data_governance_lineage.md)
- [♻️ Backup, Replay & Disaster Recovery](./data_recovery_replay.md)
- [Phase 3 Index](./readme.md)
- [Phase 2 Storage & Integration](../Phase2/readme.md)
- [Data Engineering Overview](../README.md)

---

[⬆ Back to Contents](#contents) | [⬅️ Master Index](../../README.md) | [🎯 Role
Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
