
# 🛠️ Phase 3: Operations & Governance

<div align="center">

**Operate reliably, test changes, control access, and recover with evidence**

*Observability • Testing & CI/CD • Governance & Lineage • Backup & Replay*

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md)*

![Phase](https://img.shields.io/badge/Phase-3_Operations_%26_Governance-blue?style=for-the-badge)
![Labs](https://img.shields.io/badge/Local_Labs-4_Verified-darkgreen?style=for-the-badge)

**[Data Engineering Overview](../README.md) · [Phase 2 Storage & Integration](../Phase2/readme.md)**

</div>

_Last reviewed: 2026-09-11. Four local labs executed on Python 3.12.14 and SQLite 3.53.1 where used. See each guide's Verification Record for limits._

## 🎯 Purpose

Complete the learning path with the operational practices needed to keep data useful after the first successful run:
detect failures, validate changes, control data use, and rehearse recovery.

## ⚙️ Function

Connect reliability measures to runbooks, tests to release decisions, ownership to enforced boundaries, and backups
to verified replay. Each guide includes a local exercise, failure cases, self-check questions, and technical references.

## 🏆 Goal

Help practitioners support a dataset with evidence: who owns it, what a healthy outcome means, what changed,
who may access it, and which recovery procedure actually worked.

## 📋 When to Use

- Preparing an existing pipeline for ongoing operation.
- Responding to stale, incomplete, or incorrect results.
- Reviewing schema, dependency, access, or deployment changes.
- Planning a backup restore, historical rebuild, or recovery drill.

---

<a id="contents"></a>

## 📋 Table of Contents

- [Guide Index](#guides)
- [Prerequisites & Reading Order](#prerequisites)
- [Local Labs & Verification](#labs)
- [Operational Deliverables](#deliverables)
- [Completion Checklist](#checklist)
- [Contributing & Navigation](#navigation)

---

<a id="guides"></a>

## 📚 Guide Index

| # | Guide | Coverage | Lab |
| --- | --- | --- | --- |
| 1 | [Pipeline Observability & Reliability](./pipeline_observability.md) | Freshness, throughput, lag, service levels, error budgets, alerting, reconciliation, runbooks, and recovery drills | Synthetic monitoring and budget calculation; stale/unknown detection; equal-count mismatch |
| 2 | [Pipeline Testing & CI/CD](./pipeline_testing_cicd.md) | Unit and integration tests, synthetic fixtures, schema checks, dependency pinning, review gates, and staged releases | Eight unit/integration tests and a deliberate mutation; optional GitHub Actions example |
| 3 | [Data Governance, Lineage & Access](./data_governance_lineage.md) | Ownership, source lineage, sensitive fields, access boundaries, secrets, retention, deletion, and audit trails | Catalog, field-policy model, lineage impact, retention candidate report, and audit-chain checks |
| 4 | [Backup, Replay & Disaster Recovery](./data_recovery_replay.md) | Backups versus replication, restore exercises, replay boundaries, recovery objectives, deduplication, and rebuilding derived data | SQLite backup, isolated restore, replay, deletion protection, and derived rebuild |

---

<a id="prerequisites"></a>

## 🧭 Prerequisites & Reading Order

Start with [Phase 1](../Phase1/) and [Phase 2](../Phase2/readme.md). In particular, understand
[ETL & ELT](../Phase1/etl_elt_pipeline_design.md), [Quality & Contracts](../Phase1/data_quality_schema_contracts.md),
[Orchestration](../Phase2/workflow_orchestration.md), and [Streaming & CDC](../Phase2/streaming_cdc.md).

Read the guides in the order listed. Reliability defines outcomes, testing controls changes, governance establishes
responsibility and boundaries, and recovery brings those decisions together. The guides also work as standalone references.

Core labs target Python 3.10+; the database labs need Python's `sqlite3` module. Only Python 3.12.14 was executed here.
No cloud account, credentials, monitoring service, or CI runner is required for the local exercises.

---

<a id="labs"></a>

## 🧪 Local Labs & Verification

Save the complete Python block from a guide under its stated filename and run it with `python3 filename.py`.
Do not use Python's `-O` option: standalone drills use assertions. File-based labs create and clean up temporary directories.

| Guide | What was exercised | What was not exercised |
| --- | --- | --- |
| Observability | Budget math, missing/stale observations, timestamp guards, reconciliation | Metrics server, notification delivery, rolling-window collection |
| Testing | Eight unit/integration tests and deliberate mutation detection | Remote CI, production deployments, another database engine |
| Governance | Fictional permissions, lineage, retention candidates, audit checks | Authentication, real grants, deletion, legal compliance |
| Recovery | SQLite backup, isolated restore, replay and corruption/gap checks | Offsite failure, production recovery timing, failover/failback |

The optional GitHub Actions configuration is documentation, not an installed workflow. The governance example makes
no real access changes. Recovery claims are limited to the local fixture and do not establish a production RPO or RTO.

---

<a id="deliverables"></a>

## 📋 Operational Deliverables

| Deliverable | Minimum useful content |
| --- | --- |
| Reliability definition | Consumer outcome, indicator, target, window, missing-data policy |
| Alert and runbook | Trigger, owner, impact, safe checks, recovery and closure evidence |
| Release record | Source/artifact identity, tests, schema effects, rollout and rollback plan |
| Dataset record | Owner, sensitivity, lineage, approved uses, grants and retention |
| Recovery record | Base/checkpoint, retained history, keys, restore result and measured timing |

Keep these records versioned and assign owners. Completing a lab is a starting point for producing the corresponding
record for a real system, not proof that the live system already meets it.

---

<a id="checklist"></a>

## ✅ Completion Checklist

- [ ] Distinguish fresh publication from fresh source data.
- [ ] Define an SLI, its denominator, missing-data policy, and SLO window.
- [ ] Detect a reconciliation error even when row counts match.
- [ ] Connect an actionable alert to an owner and runbook.
- [ ] Test contracts, persistence, replay and rollback with synthetic data.
- [ ] Identify and promote a tested release artifact.
- [ ] Explain why rollback of code may not undo data changes.
- [ ] Assign dataset ownership and identify sensitive fields and downstream consumers.
- [ ] Test real access enforcement separately from policy modeling.
- [ ] Account for holds, copies, and restored deletion state.
- [ ] Distinguish backups, replicas, snapshots and replay logs.
- [ ] Restore in isolation, reconcile, and measure realistic recovery objectives.

---

<a id="navigation"></a>

## 🤝 Contributing & Navigation

Use synthetic reproductions, direct technical references, and honest verification records. Follow the
[style guide](../../STYLE_GUIDE.md) and [contribution guidance](../../.github/CONTRIBUTING.md).

Phase 3 documents belong in `Data-Engineering/Phase3/`. Sibling guides use `./`, earlier phases use `../Phase1/`
or `../Phase2/`, and repository-level resources use `../../`.

After these exercises, apply the practices to [Secure Data Pipelines & Security Automation](../data_pipelines.md)
or another pipeline you operate. This phase completes the planned documentation sequence; live-service validation
remains specific to each deployment.

---

[⬆ Contents](#contents) | [Data Engineering](../README.md) | [⬅️ Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
