# 🗄️ Data Engineering & Pipeline Infrastructure

<div align="center">

**Data ingestion, transformation, storage, streaming, quality, and repeatable infrastructure**

*General data engineering foundations with practical applications to cybersecurity and operational telemetry*

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Data Engineering](https://img.shields.io/badge/Discipline-Data_Engineering-blue?style=for-the-badge)
![Pipelines](https://img.shields.io/badge/Architecture-Batch_%7C_Streaming-darkgreen?style=for-the-badge)
![Security](https://img.shields.io/badge/Focus-Secure_%26_Reliable-purple?style=for-the-badge)
![Automation](https://img.shields.io/badge/Infrastructure-Versioned_%26_Repeatable-orange?style=for-the-badge)
![Phase 1](https://img.shields.io/badge/Phase_1-Published-success?style=for-the-badge)

</div>

---

_Index reviewed: 2026-09-11. Existing links checked against the repository. Phase 1 foundations are published in `Phase1/`; Phase 2 and Phase 3 remain proposed and are identified separately._

## 🎯 Purpose

Provide a central learning and reference section for building systems that collect, move, transform, store, and deliver useful data. The scope includes application records, API responses, database extracts, operational metrics, and security logs.

## ⚙️ Function

Organize data engineering knowledge across the full data lifecycle, link to relevant guides already in the repository, and outline recommended future documents. Security telemetry provides the first practical pipeline example, while the broader learning path extends to databases, analytical storage, data quality, and workflow orchestration.

## 🏆 Goal

Help practitioners build understandable, reliable, secure, and maintainable data pipelines—and explain where data came from, how it changed, whether it is complete, and how to recover when processing fails.

## 📋 When to Use

- Learning data engineering fundamentals alongside cybersecurity and infrastructure work.
- Moving data from files, APIs, applications, or databases into a central destination.
- Cleaning inconsistent records and designing a reusable event or dataset schema.
- Building batch jobs, event streams, or log aggregation pipelines.
- Replacing manual deployment and processing steps with repeatable workflows.
- Investigating missing records, stale data, duplicates, failed jobs, or unexpected storage growth.

---

<a id="contents"></a>

## 📋 Table of Contents

- [Overview & Scope](#overview)
- [Start Here: Choose Your Entry Point](#start-here)
- [Phase 1: Foundations](#phase-1)
- [Secure Data Pipelines](#secure-pipelines)
- [Existing Repository Resources](#existing-resources)
- [Core Data Engineering Categories](#categories)
- [Recommended Future Documents](#future-documents)
- [Learning & Implementation Workflow](#workflow)
- [Data Handling & Operational Practices](#data-handling)
- [Contributing](#contributing)
- [Quick Links](#quick-links)
- [Section Status](#section-status)

---

<a id="overview"></a>

## 🎯 Overview & Scope

Data engineering makes data usable by other systems and people. A pipeline may be a small scheduled file import or a distributed stream processing system; the appropriate design depends on the data, latency requirements, failure tolerance, and operating budget.

This section treats cybersecurity as one application of data engineering. The same foundations also support inventory reporting, application analytics, service monitoring, business reporting, and internal automation.

| Area | Main Question |
| --- | --- |
| **Data engineering** | How do we deliver trustworthy data to its destination reliably? |
| **Analytics** | What does the prepared data tell us about an activity or outcome? |
| **Detection engineering** | Which patterns in telemetry should trigger a security investigation? |
| **Infrastructure engineering** | How do we deploy, secure, and operate the systems doing the work? |

These areas overlap. Use this section for the data pipeline foundations and the [Incident Response section](../IncidentResponse/README.md) for security investigations and response procedures.

---

<a id="start-here"></a>

## 🚀 Start Here: Choose Your Entry Point

Two entry points serve different goals. Either can be taken first.

| If you want to… | Start with | Why |
| --- | --- | --- |
| **Learn data engineering from the beginning** | [Phase 1 foundations](#phase-1) | Lifecycle, Python, SQL, ETL/ELT, and quality — each with a runnable lab requiring no server or third-party package |
| **Build a secure security-telemetry pipeline now** | [Secure Data Pipelines](#secure-pipelines) | TLS, SSH, Git, parsing, caching, Kafka, and Ansible in one applied project |

**Recommended combined path:** Work through Phase 1 in order, then apply it to security telemetry in `data_pipelines.md`. The foundations explain *why* the pipeline guide handles quarantine, event identity, and idempotence the way it does.

---

<a id="phase-1"></a>

## 🟢 Phase 1: Foundations

Five published guides in [`Phase1/`](./Phase1/). Each is self-contained, states its prerequisites, and ends with a **Verification Record** listing the checks actually performed and what remains unverified.

| # | Guide | Coverage | Lab |
| --- | --- | --- | --- |
| 1 | 🧱 [Data Engineering Fundamentals](./Phase1/data_engineering_fundamentals.md) | Lifecycle, terminology, requirements template, batch/streaming decisions, source-to-destination design | CSV → SQLite loader with validation, quarantine, idempotent upserts, and a run log |
| 2 | 🐍 [Python for Data Processing](./Phase1/python_data_processing.md) | Bounded-memory iteration, encoding, CSV and JSON Lines, timestamps, logging, packaging, tests | Installable `assetpipe` package with a `unittest` suite and a console entry point |
| 3 | 🗃️ [SQL & Data Modeling](./Phase1/sql_data_modeling.md) | Keys, constraints, NULL semantics, joins, aggregates, window functions, transactions, indexes, query plans | Inventory and telemetry schema, then a star schema with an enforced grain |
| 4 | 🔄 [ETL & ELT Pipeline Design](./Phase1/etl_elt_pipeline_design.md) | ETL versus ELT, staging layers, watermarks, overlap windows, merge writes, checkpoints, backfills | Incremental pipeline demonstrating idempotent reruns, a backfill repair, and reconciliation |
| 5 | ✅ [Data Quality & Schema Contracts](./Phase1/data_quality_schema_contracts.md) | Quality dimensions, record and batch validation, nulls, duplicates, schema evolution, quarantine, producer/consumer obligations | Contract-driven validator and a compatibility gate that fails a build on breaking changes |

### 📘 Reading order and dependencies

```text
1. Fundamentals ──┬──► 2. Python ──┐
                  │                ├──► 4. ETL & ELT ──► 5. Data Quality
                  └──► 3. SQL ─────┘
```

Guides 2 and 3 can be read in either order. Guide 4 assumes both. Guide 5 assumes guide 4's load structure.

### 🧰 Shared characteristics

| Property | Detail |
| --- | --- |
| **Dependencies** | Python standard library and SQLite only — no servers, containers, or package installs |
| **Data** | Synthetic fixtures throughout; nothing contacts a network service |
| **Verification** | Every lab was executed; documented outputs are actual results, with limitations stated |
| **Failure handling** | Each guide covers what breaks, how it presents, and which check detects it |

> [!NOTE]
> The labs deliberately use SQLite so they run anywhere, including locked-down hosts. Each guide flags where the patterns differ on PostgreSQL, MySQL, or SQL Server, and the Verification Record states which engine was actually tested.

---

<a id="secure-pipelines"></a>

## 🛡️ Secure Data Pipelines

### 🔐 [Secure Data Pipelines & Security Automation](./data_pipelines.md)

The applied security guide in this section connects six practical capabilities in one document:

| Capability | Covered Topics | Jump to Guide Section |
| --- | --- | --- |
| 🔐 **Protect data in transit** | TLS certificates, hostname verification, SSH identities, and administrative access | [TLS](./data_pipelines.md#3-encrypt-and-authenticate-with-tls) · [SSH](./data_pipelines.md#4-secure-administration-with-ssh) |
| 🗃️ **Version code and configuration** | Git branches, staged review, commits, and rollback concepts | [Git workflow](./data_pipelines.md#5-manage-code-and-configuration-with-git) |
| 🧹 **Transform messy logs** | Python parsing, JSON Lines, timestamps, validation, and quarantine | [Structured events](./data_pipelines.md#6-transform-messy-logs-into-structured-events) |
| 🧠 **Enrich records with context** | Redis and Memcached lookup caches, expiry, misses, and outage handling | [Cached threat intelligence](./data_pipelines.md#7-enrich-events-with-redis-and-memcached) |
| 📡 **Stream and centralize events** | Kafka topics, partitions, consumer groups, replay, and delivery considerations | [Kafka](./data_pipelines.md#8-stream-and-centralize-events-with-kafka) |
| ⚙️ **Automate deployment** | Ansible inventory, templates, validation, and idempotence | [Ansible](./data_pipelines.md#9-automate-deployments-with-ansible) |

**Suggested first project:** Follow the guide's synthetic SSH-log exercise, trace each accepted event through parsing and enrichment, and then work through the Kafka and deployment milestones.

**Foundations behind this guide:** its parsing and quarantine approach is explained generally in [Data Quality & Schema Contracts](./Phase1/data_quality_schema_contracts.md), its event-identity and replay handling in [Data Engineering Fundamentals](./Phase1/data_engineering_fundamentals.md), and its Python patterns in [Python for Data Processing](./Phase1/python_data_processing.md).

> [!NOTE]
> The guide distinguishes runnable local exercises, configuration templates, and further integration work. Read its [verification record](./data_pipelines.md#verification-record) for the checks performed and the deployment steps that remain unverified.

---

<a id="existing-resources"></a>

## 📚 Existing Repository Resources

These documents already exist elsewhere in the repository. Link to them for their established subject areas rather than duplicating their content here.

### 📊 Ingestion, Logs & Search

| Existing Resource | Relevance to Data Engineering |
| --- | --- |
| [Log Aggregation & Visibility](../IncidentResponse/log_agg.md) | Log-source collection and forwarding into centralized security tooling. |
| [Linux Auditd & Syslog](../IncidentResponse/Endpoint-Visibility/Linux/auditd_syslog.md) | Linux audit sources, logging configuration, and forwarding considerations. |
| [SIEM Deployment Index](../IncidentResponse/SIEM/README.md) | Entry point to the repository's security information and event management platform guides. |
| [ELK Stack Guide](../IncidentResponse/SIEM/elk_stack.md) | Logstash processing, Elasticsearch indexing, and Kibana visualization in a security logging context. |
| [Graylog Guide](../IncidentResponse/SIEM/graylog.md) | Inputs, stream routing, processing pipelines, and log retention topics. |

### 🔐 Security & Supporting Infrastructure

| Existing Resource | Relevance to Data Engineering |
| --- | --- |
| [Applied Cryptography](../Cryptography/applied-crypto.md) | Transport protection, key management, and authentication foundations. |
| [Container Image & Runtime Security](../ContainerSecurity/containers.md) | Image and runtime security considerations for containerized pipeline components. |
| [Cybersecurity Homelab](../Homelab/README.md) | Lab infrastructure and isolation planning before experimenting with services and data flows. |

**Scope of this index review:** Linked files and their relevant subject coverage were checked. This does not certify every command, dependency version, or deployment claim inside those separate documents.

---

<a id="categories"></a>

## 🗂️ Core Data Engineering Categories

Use these categories to organize future material and identify gaps in a project.

| Category | Learning Focus | Current Starting Point |
| --- | --- | --- |
| 🧱 **Foundations & architecture** | Data lifecycle, batch versus streaming, latency, ownership, and failure boundaries | [Data Engineering Fundamentals](./Phase1/data_engineering_fundamentals.md) |
| 📥 **Ingestion & integration** | Files, APIs, pagination, incremental loads, checkpoints, and database changes | [Incremental extraction](./Phase1/etl_elt_pipeline_design.md#3-incremental-extraction) and [log aggregation](../IncidentResponse/log_agg.md); dedicated API ingestion guide proposed |
| 🧹 **Transformation & modeling** | Parsing, types, timestamps, SQL, joins, schemas, and reusable transformations | [Python for Data Processing](./Phase1/python_data_processing.md) and [SQL & Data Modeling](./Phase1/sql_data_modeling.md) |
| 🗄️ **Storage & serving** | Relational databases, object storage, analytical stores, file formats, and retention | [Analytical modeling](./Phase1/sql_data_modeling.md#9-analytical-modeling) and [search/log platform guides](../IncidentResponse/SIEM/README.md); general storage guide proposed |
| 📡 **Streaming & messaging** | Event identity, ordering, offsets, replay, backpressure, and delivery semantics | [Batch versus streaming](./Phase1/data_engineering_fundamentals.md#5-batch-micro-batch-and-streaming) and the [Kafka introduction](./data_pipelines.md#8-stream-and-centralize-events-with-kafka) |
| 🧠 **Enrichment & caching** | Lookup data, freshness, expiry, cache misses, and authoritative sources | [Redis and Memcached](./data_pipelines.md#7-enrich-events-with-redis-and-memcached) |
| ✅ **Quality & contracts** | Required fields, uniqueness, completeness, compatibility, and rejected records | [Data Quality & Schema Contracts](./Phase1/data_quality_schema_contracts.md) |
| ⚙️ **Orchestration & deployment** | Job dependencies, scheduling, retries, backfills, versioned configuration, and deployment | [Checkpoints and backfills](./Phase1/etl_elt_pipeline_design.md#5-checkpoints-and-run-state), plus [Git](./data_pipelines.md#5-manage-code-and-configuration-with-git) and [Ansible](./data_pipelines.md#9-automate-deployments-with-ansible); orchestration guide proposed |
| 🔎 **Observability & recovery** | Freshness, processing lag, errors, reconciliation, replay, and restore procedures | [Reconciliation](./Phase1/etl_elt_pipeline_design.md#8-reconciliation) and the [troubleshooting reference](./data_pipelines.md#11-troubleshooting-reference); dedicated operations guides proposed |
| 🔐 **Governance & protection** | Access control, secrets, lineage, classification, retention, and auditability | [Producer and consumer obligations](./Phase1/data_quality_schema_contracts.md#10-producer-and-consumer-obligations) and [applied cryptography](../Cryptography/applied-crypto.md); data governance guide proposed |

**Useful distinction:** Deployment automation configures the services that run pipelines. Workflow orchestration schedules and coordinates the data-processing jobs themselves. A section about Ansible does not replace a guide to job dependencies, retries, and backfills.

---

<a id="future-documents"></a>

## 📝 Documentation Roadmap

Phase 1 is published. Phases 2 and 3 remain a proposed roadmap, not a list of completed or scheduled work; their filenames are suggestions within `Data-Engineering/` and intentionally remain unlinked until the documents are created.

### 🟢 Phase 1: General Foundations — Published

| Document | Location | Coverage |
| --- | --- | --- |
| **Data Engineering Fundamentals** | [`Phase1/data_engineering_fundamentals.md`](./Phase1/data_engineering_fundamentals.md) | Lifecycle, batch/streaming decisions, source-to-destination design, terminology, requirements, and a small file-to-database project. |
| **Python for Data Processing** | [`Phase1/python_data_processing.md`](./Phase1/python_data_processing.md) | CSV and JSON handling, iterators, bounded memory use, encoding, timestamp conversion, packaging, logging, and tests. |
| **SQL & Data Modeling** | [`Phase1/sql_data_modeling.md`](./Phase1/sql_data_modeling.md) | Queries, joins, aggregates, window functions, keys, constraints, transactions, indexes, and introductory analytical models. |
| **ETL & ELT Pipeline Design** | [`Phase1/etl_elt_pipeline_design.md`](./Phase1/etl_elt_pipeline_design.md) | Extract-transform-load versus extract-load-transform, staging, incremental loads, idempotent writes, checkpoints, and reconciliation. |
| **Data Quality & Schema Contracts** | [`Phase1/data_quality_schema_contracts.md`](./Phase1/data_quality_schema_contracts.md) | Validation, nulls, duplicates, schema evolution, compatibility checks, quarantine, and producer/consumer expectations. |

### 🟡 Phase 2: Storage & Integration — Published

| Document | Location | Coverage |
| --- | --- | --- |
| **Data Storage & File Formats** | [`data_storage_file_formats.md`](./Phase2/data_storage_file_formats.md) | Relational versus object versus analytical storage; CSV, JSON Lines, and Parquet; partitioning, compression, and retention. |
| **API & File Ingestion** | [`api_file_ingestion.md`](./Phase2/api_file_ingestion.md) | Authentication, pagination, rate limits, retries with backoff, watermarks, changed files, and partial-download recovery. |
| **Workflow Orchestration** | [`workflow_orchestration.md`](./Phase2/workflow_orchestration.md) | Schedules, dependencies, retries, concurrency, parameterized jobs, backfills, and separating orchestration from processing. |
| **Streaming & Change Data Capture** | [`streaming_cdc.md`](./Phase2/streaming_cdc.md) | Database change capture, snapshots, event time, ordering, duplicates, late records, replay, and consumer compatibility. |

### 🔵 Phase 3: Operations & Governance — Proposed

| Proposed Document | Suggested Filename | Recommended Coverage |
| --- | --- | --- |
| **Pipeline Observability & Reliability** | `pipeline_observability.md` | Freshness, throughput, lag, error budgets, alerting, reconciliation, runbooks, and recovery drills. |
| **Pipeline Testing & CI/CD** | `pipeline_testing_cicd.md` | Unit and integration tests, synthetic fixtures, schema checks, dependency pinning, review gates, and staged releases. |
| **Data Governance, Lineage & Access** | `data_governance_lineage.md` | Ownership, source lineage, sensitive fields, access boundaries, secrets, retention, deletion, and audit trails. |
| **Backup, Replay & Disaster Recovery** | `data_recovery_replay.md` | Backups versus replication, restore exercises, replay boundaries, recovery objectives, deduplication, and rebuilding derived data. |

**Suggested continuation:** With foundations in place, expand into storage formats and orchestration before adding more distributed components. Each new document should include one small practical exercise with observable success and failure conditions, and a verification record stating what was actually executed.

**Placement convention:** Phase 1 guides live in `Phase1/`. Later phases may use `Phase2/` and `Phase3/` for consistency; whichever is chosen, update the relative links inside the guides to match their depth.

---

<a id="workflow"></a>

## 🚀 Learning & Implementation Workflow

| Step | Action | Deliverable | Related Guide |
| --- | --- | --- | --- |
| **1. Define the purpose** | Identify the source, consumer, sensitivity, expected volume, and acceptable delay. | Short requirements and ownership record. | [Requirements before code](./Phase1/data_engineering_fundamentals.md#4-requirements-before-code) |
| **2. Build a small path** | Move a synthetic sample from one source to one destination. | Reproducible working example. | [File-to-database lab](./Phase1/data_engineering_fundamentals.md#7-lab-file-to-database-pipeline) |
| **3. Establish the contract** | Define field types, event identity, timestamps, and rejected-record handling. | Schema and accepted/rejected fixtures. | [What a contract contains](./Phase1/data_quality_schema_contracts.md#2-what-a-contract-contains) |
| **4. Protect access** | Configure verified transport, least-privilege identities, and secret handling. | Documented access and trust configuration. | [TLS and SSH](./data_pipelines.md#3-encrypt-and-authenticate-with-tls) |
| **5. Make writes repeatable** | Decide how incremental loads, retries, and duplicate records behave. | Replay and reconciliation checks. | [Idempotent writes and merge](./Phase1/etl_elt_pipeline_design.md#4-idempotent-writes-and-merge) |
| **6. Automate execution** | Version configuration, deploy consistently, and schedule jobs where needed. | Reviewed configuration and run procedure. | [Git](./data_pipelines.md#5-manage-code-and-configuration-with-git) and [Ansible](./data_pipelines.md#9-automate-deployments-with-ansible) |
| **7. Observe failures** | Test unavailable sources, bad records, destination failures, and stale data. | Metrics, alerts, and troubleshooting notes. | [Failure drills](./Phase1/data_engineering_fundamentals.md#8-failure-drills) and [failure modes](./Phase1/etl_elt_pipeline_design.md#9-failure-modes) |
| **8. Expand deliberately** | Measure bottlenecks before introducing new services or partitions. | Capacity notes and tested recovery plan. | [Indexes and query plans](./Phase1/sql_data_modeling.md#8-indexes-and-query-plans) |

### 🧪 Suggested Practice Projects

- **Inventory reporting:** Import synthetic asset CSV files into a relational database, validate serial-number uniqueness, and produce a queryable current inventory. Implemented as the [file-to-database lab](./Phase1/data_engineering_fundamentals.md#7-lab-file-to-database-pipeline), extended by the [star schema lab](./Phase1/sql_data_modeling.md#10-lab-build-the-star-schema).
- **Incremental load with recovery:** Run a watermark-based pipeline, prove the second run changes nothing, then simulate data loss and repair it with a backfill. Implemented as the [incremental pipeline lab](./Phase1/etl_elt_pipeline_design.md#6-lab-the-incremental-pipeline).
- **Contract enforcement:** Declare a contract, validate a defective batch against it, and gate a schema change on compatibility. Implemented as the [contract validator lab](./Phase1/data_quality_schema_contracts.md#7-lab-the-contract-validator).
- **Security telemetry:** Parse synthetic authentication logs, add cached context, and publish structured events using [data_pipelines.md](./data_pipelines.md).
- **API ingestion:** Collect records from a permitted test API with pagination and checkpoints, then demonstrate recovery after an interrupted run. This is a proposed exercise for the future ingestion guide.

---

<a id="data-handling"></a>

## 🔐 Data Handling & Operational Practices

- Use synthetic or sanitized samples in public documentation and tests.
- Keep credentials, private keys, customer records, and sensitive raw logs out of Git.
- Preserve source identity and processing history so results can be traced and reconciled.
- Separate an empty result from a failed lookup or incomplete ingestion.
- Define retention and access rules for raw, quarantined, transformed, and archived data.
- Test restore and replay procedures before relying on them during an outage.
- Keep documented test results specific to the environment and versions actually checked.

> [!CAUTION]
> Quarantined records inherit the classification of their source. A reject file assembled from security logs or customer data carries the same handling obligations as the original, and the fact that a record failed validation does not make it non-sensitive. See [quarantine and reject handling](./Phase1/data_quality_schema_contracts.md#9-quarantine-and-reject-handling).

---

<a id="contributing"></a>

## 🤝 Contributing

Contributions can extend the general foundations, add small reproducible labs, or improve links to existing repository material.

**Submission Guidelines:**

1. Check this index and related sections before creating a duplicate guide.
2. Follow the [repository style guide](../STYLE_GUIDE.md) and [contribution guidance](../.github/CONTRIBUTING.md).
3. State prerequisites, tested versions, expected results, and known limitations.
4. Include sanitized examples and failure-handling exercises where practical.
5. Add a relative link here when a proposed document is created; remove its proposed-only status.
6. Include a verification record stating what was executed, the output observed, and what remains unverified.
7. Prefer standard-library and single-file-database examples so labs run without installation.
8. When placing a guide in a phase subfolder, check that its relative links account for the extra directory level.
9. Update the [master index](../README.md) when adding a new guide or major section.

---

<a id="quick-links"></a>

## 🔗 Quick Links

### 🟢 Phase 1 Foundations

- [🧱 Data Engineering Fundamentals](./Phase1/data_engineering_fundamentals.md)
- [🐍 Python for Data Processing](./Phase1/python_data_processing.md)
- [🗃️ SQL & Data Modeling](./Phase1/sql_data_modeling.md)
- [🔄 ETL & ELT Pipeline Design](./Phase1/etl_elt_pipeline_design.md)
- [✅ Data Quality & Schema Contracts](./Phase1/data_quality_schema_contracts.md)

### 🔐 Applied & Related

- [🛡️ Secure Data Pipelines & Security Automation](./data_pipelines.md)
- [🚨 Incident Response](../IncidentResponse/README.md)
- [📊 Log Aggregation](../IncidentResponse/log_agg.md)
- [🔐 Applied Cryptography](../Cryptography/applied-crypto.md)
- [🐳 Container Security](../ContainerSecurity/containers.md)
- [🏠 Homelab](../Homelab/README.md)
- [📖 Glossary](../GLOSSARY.md)

---

<a id="section-status"></a>

## 📊 Section Status

| Item | Status |
| --- | --- |
| **Section directory** | `Data-Engineering/` |
| **Applied security guide** | [data_pipelines.md](./data_pipelines.md) |
| **Phase 1 foundations** | Published — 5 guides in [`Phase1/`](./Phase1/) |
| **Phase 2 & 3** | Proposed roadmap; not yet linked as published guides |
| **Existing supporting resources** | Linked from their current repository locations |
| **Lab dependencies** | Python standard library and SQLite; no servers or third-party packages |
| **Index review** | September 11, 2026 |

---

<div align="center">

**🗄️ Collect Carefully. Transform Clearly. Deliver Reliably.**

*Build useful data systems with traceable inputs, explicit failure handling, and repeatable operations.*

**Repository:** [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Pacific Northwest Computers:** [PNWC on GitHub](https://github.com/Pnwcomputers)

[🏠 Master Index](../README.md) | [🎯 Role Navigation](../START_HERE.md) | [📋 Contents](#contents) | [📜 Legal Notice](../LEGAL.md)

⭐ **Star the repository if you find it useful!** ⭐

</div>
