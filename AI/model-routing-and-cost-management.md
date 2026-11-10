# AI Model Selection, Routing, Privacy & Cost Management

_Last reviewed: 2026-11-09 · Models, prices, quotas and service terms change; verify before deployment._

A model-routing policy decides which provider or local model should perform a specific class of work based on **required capability, privacy, measured quality, latency, resilience and price**. Cheapest per token is not necessarily cheapest per verified outcome.

## 1. Build a Model/Workload Inventory

| Workload | Hard Requirements | Typical Preferred Route |
|---|---|---|
| Sensitive client evidence summary | Approved data boundary, access control, grounding | Authorized local/private endpoint |
| Public documentation lookup | Source access, accurate citations | Current retrieval + capable model |
| Coding with repository tools | Tool/schema reliability, code eval pass | Model tested on target repo/tasks |
| High-stakes release review | Independent evidence, approvals | Verified testing + reviewer, not model alone |
| Routine synthetic log categorization | Low cost, fixed schema, fast response | Small model if benchmark passes |
| Long research report | Large source set, context and grounding | RAG/hybrid retrieval + evaluated model |
| Offline lab | No external network and auditable local setup | Pinned local model/environment |

A local model avoids cloud inference calls only if **all** embedding, tool, telemetry, retrieval and fallback paths remain local. Self-hosting is not automatically a privacy guarantee.

## 2. Selection Criteria

Evaluate each candidate against a standardized dataset and profile:

| Dimension | Measure | Failure Threshold |
|---|---|---|
| Correctness | Acceptance by verified task rubric | Below required pass rate |
| Grounding | Claim-to-source support | Unsupported critical claims |
| Tool behavior | Invalid/unauthorized calls | Any unapproved high-impact side effect |
| Context | Input/output limits and real retrieval fidelity | Truncation or lost source |
| Latency | P50/P95 end-to-end | Exceeds service objective |
| Availability | Error/timeouts over a defined window | Unacceptable outage impact |
| Privacy | Geography, retention, subprocessor/data terms | Outside authorized policy |
| Cost | Input/output/cache/tool/retry costs per accepted task | Exceeds budget |
| Operations | Deployment, rollback, updates, licensing | Unmaintainable |

Record date, model ID, provider, API version, settings, quantization (for local models), prompt revision and tool versions. Avoid claims that a specific named model is categorically best forever.

## 3. Routing Policy & Safe Fallback

```text
INPUT -> classify sensitivity, scope and required tools
      -> deny unapproved destinations
      -> choose tested model/provider meeting capability + data policy
      -> enforce time/cost/turn budget
      -> validate output and tool choices
      -> fallback ONLY if destination has equivalent approval and controls
      -> verify end state and record actual cost/performance
```

**Illustrative policy**, not a vendor configuration file:

```yaml
routes:
  confidential_client:
    approved_destinations: ["local-private"]
    require_retrieval_acl: true
    fallback: "stop-and-escalate"
  public_research:
    approved_destinations: ["cloud-provider-a", "local-private"]
    require_source_citations: true
    fallback: "another-approved-destination"
  synthetic_triage:
    approved_destinations: ["small-local-model"]
    max_tool_calls: 6
    require_schema_validation: true

global:
  max_retry_attempts: 2
  no_unapproved_cross_boundary_fallback: true
  require_human_release_approval: true
```

When a private endpoint fails, **do not silently send confidential input to an external API** as a fallback.

## 4. Calculate Real Costs

For a usage-priced API, estimate:

```text
estimated_model_cost =
  input_tokens / 1_000_000 * input_price_per_million
+ output_tokens / 1_000_000 * output_price_per_million
+ any applicable tool, retrieval, cache or other service charges
```

For locally hosted models also count amortized hardware, power, storage, monitoring, maintenance and operator time. Include unsuccessful attempts, retries and evaluation runs.

**Illustrative calculation only:** at assumed rates of $1.00 per million input tokens and $4.00 per million output tokens, a task using 15,000 input and 3,000 output tokens would have $0.015 + $0.012 = **$0.027 model usage cost**, excluding all other charges. These are hypothetical rates, **not current provider prices**.

More meaningful metric: **total cost per independently accepted task**, including failures and rework. Measure both unit economics and quality; a cheap model needing four retries can be worse than a more expensive reliable model.

## 5. Practical Benchmark Procedure

1. Choose 30+ representative, approved test tasks with explicit success criteria and risk categories.
2. Include a held-out set, exact identifiers, long-context tasks, tool errors and ambiguous requests.
3. Fix prompt, retrieval source version and tool schemas as much as possible.
4. Run each candidate with same data and bounded settings; record model ID and revisions.
5. Collect real input/output token usage, latency, failed calls and source grounding.
6. Independently check accepted results, especially security and client-facing outputs.
7. Compare **Pareto frontier**: acceptable quality versus actual cost/latency.
8. Apply privacy/security hard gates **before** optimizing cost.
9. Test fallback during controlled outage and rate-limit conditions.
10. Publish routing decisions with date and re-evaluation triggers.

## 6. Local Model Operations

For Ollama or another local stack:
- Pin model artifact and quantization; verify checksums/provenance.
- Check GPU/CPU memory and concurrent-user throughput.
- Restrict listening interfaces and API access; require authentication at the gateway where appropriate.
- Validate local embedding service, telemetry exporter and network egress, not inference endpoint alone.
- Track model load times, queue depth, first-token latency, inference speed, memory pressure and unexpected OOM.
- Test model upgrades on a staging endpoint and keep rollback artifacts.
- Keep client data separated across workspaces and indexes.

Use [Offline LLM Deployment](offline-llm.md) for architecture and installation details; this guide focuses on **routing decisions and measurement**.

## 7. Common Routing Failures

| Failure | Why | Mitigation |
|---|---|---|
| Confidential input sent to cloud | Blind automatic fallback | Destination allowlist and fail-closed rule |
| Cheap route hallucinates | No task-specific eval | Quality floor and sample-based audit |
| Huge context becomes expensive | Excessive retrieval dumps | Chunk/rerank, compaction and budgets |
| API model changes behavior | Unpinned alias / provider update | Record model ID, benchmark release |
| Local inference overload | More concurrent jobs than capacity | Queue/concurrency caps and backpressure |
| Repeated tool loops consume budget | No stop condition | Max turns, calls, time and spend |
| Prompt cache hides costs | Incorrect usage attribution | Track actual billed usage and cache metadata |

## 8. Acceptance Checklist

A routing decision is ready when (a) target data boundary approved, (b) test suite run and reviewed, (c) measurable quality floor achieved, (d) fallback tested and privacy-preserving, (e) tool permissions validated, (f) costs measured rather than guessed, and (g) owner has an upgrade/rollback plan.

## Related Guides & Primary Sources

[Offline LLM](offline-llm.md) · [Agent Evals](ai-evaluation-and-regression-testing.md) · [Observability](ai-observability-and-auditing.md) · [RAG](rag-and-knowledge-engineering.md) · [Context Engineering](context-engineering-and-memory.md)

References: [OpenAI Model Docs](https://developers.openai.com/api/docs/models) · [OpenAI Agent Evals](https://developers.openai.com/api/docs/guides/agent-evals) · [Ollama Docs](https://docs.ollama.com/) · [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework).

---

[AI Index](README.md) | [Master Index](../README.md)
