# AI Agent Observability, Tracing, Audit Trails & SIEM Integration

_Last reviewed: 2026-11-09 · Runtime details vary by model, agent framework and telemetry provider._

Observability answers **what actually happened inside an agent workflow**, while an audit record answers **who authorized what action, against which resource, and with which outcome**. A trace, log, metric and evidence report serve different purposes and must not be conflated.

## 1. The Four Evidence Surfaces

| Surface | What It Shows | Use | Limitation |
|---|---|---|---|
| **Trace** | Parent run and child spans: model, retrieval, tool, handoff | Debug latency and execution flow | May be sampled, unavailable or redacted |
| **Event log** | Timestamped action, result, error and correlation ID | Operational troubleshooting | A log line is not a verified end state |
| **Metric** | Aggregated errors, latencies, counts, costs and queue depth | Alerting and capacity | Averages hide individual critical failures |
| **Audit/evidence register** | Identity, approval, exact target, post-action verification | Accountability, milestones, compliance | Requires independent integrity/retention controls |

### Reference Architecture

```text
AI application / gateway / agent
   |
   +-- trace spans (request -> retrieve -> model -> tool -> verify)
   +-- structured events (authorization, failure, approval, result)
   +-- metrics (latency, cost, retry/queue/error counters)
   |
   v
Redaction + policy filter + sampling + correlation
   |
   +----> Restricted observability store (traces, metrics)
   +----> Tamper-resistant audit store
   +----> Security event adapter -> Wazuh / SIEM
   |
   v
Operator dashboards + alert rules + evidence references
```

Do not forward full prompts, credentials or client logs to every monitoring backend. Tracing is a **new data-exfiltration surface** and requires a data-flow/privacy review.

## 2. Define a Trace & Audit Schema

```json
{
  "timestamp": "2026-11-09T16:00:00-08:00",
  "event_id": "synthetic-evt-014",
  "trace_id": "lab-trace-014",
  "parent_task_id": "lab-m3",
  "agent_role": "verifier",
  "environment": "authorized-lab",
  "action": "read_alert",
  "target_ref": "LAB-ALERT-014",
  "permission_decision": "allow-read-only",
  "approval_ref": null,
  "outcome": "success",
  "verified_postcondition": "readback-matched",
  "source_version": "EXAMPLE_SHA",
  "duration_ms": 118,
  "sensitivity": "synthetic"
}
```

Production schemas should also capture tool/server version, request shape/version (without secrets), retry count, error category and safe artifact pointer. Use a real trace/event ID generator: IDs here are illustrative.

**Prefer correlating by IDs** rather than copying payloads. An event can be traced across an orchestrator, worker, MCP server, queue and destination service without exporting raw messages.

## 3. Instrument an Agent Run

1. Assign a unique **run ID** and **task ID** at ingress; propagate them across all services.
2. Record current code commit, model/provider identifier, tool/schema version, workspace and tenant boundary.
3. Instrument stages: retrieval, model response, proposed tool call, authorization decision, tool result, independent readback and handoff.
4. Mark start/end/status and **redacted** errors. Keep expected/actual side effects separate.
5. Measure token/request counts where provider supports them; label unavailable fields rather than inventing.
6. Export only to destinations approved for this data classification.
7. Correlate critical failures to an on-call owner and an incident response runbook.
8. Verify logging coverage by deliberately inducing a synthetic denied call and a controlled timeout.

### Simple Python Structured Event Example

```python
# Demonstrates structured redacted logging. No external services are contacted.
import json, logging, datetime
logger = logging.getLogger("ai-audit")
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

def audit(event_id, tool, outcome, trace_id, target_ref):
    allowed_outcomes = {"allowed", "denied", "success", "failed", "unknown"}
    if outcome not in allowed_outcomes:
        raise ValueError("Unknown audit outcome")
    record = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_id": str(event_id),
        "trace_id": str(trace_id),
        "tool": str(tool),
        "target_ref": str(target_ref),  # Use opaque IDs, not raw customer data.
        "outcome": outcome
    }
    logger.info(json.dumps(record, separators=(",", ":")))

audit("LAB-001", "wazuh.read_alert", "success", "TRACE-LAB-001", "ALERT-LAB-001")
```

For real deployments add authenticated transports, schema validation, length checks, redaction, durable storage, access control and retention enforcement. A stdout log is **not** tamper-proof.

## 4. Metrics & Operational SLIs

| Indicator | Definition | Alert Example |
|---|---|---|
| Failed tool-call fraction | Failed calls / attempted calls | Sharp rise over baseline |
| Unauthorized attempted actions | Denied privileged calls by agent/tenant | Any unexpected high-risk attempt |
| End-state verification coverage | Verified writes / attempted writes | Drops below stated target |
| Duplicate side-effect rate | Duplicates / write requests | Nonzero after change |
| P95 run latency | End-to-end duration, 95th percentile | Higher than agreed SLO |
| Pending approval age | Age of oldest blocked approval | Queue waits too long |
| Retrieved-source failure | Stale/missing citations per evaluated case | Regression in evidence quality |
| Unit-cost drift | Spend per accepted task | Above budget threshold |
| Logging coverage | Audited critical actions / expected critical actions | Missing receipts or gaps |

For low-volume systems, thresholds should use minimum counts and sensible windows to avoid misleading rates.

## 5. Integrate With Wazuh/SIEM Safely

A practical approach is to write **sanitized JSON security events** from your agent application and use a supported log shipper/Wazuh agent or ingestion method to collect them. Do not assume Wazuh automatically recognizes your custom schema as an alert.

1. Define agent event fields and severity mapping independently of the model.
2. Send synthetic events to a test log source; verify timestamp parsing and retention.
3. Configure/test the Wazuh decoder and rule mapping for your exact version.
4. Alert on denied high-risk operations, invalid approval, repeated auth failures, unknown tool use, unexpected egress and possible sensitive output.
5. Correlate events with agent trace/task IDs and source resource IDs.
6. Verify false-positive behavior, rule firing, dashboard filtering and access controls.
7. Set rate limits/deduplication so a failing hook does not flood the SIEM.

**Example rule concept (not a Wazuh XML drop-in):** "If `event_type=agent_tool_authorization` and `decision=denied` and `risk=critical`, raise a security event and route it to human review; never automatically approve or invoke the denied tool." Verify real decoder/rule syntax with the supported Wazuh documentation before deploying.

## 6. Privacy, Retention & Incident Review

Treat model prompts, user content, retrieved passages, tool arguments, tool responses and raw traces as potentially confidential. Minimize content capture, scrub tokens/PII, set retention schedules, encrypt at rest/transit, enforce role-based access, and keep an integrity-protected audit trail. ZDR or private deployments may disable some vendor tracing surfaces; confirm the product-specific contract.

If an incident occurs, preserve trace IDs and evidence pointers before disabling risky connections. Assess whether data crossed organizational boundaries; avoid deleting evidence prematurely. For regulated workflows follow the applicable legal and contractual retention/notification policy.

## 7. Operational Troubleshooting

| Symptom | Likely Cause | Safe Investigation |
|---|---|---|
| Missing trace | Tracing disabled, SDK runtime limitation, export failure | Check runtime-specific tracing config and exporter health |
| Tool says success but no target change | Async service, wrong resource, unverified receipt | Read actual target state |
| SIEM shows no custom events | Parsing/decoder/shipper mismatch | Send known synthetic event, inspect each hop |
| Repeated alerts | Retry or no dedup | Group by event ID and verify idempotency |
| Private data appears in trace | Content capture enabled | Stop export, restrict access, redact/rotate as needed |
| Latency spikes | Tool queue, token size, provider throttling | Compare span durations and retry counters |

## 8. Acceptance Exercise

Instrument a synthetic triage workflow. Trigger a normal read, denied unauthorized write, duplicate event and timeout. Confirm each has a trace/correlation ID, safe event log, correct aggregate metric and a visible Wazuh alert only where intended. Document which evidence exists and which tools were **not** run.

## Related Guides & Primary Sources

[Security Operations](ai-security-operations-workflows.md) · [Reliability](agent-reliability-and-recovery.md) · [Evaluations](ai-evaluation-and-regression-testing.md) · [Agent Security](agent-threat-modeling-and-security.md)

References: [OpenTelemetry GenAI Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) · [OpenAI Agents Tracing](https://openai.github.io/openai-agents-js/guides/tracing/) · [OpenAI Integrations & Observability](https://developers.openai.com/api/docs/guides/agents/integrations-observability) · [Wazuh Docs](https://documentation.wazuh.com/).

---

[AI Index](README.md) | [Master Index](../README.md)
