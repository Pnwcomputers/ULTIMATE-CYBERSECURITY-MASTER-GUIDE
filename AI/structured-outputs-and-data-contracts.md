# Structured AI Outputs, JSON Schema & Workflow Contracts

_Last reviewed: 2026-11-09 · Platform-neutral; API-specific structured-output features may differ._

When AI output controls scripts, tickets, databases or security actions, plain prose is a dangerous integration boundary. Use a **validated, versioned data contract** to distinguish model suggestions from permitted instructions and verified outcomes.

## 1. Output Format Versus Business Truth

| Layer | Question | Enforcement |
|---|---|---|
| Syntax | Is it parseable JSON/YAML? | Parser |
| Schema | Are fields, types, required data correct? | JSON Schema or typed validator |
| Semantics | Does severity match evidence? | Rules and independent data checks |
| Identity | Is the target real and in scope? | Server lookup + authenticated ACL |
| Authorization | May this caller do the requested action? | Host/service IAM and approval |
| Execution | Did the service actually make the change? | Target API receipt |
| Verification | Does target state match desired state? | Post-action readback + audit |

**Schema compliance does not imply truth or authorization.** Even a strict provider schema cannot validate an undocumented client asset or a human approval.

## 2. Design a Versioned Contract

A bounded incident-triage draft:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "LabIncidentTriageV1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version", "case_id", "severity", "status",
    "source_ids", "summary", "uncertainties"
  ],
  "properties": {
    "schema_version": {"const": "1.0"},
    "case_id": {"type": "string", "pattern": "^LAB-[A-Z0-9-]{3,30}$"},
    "severity": {"enum": ["low", "medium", "high", "critical"]},
    "status": {"enum": ["draft", "needs_review"]},
    "source_ids": {
      "type": "array", "minItems": 1, "maxItems": 20,
      "items": {"type": "string", "maxLength": 80},
      "uniqueItems": true
    },
    "summary": {"type": "string", "minLength": 1, "maxLength": 1000},
    "uncertainties": {
      "type": "array", "maxItems": 10,
      "items": {"type": "string", "maxLength": 300}
    }
  }
}
```

This is a **general JSON Schema**, not a promise it is accepted unchanged by every vendor's structured-output feature. Vendor APIs often support a subset and may impose additional requirements, so consult the current provider-specific contract.

### Example Valid Output

```json
{
  "schema_version": "1.0",
  "case_id": "LAB-SSH-014",
  "severity": "medium",
  "status": "needs_review",
  "source_ids": ["LAB-ALERT-014"],
  "summary": "Synthetic SSH failures were observed; intent is not established.",
  "uncertainties": ["No correlated endpoint outcome was provided."]
}
```

## 3. Validate Before Any Action

1. Parse structured output using a strict parser (no executing generated code).
2. Validate against the **expected version** of the schema.
3. Apply domain rules: severity mapping, source coverage, timestamps and ownership.
4. Cross-check case ID and source IDs against an authenticated data store.
5. Reject unauthorized destinations/tenants, regardless of valid format.
6. Present exact proposed side effects to the human gate where required.
7. Execute through service-side controlled tools with idempotency key.
8. Read back resulting target; record both receipt and observed state.
9. If any check fails, return a bounded error or request new draft; never silently coerce dangerous values.

```python
# Minimal deterministic illustration of *business* checks; NOT full JSON Schema validation.
import json
def validate_draft(text, authorized_cases, source_catalog):
    obj = json.loads(text)        # ValueError/JSONDecodeError => reject
    if not isinstance(obj, dict):
        raise ValueError("Expected object")
    expected = {"schema_version","case_id","severity","status",
                "source_ids","summary","uncertainties"}
    if set(obj) != expected:
        raise ValueError("Unexpected/missing fields")
    if obj["schema_version"] != "1.0" or obj["status"] not in {"draft","needs_review"}:
        raise ValueError("Unsupported state")
    if obj["case_id"] not in authorized_cases:
        raise PermissionError("Case not authorized")
    ids = obj["source_ids"]
    if not isinstance(ids,list) or not ids or not all(isinstance(x,str) and x in source_catalog for x in ids):
        raise ValueError("Unknown sources")
    if obj["severity"] not in {"low","medium","high","critical"}:
        raise ValueError("Severity invalid")
    if not isinstance(obj["summary"],str) or not obj["summary"].strip():
        raise ValueError("Summary required")
    if not isinstance(obj["uncertainties"],list):
        raise ValueError("Uncertainties invalid")
    # Use a real JSON Schema validator for remaining length/pattern limits.
    return obj
```

The code above intentionally shows why **parsing and policy checks are separate**; deploy a full JSON Schema validator rather than treating the sample as complete validation.

## 4. Schema Evolution & Compatibility

| Change | Compatibility Concern | Recommended Practice |
|---|---|---|
| New optional field | Old clients ignore? | Version and test parser behavior |
| New required field | Breaks old data | Major version or migration |
| Enum change | Unexpected route/action | Strictly reject unknown values |
| Tool parameter rename | Agent sends stale arguments | Deploy coordinated client/server update |
| Numeric unit change | Wrong money/time/network semantics | Include units and range checks |
| Source ID scheme change | Broken evidence linking | Migration map and validation |
| Sensitive-field addition | New leakage surface | Privacy review and redaction test |

For security outputs, include **source references and uncertainty fields** so consumers can distinguish a verified observation from a model inference.

## 5. Tool Schemas Are Not Authorization Schemas

A tool might accept `{"recipient":"outside@example.invalid","message":"..."}` while the service must still reject sending if the recipient is unauthorized or no human approval exists. Never embed a general-purpose "approved": true flag that the model may set to grant itself permission.

Use **typed intent → policy validation → approved execution → postcondition**. Tool descriptions from an MCP server are not trusted evidence of the server's hidden implementation.

## 6. Contract Testing

Build fixtures covering:
- Valid minimal and maximal objects.
- Missing and additional fields.
- Wrong types, enormous text, negative numbers and unexpected enum values.
- Unicode/escape handling and duplicate source IDs.
- Wrong tenant/case or forged approval.
- Wrong schema versions.
- Correct JSON with false evidence or nonexistent source IDs.
- Timeout after write and duplicated request IDs.

Each fixture should assert an explicit decision: accept draft, reject, require review or stop. Integrate tests into CI and audit any accepted changes to high-impact schemas.

## 7. Troubleshooting

| Symptom | Diagnosis | Fix |
|---|---|---|
| Model outputs prose around JSON | Wrong provider mode or incomplete schema | Use supported structured-output setting and validate |
| Schema passes but severity wrong | Semantic gap | Add source-backed checks and evals |
| Tool calls wrong client | Caller identity not bound | Enforce tenant ownership server-side |
| Old workers break after update | Version mismatch | Version, migrate and test both sides |
| Duplicate ticket | No idempotency | Stable task/event key and readback |
| Tool args contain secrets in logs | Telemetry captures raw payload | Filter sensitive fields and tighten retention |

## Related Guides & Primary Sources

[MCP Tools](mcp-tooling-and-permissions.md) · [Evaluations](ai-evaluation-and-regression-testing.md) · [Reliability](agent-reliability-and-recovery.md) · [Security Operations](ai-security-operations-workflows.md)

References: [JSON Schema Specification](https://json-schema.org/specification) · [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) · [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs).

---

[AI Index](README.md) | [Master Index](../README.md)
