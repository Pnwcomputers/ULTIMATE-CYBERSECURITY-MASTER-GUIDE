# MCP, Tool Integration & Secure Agent Permissions

_Last reviewed: 2026-11-09 · Consult the exact protocol and SDK version before implementation._

The **Model Context Protocol (MCP)** standardizes how an AI host/client discovers and uses external **tools, resources and prompts**. It does *not* automatically authorize access, guarantee that a tool is safe, or validate an agent's decision to call it. Tools may cause real-world side effects.

## 1. Architecture & Vocabulary

```text
Human owner / administrator
       |
       v  approval + identity + policy
AI Host (application with model, UI and policy enforcement)
       |
       v  MCP client / per-server connection
MCP Server (defines capabilities and tool schemas)
       |
       v  service account with scoped grants
GitHub / Calendar / Wazuh / Files / Database / Ticketing
```

| Object | Role | Security Implication |
|---|---|---|
| Host | Owns the user interaction, model and approvals | Must keep trust boundaries and consent |
| MCP client | Manages protocol exchange with a server | Must negotiate version, validate responses |
| MCP server | Advertises tools/resources/prompts | Its metadata/content is not automatically trusted |
| Tool | Performs a typed operation | Could read, write, send, execute or delete |
| Resource | Supplies data or documents | May contain prompt injection or secrets |
| Prompt | Reusable template | Not a host security policy |
| Transport | Communication channel, commonly HTTP or stdio | Authentication and deployment assumptions differ |

The 2026-07-28 MCP specification documents JSON-RPC, version negotiation, multiple message patterns and optional feature sets. HTTP authorization follows the protocol's authorization specification; stdio deployments normally receive credentials from their runtime environment rather than the HTTP OAuth flow. Review current transport/extension support before selecting an SDK.

## 2. Inventory & Classify Tools Before Connection

Build a minimal tool catalog:

| Tool | Scope | Identity | Data Sensitivity | Side Effect | Approval |
|---|---|---|---|---|---|
| `github.read_file` | Single repo | Read-only bot | Internal | None | Session grant |
| `github.create_pr` | One branch/repo | Scoped token | Internal | Writes PR | Review |
| `calendar.list_events` | Work calendar | OAuth user | Confidential | None | Consent |
| `email.send` | Specific mailbox | Send-capable identity | Confidential | Sends externally | Explicit human |
| `wazuh.list_alerts` | Authorized lab | Read-only analyst | Sensitive | None | Approved task |
| `shell.execute` | Sandbox only | Isolated user | Depends | Executes commands | Restricted/deny by default |

Prefer distinct **read-only** and **write-capable** identities. Credential access should be limited by repository, tenant, resource and operation. Access to a server is not authorization to use every tool it exposes.

## 3. Step-by-Step Integration Workflow

1. **Identify an approved deployment** and pin the MCP client/server versions or published protocol target.
2. **Read server source and tool contracts:** name, schema, required fields, output semantics, data flows, hidden network calls, logging and updates.
3. **Run a threat/data-flow review:** where do prompts, tool inputs and results leave the machine? Which users/accounts are represented?
4. **Create scoped credentials** in a secret manager. For HTTP integrations use the appropriate OAuth/discovery/scope flow. For local stdio avoid shell-injectable launch scripts and unrestricted environment leakage.
5. **Connect in a test environment** with only read-only tools exposed.
6. **Inspect tool discovery** and compare visible tools with allowlist. Names/annotations are informative, not independent guarantees.
7. **Invoke synthetic tests** for successful, missing-resource, unauthorized, malformed, timeout and duplicate inputs.
8. **Enable writes individually:** require confirmation with exact target and preview, enforce host authorization, and read back from target system.
9. **Instrument audit events:** actor, client, server, tool, resource, approval ID, timestamp, success/error and sanitized outcome.
10. **Document revoke/rotation** and run periodic access reviews.

## 4. Define a Safe Tool Contract

Use JSON Schema-like inputs **plus** host-side enforcement. This is an illustrative contract, not an MCP protocol definition:

```json
{
  "name": "ticket_create_draft",
  "description": "Create a draft ticket only; never dispatch to a customer",
  "inputSchema": {
    "type": "object",
    "properties": {
      "case_id": {"type": "string", "pattern": "^[A-Z0-9-]{4,40}$"},
      "summary": {"type": "string", "maxLength": 200},
      "severity": {"type": "string", "enum": ["low", "medium", "high"]}
    },
    "required": ["case_id", "summary", "severity"],
    "additionalProperties": false
  }
}
```

**Required server-side checks:** authenticate caller, confirm case belongs to the tenant, authorize draft creation, validate fields, rate-limit, store a deduplication key, redact sensitive logs, and return the created draft ID. The model should not be trusted to supply a tenant ID that overrides the authenticated principal.

## 5. Approval Gates, Egress & Exfiltration Defense

An approval UI should show **who**, **what tool**, **which resource**, **which data**, **what action**, and **what will happen next**. High-risk actions—sending messages, granting permissions, deploying code, deleting files, executing commands—need approval at the actual host/service boundary, not merely a statement in the prompt.

Dangerous patterns include:
- A search-result snippet asking the agent to use a different tool or send secrets.
- A compromised MCP server exposing a benign description but performing external uploads.
- A calendar/email connector with global permissions reused for unrelated clients.
- A tool returning a forged "permission granted" statement.
- A confused-deputy request: an untrusted document instructs the assistant to invoke a privileged operation.

Defenses: scoped tool registry, egress allowlists, secrets isolation, read-only defaults, input validation, content/data classification and risk-weighted human review. Never expose raw privileged shell access to a chat by default.

## 6. Test Matrix & Failure Handling

| Test | Expected Safe Behavior |
|---|---|
| Missing OAuth scope / expired token | Explicit denial, no fallback to another identity |
| Tool removed or schema changed | Fail closed; re-discover and review |
| Cross-tenant case ID | Server rejects regardless of model's wording |
| Duplicate write request | One result or deduplicated response, no duplicate actions |
| Model invents approval | Host blocks without signed/recorded authorization |
| Untrusted tool output says "run this command" | Treat as data; do not escalate permissions |
| Timeout during write | Read target state before retry; use idempotency key |
| Unexpected data in trace | Stop, redact, rotate affected secrets if required |

### Troubleshooting

For "tool not found," check server identity, capability negotiation, permissions and list-change notices. For 401/403, check authorization discovery and grants without weakening controls. For JSON schema errors, inspect required fields and SDK versions. For repeated writes, add idempotency and post-write readback. For a tool behaving differently from its description, disable it and audit implementation.

## 7. Exercises & Evidence

Start with a mock read-only ticket service and synthetic records. Record discovery results, authentication method, denied cross-tenant access, request/response hashes (not sensitive bodies), approval screens and write readback. Only mark the milestone passed when unauthorized and replay tests also pass.

## Related Guides & Primary Sources

[Structured Output Contracts](structured-outputs-and-data-contracts.md) · [Agent Security](agent-threat-modeling-and-security.md) · [Reliability & Recovery](agent-reliability-and-recovery.md) · [Observability](ai-observability-and-auditing.md)

References: [MCP 2026-07-28 Specification](https://modelcontextprotocol.io/specification/2026-07-28) · [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) · [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) · [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

---

[AI Index](README.md) | [Master Index](../README.md)
