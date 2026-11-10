# Multi-Agent Orchestration, Delegation & Conflict Resolution

_Last reviewed: 2026-11-09_

Multi-agent systems can split work into specialist roles, but create new failure modes: inconsistent context, duplicate actions, privilege amplification, handoff errors and uncertain ownership. Use multiple agents **only when a single bounded process is insufficient**; additional agents are not automatically more accurate.

## 1. Choose an Orchestration Pattern

| Pattern | Workflow | Best For | Caution |
|---|---|---|---|
| Single agent + tools | One owner calls limited tools | Straightforward tasks | Keep tool set narrow |
| Coordinator / workers | Planner assigns bounded specialists | Parallel research or distinct files | Prevent coordinator from skipping review |
| Sequential pipeline | Research → build → verify → approve | Audit and change-management | Propagate exact artifact identities |
| Fan-out / fan-in | Independent analyses, then reconcile | Multiple source checks | Disagreement must be resolved with evidence |
| Human-in-the-loop | Agent drafts; owner approves | External sends, production changes | Human approval must be at execution boundary |
| Event-driven workers | Queue receives event IDs and dispatches | SOC triage, ticket processing | Idempotency, backpressure and retries |
| Debate / voting | Several models critique proposal | Exploring alternatives | Agreement is not independent proof |

### Recommended Default

Use **one orchestrator, separate scoped workers, an evidence verifier, and a human owner for sensitive decisions**. The orchestrator owns the dependency graph and integrated status, not unlimited system permissions.

## 2. Define a Task Contract Before Delegation

```yaml
task_id: AI-024
assigned_lane: verifier
mission: "Verify lab detection M3 acceptance"
inputs:
  repository_commit: "EXAMPLE_SHA"
  fixture_ids: ["LAB-SSH-001", "LAB-SSH-002"]
allowed_tools: ["read_file", "read_test_results"]
prohibited_tools: ["shell.execute", "email.send", "production.deploy"]
outputs: ["reports/m3-verification.md"]
acceptance: ["each test matched to observed result", "unknowns labeled"]
dependencies: ["AI-020", "AI-021"]
approval_required_for: ["change test criteria", "release"]
handoff: ["diff", "evidence refs", "failed cases", "next safe action"]
```

Inputs must be immutable or version-pinned where feasible. The worker cannot mark itself independently reviewed.

## 3. Split Work Without Race Conditions

1. **Inventory dependencies.** Represent tasks as a DAG (directed acyclic graph); reject circular dependencies.
2. **Choose ownership granularity:** separate branches, files, directories or isolated lab resources.
3. **Assign least-privilege tools** per lane, not one broad credential set.
4. **Keep each task bounded** by call count, runtime, spend, retry policy and exact deliverable.
5. **Start parallel work only when independent**; never parallel-edit a shared file without coordination.
6. **Require a normalized handoff** with status, artifacts, SHA, evidence and blockers.
7. **Integrate centrally** using expected source commit and optimistic concurrency checks.
8. **Run combined tests after merge**, including cross-file links and regression checks.
9. **Advance milestones only after acceptance evidence**; avoid "worker says done" decisions.

### Handoff Contract

```text
TASK: [ID]    LANE: [role]    STATUS: PASS / BLOCKED / FAILED
SOURCE: [branch + SHA + environment]
CHANGED: [exact files / resources]
OBSERVED: [actual tool outputs]
TESTED: [commands + results]
NOT TESTED: [items]
DEPENDENCIES: [IDs]
CONFLICTS: [unresolved differences]
APPROVAL: [who / required next action]
NEXT SAFE ACTION: [one bounded step]
```

## 4. Agent Identity, Isolation & Trust

Each agent should have a distinct **service identity or delegated permission boundary** if it calls sensitive tools. Do not let a researcher inherit production deployment credentials merely because it is in the same conversation. Treat all model-generated subtask instructions and inter-agent messages as potentially fallible: the orchestrator validates references, resource IDs and permission boundaries.

Never accept a worker's assertion that another agent or human approved a request. Query a trusted approval record. A worker may supply a candidate finding; only validated evidence can move project status.

## 5. Conflict Resolution

| Conflict | Example | Resolution |
|---|---|---|
| Same file modified | Two agents change AI/README.md | Merge manually or serialize writes; rerun tests |
| Contradictory facts | Two sources disagree on product version | Check dates and primary source; record unresolved result |
| Incompatible output schemas | Researcher writes unexpected fields | Validate contract; reject/repair upstream |
| Duplicate action | Both agents create draft ticket | Idempotency key and one owner for writes |
| Policy conflict | Worker asks to expand scan scope | Stop and obtain human authorization |
| Stale task | Branch advanced during work | Rebase/review against new SHA, revalidate |
| Circular delegation | Agent A repeatedly reassigns to B | Dependency and depth limits, loop detection |

### Integration Rule

A PR or patch that passes isolated worker tests still needs **integrated verification**. Track exact base commit, final commit, changed files, merge conflicts and new tests. Re-running a test after integration is not optional for changed behavior.

## 6. Review & Verification Lane

Use a dedicated verifier that has **read-only access** to expected criteria and actual outputs. Independence requires independently obtained evidence or reproducible checks; different prompts against the same model do not magically create independent data.

A reviewer prompt:

```text
You are a read-only verifier. Inspect milestone [ID], accepted source
version, changed paths and observed test results. Report PASS/FAIL/
NOT TESTED for each criterion, identify contradictions and suggest
minimal safe fixes. Do not write, release, send, delete, or self-approve.
```

## 7. Test a Small Multi-Agent Pipeline

**Synthetic example:** Wazuh lab alert → Researcher verifies event structure → Builder drafts a rule/documentation change on a branch → Verifier runs synthetic fixtures → Owner approves merge.

Acceptance cases:
- Researcher attempts an unapproved write: host must deny.
- Two events with same ID: one triage case.
- Worker forgets source SHA: handoff rejected as incomplete.
- Review finds a failing benign fixture: milestone blocked.
- Owner approval missing: release never executed.
- Merge conflict: integrator stops and presents exact affected paths.

Log parent task ID, child IDs, source SHA, tool results, approvals and actual external state. Limit recursion depth, concurrent workers and maximum spend.

## Related Guides & Primary Sources

[Agent Project Workflows](agent-project-workflows.md) · [Reliability](agent-reliability-and-recovery.md) · [Milestones](milestones-and-acceptance-criteria.md) · [Observability](ai-observability-and-auditing.md) · [MCP](mcp-tooling-and-permissions.md)

References: [OpenAI Running Agents](https://developers.openai.com/api/docs/guides/agents/running-agents) · [OpenAI Agents SDK](https://developers.openai.com/api/docs/guides/agents/sdk) · [OpenAI Agent Evals](https://developers.openai.com/api/docs/guides/agent-evals).

---

[AI Index](README.md) | [Master Index](../README.md)
