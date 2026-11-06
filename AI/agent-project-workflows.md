# Project and Agent Workflows: Goals, Milestones, Lanes and Resuming Work

_Last reviewed: 2026-11-05_

Use a few authoritative files to make AI-assisted projects reproducible and resumable. This works with a single assistant or multiple specialist agents.

## Separate stable instructions from current status

| File | Responsibility |
|---|---|
| `PROJECT.md` | Mission, scope, explicit non-goals, milestones, definition of done |
| `AGENTS.md` | Agent lane roles, source priority, permitted tools and approval boundaries |
| `STATUS.md` | Current work queue, completed tasks, blockers and next step |
| `DECISIONS.md` | Date, decision, alternatives, reason and owner |
| `EVIDENCE.md` | Sources, tests, source commit, output hashes and tool readbacks |
| `HANDOFF.md` | Shortest accurate checkpoint for the next session |

These are example filenames, not required platform features. Keep one active source of truth and archive old handoffs; do not paste long transcripts into instructions.

## Charter and milestones

```text
MISSION: [measurable desired outcome]
SCOPE: [allowed files, accounts, environments and assets]
OUT OF SCOPE: [explicit exclusions]
AUTHORITATIVE INPUTS: [file names, timestamps and precedence]
M0 INVENTORY: complete when [baseline and gaps documented].
M1 DESIGN: complete when [design and risks reviewed].
M2 IMPLEMENT: complete when [diff or deliverable exists].
M3 VERIFY: complete when [independent checks and tests pass].
M4 RELEASE: complete when [approval and target-state readback exist].
DONE WHEN: [observable acceptance criteria].
ESCALATE BEFORE: [sends, secrets, destructive and production changes].
```

Local tests do not prove production behavior. A clean narrow run does not clear unresolved broad audit gaps.

## Agent and project lanes

| Lane | Owns | Must deliver |
|---|---|---|
| Planner | Scope, milestones, dependencies and work queue | Task contracts |
| Researcher | Primary-source gathering and contradiction checks | Dated source ledger |
| Builder | Bounded implementation | Diff, artifacts and local tests |
| Reviewer | Security, quality and regressions | Reproducible findings |
| Verifier | Independent acceptance checks | Exact commands, results and gaps |
| Human owner | Sensitive authorization and acceptance | Approval record |

A single model simulating different lanes does **not** constitute independent review. Parallel workers should own separate files or branches. Integrate changes carefully, resolve conflicts and rerun combined tests.

### Agent lane contract

```text
TASK ID: [ID]    LANE: [research/builder/reviewer/verifier]
INPUTS: [sources, files, commit and version].
OUTPUTS: [exact artifact paths].
BOUNDARIES: [read only or explicitly allowed writes].
DEPENDENCIES: [other task IDs].
DONE WHEN: [reproducible tests].
STOP IF: [missing authorization, identity or evidence].
HANDOFF: [diff, test receipts, unknowns and next step].
```

## Execute and resume

1. Read charter, agent rules, current status and latest handoff.
2. Inspect actual repository or service state before trusting older reports.
3. Reconcile contradictions and define the next small, testable milestone.
4. Execute within permissions; log exact file edits and tool outcomes.
5. Verify source facts, outputs, negative cases, permissions and regressions.
6. Review independently and record failures with reproduction steps.
7. Update status and handoff; obtain approval before sensitive release.

### Status checkpoint template

```text
UPDATED: [date/time/timezone]    CURRENT MILESTONE: [M#]
VERIFIED COMPLETED: [items -> evidence]
LOCALLY TESTED ONLY: [items -> environment]
UNVERIFIED/BLOCKED: [items -> why]
NEXT QUEUE: [ordered tasks -> owners -> acceptance]
SOURCE COMMIT: [SHA]    CHANGED PATHS: [files]
TESTS RUN: [exact commands and results]
TESTS NOT RUN: [limitations]
NEEDS OWNER: [decision and risk]
NEXT SAFE ACTION: [one bounded task]
```

Use least-privilege tools, source-linked identities, dry-run previews, bounded retries, human approval gates, confirmed API results and post-write readbacks. An AI cannot authorize its own production actions through prompt text.

## Related guides

[AI Usage](ai-usage-interaction-guide.md) · [Independent AI Audits](verification-and-ai-audits.md) · [Workspaces](ai-workspaces-notebooks-and-assistants.md) · [Assessment Findings](../PlayBooks/assessment-findings-lifecycle.md)

---

[AI index](README.md) | [Master index](../README.md) | [Start Here](../START_HERE.md)
