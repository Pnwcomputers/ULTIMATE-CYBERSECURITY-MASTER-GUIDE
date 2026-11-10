# Project and Agent Workflows: Goals, Milestones, Lanes and Resuming Work

_Last reviewed: 2026-11-05_

Use a few authoritative files to make AI-assisted projects reproducible and resumable. This works with a single assistant or multiple specialist agents.

## Separate Stable Instructions From Current Status

| File | Responsibility |
|---|---|
| `PROJECT.md` | Mission, scope, explicit non-goals, milestones, definition of done |
| `AGENTS.md` | Agent lane roles, source priority, permitted tools and approval boundaries |
| `STATUS.md` | Current work queue, completed tasks, blockers and next step |
| `DECISIONS.md` | Date, decision, alternatives, reason and owner |
| `EVIDENCE.md` | Sources, tests, source commit, output hashes and tool readbacks |
| `HANDOFF.md` | Shortest accurate checkpoint for the next session |

These are example filenames, not required platform features. Keep one active source of truth and archive old handoffs; do not paste long transcripts into instructions.

## Charter & Milestones

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

## How to Operate Milestones (Not Just Name Them)

A useful milestone has an **observable outcome**, precise acceptance criteria, owned deliverables, evidence and approval requirements. Writing `M3 VERIFY` in a prompt is only the beginning.

| Field | Example for a Lab Wazuh Detection Project |
|---|---|
| ID & Outcome | M3 — Detection Tests Pass |
| Owner / Reviewer | Builder owns rules; verifier independently checks fixtures |
| Prerequisites | M0 authorized lab and M1 approved synthetic test matrix |
| Deliverables | Rule diff, synthetic fixtures, expected/actual results |
| Positive Criterion | Expected SSH test fixture creates the specified alert |
| Negative Criterion | Agreed benign fixtures do not create high-severity findings |
| Resilience Criterion | Duplicate/malformed inputs handled as documented |
| Proof | Test commands, tool output and source commit recorded in `EVIDENCE.md` |
| Stop Condition | Unexpected production target, sensitive-data exposure, failed negative check |
| Gate | No production rollout until owner signs off on M3 and M4 |

### Work One Criterion at a Time

1. **Inspect:** Recheck authorization, current commit, environment and criteria.
2. **Assign:** Select one bounded task and name its responsible lane.
3. **Execute:** Collect the actual output rather than a narrative success claim.
4. **Validate:** Compare expected and actual behavior; include negative cases.
5. **Log:** Update evidence and record `PASS`, `FAIL`, `BLOCKED` or `NOT TESTED`.
6. **Review:** Only the designated authority accepts the milestone; a model's self-review does not substitute.
7. **Resume:** Update `STATUS.md` / `HANDOFF.md` with the next unmet criterion.

If a task fails, leave the milestone open even if earlier criteria pass. A successful build does not prove safe operation, and a locally passing test does not prove production behavior. The [full Milestones & Acceptance Criteria guide](milestones-and-acceptance-criteria.md) provides a six-stage lifecycle, cybersecurity project worked example, reusable charter/status/evidence templates, rollback plan and GitHub milestone distinction.

## How Notes & Hooks Support Progress

Use **notes** to record evidence and decisions, **hooks** to react to supported application events, **schedules** for periodic checks, and **milestones** to decide whether the resulting work meets the project standard. This is a division of responsibilities, not interchangeable terminology.

**Example:** A post-edit hook invokes a syntax check after the builder changes a rule. The hook can log its own exit status, but it cannot establish that a detection scenario passed unless the correct test was run and evidence captured. The verifier links that evidence to the milestone criterion, and the project owner approves advancing to the next stage.

Onboarding a new agent/session requires explicitly loading approved context; writing `HANDOFF.md` does not guarantee the next model will see it. Event hooks also require host-specific configuration and trusted execution permissions. See [Notes, Memory, Hooks & Automation](notes-hooks-and-automation.md) for complete setup and troubleshooting procedures.

## Agent & Project Lanes

| Lane | Owns | Must deliver |
|---|---|---|
| Planner | Scope, milestones, dependencies and work queue | Task contracts |
| Researcher | Primary-source gathering and contradiction checks | Dated source ledger |
| Builder | Bounded implementation | Diff, artifacts and local tests |
| Reviewer | Security, quality and regressions | Reproducible findings |
| Verifier | Independent acceptance checks | Exact commands, results and gaps |
| Human owner | Sensitive authorization and acceptance | Approval record |

A single model simulating different lanes does **not** constitute independent review. Parallel workers should own separate files or branches. Integrate changes carefully, resolve conflicts and rerun combined tests.

### Agent Lane Contract

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

## Execute & Resume

1. Read charter, agent rules, current status and latest handoff.
2. Inspect actual repository or service state before trusting older reports.
3. Reconcile contradictions and define the next small, testable milestone.
4. Execute within permissions; log exact file edits and tool outcomes.
5. Verify source facts, outputs, negative cases, permissions and regressions.
6. Review independently and record failures with reproduction steps.
7. Update status and handoff; obtain approval before sensitive release.

### Status Checkpoint Template

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

## Related Guides

[AI Usage](ai-usage-interaction-guide.md) · [Milestones & Acceptance](milestones-and-acceptance-criteria.md) · [Notes & Hooks](notes-hooks-and-automation.md) · [Independent AI Audits](verification-and-ai-audits.md) · [Workspaces](ai-workspaces-notebooks-and-assistants.md) · [Assessment Findings](../PlayBooks/assessment-findings-lifecycle.md)

---

[AI index](README.md) | [Master index](../README.md) | [Start Here](../START_HERE.md)
