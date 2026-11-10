# AI Project Milestones, Acceptance Criteria & Evidence-Driven Progress

_Last reviewed: 2026-11-09_

Milestones turn a large AI-assisted project into **specific outcomes that can be independently checked**. They protect against vague "almost done" claims, lost context between sessions, premature releases, and agents working outside authorization. This is a hands-on implementation guide for a solo operator or multi-agent team.

> **Core principle:** A milestone is **not** a task list, a deadline, a message saying "completed," or a Git commit by itself. It is an agreed outcome with defined acceptance criteria and inspectable evidence.

## Contents

| Topic | Outcome |
|---|---|
| [Milestones Explained](#milestones-explained) | Distinguish goals, projects, phases, tasks, deliverables and gates |
| [Design a Good Milestone](#design-a-good-milestone) | Define scope, criteria, proof, approvals and failure paths |
| [A Complete Six-Stage Workflow](#a-complete-six-stage-workflow) | Apply inventory, design, implementation, verification and release |
| [Example: Defensive Detection Pipeline](#example-defensive-detection-pipeline) | Plan a realistic, authorized cybersecurity lab project |
| [Templates You Can Reuse](#templates-you-can-reuse) | Create project, milestone, status, evidence and handoff records |
| [Agents, Dependencies & Progress](#agents-dependencies--progress) | Delegate safely and track concurrent work |
| [Review, Release & Recovery](#review-release--recovery) | Verify, accept, resume and roll back correctly |

## Milestones Explained

| Concept | Question It Answers | Example |
|---|---|---|
| **Mission / goal** | Why are we doing this? | Improve visibility into suspicious SSH authentication in the authorized lab |
| **Project** | What bounded effort delivers that goal? | Build a Wazuh SSH correlation and triage exercise |
| **Phase** | What kind of work happens next? | Research, build, verify, release |
| **Milestone** | What **observable state** must be true before progressing? | Synthetic detections fire and documented benign cases do not |
| **Task** | What small action advances a milestone? | Add a rule, generate synthetic events, run tests |
| **Deliverable** | What artifact comes out? | Rule file, test fixtures, dashboard, runbook |
| **Acceptance criterion** | What exact test decides success? | Pass all agreed fixtures and document each failure |
| **Evidence** | What proves the criterion was checked? | Test command, results, source commit, reviewer note |
| **Approval gate** | Who must accept a sensitive transition? | Named owner approves production deployment |
| **Checkpoint** | How can someone resume without guessing? | Current commit, verified status, remaining risks and next step |

A **task can be complete while its milestone remains blocked**. For example, writing a detection rule fulfills a task; it does not prove the rule works, covers expected events, or is safe to deploy.

### GitHub Milestones Versus Project Milestones

GitHub also has a **Milestones** feature that groups issues and pull requests. It is useful for tracking work, but issue closure does not automatically prove that technical acceptance tests passed. Put acceptance criteria and links to evidence in the milestone description, a tracking issue, or the project's source-controlled records. Treat the GitHub progress display as project management metadata, not technical attestation.

## Design a Good Milestone

### Step 1 — Write the Desired End State

Use an observable state rather than a vague action.

| Weak | Better |
|---|---|
| "Work on alerts" | "An authorized test event produces the expected alert and evidence record" |
| "Finish documentation" | "All listed procedures have verified commands, working internal links and a dated reviewer note" |
| "AI checks everything" | "An independent reviewer verifies the listed claims using identified sources and records unresolved exceptions" |
| "Deploy system" | "Approved change is applied to the intended environment and a separate readback confirms the target configuration" |

### Step 2 — Define the Contract

For each milestone include **all** of:

1. **ID & name:** Stable, searchable identifier such as `M3 — Detection Verification`.
2. **Owner & reviewer:** Who does the work and who accepts the result.
3. **Scope & exclusions:** Exact repositories, files, systems, test assets and prohibited actions.
4. **Inputs & prerequisites:** Authoritative source version, preceding milestones, data and approvals.
5. **Deliverables:** Expected file paths, reports, configurations or working behavior.
6. **Acceptance tests:** Steps with an unambiguous pass/fail condition, including negative cases.
7. **Evidence:** Where outputs, logs, hashes, commits or readbacks will be recorded.
8. **Risk & rollback:** Failure response and safe reversal procedure.
9. **Approval requirement:** What needs human sign-off before a subsequent phase.
10. **Status & timestamp:** One current status tied to evidence, not model confidence.

### Step 3 — Split Large Work at Meaningful Boundaries

A milestone should be large enough to represent an outcome yet small enough to verify without an open-ended investigation. Prefer bounded stages or a few independently testable deliverables over one "complete the entire system" milestone. Avoid splitting solely by the number of files or hours spent.

### Step 4 — Specify What Counts as Failure

Examples: wrong environment, missing owner authorization, stale source, failed test, unknown event coverage, unsupported configuration, absent rollback path, or unverified user/client impact. Document how the project should stop and who resolves the problem.

### Step 5 — Freeze the Acceptance Contract Before Execution

When requirements change, record the change in `DECISIONS.md`, update affected milestones and get the appropriate review. Do not silently weaken an acceptance criterion to make the work appear complete.

## A Complete Six-Stage Workflow

This is a **reference pattern**, not a mandatory fixed set of milestones. Projects may use fewer or more stages, but should retain clear gates.

| Stage | Question | Deliverable | Acceptance Gate |
|---|---|---|---|
| **M0 — Inventory & Authorization** | Do we know the actual starting state and legal/technical scope? | Asset list, source baseline, scope/consent, constraints | Owner confirms authorized targets; baseline has source and date |
| **M1 — Design & Risk Review** | Is the proposed method viable, bounded and reversible? | Architecture, data flow, test plan, failure modes | Threat/privacy review and approval of plan |
| **M2 — Build a Bounded Prototype** | Can the smallest solution work in a safe environment? | Prototype, implementation diff, synthetic test data | Basic intended behavior demonstrated, limitations labeled |
| **M3 — Validate & Harden** | Does it withstand negative cases and common failures? | Tests, security checks, defect log, updated runbook | Defined criteria pass; residual gaps explicit |
| **M4 — Release Decision & Controlled Rollout** | Is the change authorized and ready for the target environment? | Change plan, approvals, rollback, release artifact | Human approval and target-state readback |
| **M5 — Close, Monitor & Handoff** | Is the result maintainable and recoverable? | Operational record, ownership, monitoring and handoff | Owner accepts evidence and remaining risks |

### What Not to Infer

- A successful local test does **not** prove production availability or security.
- A clean test run does **not** prove that untested negative cases are safe.
- Passing lint does **not** mean all Markdown links, source claims and configurations work.
- A PR merged to GitHub does **not** verify downstream service state.
- Agent self-review does **not** equal an independent test or human authorization.
- A milestone's percent complete is **not** a substitute for its acceptance gate.

## Example: Defensive Detection Pipeline

**Scenario:** Build an AI-assisted triage workflow for synthetic suspicious SSH authentication events using Wazuh and optional read-only AI summarization. Only an explicitly authorized lab is in scope.

### Project Contract

```text
MISSION: Produce verifiable, explainable SSH alert triage in an authorized lab.
IN SCOPE: Synthetic log fixtures, lab Wazuh rules, read-only alert summaries.
OUT OF SCOPE: Production endpoints, exploitation, host isolation, user changes,
              automatic firewall blocks, external client messaging.
APPROVAL: Lab owner approves tests; separate approval before any production use.
SUCCESS: Expected synthetic events detected; benign controls assessed;
         evidence, failures, ownership and rollback documented.
```

### Milestone Plan With Acceptance Tests

| Milestone | Concrete Work | Acceptance Criteria | Evidence |
|---|---|---|---|
| **M0 Scope & Baseline** | Identify authorized lab, Wazuh versions, ingest path, test accounts and data boundaries | Scope signed; baseline system/configuration read back; no real client records | Authorization, environment inventory, source commit |
| **M1 Detection Design** | Specify target event pattern, false-positive assumptions, AI read-only output schema and rollback | Event schema reviewed; test cases and prohibited actions agreed | Design file, risk review, approved test matrix |
| **M2 Prototype** | Create sample rule and synthetic fixtures; test lab ingest | Test event reaches parser and produces the intended rule ID | Rule diff, fixture, exact test output |
| **M3 Negative & Regression Tests** | Test benign login bursts, out-of-order events, malformed inputs and duplicate alerts | Predetermined expected outcomes recorded; significant false positives resolved or accepted as limitations | Passing and failing case log; reviewer note |
| **M4 Approval & Deployment** | Prepare deployment steps without executing against production | Owner approves exact version, target, maintenance plan and rollback; if deployed, verify live configuration by readback | Approval record, release SHA, deployment/readback log |
| **M5 Monitor & Handoff** | Define alert ownership, retention and follow-up; write concise recovery notes | Maintainer can reproduce test and safely disable workflow | Runbook, status, handoff, scheduled review |

**Example M3 failure:** The intended lab detection fires, but a benign administrative test triggers the same severity. Mark `M3: blocked`; record fixture ID, rule version, expected vs actual outcome, and remediation options. Do not relabel it "passed" because the primary detection works. If the false-positive is accepted, a named approver must record the reason and residual risk.

### Safe AI Delegation Example

```text
You are the VERIFIER for M3 of the approved lab detection project.
Read PROJECT.md, MILESTONES.md, relevant rules, synthetic fixtures,
and EVIDENCE.md. Do not modify rules or run any production commands.
Check each acceptance criterion separately and report:
- Criterion ID and expected result
- Exact evidence file / test result / source version
- PASS, FAIL, BLOCKED or NOT TESTED
- Contradictions or unverified claims
- Recommended next bounded action
Do not claim the milestone is accepted; only the named owner can approve it.
```

## Templates You Can Reuse

All templates below are **illustrative Markdown/text files**, not platform-mandated APIs. Choose a small set of records, keep one active source of truth, and preserve history.

### `PROJECT.md` — Charter

```markdown
# Project: [Name]
Owner: [Name / role]
Last Reviewed: [ISO date + timezone]
Mission: [Observable end state]
Scope: [Authorized assets, paths, systems and dates]
Exclusions: [Prohibited actions, data, environments]
Reference State: [Commit, software versions, source ledger]
Success Definition: [Final measurable outcomes]
Approvals Required: [Who approves scope, writes and release]
Data Classification: [Public / internal / confidential / regulated]
Links: [MILESTONES.md, STATUS.md, SOURCES.md, EVIDENCE.md]
```

### `MILESTONES.md` — Acceptance Contract

```markdown
# Milestones

## M2 — [Name]
Status: IN PROGRESS
Owner: [role]
Reviewer: [independent person / review process]
Depends On: [M0, M1]
Scope: [specific asset, path, test environment]
Deliverables: [exact files or service behavior]
Acceptance Criteria:
- [ ] AC-1: [Observable condition + exact test]
- [ ] AC-2: [Negative case / error handling]
- [ ] AC-3: [Security and privacy constraint]
Evidence: [EVIDENCE.md entries, logs, SHA, linked output]
Stop Conditions: [Missing authority, failed test, data exposure]
Approval Gate: [Person / system policy]
Rollback: [Concrete supported reversal]
```

### `STATUS.md` — Single Current Status

```markdown
# Project Status
Updated: [ISO 8601 timestamp + timezone]
Source Commit: [SHA]
Current Milestone: M2 — [Name]
M0: ACCEPTED — [approver, evidence ref]
M1: ACCEPTED — [approver, evidence ref]
M2: IN PROGRESS — AC-1 PASS; AC-2 NOT TESTED; AC-3 BLOCKED
M3–M5: NOT STARTED
Last Verified Outcome: [What really passed, where]
Known Blockers: [Issue IDs, owner, impact]
Next Safe Action: [One scoped step]
Pending Decisions: [Approver / question]
```

### `EVIDENCE.md` — Proof Register

```markdown
# Evidence Register
- ID: EV-017
  Milestone: M2 / AC-1
  Timestamp: [date, time, timezone]
  Environment: [lab only, version]
  Source Commit: [SHA]
  Method: [exact test command or procedure]
  Expected: [expected behavior]
  Observed: [actual output, not an AI assertion]
  Artifact: [restricted path / sanitized artifact link]
  Result: PASS | FAIL | BLOCKED | NOT TESTED
  Reviewer: [person / independent process]
  Caveats: [limitations]
```

### `HANDOFF.md` — Session Resume

```text
LAST VERIFIED STATE:
- Working branch / SHA: [...]
- Milestone: [...]
- Accepted criteria: [...] with evidence IDs [...]
- Failed / not tested criteria: [...]
- Changed paths: [...]
- Tools run: [...] and their actual results
- Actions not performed: [...]
- Approvals outstanding: [...]
NEXT SAFE ACTION: [...]
STOP IF: [...] (e.g., scope changed or branch advanced)
```

### How to Actually Use the Templates

1. Create the charter and milestone contracts **before** implementation.
2. Record the current version/commit in `STATUS.md`.
3. Execute only one approved, bounded task or delegated lane at a time.
4. Save outputs and test evidence as tasks finish.
5. Review acceptance criteria **individually**; untested means `NOT TESTED`, not pass.
6. Advance a milestone only with the required evidence and owner acceptance.
7. Update `STATUS.md` and `HANDOFF.md` with the exact new state.
8. At the next session, reread the records and verify **live state** before continuing.

Keep confidential evidence out of a public repo; store its sanitized reference, not a copy of sensitive records.

## Agents, Dependencies & Progress

### Assign Clear Work Lanes

| Lane | Permitted Work | Output / Proof | Cannot Self-Approve |
|---|---|---|---|
| Planner | Define scope, tasks and dependencies | Draft milestone contracts | Scope expansion |
| Researcher | Gather dated authoritative sources | Source ledger and conflicts | Unsupported facts |
| Builder | Implement only assigned paths | Diff, tests, open failures | Release acceptance |
| Reviewer | Inspect design/security/regressions | Findings with reproductions | Own implementation as independent |
| Verifier | Execute/inspect acceptance tests | Criterion-by-criterion results | Owner approval |
| Owner | Authorize scope and sensitive changes | Decision and approval record | Skip required external control |

One AI performing all roles is useful for a preliminary check but is **not** independent validation. Use separately sourced evidence, reproducible tests, and a human or distinct trusted review process for high-impact results.

### Handling Parallel Tasks

- Assign independent files, branches or environments wherever possible.
- State dependency IDs explicitly (`M3 AC-2` cannot close before `M2 AC-1`).
- Establish one integrator for combined changes; don't let multiple agents overwrite the same files.
- Record merge conflicts and rerun checks **after** integration, not only on isolated branches.
- A claim that one worker "finished" is a handoff, not acceptance by the next worker.
- Prevent agents from changing the charter or acceptance criteria without authorized review.

### Progress States

Use consistent states such as `NOT STARTED`, `IN PROGRESS`, `BLOCKED`, `READY FOR REVIEW`, `ACCEPTED` and `SUPERSEDED`. Criterion states may be `PASS`, `FAIL`, `NOT TESTED` or `BLOCKED`.

If a dashboard needs a percent, derive it transparently from **accepted** criteria or tracked tasks and disclose what the percentage measures. Never infer an acceptance percentage from narrative confidence. A milestone with nine of ten criteria satisfied is not necessarily safe to release if the tenth is an authorization or rollback gate.

## Review, Release & Recovery

### Gate Review Procedure

For each criterion, ask:

1. Is the current source/configuration/environment the one named in the plan?
2. Did an observed tool result or independently run test satisfy the criterion?
3. Are the timestamp, command, artifact and expected/actual outputs recorded?
4. Were relevant negative, permission, regression and failure cases checked?
5. Did any test affect out-of-scope assets or disclose sensitive information?
6. Are failures, exceptions and residual risks written down?
7. Has the correct person or control actually approved the transition?

**Result:** `ACCEPTED` only when all required criteria and approval gates are met. Otherwise `BLOCKED` or `READY FOR REVIEW`, with precise missing items.

### Recover After an Interrupted Session

```text
RESUME:
1. Read PROJECT.md, MILESTONES.md, STATUS.md, HANDOFF.md.
2. Inspect current files, branch SHA, tests and environment.
3. Compare present state with the last evidence-backed checkpoint.
4. Flag differences, stale assertions and unapproved changes.
5. Select the smallest still-valid task in the active milestone.
6. Reconfirm permissions before writes/sends/production actions.
7. Work, test, log outcomes and update the handoff.
```

Never rerun a destructive step just because the handoff is ambiguous. Read back state and obtain clarification or approval when necessary.

### Release & Rollback

A release should document exact target, artifact/version, authorization, rollout order, monitoring, stop conditions, rollback owner and tested reversal approach. After release, verify the **target state**. If readback fails, do not mark the release milestone accepted. For alerting/automation changes, include checks for false positives, unwanted notifications, duplicates, data retention and ability to disable the integration.

## Frequent Failure Modes

| Failure | Why It Happens | Correction |
|---|---|---|
| Milestone is just a heading | No measurable outcome | Add criterion, expected result and evidence location |
| Tasks and milestones conflated | Activity mistaken for success | Separate task completion from outcome acceptance |
| AI claims all work is done | No independent readback | Check real files/service state and tests |
| A local run is called production-ready | Scope mismatch | Require target-specific release gate |
| Parallel agents overwrite work | No ownership boundaries | Assign branches/paths and integration owner |
| Handoffs lose important facts | Summary only, no source commit | Record actual SHA, failures and next safe task |
| Tests are cherry-picked | Positive cases only | Specify negatives and regressions up front |
| Sensitive work auto-approved | Approval in text only | Enforce external host/system approval |
| Status stays stale | No update habit | Update after each accepted criterion or blocker |
| Blocked phase marked green | Incomplete criteria | Preserve `BLOCKED`, escalation and residual risk |

## Related Reading

| Guide | Next Topic |
|---|---|
| [Notes, Memory, Hooks & Automation](notes-hooks-and-automation.md) | Context records, real hook setup, scheduled jobs and validation |
| [Project & Agent Workflows](agent-project-workflows.md) | Agent lanes, progress tracking and resume mechanics |
| [Practical AI Usage](ai-usage-interaction-guide.md) | Bounded, verifiable prompts |
| [Verification & AI Audits](verification-and-ai-audits.md) | Independent fact-checks and tool verification |
| [Workspaces & Assistants](ai-workspaces-notebooks-and-assistants.md) | Project file and workspace structure |
| [Assessment Lifecycle](../PlayBooks/assessment-findings-lifecycle.md) | Cybersecurity finding status, evidence and retest discipline |

---

[AI Index](README.md) | [Master Index](../README.md) | [Start Here](../START_HERE.md)
