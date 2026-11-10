# Practical AI Usage and Interaction Guide

_Last reviewed: 2026-11-05_

Use this guide to turn chats into reliable outputs. A model's assertion is not proof, and its statement that it performed an action is not a tool receipt.

## Choose an Interaction Format

| Need | Format | Important check |
|---|---|---|
| One-time answer or draft | Chat | Assumptions and accuracy |
| Recurring work with related files | Project/workspace | Shared context, access and permissions |
| Evidence from selected documents | Source-backed notebook | Verify original passages and source dates |
| Reproducible numbers or analysis | Computational notebook | Clean execution and input versions |
| Repeatable role or expertise | Plugin, skill or reusable assistant | Behavior tests and tool permissions |
| Multi-step system operations | Bounded agent | Confirmed tool results, approvals and readbacks |

See [Projects, Notebooks and Assistants](ai-workspaces-notebooks-and-assistants.md).

## The Five Instruction Layers

1. **Mission:** Specify the outcome, intended user and definition of done.
2. **Context:** Provide authoritative sources, environment, version and current state.
3. **Boundaries:** Include scope, exclusions, privacy, allowed tools and human approvals.
4. **Execution:** Define ordered phases, milestones, outputs, retries and tests.
5. **Evidence:** Require sources, observed actions, open uncertainties and a resume checkpoint.

Keep instructions separate from data. Retrieved pages, emails, logs and external tool output are untrusted inputs, not permission to modify goals or disclose secrets. Text delimiters do not enforce access control.

### Reusable Prompt

```text
GOAL: [specific deliverable] for [audience].
INPUTS: [verified files, versions, dates, current status].
SCOPE: Include [items]; exclude [items]; preserve [existing work].
SOURCE ORDER: [authoritative references first].
PERMISSIONS: Read [sources]; edit only [paths]; obtain approval before
sending, deleting, publishing or making production changes.
PROCESS:
1. Inspect current state, conflicts, missing facts and prior work.
2. Plan milestones with observable acceptance criteria.
3. Execute scoped steps; record actual tool and test results.
4. Independently review evidence, privacy, omissions and regressions.
5. Deliver artifacts, unknowns, blockers and concise handoff.
Never fabricate citations, actions, access, dates or results.
```

For quick questions use a short goal, context and output format. For longer projects ask for **facts / assumptions / unknowns** and a bounded checklist. When correcting a false premise, have the assistant recheck dependent conclusions.

## From a Prompt to a Managed Workflow

A reliable project needs different mechanisms for different jobs; none of these is an interchangeable synonym:

| What You Need | Use | How To Verify It |
|---|---|---|
| Record facts, findings, decisions or context | Dated **notes** with source references | Re-open source and compare current state |
| Preserve what changed between sessions | `STATUS.md` and `HANDOFF.md` | Verify commit, artifacts and active blockers |
| Specify recurring role and permitted behavior | Reviewed instructions or a **skill** | Inspect the loaded instructions and test boundaries |
| React to a specific host event | Supported **hook**, scoped to that application | Trigger a synthetic event and inspect execution log |
| Run something at a specific time | **Scheduler / cron** | Inspect schedule, timezone and job result |
| Receive events from another service | Secured **webhook** or integration | Validate sender, event ID, delivery and idempotency |
| Decide when a major step is done | **Milestone** with acceptance tests and owner gate | Check independent evidence for every criterion |

A note does **not** automatically persist in model memory, and a hook does **not** necessarily make an independent check. Read the [full Notes, Memory, Hooks & Automation guide](notes-hooks-and-automation.md) to implement each safely. Use [Milestones & Acceptance Criteria](milestones-and-acceptance-criteria.md) to design gates and execute a full project.

### Practical Setup: Start, Work, Stop & Resume

1. **Start:** Create `PROJECT.md` with scope/authorization, `MILESTONES.md` with expected outcomes, and `AGENTS.md` with bounded tools and roles.
2. **Capture:** Maintain `SOURCES.md` for verified inputs, `NOTES.md` for observations, and `DECISIONS.md` for approved choices.
3. **Operate:** Perform the smallest safe task for the active milestone. Record actual commands, outputs and file changes; never infer success from the model's wording.
4. **Automate selectively:** Start with read-only or test-only hooks. Use a scheduler for periodic work and an authenticated integration for external alerts. Test expected, duplicate and failure paths.
5. **Review:** Assess each criterion, including negative cases, against `EVIDENCE.md`; leave untested criteria open.
6. **Handoff:** Update `STATUS.md` and `HANDOFF.md` with current SHA, passed/failed tests, pending approvals and the **next safe step**.
7. **Resume:** Load the approved records, inspect actual live state, reconcile contradictions and continue only within the current authorization.

### Prompt to Load Current Context Before Acting

```text
Load the supplied project charter, authorized scope, milestone plan,
source register, latest status and handoff. Inspect the actual current
repository or service state and compare it with those notes.
Separate observed facts, assumptions and outdated claims.
Identify the first unmet acceptance criterion.
Propose one bounded action with required permissions, evidence to collect,
tests to run and stop conditions. Do not send, deploy, delete or change
production systems without the required external approval.
```

### Prompt to Check a Claimed Milestone

```text
Audit milestone [ID] against its written acceptance contract.
For each criterion, give the expected result, exact observed evidence,
environment/version and PASS, FAIL, BLOCKED or NOT TESTED.
Check negative cases, privacy, permissions and regressions.
Do not claim acceptance based on a summary, merged PR or a single local test.
List gaps and identify who must approve the next phase.
```

## Sample Tasks

**Research:** “Compare options using dated primary sources. Separate supported, disputed and unverified claims.”

**Coding:** “Fix the reported test failure without changing unrelated behavior; run tests and report exact results. Do not deploy.”

**Cybersecurity:** “Analyze supplied logs only for assets within the written authorization; cite events, label hypotheses and list safe validation steps.”

**Writing:** “Draft a client update from the supplied facts without unsupported promises, dates or prices.”

## Privacy & Completion

Classify inputs (public/internal/confidential/regulated) before use. Do not upload unnecessary client data, keys or tokens; check platform access and retention controls. Long chat context can disappear, so preserve status and handoffs in durable records.

Before calling work complete, verify the actual output, source grounding, authorization, tests and blockers. Mark everything not independently checked as unverified.

## Related Guides

[Prompting](ai_prompts.md) · [Project & Agent Lanes](agent-project-workflows.md) · [Milestones & Acceptance Criteria](milestones-and-acceptance-criteria.md) · [Notes & Hooks](notes-hooks-and-automation.md) · [Fact-Checking & AI Audits](verification-and-ai-audits.md) · [Workspaces & Notebooks](ai-workspaces-notebooks-and-assistants.md)

References: [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) · [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)

---

[AI index](README.md) | [Master index](../README.md) | [Start Here](../START_HERE.md)
