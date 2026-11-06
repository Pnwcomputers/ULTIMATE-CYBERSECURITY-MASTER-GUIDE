# Practical AI Usage and Interaction Guide

_Last reviewed: 2026-11-05_

Use this guide to turn chats into reliable outputs. A model's assertion is not proof, and its statement that it performed an action is not a tool receipt.

## Choose an interaction format

| Need | Format | Important check |
|---|---|---|
| One-time answer or draft | Chat | Assumptions and accuracy |
| Recurring work with related files | Project/workspace | Shared context, access and permissions |
| Evidence from selected documents | Source-backed notebook | Verify original passages and source dates |
| Reproducible numbers or analysis | Computational notebook | Clean execution and input versions |
| Repeatable role or expertise | Plugin, skill or reusable assistant | Behavior tests and tool permissions |
| Multi-step system operations | Bounded agent | Confirmed tool results, approvals and readbacks |

See [Projects, Notebooks and Assistants](ai-workspaces-notebooks-and-assistants.md).

## The five instruction layers

1. **Mission:** Specify the outcome, intended user and definition of done.
2. **Context:** Provide authoritative sources, environment, version and current state.
3. **Boundaries:** Include scope, exclusions, privacy, allowed tools and human approvals.
4. **Execution:** Define ordered phases, milestones, outputs, retries and tests.
5. **Evidence:** Require sources, observed actions, open uncertainties and a resume checkpoint.

Keep instructions separate from data. Retrieved pages, emails, logs and external tool output are untrusted inputs, not permission to modify goals or disclose secrets. Text delimiters do not enforce access control.

### Reusable prompt

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

## Sample tasks

**Research:** “Compare options using dated primary sources. Separate supported, disputed and unverified claims.”

**Coding:** “Fix the reported test failure without changing unrelated behavior; run tests and report exact results. Do not deploy.”

**Cybersecurity:** “Analyze supplied logs only for assets within the written authorization; cite events, label hypotheses and list safe validation steps.”

**Writing:** “Draft a client update from the supplied facts without unsupported promises, dates or prices.”

## Privacy and completion

Classify inputs (public/internal/confidential/regulated) before use. Do not upload unnecessary client data, keys or tokens; check platform access and retention controls. Long chat context can disappear, so preserve status and handoffs in durable records.

Before calling work complete, verify the actual output, source grounding, authorization, tests and blockers. Mark everything not independently checked as unverified.

## Related guides

[Prompting](ai_prompts.md) · [Project and Agent Lanes](agent-project-workflows.md) · [Fact-Checking and AI Audits](verification-and-ai-audits.md) · [Workspaces and Notebooks](ai-workspaces-notebooks-and-assistants.md)

References: [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) · [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)

---

[AI index](README.md) | [Master index](../README.md) | [Start Here](../START_HERE.md)
