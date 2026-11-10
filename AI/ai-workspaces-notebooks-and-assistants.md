# AI Projects, Notebooks, GPTs, Plugins and Reusable Assistants

_Last reviewed: 2026-11-05_

Choose the smallest workspace that maintains necessary context and evidence without granting excessive access.

## Compare the Options

| Format | Best for | Verify |
|---|---|---|
| Chat | Questions and short drafts | Context and factual accuracy |
| ChatGPT Project | Shared instructions, files and related chats | Sharing, memory and tool access |
| Claude Project | Project knowledge and instructions | Which chats see which sources |
| Source-based notebook (e.g., NotebookLM) | Summaries grounded in selected documents | Passages, dates and source coverage |
| Jupyter notebook | Reproducible calculations, code and data | Clean rerun, inputs and dependency versions |
| GPT/plugin/skill | Reusable specialized behavior | Migration, permissions, reference files and tests |
| Tool-using agent | Multi-step actions | Human authorizations and tool outcomes |

### Projects & Source-Backed Notebooks

Keep behavior rules distinct from reference facts. Use a dated source register, current status and concise handoff for multi-session work. Inspect sharing and privacy settings before uploading confidential materials. Read primary source passages rather than trusting a notebook's citations without checking.

References: [ChatGPT Projects](https://help.openai.com/en/articles/10169521-projects-in-chatgpt), [NotebookLM](https://notebooklm.google.com/), [Project Jupyter](https://jupyter.org/).

### Computational Notebooks

Record data versions and hashes where possible, software dependencies, seeds and assumptions. Execute Jupyter from a clean kernel and compare results. Out-of-order cells and stale variables can create falsely reassuring outputs.

### Custom GPT Retirement & Plugin Migration

As of November 2026, OpenAI has announced custom GPT retirement on **December 11, 2026**, with specified FedRAMP and approved Enterprise deferrals until **February 11, 2027**. Availability and eligibility vary; confirm in-product notices and the [official migration FAQ](https://help.openai.com/en/articles/20001519-custom-gpt-retirement-and-migration-faq).

For an existing GPT, inventory its instructions, files, tools, users and test prompts. When migration is offered, review the copied instructions and knowledge and test the replacement. Custom GPT API actions **do not transfer automatically** and must be rebuilt and independently validated. Migration starts with a private plugin; other users do not automatically gain access. Personal ChatGPT accounts cannot create or publish new custom GPTs.

### Reusable Agents & Skills

Specify mission, tool permissions, source precedence, example inputs, failure handling and evaluation criteria. Use synthetic adversarial tests and enforce external-action permissions outside model prompts. Self-hosting does not automatically guarantee data isolation.

For implementation details consult [Offline LLM](offline-llm.md), [AnythingLLM](AnythingLLM/README.md) and [OpenClaw](OpenClaw/README.md).

## Build an Evidence-Backed AI Project Workspace

For a project spanning multiple sessions or agents, use an explicit workspace rather than relying on a single conversation to hold all state.

### Step 1 — Establish the Trust Boundary

Create a project workspace with the least broad sharing and tool access appropriate to the work. Before importing reference material, classify it and decide whether it is safe for the chosen provider or needs a local/offline environment. Never upload live client credentials or sensitive security evidence as casual reference files.

### Step 2 — Store Different Kinds of Knowledge Separately

| File / Mechanism | Store Here | Do Not Assume |
|---|---|---|
| `PROJECT.md` / project instructions | Mission, authorized scope, non-goals and definition of done | Text policies can grant or revoke host-level permissions |
| `SOURCES.md` / attached reference files | Approved primary sources, timestamps, version information | An AI summary reflects the entire reference or its latest state |
| `NOTES.md` / investigation notes | Observed events, hypotheses and source pointers | Notes automatically become permanent assistant memory |
| `DECISIONS.md` | Owner decisions, alternatives, reasons and dates | An AI can approve its own high-impact action |
| `MILESTONES.md` | Measurable outcomes, criteria, owner gates, rollback | Task completion means milestone acceptance |
| `STATUS.md` and `HANDOFF.md` | Latest verified progress and next safe step | A later chat will automatically inherit current state |
| `EVIDENCE.md` | Actual tests and readbacks, sanitized evidence references | A tool invocation is proof of desired end-state |
| Hook / scheduler configuration | Event-driven or periodic automation setup | Every AI chat or workspace implements hooks in the same way |

For examples, see [Notes, Memory, Hooks & Automation](notes-hooks-and-automation.md) and [Milestones & Acceptance Criteria](milestones-and-acceptance-criteria.md).

### Step 3 — Load Approved Context & Check Freshness

At the start of a new session, explicitly provide or load the charter, rules, latest source register, current milestone and handoff. Ask the assistant to read the actual files and compare them with the repository head/service state. Identify any missing files, stale assertions or conflicting inputs **before** writing. Not every platform loads all project files into each chat or agent run.

### Step 4 — Enable Automation Selectively

A project workspace stores context; **hooks and scheduled jobs live in the relevant host's configuration**. Use a hook when the host exposes the needed lifecycle event, a scheduler for recurring tasks, and a secured webhook for cross-system events. First test with synthetic data, and ensure the handler cannot exceed its account or tool permissions. Document event ID handling, failures and rollback in the project records.

### Step 5 — Accept the Result & Preserve a Handoff

Run acceptance tests, inspect actual output, verify negative cases and capture version-specific evidence. Keep `NOT TESTED` separate from `PASS`; do not promote an AI-generated conclusion into a factual record without review. Update status, write the next safe task and obtain the required human approval before rollout.

## Portable Project Structure

```text
workspace/
  PROJECT.md      mission, scope and milestones
  AGENTS.md       lane and tool rules
  SOURCES.md      dated references
  STATUS.md       work queue and blockers
  DECISIONS.md    choices and rationale
  EVIDENCE.md     observed tests and tool outcomes
  HANDOFF.md      resume checkpoint
  outputs/        versioned, sanitized deliverables
```

These are general conventions, not platform requirements.

### Architecture Extensions for Long-Running Agents

Workspace files supply project context, but a reliable agent also needs the surrounding runtime. See [Context Engineering](context-engineering-and-memory.md) for loading and freshness; [RAG & Knowledge Engineering](rag-and-knowledge-engineering.md) for access-controlled source lookup; [MCP & Permissions](mcp-tooling-and-permissions.md) for privileged tools; [Reliability & Recovery](agent-reliability-and-recovery.md) for retries and checkpoints; and [Observability](ai-observability-and-auditing.md) for evidence-backed auditing. An attached note cannot independently guarantee any of these controls.

## Related Guides

[AI Usage](ai-usage-interaction-guide.md) · [Notes & Hooks](notes-hooks-and-automation.md) · [Milestones & Acceptance](milestones-and-acceptance-criteria.md) · [Agent Projects](agent-project-workflows.md) · [Independent Audits](verification-and-ai-audits.md) · [Prompt Engineering](ai_prompts.md)

---

[AI index](README.md) | [Master index](../README.md) | [Start Here](../START_HERE.md)
