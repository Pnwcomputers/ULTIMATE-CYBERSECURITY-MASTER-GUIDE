# AI Projects, Notebooks, GPTs, Plugins and Reusable Assistants

_Last reviewed: 2026-11-05_

Choose the smallest workspace that maintains necessary context and evidence without granting excessive access.

## Compare the options

| Format | Best for | Verify |
|---|---|---|
| Chat | Questions and short drafts | Context and factual accuracy |
| ChatGPT Project | Shared instructions, files and related chats | Sharing, memory and tool access |
| Claude Project | Project knowledge and instructions | Which chats see which sources |
| Source-based notebook (e.g., NotebookLM) | Summaries grounded in selected documents | Passages, dates and source coverage |
| Jupyter notebook | Reproducible calculations, code and data | Clean rerun, inputs and dependency versions |
| GPT/plugin/skill | Reusable specialized behavior | Migration, permissions, reference files and tests |
| Tool-using agent | Multi-step actions | Human authorizations and tool outcomes |

### Projects and source-based notebooks

Keep behavior rules distinct from reference facts. Use a dated source register, current status and concise handoff for multi-session work. Inspect sharing and privacy settings before uploading confidential materials. Read primary source passages rather than trusting a notebook's citations without checking.

References: [ChatGPT Projects](https://help.openai.com/en/articles/10169521-projects-in-chatgpt), [NotebookLM](https://notebooklm.google.com/), [Project Jupyter](https://jupyter.org/).

### Computational notebooks

Record data versions and hashes where possible, software dependencies, seeds and assumptions. Execute Jupyter from a clean kernel and compare results. Out-of-order cells and stale variables can create falsely reassuring outputs.

### Custom GPT retirement and plugin migration

As of November 2026, OpenAI has announced custom GPT retirement on **December 11, 2026**, with specified FedRAMP and approved Enterprise deferrals until **February 11, 2027**. Availability and eligibility vary; confirm in-product notices and the [official migration FAQ](https://help.openai.com/en/articles/20001519-custom-gpt-retirement-and-migration-faq).

For an existing GPT, inventory its instructions, files, tools, users and test prompts. When migration is offered, review the copied instructions and knowledge and test the replacement. Custom GPT API actions **do not transfer automatically** and must be rebuilt and independently validated. Migration starts with a private plugin; other users do not automatically gain access. Personal ChatGPT accounts cannot create or publish new custom GPTs.

### Reusable agents and skills

Specify mission, tool permissions, source precedence, example inputs, failure handling and evaluation criteria. Use synthetic adversarial tests and enforce external-action permissions outside model prompts. Self-hosting does not automatically guarantee data isolation.

For implementation details consult [Offline LLM](offline-llm.md), [AnythingLLM](AnythingLLM/README.md) and [OpenClaw](OpenClaw/README.md).

## Portable project structure

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

## Related guides

[AI Usage](ai-usage-interaction-guide.md) · [Agent Projects](agent-project-workflows.md) · [Independent Audits](verification-and-ai-audits.md) · [Prompt Engineering](ai_prompts.md)

---

[AI index](README.md) | [Master index](../README.md) | [Start Here](../START_HERE.md)
