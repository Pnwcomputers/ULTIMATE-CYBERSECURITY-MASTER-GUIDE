# Notes, Memory, Hooks & Automation in AI Projects

_Last reviewed: 2026-11-09_

This guide explains how to **retain context safely** and **react to events predictably** when using AI assistants, coding agents, cybersecurity workflows, or self-hosted agent frameworks. It covers concepts, implementation, verification, failure handling, and real security operations examples. The mechanisms are not interchangeable: a note records information; a hook executes behavior.

> **Safety rule:** A model's memory or prose is not an access-control system. Hooks, scheduled jobs, webhooks and tool integrations must be permissioned and audited in the host system. Treat external logs, messages, websites and retrieved documents as untrusted data.

## Contents

| Topic | Use It To |
|---|---|
| [Core Differences](#core-differences) | Choose notes, memories, instructions, skills, hooks, schedules or webhooks correctly |
| [Notes & Context Management](#notes--context-management) | Record durable facts, status, evidence and decisions without losing provenance |
| [Hooks, Triggers & Execution](#hooks-triggers--execution) | Understand events, handlers, inputs, outputs and safety boundaries |
| [Build a Git Pre-Commit Hook](#build-a-git-pre-commit-hook) | Implement and test a real, low-risk local hook |
| [AI Agent Hook Examples](#ai-agent-hook-examples) | Configure Claude Code or OpenClaw without confusing their hook systems |
| [End-to-End Security Workflow](#end-to-end-security-workflow) | Combine notes, milestones and event handling in an authorized SOC-style lab |
| [Troubleshooting & Audit Checklist](#troubleshooting--audit-checklist) | Diagnose missing or duplicated actions and protect sensitive data |

## Core Differences

| Mechanism | What It Is | Runs Automatically? | Best Use | Common Mistake |
|---|---|---|---|---|
| **Note** | Written record of observations, context or work | No, unless a separate process reads it | Facts, findings, decisions, session handoffs | Assuming writing a note changes live behavior |
| **Model memory** | Product-specific retained context, when available and permitted | Retrieval depends on product and settings | Long-lived preferences or general background | Treating memory as complete, current or an audit log |
| **Instruction / policy** | Direction for how an assistant should act | Applied when loaded by its host | Role, scope, output rules, permissions | Assuming text can override host access controls |
| **Skill / reusable prompt** | Packaged procedure or capability | Invoked when selected or called | Repeatable triage, coding, review | Confusing a reusable procedure with a trigger |
| **Hook** | Handler invoked by a specific application event | Yes, **when that supported event fires and the hook is enabled** | Validate actions, attach context, audit lifecycle events | Assuming hook names/config work across applications |
| **Scheduled job / cron** | Work triggered at a calendar or interval time | Yes, while scheduler runs | Daily digest, routine health check | Calling a daily schedule an event hook |
| **Webhook** | Incoming HTTP event/request handled by a service | On authenticated/allowed requests | Wazuh-to-service signal, ticket updates | Trusting HTTP payload as proof of identity or authorization |
| **Milestone** | A defined project outcome and acceptance gate | No, unless a workflow updates status from verified evidence | Measure progress and approve transitions | Marking a phase done solely because an assistant says so |

**Decision rule:** Need to remember *what happened*? Write a note. Need to specify *how to work*? Write instructions or a skill. Need an automatic response to *an event*? Use a hook. Need something at *8:00 each day*? Use a scheduler. Need an external system to *notify* your service? Use a webhook with an authenticated integration. Need to establish *what counts as done*? Define a milestone with acceptance evidence.

### How These Pieces Fit Together

```text
Authoritative sources and approved scope
                |
                v
Project instructions + verified reference notes
                |
                v
       Agent performs bounded work
                |
          Event occurs
                |
                v
   Hook / schedule / webhook handler
     |        |               |
   validate  log metadata   notify / queue
     |        |               |
     +--------+---------------+
                |
                v
      Tests + evidence records
                |
                v
     Milestone acceptance review
                |
                v
   Status update + session handoff
```

A hook can record an event, but a recorded event is **not** proof that the requested task succeeded. The task needs its own check, e.g. read back the edited file, inspect the real alert, or test a restored backup.

## Notes & Context Management

### What Belongs in a Note?

Use separate files or fields for separate kinds of truth. Examples below are **portable conventions**, not built-in ChatGPT, Claude, OpenClaw or GitHub requirements.

| Record | Include | Refresh / Owner |
|---|---|---|
| `PROJECT.md` | Mission, assets in scope, prohibited actions, definition of done | Project owner when scope changes |
| `SOURCES.md` | Source URLs/paths, dates, versions, trust priority | Researcher upon new input |
| `NOTES.md` | Investigative observations, hypotheses, questions, timestamps | Analyst during investigation |
| `DECISIONS.md` | Decision, alternatives, rationale, approver, effective date | Approver after decision |
| `STATUS.md` | Current milestone, verified completions, blockers, next tasks | Operator after meaningful work |
| `EVIDENCE.md` | Command, output location, checksum, test result, reviewer | Operator and verifier |
| `HANDOFF.md` | Compact current state, unresolved risks, next safe action | Operator before session ends |
| `AGENTS.md` | Agent roles, boundaries, tool access and escalation rules | Project owner when policy changes |

#### Step-by-Step: Create a Reliable Project Note

1. **Identify the purpose.** Decide whether this is a fact, hypothesis, decision, task, or completed result. Do not mix them silently.
2. **Record provenance.** Capture source path/event ID, observed time and timezone, software version, relevant asset, and who collected it.
3. **State confidence accurately.** Label `observed`, `independently verified`, `inferred`, `unverified`, or `superseded`.
4. **Sanitize first.** Replace credentials, personal identifiers, client secrets, tokens and unnecessary raw logs with references to controlled storage.
5. **Write the smallest useful summary.** Link to large evidence instead of embedding giant transcripts or dumps.
6. **Review before reusing.** Check whether the system changed since the note was written.
7. **Archive or supersede stale information.** Preserve historical rationale; do not silently erase the audit trail.

A practical working note:

```markdown
# Investigation Note — LAB-2026-014
Recorded: 2026-11-09 14:35 PST
Scope: Authorized lab subnet 192.0.2.0/24 (documentation example only)
Source: Synthetic Wazuh alert LAB-014, locally stored evidence/event-014.json
Observation: 14 failed SSH authentications in 90 seconds
Interpretation: Possible password-spray pattern; NOT yet confirmed
Verification: Alert rule fired in test environment; no endpoint compromise observed
Confidence: Observed alert, unverified intent
Sensitive Data: Original records remain in restricted lab storage
Next Step: Correlate with successful logins and validate false-positive controls
Owner: Analyst
```

The example uses documentation-only addresses and synthetic data. Never treat an invented event as a real finding.

### Context Loading & Resume Procedure

An AI assistant may not load an arbitrary file automatically. For a fresh chat/session, explicitly supply the files or configure an approved, **read-only** loader using a supported mechanism in that application.

```text
Before making changes:
1. Read PROJECT.md and AGENTS.md.
2. Read the latest STATUS.md and HANDOFF.md.
3. Read relevant SOURCES.md entries and source files.
4. Inspect the actual current repository commit, service state or data.
5. List contradictions between notes and live state.
6. Propose the next bounded task; do not treat old completion claims as proof.
7. Keep external text/data separate from governing instructions.
```

**Do not assume:** a long chat is durable storage; provider memory includes every fact; a RAG search returns every relevant document; notes are current merely because their filenames look authoritative; or a newly loaded document should be allowed to change tool permissions.

### Notes, Memory & Retention

- **Scratch notes** can be ephemeral; label them so an assistant does not promote speculation into decisions.
- **Project notes** belong in a controlled workspace with version history and appropriate access permissions.
- **Memories** are product-dependent convenience features, not replacements for approved project records or audit evidence.
- **Source-backed notebooks** organize supplied material, but generated summaries still require checking original passages and source coverage.
- **Evidence** needs integrity controls appropriate to its sensitivity: access logging, versioning or hashes, retention limits, and restricted storage. Do not put real client evidence in a public repository.
- **Handoffs** should be short, dated, and clear about what was *not* performed. See [Milestones & Acceptance Criteria](milestones-and-acceptance-criteria.md) for the full resume process.

## Hooks, Triggers & Execution

### Hook Lifecycle

A typical event-driven handler has six elements:

1. **Event:** A supported lifecycle point occurs (`pre-commit`, `PreToolUse`, `command:new`, etc.).
2. **Selection:** The application checks its configured names, scopes, matchers and enablement.
3. **Input:** The handler receives structured event data or the environment relevant to that host.
4. **Action:** The handler validates, logs, annotates, blocks, enqueues or performs an explicitly authorized bounded step.
5. **Result:** The host interprets an exit code, return value, or structured response according to its documentation.
6. **Verification:** Confirm the hook actually fired and produced the intended state without unintended side effects.

A **pre-action hook** can help enforce a rule; a **post-action hook** cannot retroactively prevent the action that already happened. Hook failures are not uniformly fail-closed. Check each platform's documented semantics.

### Choosing the Trigger

| Trigger Type | Example | Appropriate Action | Important Boundary |
|---|---|---|---|
| Before file commit | Git `pre-commit` | Reject whitespace errors or invalid metadata | Local hooks may be absent/bypassed; add CI enforcement |
| Before AI tool use | Agent-specific pre-tool hook | Validate tool/path policy; require approval | Do not treat a prompt-only check as a hard authorization boundary |
| After AI tool use | Agent-specific post-tool hook | Run lint/check or record actual tool outcome | Tool success does not imply end-to-end success |
| At session start/reset | Agent lifecycle event | Load approved note summary or write a reset record | Avoid dumping secrets, long histories or stale claims |
| On security event | Wazuh/service integration → secured handler | Queue triage with event ID and severity | Validate sender, replay, scope, signature/token and data handling |
| Every morning | Cron or scheduler | Generate dated health-check summary | Scheduling is **not** a session or tool hook |
| Before deployment | CI workflow and protected environments | Run tests and require approval | Keep deployment permission outside the model |

### Security Design Before Enabling a Hook

- **Document the event contract:** exact event name, payload schema, retry behavior, ordering, timeout, and whether the handler can block actions.
- **Least privilege:** handler account gets only required files, network access and tools. Use a separate account or sandbox for risky handlers.
- **Trust boundaries:** external text and event payloads are untrusted. Validate type, length, path, issuer, freshness and allowed values.
- **Secret handling:** never hard-code tokens in examples, config committed to Git, model prompts, or logs. Use secrets management and redact output.
- **Idempotency:** use an event ID/deduplication key so retries do not send two messages or create two tickets.
- **No recursion:** make a guard so the hook's own file writes, tool calls or messages do not retrigger it endlessly.
- **Safe defaults:** begin in observe-only or dry-run mode. For destructive operations, external sends, deployment or access changes, require an independent authorization mechanism.
- **Telemetry & failure:** log timestamp, hook version, event ID, outcome and sanitized error; alarm on missed/failed handlers. Set retention limits.
- **Rollback:** know how to disable the handler and restore the previous state before enabling it.

## Build a Git Pre-Commit Hook

A working local example demonstrates a real hook without granting an AI agent new powers. It checks staged changes for Git-recognized whitespace errors. Run it in a **test repository** first.

### Step 1 — Add a Tracked Hook Script

```bash
mkdir -p .githooks
cat > .githooks/pre-commit <<'SH'
#!/bin/sh
# Exit nonzero if Git detects whitespace errors in staged changes.
# Does NOT lint Markdown semantics, scan secrets or run project tests.
git diff --cached --check
SH
chmod +x .githooks/pre-commit
```

### Step 2 — Enable It Locally

```bash
git config --local core.hooksPath .githooks
git config --local --get core.hooksPath
```

The local configuration activates the version-controlled `.githooks` directory **for that clone**. Cloning a repository does not automatically authorize these scripts. Review the scripts before configuring any hook path.

### Step 3 — Test & Verify

```bash
# Run a safe, manual check on existing staged changes:
sh .githooks/pre-commit

# Check behavior after staging a deliberate whitespace error in a test file:
git diff --cached --check

# Confirm configuration and file permissions:
git config --local --get core.hooksPath
ls -l .githooks/pre-commit
```

If a staged change contains a trailing whitespace error, the hook should exit nonzero and a normal `git commit` should stop. If no such error exists, it should exit zero. Restore your test file afterward. This script **does not** enforce all quality or security checks; use CI and branch protection for centrally enforced gates.

To disable this local hook path, run `git config --local --unset core.hooksPath`. This reverts to Git's default hook location; it does not guarantee that no other hooks exist.

**Official reference:** [Git githooks documentation](https://git-scm.com/docs/githooks).

## AI Agent Hook Examples

Hook names, file paths and return values are **platform-specific**. Do not copy a Claude Code configuration into OpenClaw or confuse an OpenClaw internal hook with an HTTP webhook.

### Claude Code — Post-Edit Validation

Claude Code supports tool lifecycle hooks configured in JSON settings. For a repository using Claude Code, the following example runs a simple **working-tree whitespace check** after a matching edit operation:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "sh \"$CLAUDE_PROJECT_DIR/scripts/check-working-tree.sh\""
          }
        ]
      }
    ]
  }
}
```

Save the configuration under `.claude/settings.json` only after inspecting and approving the behavior. Create the referenced script first:

```bash
mkdir -p scripts
cat > scripts/check-working-tree.sh <<'SH'
#!/bin/sh
# Deliberately read-only: checks tracked, unstaged changes only.
cd "${CLAUDE_PROJECT_DIR:?Project directory required}" || exit 1
git diff --check
SH
chmod +x scripts/check-working-tree.sh
```

Test the script manually, then confirm via hook logs/agent behavior that it runs after an edit. `git diff --check` does **not** check new untracked files or staged changes, so pair this with other project checks. The handler inherits execution permissions and environment from its host; never enable arbitrary downloaded hook commands without review. Hook return/exit semantics vary by event.

**Official reference:** [Anthropic — Configuring Claude Code Hooks](https://claude.com/resources/articles/how-to-configure-hooks).

### OpenClaw — Internal Hooks Versus Plugin Hooks Versus Webhooks

OpenClaw currently documents **three distinct hook surfaces**:

| Surface | What It Handles | Correct Starting Point |
|---|---|---|
| **Internal event hooks** | Gateway lifecycle, message and command events, e.g. `command:new` | A bundled or installed handler, enabled through the hooks CLI |
| **Typed plugin hooks** | Agent/tool/message lifecycle interception, e.g. `api.on("before_tool_call", ...)` | A reviewed plugin following its typed hook contract |
| **HTTP webhooks** | Requests sent from external systems to Gateway endpoints | Explicit HTTP ingress config, authentication and routing |

For a first, non-destructive experiment on a **test Gateway**, inspect the built-in `command-logger` hook:

```bash
openclaw hooks list
openclaw hooks info command-logger
openclaw hooks check
# Only after reviewing where the logger writes and what it captures:
openclaw hooks enable command-logger
# Disable again after the controlled test:
openclaw hooks disable command-logger
```

These commands act on the Gateway host/configuration selected by the CLI. Enabling a local hook does not necessarily mutate a remote Gateway. If using a multi-agent installation, inspect the selection and scoping behavior first. Keep log data restricted and retained only as long as necessary.

**Important:** OpenClaw's current internal hook configuration uses named `hooks.internal.entries` / installed hook directories; do **not** build `hooks.internal` as an array of `{event, prompt, enabled}` objects or assume that text prompts themselves are handlers. To implement a custom event, follow the documented `HOOK.md` + handler contract. HTTP webhook settings under `hooks.enabled` are separate. A daily security digest belongs in OpenClaw's scheduler/cron facilities, not an internal `command:new` hook.

**Official references:** [OpenClaw Hooks](https://docs.openclaw.ai/automation/hooks) · [Internal Hook Configuration](https://docs.openclaw.ai/automation/hooks/configuration) · [Plugin Hooks](https://docs.openclaw.ai/plugins/hooks) · [HTTP Hook Configuration](https://docs.openclaw.ai/gateway/config-hooks).

### Platform Capability Checklist

Before adopting another tool's hook example, confirm its current documentation supports: the event key, configuration version, handler location, scope (user vs project vs agent), input and output schema, execution identity, block/fail behavior, timeouts, retries, and enable/disable commands. **Never extrapolate hooks support from a product's ability to run tasks, access files or remember context.**

## End-to-End Security Workflow

**Scenario:** An authorized, synthetic Wazuh alert in a lab needs triage. The AI may summarize data and draft a response, but must not quarantine endpoints, change firewall rules or message a client without approval.

| Stage | Note / Record | Hook Or Automation | Acceptance Evidence |
|---|---|---|---|
| 1. Define scope | `PROJECT.md`: authorized lab assets, exclusions | None | Owner-approved scope |
| 2. Receive event | `NOTES.md`: event ID, source, observed facts | Secured, deduplicating event receiver queues triage | Queue receipt with sanitized event ID |
| 3. Triage | `SOURCES.md` + restricted alert evidence | Agent runs bounded read-only analysis | Source-linked draft with uncertainties |
| 4. Validate | `EVIDENCE.md` + reviewer note | Read-only test/checks, possibly a post-action hook | Real log correlation and test results |
| 5. Review | `DECISIONS.md`: disposition and approver | Human approval gate, not just AI prose | Review record |
| 6. Close & resume | `STATUS.md` + `HANDOFF.md` | Optional scheduled digest summarizing approved status | Milestone accepted with linked evidence |

For a production integration, additionally document HTTP authentication, TLS, event schema, replay prevention, routing permissions, dead-letter handling, data minimization and incident-response escalation. A hook firing is one step in a workflow, not proof that a case was resolved.

For a complete, measurable phase plan, see [Milestones & Acceptance Criteria](milestones-and-acceptance-criteria.md); for Wazuh procedures see [Wazuh & Honeypot Integration](../PlayBooks/assessment-service-integration-map.md) and the relevant repository detection/response sections.

## Troubleshooting & Audit Checklist

| Symptom | Verify First | Typical Fix |
|---|---|---|
| Note not visible to assistant | Was it actually attached, indexed or loaded for this session? | Provide the file or configure a supported, scoped loader |
| Old note contradicts live state | Source version, timestamp and current commit | Mark stale information superseded; update with readback |
| Hook never fires | Exact event name, enabled state, scope and execution logs | Use the platform's inspect/check tools and a minimal synthetic event |
| Hook fires twice | Retries, overlapping handlers and deduplication key | Add idempotent event IDs; inspect registrations |
| Hook appears successful but task failed | Does its exit status validate the true outcome? | Add post-action readback and independent acceptance test |
| Hook leaks sensitive data | Log destination, handler permissions, input redaction | Disable, rotate exposed credentials if needed, sanitize and review |
| Hook loops or stalls | Handler invokes its own triggering action | Guard recursive events and apply timeout/queue limits |
| Scheduled task didn't run | Scheduler state, timezone, credentials, host availability | Repair scheduler, not hook registration |
| Agent attempts out-of-scope action | Host tool permissions and approval gate | Revoke excess permissions; enforce authorization outside prompts |
| Milestone claimed completed without evidence | Acceptance criteria and evidence record | Reopen as unverified and test before approval |

### Pre-Enable Review

- [ ] Event names, host version and config format checked against current official docs
- [ ] Minimal permissions, explicit scope and owner approval established
- [ ] External payloads validated; secrets excluded from prompts, code and logs
- [ ] Dry-run tested with expected event, non-event and failure cases
- [ ] Handler logs event IDs and outcomes, without unnecessary sensitive content
- [ ] Duplicate delivery, timeouts, failure and rollback tested
- [ ] Independent check confirms intended state, not merely hook execution
- [ ] Retention, ownership and escalation documented

## Further Reading

| Guide | Why It Matters |
|---|---|
| [Milestones & Acceptance Criteria](milestones-and-acceptance-criteria.md) | Define verifiable stage transitions, gates and checkpoints |
| [Project & Agent Workflows](agent-project-workflows.md) | Coordinate agents, owners, handoffs and evidence |
| [Practical AI Usage](ai-usage-interaction-guide.md) | Compose bounded instructions and prompts |
| [Verification & AI Audits](verification-and-ai-audits.md) | Challenge unsupported claims and validate tool actions |
| [Workspaces, Notebooks & Assistants](ai-workspaces-notebooks-and-assistants.md) | Decide how context and files should be organized |
| [OpenClaw Configuration](OpenClaw/agent_skill_config.md) | Example OpenClaw agent operations and corrected hook guidance |

---

[AI Index](README.md) | [Master Index](../README.md) | [Start Here](../START_HERE.md)
