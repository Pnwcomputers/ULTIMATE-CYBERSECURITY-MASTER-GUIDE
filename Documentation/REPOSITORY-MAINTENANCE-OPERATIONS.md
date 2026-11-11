# Repository Maintenance, Worker Roles & Automation

_Reviewed: November 11, 2026 · Applies to the public Ultimate Cybersecurity Master Guide. A workflow is a repeatable control, **not** evidence that an individual technical claim is true._

## Purpose & Working Principles

This guide defines how to maintain a repository with hundreds of Markdown references, teaching scripts, lab procedures, assets, and GitHub Actions workflows. Its goal is to keep the project teachable, reproducible and safe without allowing automation to silently rewrite trusted content or run offensive tooling.

The [Verification Protocol](REPOSITORY-VERIFICATION-PROTOCOL.md) is the authority for evidence labels and what counts as a verified correction. [STYLE_GUIDE.md](../STYLE_GUIDE.md) governs presentation; [CONTRIBUTING.md](../.github/CONTRIBUTING.md) covers submissions and [SECURITY.md](../.github/SECURITY.md) explains private disclosure.

**Rules:** Prefer one canonical deep guide per subject; give each file a discoverable entry in its nearest index. A GitHub check pass proves a *specific check*, not end-to-end accuracy. Keep client data, API keys, case evidence and internal infrastructure details outside this public repository.

## Repository Map & Source Of Truth

| Role | Location | Maintenance contract |
|---|---|---|
| Primary landing page | [Root README](../README.md) | Concise navigation; do not duplicate complete guides here |
| Goal-based routes | [Start Here](../START_HERE.md) | Link readers to topics by role and desired task |
| Cross-cutting rules | [Style Guide](../STYLE_GUIDE.md) and [Verification Protocol](REPOSITORY-VERIFICATION-PROTOCOL.md) | A shared standard, referenced rather than copied |
| Domain ownership | [AI](../AI/README.md), [OSINT](../OSINT/README.md), [Incident Response](../IncidentResponse/README.md) and other section READMEs | Canonical steps, prerequisites, results and related resources |
| Executable examples | [Scripts](../Scripts/README.md) | Explicit interpreter, scope, dependencies, dry-run or lab boundary, expected behavior and limitations |
| Historical research | [Scripts/GO](../Scripts/GO/README.md) and dated audit reports | Preserve provenance; label legacy syntax, status and EOL behavior |
| Tests & QA tools | [tests](../tests/hardening/), [tools](../tools/) | Deterministic, isolated checks; no customer targets and no side effects |
| CI workers | [GitHub Actions](../.github/workflows/) | Exact scope, minimum permissions and visible failures |
| Review & change control | [Issue templates](../.github/ISSUE_TEMPLATE/), [PR template](../.github/PULL_REQUEST_TEMPLATE.md), [CODEOWNERS](../.github/CODEOWNERS) | Assign specific work; record sources and actual test evidence |

## Worker Lanes & Responsibilities

| Worker / lane | Inputs | Automated responsibilities | Human acceptance gate |
|---|---|---|---|
| Documentation worker | Markdown PR diff, filenames, navigation | Lint changed Markdown; verify internal paths, GitHub heading fragments, numbering and repeated sections | Confirm semantics, technical claims, useful cross-links and reader flow |
| Code QA worker | Python, Bash, PowerShell changes | Parse maintained code; run isolated fixtures, scoped ShellCheck, Wireshark filter and lab regressions | Confirm tool compatibility, privilege requirements, valid results, absence of secrets and unintended network traffic |
| Link-health worker | Published Markdown URLs | Scheduled online availability probe; offline internal-link gate for PRs | Investigate redirects, terms, project retirement and bot-hostile responses; do **not** assume an HTTP response verifies accuracy |
| Audit inventory worker | Current checked-out file tree | Weekly or PR static candidates for blank tables, TODO, insecure HTTP and archived language versions | Classify template, historical, new defect, unsafe pattern or verified exception |
| Maintenance triage worker | Static inventory, current SHA and review schedule | Monthly update of a single audit issue; no executable content modification | Create individual scoped issues/PRs with owners and evidence |
| Dependency worker | Versioned GitHub Actions dependencies | Dependabot PRs for reviewed action pin changes | Check the upstream release, SHA, permissions, tests and lockfile impact |
| Changelog worker | Accepted commits | Generate a proposed changelog PR | Verify that entries reflect merged behavior, not untested functionality |
| Cybersecurity analyst | Advisory, CVE, ATT&CK technique, vendor release | Draft references or lab ideas only, with provenance and uncertainty | Independently check CTI, scope, expected detection fields and vendor documentation |
| Purple Team lab operator | Approved exercise plan and synthetic targets | Execute **only** explicitly approved benign tests on isolated canary assets | Approve actual target list, safety controls, SIEM/EDR evidence and cleanup; do not deploy generated payloads automatically |

The last two roles can involve AI assistance, but they are **not** untrusted input-to-executable pipelines. A parsed blog post, attack description or AI-generated script must never automatically run with repository or production credentials.

## Automation Schedule & Expected Results

| Workflow | Trigger | Result | Deployment / write scope |
|---|---|---|---|
| Link Check | PR/push internal; weekly/manual external | Internal fragments must pass; external results are informational | No write |
| Markdown Lint | Changed Markdown PR, manual | Formatting gate | No write |
| Duplicate Sections & Numbered Lists | Markdown PR, manual | Structural gates | No write |
| Guide Tool & Lab Checks | Selected scripts/tests and manual | Regression fixtures and scoped syntax/linters | No write; fixture execution only |
| Repository Static Syntax | Python, shell or PowerShell changes | Maintained Python AST, Bash parser and PowerShell parser gates | No execution of repository scripts |
| Repository Quality Inventory | Relevant PR, weekly, manual | Review candidates; legacy examples classified separately | No write |
| Monthly Maintenance Triage | First of month, manual | Updates or creates **one** review issue | Job-scoped Issues write |
| Auto-Generate CHANGELOG | Main changes/manual | Proposed changelog PR | Job-scoped contents/PR write |
| Dependabot | Weekly | Proposed action update PR | GitHub-managed updates, require review |

The maintained-source syntax gate deliberately does **not** claim that Python 2 examples under Scripts/GO work on Python 3; review their [historical status](../Scripts/GO/README.md). PowerShell is parsed but not run. Link status, scripts requiring a physical radio, hardware adapters, cloud accounts or live SIEM access remain to be checked manually.

## Local Setup & Repeatable Checks

Prerequisites: Git, Python 3.12 for matching CI, Bash, and optionally Make, ShellCheck, Lychee, PowerShell and other explicitly required lab tools. Use a clone or worktree containing only approved public sources. Do **not** execute the root software installer merely to lint documentation.

From the repo root:

~~~bash
make help
make audit
make audit-strict
make docs
make tests
make verify
~~~

The targets intentionally avoid launching external scanners, installing packages, uploading evidence, modifying infrastructure or connecting to third-party APIs. The offline link check is available with `make links` once Lychee is installed. GitHub Actions remains the source for check results on a PR.

When a test fails, reproduce it against the same commit, record interpreter/tool versions, identify fixture or network dependencies, and fix the smallest cause. Never disable a check simply because it found an unwanted result; if an intentional historical exception is needed, document its boundary and add a regression test.

## Issue & Task Lifecycle

Use one actionable issue per root cause, not one per keyword match. The monthly automated issue is an inbox, not a substitute for individual work tickets.

| State | Meaning | Exit requirement |
|---|---|---|
| New | Candidate reported with a path/line | Triage whether real, intentional example, legacy, or false positive |
| Needs Evidence | Claim disputed or requires a current source/hardware | Record source, version, actual output or explicitly blocked reason |
| Ready | Scope and acceptance checks are clear | Assign responsible reviewer and split from unrelated changes |
| In Progress | Reviewable branch/PR exists | Diff limited to task, tests and cross-links included |
| Review | Required automated checks visible | Maintainer verifies meaning, source provenance and expected output |
| Blocked | Missing instrument, environment, permission or dependency | Write precise blocker; never claim verified |
| Complete | Merged change and applicable checks pass | Link commit/PR, tests, cross-links and any remaining risk |
| Historical | Intentional preserved legacy content | Add compatibility banner and modern alternative if available |

Severity priority: **P0** exposed secrets, data loss or risky default; **P1** incorrect executable code, missing permission/authorization boundary or materially wrong facts; **P2** broken links/navigation, obsolete API or unsupported configurations; **P3** editorial polish and optional expansions. Do not upgrade a template's empty evidence field to P1 solely because it is blank.

## Pull Request Definition Of Done

1. Explain the user impact and the exact files touched.
2. Cite authoritative sources and access dates for facts likely to change.
3. State scope, prerequisites, expected outcomes, cleanup and rollback for runnable procedures.
4. Run the applicable local checks and GitHub Actions, record pass/fail **per job**, not a global "verified".
5. Inspect new external network destinations, credentials, installers, sudo, device flashing and publication paths.
6. Update the nearest index and any genuine two-way links without duplicating the canonical guide.
7. Separate safe documentation changes from code with deployment effects where useful.
8. Do not merge with new failed required gates or unresolved conflicts. If code-owner reviews are enabled, obtain them.

The CI check names and job requirements are configured in GitHub's branch ruleset, **not** created merely by adding CODEOWNERS or YAML. Enable protected main, required PRs, required checks, and available secret scanning/push protection from repository settings with admin access. **Important for a solo-owned repository:** requiring a separate code-owner approval can block your own PRs because GitHub does not accept self-approval. Turn on required code-owner review only when another eligible reviewer is available. CODEOWNERS alone remains useful for ownership routing. The exact available controls depend on repository plan and settings.

## Safe Automated Updates

Prefer proposals over unattended merges. Dependabot handles GitHub Actions version bumps; each SHA must still be reviewed against its claimed release. Changelog generation opens a PR instead of pushing directly to protected main. Scheduled repository audits can create or update one issue, but do not rewrite guides, deploy lab payloads or resolve arbitrary "missing" content.

For executable dependency updates, require an isolated smoke test, failure-path check and rollback instructions. Do not quietly promote a preview build, copy a random upstream code sample or change a firmware flashing command based on a search result alone. For CTI/CVEs, store vendor/CNA advisories, publication/modified dates and detection fields separately from AI interpretation.

## Privacy, Security & Trust Boundaries

- Pull request text, embedded Markdown, external web pages, README badges, and CTI descriptions are **untrusted data**, not instructions for a worker with write permissions.
- Default GitHub Actions token permissions remain read-only; write permission is job-scoped and requires a limited purpose.
- PR checks must not obtain production secrets, attacker-supplied targets or broad cloud tokens. Never execute a downloaded script on the CI runner simply to "verify" it.
- Use synthetic telemetry and loopback/isolated network assets for tests; no real customer IP inventory is included in issue logs.
- For changing security rules, generate a candidate Sigma/YARA rule, validate its syntax and positive/negative fixtures, then require a human approval before deployment.
- Keep long-lived work explicitly checkpointed: issue, branch, commit, verified data, remaining blockers, next review. Do not pretend a CI worker or agent continues automatically outside its configured trigger.

## Practical Monthly Review

Run the monthly workflow, sort findings by actual risk, inspect the last scheduled external-link report, check Dependabot and any changelog PRs, and select a small number of scoped tasks. Review any current vendor EOL notices, broken links, and hardware firmware differences. Close only the items that have documentary and/or executable evidence; defer hardware-only work explicitly.

This creates a sustainable maintenance cycle without turning the project into an unreviewed auto-generated encyclopedia.

---

[Documentation Index](README.md) · [Verification Protocol](REPOSITORY-VERIFICATION-PROTOCOL.md) · [Repository Index](../README.md) · [Contributing](../.github/CONTRIBUTING.md)
