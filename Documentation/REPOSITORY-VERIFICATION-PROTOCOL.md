# Repository Verification & Content Completeness Protocol

_Review initiated: 2026-11-11 · Baseline commit: `c94db6b4cbea0068aeff61ee49f0ff4aff9109a4` · Scope: process and sampled findings, **not** a certification of all files._

## Purpose

Keep technical explanations, source links, code samples, and client-facing procedures correct as tools, threats, hardware revisions, and operating systems change. Do not equate a successful lint run with a working deployment or a verified security claim.

**Use this protocol when adding, editing, reviewing, or running any guide or script.** Read [STYLE_GUIDE.md](../STYLE_GUIDE.md), [LEGAL.md](../LEGAL.md), and the relevant section index first.

## Evidence & Confidence Labels

| Status | Meaning | Evidence required |
|---|---|---|
| **Verified: source** | Assertion checked against an authoritative, current reference | Exact URL, access/review date, scope and relevant product/version |
| **Verified: static** | Parsing, syntax, link, schema or unit-fixture check passed | Command, tool version, fixture, observed result and commit |
| **Verified: lab** | Code actually ran in an isolated, authorized environment | OS/tool versions, sanitized configuration, input, observed result, test date, cleanup |
| **Verified: production** | Deployment-specific behavior was separately approved and measured | Customer authorization, scope, approvals, redacted evidence, rollback and sign-off (store privately) |
| **Not verified** | A useful example or claim that has not been checked sufficiently | State the missing check instead of implying a pass |
| **Blocked / unsupported** | Cannot run safely or without unavailable hardware, access, license, or network conditions | Why it is blocked and the specific prerequisite |
| **Deprecated / historical** | Legacy feature, syntax or product documented for backward compatibility | Last known tested environment, current preferred alternative, EOL caveat |

A test result proves only the behaviors it actually exercises. Versions, timestamps, and scope must accompany "tested" badges; do not copy stale review dates onto new material.

## Current Snapshot & Automated Gate Limits

As of the baseline commit: **857 tracked paths**, including **361 Markdown**, **161 Python**, **95 shell**, and **12 PowerShell** files; **10 GitHub Actions workflows**. These are measured inventory values, **not** evergreen badges. The root index maintains a separately labeled historical snapshot.

| Gate | What it does | What it does **not** prove |
|---|---|---|
| Internal link workflow | Offline relative paths and heading fragments across Markdown | External sites still exist, are trustworthy, or explain current versions |
| External link workflow | Scheduled/manual online link sweep; currently **informational** | A green push/PR means that external resources passed; 401/403/429 are explicitly accepted |
| Markdown lint | Markdown formatting of files selected by the workflow | An embedded command is executable or operationally safe |
| ShellCheck / `bash -n` | Shell syntax and selected warning-level patterns for selected scripts | Third-party binaries, package availability, network success, correct runtime output |
| Python hardening fixtures | Known OSINT/installer regressions for test-specified cases | Every Python file or every external service integration |
| Other focused workflows | Selected Wireshark, network and documentation checks | End-to-end SIEM, EDR, SDR, physical hardware, or production behavior |

**A green check must never be cited as a global security certification.**

## Required Review Sequence

1. **Inventory:** identify the canonical guide, related indexes, executable assets, and references. Check that the path and exact capitalization exist.
2. **Completeness:** look for empty cells, missing context, unexpanded abbreviations, TODO/FIXME/TBD, fake URLs, `YOUR_*`, `EXAMPLE_*`, snippets with `pass`, and fenced samples that are only pseudocode. An example IP, domain, credential, API key, or field intended for substitution is not a broken link or incomplete tutorial *if it is explicitly labeled and its replacement is described*. Never fabricate a live key, address, test output, or source to make a template look complete.
3. **Static safety:** parse Python, Shell and PowerShell where the interpreter is available, run ShellCheck, inspect quoting and parameter validation, identify privilege requirements, check for destructive defaults and implicit network calls, and preserve exit status and error evidence.
4. **Dependency & version check:** look up the official vendor documentation and current install method. Record OS/kernel/package/firmware revisions, model variants, architecture and requirements. Avoid unaudited `curl | sh` and unpinned downloads.
5. **Reproducible lab:** execute read-only, synthetic or explicitly permitted tests in an isolated environment. Record expected *and observed* stdout/stderr/exit code. Distinguish a stub, fixture, mock and dry run from real hardware/service integration.
6. **Factual traceability:** verify factual and version-sensitive statements against primary sources. Distinguish vulnerability **severity** from environmental **risk**; public proof-of-concept availability from actual in-the-wild exploitation; claimed compatibility from demonstrated compatibility.
7. **Privacy & authorization:** verify signed scope and collection retention; avoid uploading private hostnames, tokens, credentials, IP inventories, malware, evidence or client logs to external services unless permitted. Third-party API calls expose their query to that provider. Prefer TLS and enforce redirects to trusted schemes.
8. **Navigation & presentation:** apply the project's heading conventions (title case, `&` where appropriate), table indexes, consistent return links, correct GitHub fragments, useful cross-links, and a single canonical deep treatment per topic.
9. **Closeout:** run applicable CI checks and manual smoke tests, note exceptions, compare diffs, and record a changelog/PR explaining which files were actually reviewed and what remains unverified.

## Placeholder Disposition

| Example | Classification | Action |
|---|---|---|
| `192.0.2.10`, `example.com`, `CVE-YYYY-NNNN` | Documentation-only examples | Keep, label as examples, show how to supply a legitimate authorized value |
| API-key, credentials and case-intake templates | Operator input, deliberately blank | Explain private storage and required fields; **never** put real secrets in public files |
| Report forms with empty evidence/score fields | Deliberate blank until assessment | Define evidence requirements, `Not assessed` / `Not applicable`, and sign-off |
| TODO for a missing procedure or `pass` in an advertised working script | Actual gap | Implement and test, or clearly mark the feature **not implemented** |
| Stale "Coming soon", incorrect counts or missing-phase claims | Documentation defect | Verify current tree, update assertions, and cross-link the already existing material |
| Tool output shown as an illustrative response | Synthetic example | Label "illustrative — not actual tool output" and never claim runtime verification |

Avoid global replacement of examples: the repo includes wordlists, security-test fixtures and intentionally vulnerable practice material that should not be silently modified.

## Vulnerability Intelligence & Source Hierarchy

For CVEs: confirm identity and CNA/vendor advisories, check [NVD CVE 2.0 documentation](https://nvd.nist.gov/developers/vulnerabilities), query the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for independently confirmed exploitation, and follow [FIRST CVSS v4.0](https://www.first.org/cvss/v4.0/) for v4 vectors. CVSS v3.1 and v4 are distinct metrics; preserve the actual published version/vector and never manufacture absent scores. KEV absence **does not** prove absence of exploitation; EPSS probability is not evidence of observed exploitation. Prioritize with exposure, asset criticality, compensating controls and vendor fixes, not a fixed "all Critical = 24 hours" rule.

For ATT&CK or threat reports: provide technique ID, technique version or access date, observable telemetry fields and expected defensive behavior. Avoid treating MITRE tags, Sigma rules or YARA matches as proof of a successful attack.

For hardware/firmware: cite the precise board revision, chip, tool build and flash/reset method; RF transmission may require additional legal permissions. For OSINT: preserve query time, URL, rate limits, ToS constraints, registration vs geolocation distinctions, and evidence errors.

## Audit Register For This Pass

| ID | Finding | Source | Disposition |
|---|---|---|---|
| NOV11-01 | Phase 2 incorrectly described the already published Phase 3 as empty; the Data Engineering index retained upload-stage text | `Data-Engineering/Phase2/README.md`, `Data-Engineering/README.md` | Documentation corrected on the audit branch |
| NOV11-02 | Documentation index reported an obsolete document count and June 2026 date; architecture coverage was an unscoped "Coming Soon" | `Documentation/README.md` | Replaced with maintainable status and linked coverage roadmap |
| NOV11-03 | OSINT Playbook index describes multiple existing menu functions and command options as nonexistent | `OSINT/Playbook/README.md` vs `osint_investigator.sh` | Correct feature/limitation matrix; runtime compatibility still needs live tests |
| NOV11-04 | IP lookup sends queried address to the non-commercial, HTTP-only `ip-api.com` free endpoint | `OSINT/Playbook/osint_investigator.sh` | Remove this default and document the replacement's different scope |
| NOV11-05 | CVE research flow focuses on CVSS v3 and invites unsupported exploitation/patch claims | `AI/AnythingLLM/flow-cve_lookup.md` | Add CVSS v4, KEV, evidence/provenance and explicit verification gates |
| NOV11-06 | Historical remediation plan contains unrecorded original base/owner fields | `SECURITY_REMEDIATION_PLAN.md` | Mark unknown historical values; do not invent history |
| NOV11-07 | Playbook contains literal report placeholders | `PlayBooks/cybersecurity_playbooks.md` | Keep as a clearly labeled fill-in template |
| NOV11-08 | No comprehensive offline execution of every sample or external-link success proof in this audit | Entire repository | **OPEN**; scope must be recorded per topic and tests never implied |

## Minimum PR Review Record

Copy this into a PR description and **complete it with actual evidence**:

| Field | Required value |
|---|---|
| Baseline & proposed commit | Exact SHAs |
| File scope | Paths actually inspected and changed |
| Runtime/OS/firmware | Version or "Not tested" |
| Primary sources | Official URLs and check date |
| Local tests & results | Commands and observed exit codes |
| External links | Checked/unchecked, with unresolved errors |
| Hardware & production | Tested or explicitly blocked |
| Privacy/authorization | Scope and secret redaction confirmed |
| Outstanding risks | Open issues with concrete next steps |

---

[Back to Documentation](README.md) · [Main Index](../README.md) · [Style Guide](../STYLE_GUIDE.md)
