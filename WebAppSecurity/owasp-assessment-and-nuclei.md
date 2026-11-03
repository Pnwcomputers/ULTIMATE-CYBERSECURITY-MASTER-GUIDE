# OWASP Standards, Test Cases and Nuclei Template Review

_Last reviewed: 2026-11-02 (upstream references; no target scanning performed)_

> [!CAUTION]
> **Authorized testing only.** Identify written scope, approved accounts, maintenance
> windows, exclusions and rules of engagement before sending test traffic.
> Do not treat public API schemas, vulnerabilities or templates as authorization.
> See [legal terms](../LEGAL.md).

**Prerequisites:** [Web application methodology](methodology.md) ·
[OWASP Top 10](owasp-top-10.md) · [Network audit playbook](../PlayBooks/NetworkAuditPlayBook.md).

## Distinguish requirements from test methods

| Source | How PNWC should use it | Evidence to retain |
| --- | --- | --- |
| [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS) | Versioned *verification requirements* for application and API controls; choose the appropriate level with the customer | Exact **ASVS version and requirement ID**, outcome, observed control and exceptions |
| [OWASP WSTG](https://github.com/OWASP/wstg) | Versioned *test methodology* for web/authentication, authorization, sessions, configuration and APIs | Scenario/test identifier, test inputs (sanitized), request/response metadata and observed behavior |
| [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries) | Defensive implementation advice to accompany remediation | Specific recommended control, environment, developer/owner |
| [ProjectDiscovery Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) | Optional **reviewed** automated checks for explicitly approved assets | Template ID + hash/version, matcher evidence, scope, false-positive review |

ASVS and WSTG are **not interchangeable**: requirements describe what a system
should satisfy; tests describe how to evaluate it. ASVS 5.0.0 is a published
stable reference, but WSTG development continues; pin the version or commit
rather than calling a moving HEAD the latest released WSTG.

## Engagement workflow

1. Record application, environment, API hostnames, test accounts, sensitive paths,
   allowed methods, contact/escalation and data handling.
2. Pick applicable ASVS requirements with the customer and capture the **version**.
   Mark each as applicable, excluded with rationale, or requiring clarification.
3. Map each applicable requirement to one or more WSTG/manual procedures.
   The map is many-to-many; do not imply a one-to-one official mapping.
4. Validate authentication, authorization, input handling and business logic
   manually in staging with synthetic records.
5. If Nuclei is approved, **review templates before execution**: source,
   severity tags, requests/methods, matchers, redirects and any side effects.
   Pin reviewed template commit; start with a small allowlist and cautious
   concurrency. Never run the entire community pack blindly.
6. Reproduce findings safely, distinguish confirmed exposure from inferred
   severity and avoid extracting actual customer records.
7. Write remediation and retest evidence; link to the
   [findings lifecycle guide](../PlayBooks/assessment-findings-lifecycle.md).

## Example reporting matrix

| Asset and test | Requirement / test reference | Evidence | Status |
| --- | --- | --- | --- |
| Staging app login (approved test user) | ASVS v5.0.0 **ID chosen from official release** + WSTG case ID | Redacted session trace and server-side settings | Pass / Fail / Not tested |
| Staging API object access | Versioned access-control requirement and test | Synthetic account A/B authorization comparison | Pass / Fail / Not tested |
| TLS endpoint configuration | Applicable configuration requirement | Certificate/transport observation | Pass / Fail / Not tested |

Do **not** invent a requirement identifier in a customer report. Link the
actual versioned item from the official ASVS release or official WSTG URL.

## Nuclei triage, rather than uncontrolled template execution

The [Nuclei template directory](https://github.com/projectdiscovery/nuclei-templates)
is community maintained. Template metadata and matchers are not proof of a
vulnerability. Triage the template's YAML and applicable CVE/configuration,
record its commit hash, evaluate scope and potentially intrusive requests,
then run a controlled, approved subset only. Verify high-impact findings
independently and map to [NVD/KEV references](../Documentation/security-public-api-catalog.md).

**Suggested deliverables:** requirements/test mapping sheet, evidence inventory,
exception register, risk-ranked findings, remediation owner and retest date.

## Sources and navigation

- [OWASP ASVS 5.0.0](https://asvs.owasp.org/) ([repository](https://github.com/OWASP/ASVS); CC BY-SA 4.0).
- [OWASP WSTG](https://github.com/OWASP/wstg) ([official testing guide](https://owasp.org/www-project-web-security-testing-guide/); CC BY-SA 4.0).
- [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) (MIT).
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/).
- [WebApp index](README.md) · [Methodology](methodology.md) ·
  [Findings and retesting](../PlayBooks/assessment-findings-lifecycle.md).

The content here is original guidance and citation, not a wholesale
republication of CC BY-SA standard text or community scanning templates.

---

[Back to WebAppSecurity](README.md) · [Main README](../README.md) ·
[Legal terms](../LEGAL.md)
