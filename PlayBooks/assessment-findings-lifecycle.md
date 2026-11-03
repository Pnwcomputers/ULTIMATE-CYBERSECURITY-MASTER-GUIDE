# Client Assessment Findings: DefectDojo and Retesting Workflow

_Last reviewed: 2026-11-02 (documentation review; no issue tracker installed)_

**Prerequisites:** [Network audit](NetworkAuditPlayBook.md) · [WebApp testing](../WebAppSecurity/owasp-assessment-and-nuclei.md) · [Cloud/SCuBA assessment](../Cloud/m365-scuba-assessment.md).

## Fit for PNWC

[DefectDojo](https://github.com/DefectDojo/django-DefectDojo) is a vulnerability and findings-management platform for organizing scan results, manual observations, duplicates, verification and follow-up. Its [docs](https://docs.defectdojo.com/) explain supported deployment and integrations. It is a potential backend for staged client assessments, not a substitute for authorization or a customer-ready report.

**No DefectDojo installation or automatic scanner import was performed.** Before accepting client information, verify application deployment support, MFA/SSO, client isolation, RBAC, retention, access logging, encrypted backups and export controls.

## End-to-end case process

1. **Authorize:** record legal entity, approved hosts/accounts, internal/external exclusions, testing methods, maintenance windows, safety contacts and signed rules of engagement.
2. **Create engagement:** assign client/job ID, assessor, encrypted evidence folder, agreed report recipients and an isolated tracking context.
3. **Ingest:** preserve original test provenance: OWASP method, SCuBA baseline, Nuclei template, Wazuh result or manual observation, with tool version, target and UTC timestamp.
4. **Normalize:** record affected asset, sanitized reproducible steps, expected control, observed behavior, business impact, prerequisites and any supportable CVE/CWE/ATT&CK links.
5. **Deduplicate:** combine evidence from tests describing the same root cause without losing independent source provenance; never inflate counts by treating each scanner alert as unique.
6. **Assign severity:** incorporate exploitability, verified exposure and business context. A template's severity tag is not confirmation of a vulnerability.
7. **Remediate:** define owner, recommendation, change/rollback plan, acceptance criteria and due date, approved by the customer.
8. **Retest:** repeat the bounded procedure, preserving before/after evidence. Separate fixed, mitigated, accepted, still open and inconclusive states.
9. **Close:** deliver an executive summary and sanitized technical report, enforce agreed evidence retention, and schedule the next review.

## Minimum finding schema

| Field | Required record |
| --- | --- |
| Customer/engagement | Stable case ID, approved scope reference |
| Asset | System, URL and environment |
| Evidence | Encrypted URI, hash, collection time and provenance |
| Control | Versioned ASVS/WSTG, SCuBA, CIS or internal ID |
| Status | Validation confidence, impact and remediation priority |
| Ownership | Remediation contact, approved exception, review date |
| Retest | New evidence, tester and result |
| Data handling | Recipients, retention and legal hold |

## Integration guardrails

Avoid automatically uploading raw scans, employee identities, network maps or incident evidence to a hosted service without an approved data processing agreement. For later automation use idempotent import keys based on engagement, asset and check ID; never equate a successful import with a verified flaw. Test retention and restoration before use.

## Sources and linked procedures

- [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) and [official documentation](https://docs.defectdojo.com/) (BSD-3-Clause source repository; verify current per-file terms).
- [Purple Team validation](purple-team-detection-validation.md) · [DFIR triage](../IncidentResponse/Digital-Forensics/velociraptor-artifact-triage.md) · [API catalog](../Documentation/security-public-api-catalog.md).

---

[Playbooks index](README.md) · [Main README](../README.md) · [Legal notice](../LEGAL.md)
