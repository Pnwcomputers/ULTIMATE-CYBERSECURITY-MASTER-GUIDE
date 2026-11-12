# PNWC Staged Security Assessment: Integration Blueprint

_Last reviewed: 2026-11-02 (documentation architecture only; no services deployed)_

This guide provides a **process map**, not a claim of automated software
integration. The goal is to make separate source-backed tools useful together
for consented client internal/external audits without turning the existing
cybersecurity guide into an unmaintainable product catalogue.

## Workflow stages and source-backed procedures

| Phase | Main guide | Candidate sources and result |
| --- | --- | --- |
| 0. Consent and scoping | [Network Audit Playbook](NetworkAuditPlayBook.md) | Signed authorization; exclusions; contacts; immutable engagement ID |
| 1. Web/API verification | [OWASP assessment mapping](../WebAppSecurity/owasp-assessment-and-nuclei.md) | WSTG procedures, versioned ASVS controls; optionally reviewed Nuclei templates |
| 2. Microsoft cloud posture | [ScubaGear checklist](../Cloud/m365-scuba-assessment.md) | CISA baseline deviations, approved exceptions |
| 3. Software/software supply chain | [SBOM assessment](../ContainerSecurity/software-supply-chain-assessment.md) | Pinned image/SBOM, advisories, secret scan results |
| 4. Endpoint / incident evidence | [Velociraptor and artifacts](../IncidentResponse/Digital-Forensics/velociraptor-artifact-triage.md) | Authorized minimal collection, hashes, custody |
| 5. Detection testing | [Atomic/Sigma exercises](purple-team-detection-validation.md) | Positive and negative tests; Wazuh alerts/telemetry gaps |
| 5b. Hak5 wireless campaigns and payload review | [Mark VII five campaigns](../Wardriving/README.md#optimized-mark-vii-setup--campaign-configuration) · [Pager sideload/audit](../Wardriving/README.md#wifi-pineapple-pager--payloads-sideloading--defensive-labs) · [Hak5 platform matrix](../HardwareHacking/README.md#hak5-payload-ecosystem-official--side-loaded-code) | Preflight allowlists, local-only reports, synthetic AP and WIDS correlation |
| 5a. Physical USB & wireless security | [Bash Bunny](../Scripts/Bash/BashBunny/README.md#authorized-field-assessment-labs--deployment-examples) · [USB Rubber Ducky](../Scripts/Ducky/README.md#authorized-hid-injection-field-exercises) · [WiFi Pineapple Mark VII](../Wardriving/README.md#wifi-pineapple-mark-vii--authorized-wireless-security-assessment) | Approved host/RF scope, synthetic test, device-control/WIDS alerts, rollback |
| 6. Intelligence / privacy | [Bellingcat verification](../OSINT/bellingcat-source-verification.md) · [Mobile MVT](../Mobile/mvt-forensic-triage.md) | Defensible, minimal evidence and documented uncertainty |
| 7. AI agent QA | [Promptfoo evaluations](../AI/llm-security-evaluation-promptfoo.md) | Synthetic injection/tool-boundary tests and regression |
| 8. Findings and retest | [Findings lifecycle](assessment-findings-lifecycle.md) | Verified severity, owner, remediation, retest evidence |

All stages require legal/contract scope, approved test accounts and safe
collection. Not every client needs every phase.

## Portable cyberdeck / lab design

- **Operator workstation / cyberdeck:** consent capture and secure project
  workspace; do not silently collect customer data or run arbitrary tests.
- **VM isolation:** snapshots, immutable base images, synthetic evidence
  first, version-pinned tools and controlled network egress.
- **Gateway/network devices:** explicit routing and client-allowlisted
  egress for active assessments; avoid public proxy lists.
- **Evidence vault:** encrypted case folders, UTC manifest, source hashes,
  role-based sharing and tested backups.
- **Analysis systems:** offline or controlled-access tools as needed;
  isolate raw datasets from reporting copies and shared AI models.
- **Workflow engine (future):** holds a human approval checkpoint for each
  network-invasive or privileged operation. Build resumable steps and log
  both successful and rejected actions.

## Suggested manifest schema

| Field | Suggested representation |
| --- | --- |
| Engagement | Random case ID; consent record reference |
| Scope | Approved hosts/ranges/identities; excluded targets |
| Stage | Tool name, version, start/end UTC, operator and outcome |
| Provenance | Upstream repo/commit, rule/test/config ID |
| Evidence | Hash, encrypted URI, ACL, retention and legal hold |
| Result | Observed vs inferred, confidence, impact and validation |
| Approvals | Authorized testing, changes and retests separately |
| Delivery | Redacted executive report, reviewer and customer receipt |

**Important:** This is a documentation and planning integration. No
consent form, task runner, CI automation, customer deployment or
DefectDojo import was created by this change. Treat those as separate
implementation projects with threat modeling, customer-approved testing
and operational acceptance criteria.

## Sources and further reading

The [source integration register](../Documentation/upstream-security-projects-register.md)
links to all upstream projects, licenses and internal landing pages.
For operational security see [OPSEC](../OPSEC/README.md) and
[legal terms](../LEGAL.md).

---

[Playbooks](README.md) · [START_HERE](../START_HERE.md) · [Main guide](../README.md)
