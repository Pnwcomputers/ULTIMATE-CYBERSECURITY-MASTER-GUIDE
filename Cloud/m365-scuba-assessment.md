# Microsoft 365 and Entra Configuration Assessment with CISA ScubaGear

_Last reviewed: 2026-11-02 (upstream configuration documentation; no tenant accessed)_

> [!CAUTION]
> Obtain written permission from an authorized Microsoft 365 tenant
> administrator. Administrative configuration and identity settings can contain
> confidential data. Review permission scopes before granting consent; do not
> disable tenant controls or remediate automatically without change approval.

**Prerequisites:** [Azure/Entra security](azure.md) · [Cloud index](README.md) ·
[Client findings workflow](../PlayBooks/assessment-findings-lifecycle.md).

## What CISA's project contributes

[CISA ScubaGear](https://github.com/cisagov/ScubaGear) checks supported Microsoft
365 configurations against
[CISA SCuBA Secure Configuration Baselines](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project).
It is a *configuration compliance assessment*, not an authenticated
penetration test, full Microsoft Secure Score review, continuous MDR service,
or vulnerability scanner. Review its
[official documentation](https://cisagov.github.io/ScubaGear/) for covered
products and current permissions.

## Pre-assessment record

- Tenant ID and approved organization, contact, testing window, administrator
  and documented collection scope.
- Baseline version/date, ScubaGear release and dependencies, PowerShell
  version and account privileges.
- Approved consent scopes and a decision on whether temporary administrative
  privileges are required; do not assume least privilege without verifying
  current requirements.
- Output storage location: configuration reports can disclose tenant
  architecture, policies, users and authentication settings.
- An exception list for intentional deviations and legacy operational
  constraints, including conditional access and break-glass accounts.

## Controlled assessment sequence

1. Read the
   [ScubaGear README and current Quick Start](https://github.com/cisagov/ScubaGear)
   in an isolated, patched Windows/PowerShell assessment station.
2. Verify the publisher, required modules, installation and release sources.
   Avoid piping unreviewed downloaded scripts directly to a shell.
3. Confirm admin approval for Microsoft Graph/PowerShell permissions. Prefer
   a scoped, supervised test account and keep audit logs for its actions.
4. Collect a baseline according to upstream supported commands **after**
   checking the installed version. The guide does not include copied commands
   whose flags might change across releases.
5. Preserve ScubaGear result files, tool version, baseline and collection
   time. Keep raw exports private; share a redacted customer summary.
6. Triage each deviation as verified noncompliance, approved exception,
   not applicable or inconclusive. Investigate dependencies and licensing
   constraints before recommending enforcement.
7. Recommend change control with rollback, admin/customer sign-off,
   validation of sign-in/availability, and a dated follow-up assessment.

## Client report fields

| Field | Example expectation |
| --- | --- |
| Scope | Tenant and supported Microsoft 365 services |
| Requirement | SCuBA product and control identifier, baseline revision |
| Actual condition | Configuration or policy observed, scrubbed as needed |
| Risk | Exposure, affected users and operational trade-offs |
| Remediation | Proposed safe setting, prerequisite, change owner |
| Exception | Justification, approval, compensating control, review date |
| Validation | Tool run timestamp, evidence reference and retest outcome |

Link issues to [DefectDojo/finding workflow](../PlayBooks/assessment-findings-lifecycle.md)
without uploading tenant-wide exports to any third-party service absent a data
processing agreement.

## References and limitations

- [CISA ScubaGear](https://github.com/cisagov/ScubaGear) (CC0-1.0).
- [CISA SCuBA project](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project).
- [Microsoft Entra documentation](https://learn.microsoft.com/en-us/entra/).
- [Azure/Entra guide](azure.md) · [Compliance](../Compliance/README.md).

No tenant connection, assessment, remediation or licensing verification was
performed by this documentation change.

---

[Cloud index](README.md) · [Main README](../README.md) ·
[Legal terms](../LEGAL.md)
