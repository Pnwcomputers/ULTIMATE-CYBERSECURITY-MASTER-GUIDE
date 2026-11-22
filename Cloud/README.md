# ☁️ Cloud Security
**PCI payment workloads:** [PCI DSS Scoping & Segmentation Field Guide](../Compliance/pci-dss-scoping.md#segmentation--modern-architecture) covers cloud/hybrid CDE reachability, management-plane impact, microsegmentation and service-provider evidence. A VPC/VNet alone does not establish scope exclusion.

**Historical cloud reference:** [Cypherpunk Symposium toolkit review](../Documentation/cypherpunk-pentesting-toolkit-review.md) distinguishes archived IAM/Kubernetes tips from current provider controls and maintained tools.



<div align="center">

**Attack surface, assessment tooling, and hardening for AWS, Azure, and GCP**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Focus](https://img.shields.io/badge/Focus-Cloud_Security-blue?style=for-the-badge)
![Providers](https://img.shields.io/badge/Providers-AWS_%7C_Azure_%7C_GCP-orange?style=for-the-badge)
![Use](https://img.shields.io/badge/Use-Authorized_Only-red?style=for-the-badge)

</div>

---

**Cloud research references:** [h4cker cloud/container security](https://github.com/The-Art-of-Hacking/h4cker/tree/master/cybersecurity-domains/cloud-container-security) and [PNWC's source map](../Documentation/awesome-hacking-collections-integration.md). Verify current AWS/Azure/GCP APIs before deployment.

**External documentation:** [Curated technical docs](../Documentation/curated-technical-docs.md) includes infrastructure references such as [Linode/Akamai](https://github.com/linode/docs/tree/develop/docs/guides), and the [Docker operations guide](../ContainerSecurity/docker-cli-operations-reference.md) covers local Engine diagnostics; cloud-native workload hardening still requires provider-specific controls.

**Cloud API and supply-chain references:** [Curated Security API Catalog](../Documentation/security-public-api-catalog.md) covers Cloudflare's managed API, GitHub advisories, NVD and CISA KEV for risk triage. Cloud/API tokens must remain least-privilege and outside committed files.

**Additional assessment paths:** [CISA ScubaGear for Microsoft 365/Entra](m365-scuba-assessment.md) evaluates configuration against SCuBA baselines; [software supply-chain and SBOM checks](../ContainerSecurity/software-supply-chain-assessment.md) apply to cloud artifacts, with credentials and tenant approval handled separately.

## 🎯 Purpose
Dedicated home for cloud security - the shared-responsibility model, the recurring
misconfiguration classes, assessment tooling, and per-provider attack surface and
hardening for AWS, Azure/Entra ID, and GCP.

## ⚙️ Function
Indexes the Cloud Security section: cross-cutting fundamentals (shared
responsibility, IAM, CSPM, common misconfig classes, multi-cloud tooling) plus
three provider deep-dives - each pairing the offensive perspective (enumeration,
privilege escalation, common misconfigurations) with hardening and detection.

## 🏆 Goal
Give practitioners a single canonical cloud-security reference: understand what the
cloud provider secures vs. what you must, how cloud environments are commonly
assessed and attacked, and how to harden and monitor each platform.

## 📋 When To Use
- Scoping or executing an authorized cloud configuration review / penetration test
- Looking up a provider's IAM model, common misconfigurations, or hardening baseline
- Selecting assessment tooling (Prowler, ScoutSuite, Pacu, ROADtools)
- Reviewing a cloud estate defensively against CIS benchmarks and the ATT&CK Cloud matrix

---

## 📋 Table Of Contents

- [Overview](#-overview)
- [Shared Responsibility Model](#-shared-responsibility-model)
- [Recurring Misconfiguration Classes](#-recurring-misconfiguration-classes)
- [Assessment Tooling](#-assessment-tooling)
- [Folder Contents](#-folder-contents)
- [Security & Legal Disclaimer](#-security--legal-disclaimer)
- [Resources](#-resources)

---

## 🎯 Overview

Cloud incidents can involve customer configuration or identity, provider
services or software, compromised credentials, and other factors. Attribute a
cause only when incident-specific evidence supports it. This section consolidates
cloud security - previously scattered across the master guides - into shared
fundamentals plus per-provider depth.

Like [Tradecraft](../Tradecraft/) and [WebAppSecurity](../WebAppSecurity/), the
material is **dual-use**: each provider guide pairs the offensive view (how an
estate is enumerated and abused) with hardening and detection.

---

## 🔀 Shared Responsibility Model

![Cloud provider and customer security responsibilities](../assets/diagrams/cloud-shared-responsibility.svg)

*Responsibilities vary by service model, offering, and contractual terms.*

The provider secures the infrastructure and service components it operates;
the customer secures the workloads, data, identities, and settings assigned to
them. The boundary shifts by service model and by the specific service:

| Area | IaaS (typical) | PaaS (typical) | SaaS (typical) |
|------|----------------|----------------|----------------|
| Datacenter, physical hosts, physical network | Provider | Provider | Provider |
| Underlying service platform and managed runtime | Provider | Provider | Provider |
| Guest operating system and patching | Customer | Provider | Provider |
| Application code and deployment | Customer | Customer / shared | Provider / shared |
| Virtual network, firewall, and service access settings | Customer | Shared / service-specific | Provider service controls; customer sharing settings |
| Customer data, identities, and access policy | Customer | Customer | Customer |

This is a high-level guide, not a contract. “Shared” and service-specific rows
depend on the cloud product, feature, configuration, and agreement. For example,
a provider operates the physical network, while an IaaS customer configures
virtual networks and firewall rules. In all service models, customers still need
to manage their data, identities, and the settings exposed to them. Use the
provider’s matrix for the exact service before assigning a control or incident
cause.

Further reading: [Microsoft's shared responsibility matrix](https://learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility) and [AWS's shared responsibility model](https://docs.aws.amazon.com/wellarchitected/latest/framework/shared-responsibility.html). These provider examples illustrate the model; consult the documentation for the service actually in scope.

---

## ⚠️ Recurring Misconfiguration Classes

The same issues appear across all three providers:

- **Public storage** - world-readable buckets/blobs (S3, Azure Blob, GCS).
- **Over-permissive IAM** - wildcard permissions, unused privileged roles, no
  least privilege; **privilege-escalation paths** through role assumption / policy
  editing.
- **Exposed secrets** - keys in code, environment variables, or metadata.
- **Instance metadata abuse** - SSRF may expose instance identity or credentials
  depending on the request path and service configuration. AWS IMDSv2 blocks some
  SSRF paths that cannot issue the required PUT request and headers; it is not a
  universal SSRF fix. Remediate the SSRF and scope instance-role permissions.
- **Logging coverage gaps** - Default audit coverage differs by provider and
  does not guarantee the data-plane, identity, retention, or centralization coverage
  an investigation needs. AWS CloudTrail Event history covers 90 days of management
  events in one Region; it does not show data events. Configure trails or an event
  data store for the event types and ongoing or organization-wide collection you
  require. Azure Activity Log is collected automatically and retained for 90 days,
  but is primarily a control-plane log, does not typically capture reads, and is
  not an authentication or authorization audit log. Configure diagnostic settings
  for resource-log export and plan separately for Microsoft Entra sign-in and audit
  logs. In Google Cloud, Admin Activity and System Event logs are on by default,
  while Data Access logs are disabled by default for most services (BigQuery is an
  exception); enable the required services and plan routing and retention. Verify
  coverage, exclusions, destination, retention, and cost against the actual services
  in scope.
- **Weak network exposure** - management ports open to the internet, permissive
  security groups / NSGs / firewall rules.
- **Identity gaps** - no MFA, long-lived access keys, stale accounts.

### Logging defaults and coverage

The baseline differs by provider, so validate the exact event types and sources a
detection or investigation needs:

```mermaid
flowchart TD
    Goal["Set evidence, detection, and retention goals"]

    subgraph AWS["AWS"]
        AWSBase["Event history: management events<br/>90 days, one Region"]
        AWSMore["Trail or event data store<br/>for data events, longer retention,<br/>or organization-wide collection"]
        AWSBase --> AWSMore
    end

    subgraph Azure["Azure and Microsoft Entra"]
        AzureBase["Activity Log: collected automatically<br/>control-plane activity, 90 days"]
        AzureMore["Diagnostic settings for resource logs<br/>and separate Entra sign-in / audit logs"]
        AzureBase --> AzureMore
    end

    subgraph GCP["Google Cloud"]
        GCPBase["Admin Activity and System Event<br/>logs are on by default"]
        GCPMore["Enable Data Access logs for<br/>required services; plan routing<br/>and retention"]
        GCPBase --> GCPMore
    end

    Goal --> AWSBase
    Goal --> AzureBase
    Goal --> GCPBase
```

*The diagram summarizes common defaults, not every service's logging behavior.
Check provider documentation for service-specific exceptions, available event
types, diagnostic settings, retention, and charges.*

Primary references: [AWS CloudTrail Event history](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html),
[Azure Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log),
[Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit), and
[Google Cloud Data Access audit-log configuration](https://cloud.google.com/logging/docs/audit/configure-data-access).

---

## 🛠️ Assessment Tooling

| Tool | Scope | Role and limits |
|------|-------|------|
| [Prowler](https://github.com/prowler-cloud/prowler) | AWS, Azure, GCP, Kubernetes | Cloud posture checks against configurable security standards; confirm the selected provider, permissions, and check set. |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud | Uses provider APIs to collect configuration for a point-in-time report; protect the report as sensitive environment inventory. |
| [Pacu](https://github.com/RhinoSecurityLabs/pacu) | AWS | Adversary-simulation framework, not a baseline scanner; use only for specifically approved, controlled scenarios. |
| [ROADtools](https://github.com/dirkjanm/ROADtools) | Microsoft Entra ID | Identity-focused exploration and analysis; confirm tenant, account permissions, and data handling before collection. |
| [AzureHound](https://github.com/SpecterOps/AzureHound) | Microsoft Azure and Entra ID | BloodHound data collector; collection output can expose sensitive identity and resource relationships. |
| [Trivy](https://github.com/aquasecurity/trivy) | IaC, filesystems, repositories, and images by scan mode | Finds vulnerabilities, secrets, and selected misconfigurations. A local artifact scan does not establish the deployed cloud configuration. |

Provider-native options include **AWS** IAM Access Analyzer, GuardDuty, and Security Hub; **Azure** Microsoft Defender for Cloud; and **Google Cloud** Security Command Center. Select services and features for the assessment objective rather than treating any one product as complete coverage.

### Scope collection and protect results

```mermaid
flowchart LR
    A[Confirm owner approval<br/>and account, tenant, or project scope] --> B{Choose assessment surface}
    B -->|Live cloud inventory| C[Use an approved identity<br/>with only required access]
    B -->|IaC or image artifact| D[Scan the named artifact<br/>and record its revision]
    C --> E[Collect only required<br/>configuration and relationships]
    D --> E
    E --> F[Protect reports as<br/>sensitive environment data]
    F --> G[Validate findings against<br/>provider controls and source evidence]
    G --> H[Owner reviews remediation<br/>and authorized retest]
    H --> I[Apply retention and<br/>delete expired exports]
```

A live inventory and an offline artifact scan answer different questions: the first observes selected cloud API data at a point in time; the second evaluates the files and scan modes supplied to it. Neither alone proves full coverage. Read-only collection can still generate audit activity, consume API quotas, and produce sensitive reports, so check tool permissions, provider logging, cost, and retention before running it.

Trivy's [misconfiguration scanner documentation](https://trivy.dev/docs/latest/guide/scanner/misconfiguration/) notes that misconfiguration scanning is not enabled by default in image, filesystem, and repository scans. ScoutSuite describes itself as an API-based, point-in-time posture assessment in its [project documentation](https://github.com/nccgroup/ScoutSuite). SpecterOps identifies AzureHound as the [BloodHound data collector for Microsoft Azure](https://github.com/SpecterOps/AzureHound).
---

## 📂 Folder Contents

| File | Description | Status |
|------|-------------|--------|
| **[aws.md](./aws.md)** | AWS security - IAM, S3, IMDS/SSRF credential theft, enumeration & privesc, hardening, logging | ✅ Complete |
| **[azure.md](./azure.md)** | Azure & Entra ID - roles, consent/illicit-grant attacks, ROADtools/AzureHound, hardening | ✅ Complete |
| **[gcp.md](./gcp.md)** | GCP - IAM, service accounts, privilege escalation, assessment, hardening | ✅ Complete |

---

## ⚠️ Security & Legal Disclaimer

> [!CAUTION]
> **Authorized use only.** The techniques here are for authorized cloud assessment,
> education, and defensive research. Testing cloud accounts or tenants you do not
> own or lack **explicit written permission** to assess is illegal - and note that
> cloud providers also have their own **penetration-testing policies** you must
> follow. Always work within a signed scope. See [LEGAL.md](../LEGAL.md).

---

## 📚 Resources

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/) - cloud adversary TTPs
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - per-provider hardening baselines
- [AWS Well-Architected - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Microsoft Cloud Adoption Framework - Security](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/secure/)
- [Google Cloud Security Best Practices](https://cloud.google.com/security/best-practices)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/) - vendor-neutral guidance

---

<div align="center">

**⚠️ USE THIS REPO RESPONSIBLY AND LEGALLY ⚠️**

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

</div>

---

## Related Files
- [aws.md](aws.md) - Amazon Web Services security
- [azure.md](azure.md) - Microsoft Azure & Entra ID security
- [gcp.md](gcp.md) - Google Cloud Platform security
- [../WebAppSecurity/README.md](../WebAppSecurity/README.md) - Web app security (cloud-hosted apps)
- [../LEGAL.md](../LEGAL.md) - Legal notice and authorized-use terms

---
| [⬅️ Back to Master Index](../README.md) |
