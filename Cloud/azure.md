# 🟦 Azure & Entra ID Security

> [!CAUTION]
> **Authorized use only.** The techniques below are for authorized assessment,
> education, and defensive research. Test only tenants/subscriptions you own or
> have **explicit written permission** to assess, and follow the
> [Microsoft penetration testing rules of engagement](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement).
> See [LEGAL.md](../LEGAL.md).

## 🎯 Purpose
Microsoft Azure and **Entra ID** (formerly Azure AD) security reference - the
identity model, the recurring attack paths, assessment tooling, and hardening.

## ⚙️ Function
Covers the Entra ID / Azure RBAC split, common identity attacks (illicit consent
grants, over-privileged app registrations, role abuse), enumeration tooling
(ROADtools, AzureHound), and the hardening/detection baseline (Conditional Access,
PIM, Defender for Cloud).

## 🏆 Goal
Let a reader assess an Azure/Entra environment and recommend concrete hardening
mapped to Microsoft-native controls and the CIS Microsoft Azure Benchmark.

## 📋 When to Use
- Authorized review or penetration test of an Azure subscription / Entra tenant
- Looking up Entra ID attack paths (consent, app registrations, role abuse)
- Building an Azure/Entra hardening and monitoring baseline

---

## 📋 Table of Contents

- [Entra ID vs Azure RBAC](#entra-id-vs-azure-rbac)
- [Common Identity Attacks](#common-identity-attacks)
- [Enumeration & Assessment](#enumeration--assessment)
- [Hardening & Detection](#hardening--detection)
- [Resources](#-resources)

---

## Entra ID vs Azure RBAC

Azure has **two distinct permission planes** - a frequent source of confusion and
misconfiguration:

- **Entra ID (formerly Azure AD)** - the identity provider: users, groups, service
  principals, app registrations, and **directory roles** (e.g. Global Administrator).
- **Azure RBAC** - permissions over **resources** (subscriptions, resource groups)
  via roles like Owner/Contributor.

A principal can be powerful in one plane and not the other; **User Access
Administrator** and **Owner** can grant themselves more, and the Entra **Global
Administrator** can elevate to Azure RBAC via the "access management for Azure
resources" toggle - a classic escalation bridge between the planes.

---

## Common Identity Attacks

- **Illicit consent grant** - a malicious/over-scoped app tricks users into
  consenting to OAuth permissions (e.g. `Mail.Read`), granting persistent access
  without a password.
- **Over-privileged app registrations / service principals** - apps with excessive
  Microsoft Graph permissions or credentials that outlive their need.
- **Directory role abuse** - standing Global Admin / Privileged Role Admin without PIM.
- **Legacy authentication** - protocols that bypass modern MFA/Conditional Access.
- **Device/PRT and token theft** - reuse of primary refresh tokens.

---

## Enumeration & Assessment

```bash
# Entra ID enumeration and analysis (authorized)
roadrecon gather                  # https://github.com/dirkjanm/ROADtools

# Configuration assessment
prowler azure                     # https://github.com/prowler-cloud/prowler
scout azure                       # https://github.com/nccgroup/ScoutSuite
```

- **ROADtools** (`roadrecon`) - enumerates Entra ID (users, apps, service
  principals, roles) into an explorable database. <https://github.com/dirkjanm/ROADtools>
- **AzureHound** - the BloodHound collector for Azure; maps attack paths across
  Entra and Azure RBAC. <https://github.com/SpecterOps/BloodHound>
- **Prowler / ScoutSuite** - configuration assessment against CIS/best practice.

---

## Hardening & Detection

- **Identity:** enforce MFA; **Conditional Access** policies; block legacy auth;
  use **Privileged Identity Management (PIM)** for just-in-time role activation.
- **Applications:** review app consent (restrict user consent; use admin consent
  workflow); audit service-principal credentials and Graph permissions.
- **RBAC:** least privilege; limit Owner/User Access Administrator; separate
  identity and resource admin duties.
- **Monitoring:** **Microsoft Defender for Cloud** (secure score + threat
  protection); ship Entra sign-in/audit logs and Azure Activity logs to a
  [SIEM](../IncidentResponse/SIEM/README.md) (or Microsoft Sentinel).
- Benchmark against the [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure).

---

## 📚 Resources

- [Microsoft Penetration Testing Rules of Engagement](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement)
- [ROADtools (Entra ID)](https://github.com/dirkjanm/ROADtools) / [AzureHound](https://github.com/SpecterOps/BloodHound)
- [Microsoft Cloud Adoption Framework - Secure](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/secure/)
- [Entra ID security operations guide](https://learn.microsoft.com/en-us/entra/architecture/security-operations-introduction)
- [MITRE ATT&CK Cloud (Azure AD / Office 365)](https://attack.mitre.org/matrices/enterprise/cloud/)

---

## Related Files
- [README.md](README.md) - Cloud Security section index
- [aws.md](aws.md) - Amazon Web Services security
- [gcp.md](gcp.md) - Google Cloud Platform security
- [../Tradecraft/active-directory.md](../Tradecraft/active-directory.md) - on-prem AD (hybrid identity context)
