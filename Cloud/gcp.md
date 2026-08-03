# 🟩 GCP Security

> [!CAUTION]
> **Authorized use only.** The techniques below are for authorized assessment,
> education, and defensive research. Test only GCP projects/organizations you own
> or have **explicit written permission** to assess. Google does not require prior
> notification for testing your own projects, but you remain bound by the
> [Acceptable Use Policy](https://cloud.google.com/terms/aup). See [LEGAL.md](../LEGAL.md).

## 🎯 Purpose
Google Cloud Platform security reference - the IAM and service-account model, the
recurring privilege-escalation paths, assessment tooling, and hardening.

## ⚙️ Function
Covers GCP IAM (members, roles, bindings), service accounts and impersonation,
common privilege-escalation primitives, storage exposure, assessment tooling
(Prowler, ScoutSuite), and the hardening/detection baseline (Security Command
Center, Cloud Audit Logs, Organization Policy).

## 🏆 Goal
Let a reader assess a GCP project/org and recommend concrete hardening mapped to
GCP-native controls and the CIS Google Cloud Benchmark.

## 📋 When to Use
- Authorized review or penetration test of a GCP project or organization
- Looking up service-account impersonation / IAM privesc paths
- Building a GCP hardening and monitoring baseline

---

## 📋 Table of Contents

- [IAM & Service Accounts](#iam--service-accounts)
- [Privilege Escalation Paths](#privilege-escalation-paths)
- [Storage & Metadata Exposure](#storage--metadata-exposure)
- [Enumeration & Assessment](#enumeration--assessment)
- [Hardening & Detection](#hardening--detection)
- [Resources](#-resources)

---

## IAM & Service Accounts

GCP IAM binds **members** (users, groups, service accounts) to **roles** on a
**resource** in a hierarchy (organization → folder → project → resource);
permissions **inherit** downward.

- **Service accounts** are both an identity *and* a resource - you can grant
  permissions **on** a service account (e.g. impersonate it), which is the root of
  most GCP privilege escalation.
- **Primitive roles** (Owner/Editor/Viewer) are broad and discouraged in favor of
  **predefined** or **custom** least-privilege roles.

---

## Privilege Escalation Paths

Common GCP privesc primitives (catalogued by Rhino Security Labs / others):

- `iam.serviceAccounts.getAccessToken` / `actAs` - impersonate a more privileged
  service account and act as it.
- `iam.serviceAccountKeys.create` - mint a key for a privileged service account.
- `iam.roles.update` - edit a custom role you're bound to.
- `cloudfunctions.functions.create` / `compute.instances.create` + `actAs` - deploy
  a resource running as a privileged service account.
- `setIamPolicy` on a resource - grant yourself a higher role.

**Test:** enumerate the caller's permissions and look for these; the
`GCPPrivEsc`/`gcp_scanner` style tooling helps. **Defend:** avoid `actAs`/token
grants except where required; disable service-account key creation via org policy.

---

## Storage & Metadata Exposure

- **Cloud Storage (GCS)** - public buckets/objects via IAM (`allUsers`/
  `allAuthenticatedUsers`); check bucket IAM and enforce **public access prevention**.
- **Instance metadata** - `metadata.google.internal` can yield service-account
  tokens if reachable via SSRF; restrict metadata access and app SSRF exposure.

---

## Enumeration & Assessment

```bash
# Who am I / what can this identity do (authorized)
gcloud auth list
gcloud projects get-iam-policy PROJECT_ID

# Configuration assessment
prowler gcp                        # https://github.com/prowler-cloud/prowler
scout gcp                          # https://github.com/nccgroup/ScoutSuite
```

- **Prowler** / **ScoutSuite** - CIS/best-practice configuration assessment.
- The `gcloud` CLI itself is the primary enumeration tool for IAM policies,
  service accounts, and resource inventory.

---

## Hardening & Detection

- **IAM:** least privilege (predefined/custom roles, not primitive); avoid broad
  `actAs`; disable service-account key creation (org policy
  `iam.disableServiceAccountKeyCreation`); enforce MFA on user accounts.
- **Data:** enforce **public access prevention** and uniform bucket-level access
  on GCS; use CMEK where required.
- **Monitoring:** **Security Command Center** (misconfiguration + threat findings);
  ensure **Cloud Audit Logs** (Admin Activity + Data Access) are enabled and
  centralized to a [SIEM](../IncidentResponse/SIEM/README.md).
- **Guardrails:** **Organization Policy** constraints to enforce estate-wide rules.
- Benchmark against the [CIS Google Cloud Platform Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform).

---

## 📚 Resources

- [Google Cloud Security Best Practices](https://cloud.google.com/security/best-practices)
- [GCP IAM documentation](https://cloud.google.com/iam/docs)
- [Prowler](https://github.com/prowler-cloud/prowler) / [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [MITRE ATT&CK Cloud (IaaS)](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)

---

## Related Files
- [README.md](README.md) - Cloud Security section index
- [aws.md](aws.md) - Amazon Web Services security
- [azure.md](azure.md) - Microsoft Azure & Entra ID security
