# 🟧 AWS Security

> [!CAUTION]
> **Authorized use only.** The techniques below are for authorized assessment,
> education, and defensive research. Test only AWS accounts you own or have
> **explicit written permission** to assess, and follow
> [AWS's customer support policy for penetration testing](https://aws.amazon.com/security/penetration-testing/).
> See [LEGAL.md](../LEGAL.md).

## 🎯 Purpose
AWS security reference - the IAM model, the recurring misconfigurations, how an
account is enumerated and escalated in an authorized test, and how to harden and
monitor it.

## ⚙️ Function
Covers IAM (users, roles, policies, privilege escalation paths), S3 exposure,
instance metadata (IMDS) credential theft, enumeration and assessment tooling
(Prowler, ScoutSuite, Pacu), and the hardening/logging baseline (CloudTrail,
GuardDuty, Security Hub, IAM Access Analyzer).

## 🏆 Goal
Let a reader assess an AWS account methodically and recommend concrete hardening
mapped to AWS-native controls and the CIS AWS Benchmark.

## 📋 When to Use
- Authorized configuration review or penetration test of an AWS account
- Looking up IAM privilege-escalation paths or S3/IMDS issues
- Building an AWS hardening and monitoring baseline

---

## 📋 Table of Contents

- [Identity & Access Management](#identity--access-management)
- [S3 Storage Exposure](#s3-storage-exposure)
- [Instance Metadata (IMDS) & Credential Theft](#instance-metadata-imds--credential-theft)
- [Enumeration & Assessment](#enumeration--assessment)
- [Privilege Escalation Paths](#privilege-escalation-paths)
- [Hardening & Detection](#hardening--detection)
- [Resources](#-resources)

---

## Identity & Access Management

IAM is the heart of AWS security. Key concepts:

- **Users / Groups** - long-lived identities; access keys are a common leak/risk.
- **Roles** - assumable identities with temporary credentials (preferred over keys).
- **Policies** - JSON permission documents; `"Action": "*"` / `"Resource": "*"` and
  `iam:*` are red flags.
- **STS** - issues temporary credentials via `AssumeRole`.

The most common IAM problems: over-broad policies, long-lived access keys, no MFA,
unused privileged roles, and policies that allow a principal to **escalate** (edit
policies, create keys, or pass a privileged role).

---

## S3 Storage Exposure

- **Public buckets/objects** - the classic breach; check bucket policy, ACLs, and
  the account-level **Block Public Access** setting.
- **Test (authorized):** `aws s3 ls s3://BUCKET` / `aws s3api get-bucket-policy`.
- **Defend:** enable Block Public Access account-wide; use bucket policies over
  ACLs (disable ACLs); enable default encryption and versioning; log access.

---

## Instance Metadata (IMDS) & Credential Theft

An EC2 instance's role credentials are reachable at the metadata endpoint
`169.254.169.254`. An **SSRF** in an app on the instance can steal them.

- **IMDSv1** (request/response) is exploitable via simple SSRF.
- **IMDSv2** (session/token, `PUT` then `GET`) mitigates most SSRF and should be
  **required**.

```bash
# On an instance (authorized) - IMDSv2 flow
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Defend:** require IMDSv2 (`HttpTokens: required`), limit the hop count, and
scope instance-role permissions tightly.

---

## Enumeration & Assessment

```bash
# Who am I / what can this identity do
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name NAME

# Configuration assessment (CIS / best practice)
prowler aws                       # https://github.com/prowler-cloud/prowler
scout aws                         # https://github.com/nccgroup/ScoutSuite
```

- **Prowler** - CIS AWS Benchmark and hundreds of checks; good for compliance evidence.
- **ScoutSuite** - multi-cloud config audit with an HTML report.
- **Pacu** - offensive AWS exploitation framework (enumeration, privesc modules) -
  authorized engagements only. <https://github.com/RhinoSecurityLabs/pacu>

---

## Privilege Escalation Paths

Rhino Security Labs catalogued ~20 IAM privesc primitives. Common ones:

- `iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion` - rewrite a policy you're attached to.
- `iam:AttachUserPolicy` / `AttachRolePolicy` - attach `AdministratorAccess`.
- `iam:CreateAccessKey` - mint keys for a more privileged user.
- `iam:PassRole` + a compute service (`lambda:CreateFunction`, `ec2:RunInstances`) -
  pass a privileged role to a resource you control.

**Test:** enumerate the current principal's permissions (Pacu's `iam__privesc_scan`)
and look for these primitives. **Defend:** deny these actions except for break-glass
admins; use permission boundaries and SCPs.

---

## Hardening & Detection

- **Logging:** enable **CloudTrail** (all regions, log-file validation) and centralize;
  enable Config for resource history.
- **Threat detection:** **GuardDuty** (anomaly/threat detection), **Security Hub**
  (aggregated findings + CIS score).
- **IAM:** enforce MFA, rotate/eliminate long-lived keys, least privilege, use
  **IAM Access Analyzer** to find external/over-broad access; apply **SCPs** at the org.
- **Data:** default encryption (KMS), Block Public Access, versioning.
- **Network:** least-privilege security groups; no management ports to `0.0.0.0/0`.
- Benchmark against the [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services).

---

## 📚 Resources

- [AWS Penetration Testing Policy](https://aws.amazon.com/security/penetration-testing/) - what is allowed without prior approval
- [AWS Well-Architected - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Pacu (AWS exploitation framework)](https://github.com/RhinoSecurityLabs/pacu)
- [Prowler](https://github.com/prowler-cloud/prowler) / [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [MITRE ATT&CK Cloud (IaaS)](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)

---

## Related Files
- [README.md](README.md) - Cloud Security section index
- [azure.md](azure.md) - Azure & Entra ID security
- [gcp.md](gcp.md) - Google Cloud Platform security
