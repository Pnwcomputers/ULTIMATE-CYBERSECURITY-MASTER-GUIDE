# 🏛️ Security Control Frameworks

> [!IMPORTANT]
> Educational reference, **not** compliance advice. Framework versions change -
> verify against the authoritative source and engage a qualified assessor before
> relying on this for an audit or certification. See the
> [section notice](README.md#-important-notice).

## 🎯 Purpose
A working reference to the major security control frameworks - what each is, when
it applies, how it is structured, and how they relate.

## ⚙️ Function
Covers NIST CSF 2.0, ISO/IEC 27001:2022, SOC 2, PCI DSS 4.0.1, CIS Controls v8,
and the NIST SP 800-53 / 800-171 baselines, with version notes verified against
each authoritative source.

## 🏆 Goal
Let a reader pick the right framework, understand its structure, and see how a
single set of technical controls maps across several of them.

## 📋 When to Use
- Selecting or comparing frameworks
- Preparing for a certification/audit
- Mapping technical controls to a framework's requirements

---

## 📋 Table of Contents

- [NIST Cybersecurity Framework (CSF) 2.0](#nist-cybersecurity-framework-csf-20)
- [ISO/IEC 27001:2022](#isoiec-270012022)
- [SOC 2](#soc-2)
- [PCI DSS 4.0.1](#pci-dss-401)
- [CIS Controls v8](#cis-controls-v8)
- [NIST SP 800-53 & 800-171](#nist-sp-800-53--800-171)
- [How They Relate](#how-they-relate)
- [Resources](#-resources)

---

## NIST Cybersecurity Framework (CSF) 2.0

Released **2024**; the widely used, voluntary, risk-based framework. CSF 2.0's
headline change is a new **Govern** function, making **six** core functions:

1. **Govern (GV)** *(new in 2.0)* - organizational context, risk strategy, roles, policy, oversight
2. **Identify (ID)** - assets, risks, and the environment
3. **Protect (PR)** - safeguards (access control, awareness, data security)
4. **Detect (DE)** - find events (monitoring, detection processes)
5. **Respond (RS)** - act on incidents
6. **Recover (RC)** - restore capabilities

- **Use it for:** a flexible program backbone; maps well to other frameworks.
- **Not a certification** - it is a framework you self-adopt/assess against.

---

## ISO/IEC 27001:2022

The leading **international, certifiable** standard for an Information Security
Management System (ISMS). The **2022** revision supersedes 2013.

- **ISMS-centric:** requires risk assessment, a Statement of Applicability, and
  continual improvement - not just controls.
- **Annex A (2022):** **93 controls** organized into **4 themes** - Organizational,
  People, Physical, Technological (down from 114 controls / 14 domains in 2013).
- **Use it for:** an internationally recognized certification via an accredited body.

---

## SOC 2

An **attestation report** (not a certification) under the AICPA's **Trust Services
Criteria** - common for SaaS/service organizations to assure customers.

- **Five Trust Services Criteria:** **Security** (the required "common criteria"),
  plus optional **Availability, Processing Integrity, Confidentiality, Privacy**.
- **Type I** - controls designed appropriately at a point in time; **Type II** -
  controls operated effectively over a period (usually 3-12 months).
- **Use it for:** demonstrating control effectiveness to customers/partners.

---

## PCI DSS 4.0.1

**Mandatory** for organizations that store, process, or transmit payment card data.
**v4.0.1** (2024) is the current version; **v3.2.1 was retired in 2024**.

- **12 requirements** across 6 goals (network security, data protection, vulnerability
  management, access control, monitoring, and policy).
- v4.x adds a **customized approach** option, more MFA, and stronger authentication
  requirements; some future-dated requirements phased in over time.
- **Use it for:** payment-card environments - compliance is contractually required.
  Validation scales from a Self-Assessment Questionnaire (SAQ) to a QSA audit.

---

## CIS Controls v8

A **prioritized, prescriptive** set of **18 controls** (v8 consolidated the prior
20), each broken into safeguards and grouped into **Implementation Groups (IG1-IG3)**
by organizational maturity/resources.

- **IG1** is the "essential cyber hygiene" baseline every org should meet.
- **Use it for:** a concrete, actionable starting point; maps to CSF, ISO, and others.
- Pairs with the **CIS Benchmarks** (per-technology hardening) referenced in the
  [Cloud](../Cloud/README.md) and endpoint guides.

---

## NIST SP 800-53 & 800-171

- **SP 800-53 (Rev 5)** - the comprehensive control catalog for **US federal**
  systems (and the basis for FedRAMP); organized into control families.
- **SP 800-171 (Rev 3)** - protecting **Controlled Unclassified Information (CUI)**
  in non-federal systems; the basis for **CMMC** in the US defense supply chain.
- **Use them for:** US government systems, federal contracting, and the defense
  industrial base.

---

## How They Relate

They overlap far more than they differ - all require access control, logging,
encryption, vulnerability management, and incident response. Practical guidance:

- Choose **one backbone** (commonly NIST CSF 2.0 or ISO 27001).
- Implement the **technical controls once** (see this repo's technical sections).
- **Map** them to every framework you must satisfy (see
  [Control Mapping](README.md#-control-mapping-do-it-once-satisfy-many)).

| Control area | CSF 2.0 | ISO 27001:2022 | SOC 2 | PCI DSS 4.0.1 |
|--------------|---------|-----------------|-------|----------------|
| Access control / MFA | PR.AA | A.5.15-.18, A.8.2-.5 | CC6 | Req. 7, 8 |
| Logging & monitoring | DE.CM | A.8.15, A.8.16 | CC7 | Req. 10 |
| Encryption | PR.DS | A.8.24 | CC6 | Req. 3, 4 |
| Vulnerability mgmt | ID.RA / PR.PS | A.8.8 | CC7 | Req. 6, 11 |
| Incident response | RS / RC | A.5.24-.28 | CC7 | Req. 12.10 |

*Mappings are indicative; use an authoritative crosswalk (NIST OLIR, SCF) for audit work.*

---

## 📚 Resources

- [NIST CSF 2.0 (final)](https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final)
- [ISO/IEC 27001](https://www.iso.org/standard/27001)
- [AICPA SOC 2 / Trust Services Criteria](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
- [PCI DSS Document Library](https://www.pcisecuritystandards.org/document_library/)
- [CIS Controls](https://www.cisecurity.org/controls)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) / [SP 800-171](https://csrc.nist.gov/pubs/sp/800/171/r3/final)
- [NIST OLIR crosswalks](https://csrc.nist.gov/projects/olir)

---

## Related Files
- [README.md](README.md) - Compliance & GRC section index
- [regulations.md](regulations.md) - data-protection regulations
- [../IncidentResponse/SIEM/README.md](../IncidentResponse/SIEM/README.md) - logging/monitoring controls (CSF Detect, PCI Req. 10)
