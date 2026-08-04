# 📋 Compliance & GRC

<div align="center">

**Governance, Risk, and Compliance - frameworks, regulations, and control mapping**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Focus](https://img.shields.io/badge/Focus-GRC-blue?style=for-the-badge)
![Frameworks](https://img.shields.io/badge/Frameworks-NIST_%7C_ISO_%7C_SOC_2-orange?style=for-the-badge)
![Type](https://img.shields.io/badge/Type-Governance-green?style=for-the-badge)

</div>

---

## 🎯 Purpose
Dedicated home for Governance, Risk, and Compliance - the major security control
frameworks, the data-protection regulations, and a practical approach to mapping
one set of controls to many requirements.

## ⚙️ Function
Indexes the Compliance & GRC section: GRC fundamentals and a control-mapping
approach (this file), the major control frameworks (NIST CSF 2.0, ISO/IEC
27001:2022, SOC 2, PCI DSS 4.0.1, CIS Controls v8, NIST 800-53/800-171), and the
key data-protection regulations (GDPR, HIPAA, CCPA/CPRA).

## 🏆 Goal
Give practitioners a single reference for which framework applies when, how the
frameworks relate, and how to implement controls once and satisfy multiple
requirements - tying governance back to the technical controls elsewhere in this
repo.

## 📋 When to Use
- Choosing a framework for an organization or a customer requirement
- Preparing for an audit or certification (SOC 2, ISO 27001, PCI DSS)
- Mapping existing technical controls to compliance requirements
- Understanding a data-protection obligation (GDPR/HIPAA/CCPA)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [What GRC Is](#-what-grc-is)
- [Choosing a Framework](#-choosing-a-framework)
- [Control Mapping (Do It Once, Satisfy Many)](#-control-mapping-do-it-once-satisfy-many)
- [Folder Contents](#-folder-contents)
- [Important Notice](#-important-notice)
- [Resources](#-resources)

---

## 🎯 Overview

Compliance is heavily referenced across this repository but previously had no home.
This section consolidates it. The theme throughout: **compliance is the evidence
that good security controls exist and operate** - the technical work lives in the
[IncidentResponse](../IncidentResponse/), [Cloud](../Cloud/),
[WebAppSecurity](../WebAppSecurity/), and [Checklists](../Checklists/) sections;
GRC organizes, requires, and demonstrates it.

---

## 🏛️ What GRC Is

- **Governance** - the policies, roles, and accountability that direct a security
  program (leadership ownership, risk appetite, standards).
- **Risk** - identifying, assessing, and treating risk (accept / mitigate /
  transfer / avoid), usually via a risk register and periodic assessment.
- **Compliance** - demonstrating adherence to chosen frameworks and applicable
  laws/regulations, with evidence.

A framework provides the **control set**; risk management decides **which controls
matter most**; governance ensures they are **owned and maintained**.

---

## 🧭 Choosing a Framework

| If you need to… | Consider |
|-----------------|----------|
| A flexible, risk-based program (US-centric, widely recognized) | **NIST CSF 2.0** |
| An internationally recognized certification | **ISO/IEC 27001:2022** |
| Assure customers/partners of your controls (SaaS/service orgs) | **SOC 2** |
| Handle payment card data | **PCI DSS 4.0.1** (mandatory) |
| A prioritized, prescriptive starting set of controls | **CIS Controls v8** |
| A US federal / government-adjacent baseline | **NIST SP 800-53 / 800-171** |

Details in [frameworks.md](./frameworks.md). Regulatory obligations (GDPR, HIPAA,
CCPA) are **not optional** and apply based on data and jurisdiction - see
[regulations.md](./regulations.md).

---

## 🔗 Control Mapping (Do It Once, Satisfy Many)

The frameworks overlap heavily. Rather than implement each in isolation:

1. **Pick a primary framework** (often NIST CSF 2.0 or ISO 27001) as the backbone.
2. **Implement the underlying technical controls** (MFA, logging, encryption,
   access control, patching) - the substance lives in this repo's technical sections.
3. **Map** those controls to each framework/regulation you must satisfy, so one
   control (e.g. centralized logging) provides evidence for CSF *Detect*, ISO
   *A.8.15/A.8.16*, SOC 2 *CC7*, and PCI *Req. 10* at once.
4. **Collect evidence** continuously (config, logs, tickets) rather than scrambling
   at audit time.

The [Secure Controls Framework (SCF)](https://securecontrolsframework.com/) and
NIST's [OLIR mappings](https://csrc.nist.gov/projects/olir) publish
cross-framework crosswalks to accelerate this.

---

## 📂 Folder Contents

| File | Description | Status |
|------|-------------|--------|
| **[frameworks.md](./frameworks.md)** | Control frameworks - NIST CSF 2.0, ISO 27001:2022, SOC 2, PCI DSS 4.0.1, CIS Controls v8, NIST 800-53/800-171 | ✅ Complete |
| **[regulations.md](./regulations.md)** | Data-protection regulations - GDPR, HIPAA, CCPA/CPRA, and breach-notification duties | ✅ Complete |

---

## ⚠️ Important Notice

> [!IMPORTANT]
> **This is educational reference material, not legal or compliance advice.**
> Framework versions, regulatory thresholds, and applicability change and depend on
> your jurisdiction, industry, and data. Verify against the authoritative source
> and consult qualified legal/compliance counsel and, where required, a qualified
> assessor (e.g. a PCI QSA or ISO certification body) before relying on it.

---

## 📚 Resources

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO/IEC 27001](https://www.iso.org/standard/27001)
- [AICPA SOC 2](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
- [PCI Security Standards Council](https://www.pcisecuritystandards.org/)
- [CIS Controls](https://www.cisecurity.org/controls)
- [Secure Controls Framework (crosswalks)](https://securecontrolsframework.com/)

---

<div align="center">

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

</div>

---

## Related Files
- [frameworks.md](frameworks.md) - Security control frameworks
- [regulations.md](regulations.md) - Data-protection regulations
- [../IncidentResponse/README.md](../IncidentResponse/README.md) - the detection/response controls compliance requires
- [../Checklists/README.md](../Checklists/README.md) - operational checklists that implement controls

---
[⬅️ Back to Master Index](README.md) | [🎯 Role Navigation](START_HERE.md) | [Legal Notice](LEGAL.md)
