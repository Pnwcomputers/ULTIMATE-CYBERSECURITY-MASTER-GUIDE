# ⚖️ Data-Protection Regulations

> [!IMPORTANT]
> Educational reference, **not** legal advice. Regulatory thresholds, definitions,
> and penalties change and depend on jurisdiction, industry, and the data involved.
> Consult qualified legal counsel for your specific situation. See the
> [section notice](README.md#-important-notice).

## 🎯 Purpose
A practitioner's orientation to the major data-protection regulations - who they
apply to, what they require, and their breach-notification duties.

## ⚙️ Function
Covers GDPR (EU/EEA), HIPAA (US healthcare), and CCPA/CPRA (California), plus the
common thread of breach notification, at the level a security practitioner needs
to know when they apply and what controls they drive.

## 🏆 Goal
Let a reader recognize which regulation applies to a given system or dataset and
what security obligations follow - then route to counsel for specifics.

## 📋 When to Use
- Determining whether a regulation applies to a system or dataset
- Understanding the security controls a regulation implies
- Preparing breach-notification readiness

---

## 📋 Table of Contents

- [GDPR (EU/EEA)](#gdpr-eueea)
- [HIPAA (US Healthcare)](#hipaa-us-healthcare)
- [CCPA / CPRA (California)](#ccpa--cpra-california)
- [Breach Notification (Common Thread)](#breach-notification-common-thread)
- [What This Means for Security](#what-this-means-for-security)
- [Resources](#-resources)

---

## GDPR (EU/EEA)

The EU **General Data Protection Regulation** - the most influential privacy law
globally.

- **Applies to:** any organization processing the personal data of people in the
  EU/EEA, **regardless of where the organization is** (extraterritorial).
- **Key principles:** lawfulness, purpose limitation, data minimization, accuracy,
  storage limitation, integrity/confidentiality, and accountability.
- **Data-subject rights:** access, rectification, erasure ("right to be forgotten"),
  portability, and objection.
- **Security duty:** "appropriate technical and organizational measures" (Art. 32) -
  encryption, resilience, testing.
- **Penalties:** up to **€20 million or 4% of global annual turnover**, whichever
  is higher.

---

## HIPAA (US Healthcare)

The US **Health Insurance Portability and Accountability Act** - protects health
information.

- **Applies to:** **covered entities** (providers, health plans, clearinghouses)
  and their **business associates** handling Protected Health Information (PHI).
- **Security Rule:** requires administrative, physical, and technical safeguards for
  electronic PHI (access control, audit controls, integrity, transmission security).
- **Privacy Rule:** governs use and disclosure of PHI.
- **Breach Notification Rule:** notify affected individuals, HHS, and (for large
  breaches) the media.
- **Penalties:** tiered civil penalties per violation, up to substantial annual caps.

---

## CCPA / CPRA (California)

The **California Consumer Privacy Act**, amended and strengthened by the **California
Privacy Rights Act (CPRA)**.

- **Applies to:** for-profit businesses handling California residents' personal
  information that meet thresholds (revenue, volume of data, or data-selling share).
- **Consumer rights:** know, delete, correct, opt out of sale/sharing, and limit
  use of sensitive personal information.
- **CPRA additions:** a dedicated enforcement agency (CPPA), a "sensitive personal
  information" category, and data-minimization/retention duties.
- **Note:** many other US states have since enacted comparable laws - check the
  specific state(s) where your users reside.

---

## Breach Notification (Common Thread)

Nearly every regime requires timely notification after a personal-data breach:

- **GDPR:** notify the supervisory authority **within 72 hours** of becoming aware
  (where feasible); notify individuals if high risk.
- **HIPAA:** notify without unreasonable delay, and **no later than 60 days**;
  large breaches also require HHS/media notice.
- **US state laws:** timelines and thresholds vary by state.

This makes **detection and logging** (see [IncidentResponse](../IncidentResponse/README.md))
a compliance requirement, not just good practice - you cannot notify about what you
cannot detect, and the clock starts when you become aware.

---

## What This Means for Security

Regulations rarely prescribe specific technology, but consistently drive the same
controls:

- **Data inventory & classification** - you must know what personal data you hold.
- **Access control & MFA** - limit who can reach regulated data.
- **Encryption** - in transit and at rest (often a safe-harbor factor for breaches).
- **Logging & monitoring** - to detect and evidence incidents within notification windows.
- **Incident response** - a tested plan that meets the notification clocks.
- **Data minimization & retention** - collect and keep less.

Implement these once (see the technical sections of this repo) and map them to each
applicable regulation and framework - see
[Control Mapping](README.md#-control-mapping-do-it-once-satisfy-many).

---

## 📚 Resources

- [GDPR - official text (EUR-Lex)](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [HHS HIPAA for Professionals](https://www.hhs.gov/hipaa/for-professionals/index.html)
- [California CCPA (OAG)](https://oag.ca.gov/privacy/ccpa)
- [California Privacy Protection Agency (CPPA)](https://cppa.ca.gov/)

---

## Related Files
- [README.md](README.md) - Compliance & GRC section index
- [frameworks.md](frameworks.md) - security control frameworks
- [../IncidentResponse/README.md](../IncidentResponse/README.md) - detection & response that breach-notification duties require
