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

- **Applies to:** processing in the context of a controller's or processor's
  establishment in the Union, regardless of where the processing occurs. For an
  entity without a Union establishment, Article 3 can also apply when processing
  relates to offering goods or services to people in the Union or monitoring
  their behavior there. A person's EU residence or data location alone does not
  decide territorial scope; assess the Article 3 criteria.
- **Key principles:** lawfulness, purpose limitation, data minimization, accuracy,
  storage limitation, integrity/confidentiality, and accountability.
- **Data-subject rights:** access, rectification, erasure ("right to be forgotten"),
  portability, and objection.
- **Security duty:** "appropriate technical and organizational measures" (Art. 32) -
  encryption, resilience, testing.
- **Penalties:** Article 83 sets two maximum tiers, depending on the infringement:
  up to **€10 million or 2% of global annual turnover**, and for higher-tier
  infringements up to **€20 million or 4%**, whichever amount is higher. These are
  statutory maxima, not automatic fines; the supervisory authority considers the
  factors in Article 83(2).

---

## HIPAA (US Healthcare)

The US **Health Insurance Portability and Accountability Act** - protects health
information.

- **Applies to:** **covered entities** (providers, health plans, clearinghouses)
  and their **business associates** handling Protected Health Information (PHI).
- **Security Rule:** requires administrative, physical, and technical safeguards for
  electronic PHI (access control, audit controls, integrity, transmission security).
- **Privacy Rule:** governs use and disclosure of PHI.
- **Breach Notification Rule:** applies to breaches of **unsecured PHI**, subject
  to defined exceptions and a risk assessment. Notification duties and timing
  vary by affected population and recipient.
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
- **2025 regulatory package:** The rules took effect January 1, 2026, but
  implementation is phased. Covered businesses begin required risk-assessment
  compliance in 2026; ADMT requirements for significant decisions begin January 1,
  2027; cybersecurity-audit certifications are due on staggered dates from 2028
  through 2030 based on revenue. Coverage, exceptions, reporting dates, and
  transition details depend on the final regulations; verify them with the CPPA
  and counsel. See the [CPPA final rulemaking and timeline](https://cppa.ca.gov/regulations/ccpa_updates)
  and [current regulations](https://cppa.ca.gov/regulations/).
- **Note:** many other US states have since enacted comparable laws - check the
  specific state(s) where your users reside.

---

## Breach Notification (Common Thread)

Nearly every regime requires timely notification after a personal-data breach:

![Distinct GDPR, HIPAA, and state-law breach-notification decision paths with separate triggers, thresholds, exceptions, and evidence records](../assets/diagrams/privacy-breach-notification-decision-path.svg)

*Conceptual triage aid only; it is not a legal decision tool. Confirm the current law, jurisdiction, roles, facts, and deadlines with qualified counsel.*

- **GDPR:** the controller notifies the supervisory authority without undue delay
  and, where feasible, within 72 hours after becoming aware, unless the breach is
  unlikely to result in a risk to people's rights and freedoms. A processor
  notifies the controller without undue delay. Notify individuals without undue
  delay when high risk is likely, subject to Article 34 exceptions.
- **HIPAA:** for a breach of unsecured PHI, apply the rule's exceptions or document
  the required risk assessment. Notify affected individuals without unreasonable
  delay and no later than 60 days after discovery. Notify HHS within 60 days for
  breaches affecting 500 or more individuals; breaches affecting fewer than 500
  may be reported annually, within 60 days after year-end. Media notice applies
  when more than 500 residents of a state or jurisdiction are affected.
  Business associates notify the covered entity without unreasonable delay and
  no later than 60 days after discovery.
- **US state laws:** triggers, deadlines, thresholds, and recipients vary by
  jurisdiction; CCPA/CPRA duties and other state breach laws should be assessed
  separately.

There is no universal breach-notification clock: GDPR uses awareness, HIPAA uses
discovery, and state laws set their own triggers. Preserve a timeline of discovery
or awareness, data types, affected people, risk findings, notices, and the
rationale for each decision. See [IncidentResponse](../IncidentResponse/README.md).

---

## What This Means for Security

Regulations rarely prescribe specific technology, but consistently drive the same
controls:

- **Data inventory & classification** - you must know what personal data you hold.
- **Access control & MFA** - limit who can reach regulated data.
- **Encryption** - in transit and at rest. Encryption changes a notification
  outcome only when the applicable law's conditions are met; GDPR Article 34 has
  defined exceptions to individual communication, and HIPAA's breach rule applies
  to PHI not rendered unusable, unreadable, or indecipherable under HHS guidance.
- **Logging & monitoring** - to detect and evidence incidents within notification windows.
- **Incident response** - a tested plan that meets the notification clocks.
- **Data minimization & retention** - collect and keep less.

Implement these once (see the technical sections of this repo) and map them to each
applicable regulation and framework - see
[Control Mapping](README.md#-control-mapping-do-it-once-satisfy-many).

---

## 📚 Resources

- [GDPR - official text (EUR-Lex)](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [HHS Breach Notification Rule](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html)
- [California CCPA (OAG)](https://oag.ca.gov/privacy/ccpa)
- [California Privacy Protection Agency regulations](https://cppa.ca.gov/regulations/)
- [CPPA 2025 CCPA updates](https://cppa.ca.gov/regulations/ccpa_updates)

---

## Related Files
- [README.md](README.md) - Compliance & GRC section index
- [frameworks.md](frameworks.md) - security control frameworks
- [../IncidentResponse/README.md](../IncidentResponse/README.md) - detection & response that breach-notification duties require
