# 🧳 Field/OTG CybSec Audit Cyberdeck: Reference Edition

<div align="center">

**Portable Network Security Assessment & Evidence Workflow**

*Public documentation & offline reference utility*

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md) by Pacific Northwest Computers*

![Architecture](https://img.shields.io/badge/Architecture-GL.iNet_%7C_MikroTik_%7C_Mini_PC-blue?style=for-the-badge)
![Workflow](https://img.shields.io/badge/Workflow-Authorization_%7C_Evidence-green?style=for-the-badge)
![Edition](https://img.shields.io/badge/Edition-Public_Reference_Only-orange?style=for-the-badge)

</div>

**Navigate:** [Main Guide](../README.md) · [Start Here](../START_HERE.md) · [Ultimate](../ultimate_cybersecurity_master_guide.md) · [Enhanced](../ENHANCED_MASTER_GUIDE.md) · [Specialized Topics](../SPECIALIZED_TOPICS_GUIDE.md) · [All Documentation](../DOCUMENTATION_INDEX.md).

> **Publication boundary:** This is a deliberately limited, independently readable public companion to a separate **private, proprietary** PNWC Cyberdeck prototype. It is **not** a copy of the private repository, a release of its local operator portal, a working penetration-testing appliance, or an offer of production-ready automation.

## Start Here

| Resource | What It Provides |
| --- | --- |
| [Build & Operations Runbook](docs/BUILD_AND_OPERATIONS.md) | Minimum build, zone policy worksheet, bring-up, field closeout and troubleshooting |
| [Acceptance & Qualification Matrix](docs/ACCEPTANCE_TESTS.md) | Measurable lab and field readiness gates without unverified hardware claims |
| [Public-to-Private Implementation Roadmap](docs/IMPLEMENTATION_ROADMAP.md) | Milestones, private data contracts and completion criteria for expanding your own setup |
| [Architecture & Network Zones](docs/ARCHITECTURE.md) | Portable layout, GL.iNet/MikroTik boundary and visibility limitations |
| [Assessment Workflow](docs/ASSESSMENT_WORKFLOW.md) | Authorization-first staged field process and example engagement profiles |
| [Evidence, Privacy & Custody](docs/EVIDENCE_AND_PRIVACY.md) | Local evidence handling, hashes, redaction, retention and limits |
| [Hardware & Feature Status](docs/HARDWARE_AND_STATUS.md) | What the private prototype reports as implemented versus planned, and what is actually in this public edition |
| [Publication Scope & Release Checklist](docs/PUBLISHING_AND_RELEASE.md) | Safe public/private boundaries, license questions, and standalone-repo handoff |
| [Example Engagement Plan](templates/ENGAGEMENT_PLAN.example.md) | Fictional, editable scope and preflight outline; **not a signed authorization or legal agreement** |
| [Example Evidence Record](templates/EVIDENCE_RECORD.example.json) | Synthetic metadata illustrating a single evidence entry |
| [Offline Evidence Manifest Tool](tools/evidence_manifest.py) | Standard-library Python script to hash an already collected local evidence folder |
| [Offline Manifest Verification](tools/verify_manifest.py) | Detect added, missing or changed regular files against a protected saved baseline |
| [Qualification Record](templates/QUALIFICATION_RECORD.example.md) | Record actual hardware, procedure, result, evidence and reviewer |
| [Assessment Report Template](templates/ASSESSMENT_REPORT.example.md) | Coverage, findings, limitations, delivery and retest structure |
| [Generator Tests](tests/test_evidence_manifest.py) · [Verifier Tests](tests/test_verify_manifest.py) | Offline hashing, comparison, malformed baselines and output safeguards |

## Use This Reference to Build Your Private Setup

Follow the [implementation roadmap](docs/IMPLEMENTATION_ROADMAP.md) to connect public design requirements to private implementation work. Start with inventory, reliable evidence handling and a complete manual synthetic case; qualify segmentation before adding supervised integrations. Keep actual configurations, application code and case data in your private environment.

The public reference includes operational worksheets and offline integrity tools. Hardware readiness and private prototype completion require actual [qualification records](templates/QUALIFICATION_RECORD.example.md); documentation alone does not complete those gates.

## Project Concept

A portable cyberdeck can combine an operator workstation, an upstream connectivity router, a downstream segmentation firewall, a local evidence vault and optional manual/specialist collection devices. The guiding principle is **method-first, consent-first, evidence-first**: establish precisely what is authorized, choose a bounded procedure, record what actually happened, and independently review findings.

```text
                   Approved upstream connection
                               |
                     GL.iNet (WISP / router)
                               |
                     MikroTik (routed policy)
                         /       |       \
                MGMT zone    SENSOR     LAB zone
                Operator     Evidence   Isolated validation
                workstation  storage    systems
                               |
                         Local evidence import
                               |
                  Human review & client report

        Separate offsite observation origin: PLANNED, NOT PROVIDED
        Client network test interface: ONLY WITH WRITTEN AUTHORIZATION
```

This is a **logical reference topology**, not an assertion that any user's GL.iNet, MikroTik, ZimaBoard or downstream interfaces have been configured, hardened, wired or validated. A router only controls traffic that traverses it; an unmanaged switch does not magically give a passive sensor all network traffic.

## Typical Field Sequence

| Stage | Outcome | Gate |
| --- | --- | --- |
| 1. Intake & Written Authorization | Named owner, assets, vantage points, windows, exclusions, contacts and permitted methods | Reviewed and accepted scope before active tests |
| 2. Outside-In Observation | Manual review from a genuinely separate approved source | External runner is **not** included in this edition |
| 3. Onsite Wired Network Review | Authorized host/service inventory, config checks and zone visibility | No implied permission from physical access |
| 4. Controlled Resilience Review | Optional benign canary/segmentation/detection validation | Separate exact methods and observer approval |
| 5. Wireless/Hardware Review | Passive, source-attributed observations where lawful and approved | Device firmware and RF limitations documented |
| 6. Evidence & Findings | Local copies, SHA-256 hashes, observed-versus-inferred labeling | Human analysis and privacy review |
| 7. Report & Close | Limitations, actionable remediation and planned retest | Secure delivery, equipment removal and retention review |

**Scope limitation:** The underlying private prototype focuses on network and infrastructure assessment, not web-app/API exploitation. A short field engagement is not a comprehensive penetration test or a security guarantee.

## Try The Offline Helper

Python 3.10+ is sufficient; no third-party packages, network access, target discovery or special hardware are needed.

From the root of the main Guide repository:

```bash
python Cyberdeck/tools/evidence_manifest.py \
  --input Cyberdeck/examples/synthetic-evidence \
  --output /tmp/pnwc-demo-evidence-manifest.json
python Cyberdeck/tools/verify_manifest.py \
  --input Cyberdeck/examples/synthetic-evidence \
  --manifest /tmp/pnwc-demo-evidence-manifest.json
python -m unittest discover -s Cyberdeck/tests -v
```

On Windows, replace the output destination with a folder you control, for example `$env:TEMP\pnwc-demo-evidence-manifest.json`, and run Python with `py -3` if appropriate. The tool only **reads existing local files** and writes a JSON manifest to a separate destination. It does not scan a network, capture traffic, sign manifests or establish a custody chain on its own.

Never put client data, case folders, credentials, signed authorization forms or real assessment exports into Git. Use an approved encrypted location **outside** this checkout.

## What Is And Is Not Published

| Included In This Public Edition | Intentionally Not Published |
| --- | --- |
| Sanitized conceptual topology and documented security boundaries | Private Python operator portal and workflow engine |
| Generic phased assessment and reporting workflow | Live customer records, scopes, signing packets and evidence |
| Fictional template examples and a harmless offline SHA-256 utility | Authentication tokens, service endpoints, VPN/router configs or credentials |
| Hardware categories, integration caveats and staged roadmap | Proprietary deployment scripts, internal SOPs, vendor-connection details and unreviewed implementations |

**Current status:** The separate private prototype has a localhost dashboard, engagement records, bounded authorized single-target Nmap functions, manual device-export intake and draft reports. Wider device automation, public-vantage scanning, real e-sign verification and validated encrypted evidence-vault deployment are not completed by publication of this reference.

## Related Guides

| Topic | Reference |
| --- | --- |
| Lab isolation and traffic visibility | [Homelab](../Homelab/README.md) |
| Engagement assessment process | [Assessment Service Integration](../PlayBooks/assessment-service-integration-map.md) |
| Authorized network audit | [Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md) |
| Wireless surveying | [Wardriving](../Wardriving/README.md) |
| Hardware and firmware references | [Hardware Hacking](../HardwareHacking/README.md) |
| Defensive monitoring | [IDS & IPS](../IncidentResponse/IDS%26IPS/readme.md) |
| Operating and legal terms for the parent guide | [Legal Terms](../LEGAL.md) |

Copyright © 2026 Pacific Northwest Computers. This public reference has **no separately granted open-source license**; visibility on GitHub must not be mistaken for permission to redistribute proprietary private project materials. See [publication notes](docs/PUBLISHING_AND_RELEASE.md).
