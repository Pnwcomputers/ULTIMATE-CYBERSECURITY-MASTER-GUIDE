<a id="diagram-and-image-asset-index"></a>
# Diagram & Image Asset Index

_Last reviewed: 2026-11-02 (repository path and placement review; visual content not re-authenticated against live equipment)_

Return to [the main guide](../README.md) or [the visual reference notes](./imageplacement.md).

This folder stores diagrams as shared assets. Embed them in the **topic guide where they clarify a specific procedure** rather than repeating the same figure across multiple unrelated README pages. Captions should identify a diagram as conceptual when it does not describe a validated PNWC deployment.

## SDR Fundamentals Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [sdr fundamentals evidence ladder](./diagrams/sdr-fundamentals-evidence-ladder.svg) | [Guide](../SDR/sdr.md) |
| [sdr fundamentals receiver rate accounting](./diagrams/sdr-fundamentals-receiver-rate-accounting.svg) | [Guide](../SDR/sdr.md) |
| [sdr fundamentals iq coordinates](./diagrams/sdr-fundamentals-iq-coordinates.svg) | [Guide](../SDR/sdr.md) |
| [sdr fundamentals receiver boundaries](./diagrams/sdr-fundamentals-receiver-boundaries.svg) | [Guide](../SDR/sdr.md) |
| [sdr fundamentals rate bandwidth](./diagrams/sdr-fundamentals-rate-bandwidth.svg) | [Guide](../SDR/sdr.md) |

<a id="integrated-png-and-svg-diagrams"></a>
## Integrated Png & Svg Diagrams

| Image | Used in | Explanation |
|---|---|---|
| [AD attack paths](./ad_attack_paths.png) | [AD attacks and defenses](../Tradecraft/active-directory.md#kerberos-attacks) | Kerberos and AD risk-path illustration |
| [AI agent architecture](./ai_agent_arch.png) | [AI section](../AI/README.md) | Conceptual file-system-first agent/tool boundaries |
| [Hardware diagnostics](./hardware_diagnostics.png) | [Hardware Testing](../HardwareTesting/README.md) | Reference board-level diagnostic workflow |
| [Network architecture](./network_security_arch.png) | [Homelab](../Homelab/README.md) | Example segmented design, not a verified live topology |
| [RAM versus storage](./ram_vs_storage.png) | [Manjaro test bench](../HardwareTesting/Manjaro_Intel_TestBench.md#5-memory-and-storage-diagnostics) | Introductory CPU/RAM/storage mental model |
| [VM compartmentalization](./vm_compartmentalization.png) | [OPSEC guide](../OPSEC/README.md#principles) | Boundary illustration with important host/guest limitations |
| [Wireless auditing](./wireless_auditing.png) | [Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md#section-2-wireless-specific-testing-procedures) | Wireless engagement workflow |
| [Penetration-test lifecycle](./pentest_lifecycle.png) | [Playbooks](../PlayBooks/README.md) | Assessment lifecycle overview |
| [JWrapper abuse case study](./jwrapper_attack.png) | [Incident Response](../IncidentResponse/README.md) | Illustrative remote-access-software abuse path, not proof of infection |
| [FIDO2 / passkey authentication](./fido2-passkey-authentication-flow.svg) | [Hardware keys and passkeys](../Cryptography/security-keys-passkeys.md#what-is-a-security-key) | **New accessible vector figure**, showing registration and sign-in |
| [Encrypted storage boundaries](./encrypted-storage-protection-boundaries.svg) | [Encrypted storage](../Cryptography/encrypted-storage.md#choose-the-right-design) | **New accessible vector figure**, locked versus unlocked data and backup limitations |
| [Journalist source-data lifecycle](./journalist-source-data-lifecycle.svg) | [Press freedom / source protection](../OPSEC/press-freedom/README.md#mission) | **New accessible vector figure**, preservation holds and approved disposition |

## HackRF Guide Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [hackrf guide iq representations](./diagrams/hackrf-guide-iq-representations.svg) | [Guide](../SDR/hackrf.md) |
| [hackrf guide passband vs span](./diagrams/hackrf-guide-passband-vs-span.svg) | [Guide](../SDR/hackrf.md) |
| [hackrf guide sweep coverage](./diagrams/hackrf-guide-sweep-coverage.svg) | [Guide](../SDR/hackrf.md) |
| [hackrf guide evidence ladder](./diagrams/hackrf-guide-evidence-ladder.svg) | [Guide](../SDR/hackrf.md) |
| [hackrf guide bench observation](./diagrams/hackrf-guide-bench-observation.svg) | [Guide](../SDR/hackrf.md) |

## Expanded Topical Svg Diagrams (November 2026)

These 19 newly authored diagrams provide short conceptual overviews beside the relevant guide sections. Each SVG contains a built-in title and description, uses local fonts and shapes only, and deliberately avoids asserting that a particular device, network or lab was tested.

| Diagram | Embedded guide | Purpose |
|---|---|---|
| [SIEM telemetry correlation](./diagrams/siem-telemetry-correlation.svg) | [IncidentResponse/SIEM/README.md](../IncidentResponse/SIEM/README.md) | Collect, normalize, correlate and validate events |
| [Honeypot sensor isolation](./diagrams/honeypot-segmented-logging.svg) | [IncidentResponse/HoneyPot/readme.md](../IncidentResponse/HoneyPot/readme.md) | Decoy isolation, log ingestion and safe triage |
| [Cloud shared responsibility](./diagrams/cloud-shared-responsibility.svg) | [Cloud/README.md](../Cloud/README.md) | Provider/customer security responsibilities |
| [Container trust boundaries](./diagrams/container-security-boundaries.svg) | [ContainerSecurity/README.md](../ContainerSecurity/README.md) | Supply chain and shared-kernel risks |
| [DFIR evidence lifecycle](./diagrams/dfir-evidence-custody.svg) | [IncidentResponse/Digital-Forensics/README.md](../IncidentResponse/Digital-Forensics/README.md) | Authorize, collect, verify, analyze and preserve |
| [OSINT verification](./diagrams/osint-verification-workflow.svg) | [OSINT/README.md](../OSINT/README.md) | Scope, corroborate, protect sources and report |
| [Wireless IDS correlation](./diagrams/wireless-ids-correlation.svg) | [IncidentResponse/IDS&IPS/readme.md](../IncidentResponse/IDS&IPS/readme.md) | Kismet/nzyme event correlation and evidence checks |
| [Web application testing](./diagrams/webapp-assessment-cycle.svg) | [WebAppSecurity/README.md](../WebAppSecurity/README.md) | Scope through retest with safe validation |
| [GRC control evidence](./diagrams/grc-controls-evidence.svg) | [Compliance/README.md](../Compliance/README.md) | Risk, mapping, control implementation and testing |
| [Reverse engineering](./diagrams/reverse-engineering-workflow.svg) | [ReverseEngineering/README.md](../ReverseEngineering/README.md) | Sample intake to defensible findings |
| [Space system segments](./diagrams/space-security-segments.svg) | [SpaceSecurity/README.md](../SpaceSecurity/README.md) | Ground, comms, spacecraft and user trust boundaries |
| [Wardriving data handling](./diagrams/wardriving-collection-lifecycle.svg) | [Wardriving/README.md](../Wardriving/README.md) | Passive survey quality, privacy and disclosure |
| [Data pipeline reliability](./diagrams/data-pipeline-reliability.svg) | [Data-Engineering/Phase2/README.md](../Data-Engineering/Phase2/README.md) | Contract, transformations, security and replay |
| [NanoVNA calibration](./diagrams/nanovna-calibration-plane.svg) | [SDR/nanovna/README.md](../SDR/nanovna/README.md) | Measurement reference plane and uncertainty |
| [Mobile security layers](./diagrams/mobile-security-boundaries.svg) | [Mobile/README.md](../Mobile/README.md) | Device, account, app, network and backups |
| [Incident response stages](./diagrams/incident-response-cycle.svg) | [IncidentResponse/README.md](../IncidentResponse/README.md) | Preparation through recovery and improvement |
| [Assessment checklist lifecycle](./diagrams/checklist-assessment-quality.svg) | [Checklists](../Checklists/README.md) | Authorization, coverage, evidence, QA and closure |
| [Safe script execution](./diagrams/safe-script-execution.svg) | [Scripts](../Scripts/README.md) | Code review, scope approval, rollback and results |
| [uConsole cautious setup](./diagrams/uconsole-six-phase-setup.svg) | [uConsole](../uConsole/README.md) | Model-aware, opt-in six-phase CM5 workflow |

## Kubernetes Security Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [kubernetes security control boundaries](./diagrams/kubernetes-security-control-boundaries.svg) | [Guide](../ContainerSecurity/kubernetes.md) |
| [kubernetes security secret lifecycle](./diagrams/kubernetes-security-secret-lifecycle.svg) | [Guide](../ContainerSecurity/kubernetes.md) |
| [kubernetes security network policy directions](./diagrams/kubernetes-security-network-policy-directions.svg) | [Guide](../ContainerSecurity/kubernetes.md) |

For an auditable record of the visual coverage review and remaining improvements, see [Visual Audit — 2026-11-02](./VISUAL-AUDIT-2026-11-02.md).

## Advanced SDR Research Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [advanced sdr lorawan security roles](./diagrams/advanced-sdr-lorawan-security-roles.svg) | [Guide](../SDR/sdr_hacking.md) |
| [advanced sdr dsp branching](./diagrams/advanced-sdr-dsp-branching.svg) | [Guide](../SDR/sdr_hacking.md) |
| [advanced sdr em inference](./diagrams/advanced-sdr-em-inference.svg) | [Guide](../SDR/sdr_hacking.md) |
| [advanced sdr evidence ladder](./diagrams/advanced-sdr-evidence-ladder.svg) | [Guide](../SDR/sdr_hacking.md) |

## Already Embedded In Hardware Chapters

| Asset | Chapter |
|---|---|
| [Trust boundary](./CollapsingtheTrustBoundary.jpg) | [Hardware Hacking — Chapter 1](../HardwareHacking/Chapter1.md) |
| [UART](./UART.jpg), [SPI](./SPI.jpg), [I²C](./i2c.jpg), [JTAG](./JTAG.jpg), [Shunt setup](./ShuntSetup.jpg) | [Hardware Hacking — Chapter 2](../HardwareHacking/Chapter2.md) |
| [Clock/voltage glitch](./ClockvsVoltage.jpg), [EMFI](./ElectromagneticFaultInjection.jpg), [Laser FI](./LaserFaultInjection.jpg) | [Hardware Hacking — Chapter 3](../HardwareHacking/Chapter3.md) |
| [SPA on RSA](./SPAonRSA.jpg) | [Hardware Hacking — Chapter 4](../HardwareHacking/Chapter4.md) |
| [CPA correlation](./CPACorrelationProcess.jpg) | [Hardware Hacking — Chapter 5](../HardwareHacking/Chapter5.md) |
| [Master guide banner](./cybersecurityguide.png) | [Master README](../README.md) and [START HERE](../START_HERE.md) |

## AWS Security Guide Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [aws request policy evaluation](./diagrams/aws-request-policy-evaluation.svg) | [Guide](../Cloud/aws.md) |
| [aws s3 independent controls](./diagrams/aws-s3-independent-controls.svg) | [Guide](../Cloud/aws.md) |
| [aws imdsv2 token boundary](./diagrams/aws-imdsv2-token-boundary.svg) | [Guide](../Cloud/aws.md) |

## Xerox DocuColor Case Study Visuals

Embedded in the [Xerox DocuColor case study](../CaseStudies/hardware/xerox-docucolor-machine-identification-code.md).

| Asset | Purpose and provenance |
|---|---|
| [Printer dots](./printerdots.jpg) | Owner-supplied illustrative introduction; not authenticated as a physical capture. |
| [MIC overview](./printerdotsbasic%20breakdown.jpg) | Owner-supplied conceptual breakdown; caption explains layout and lighting limitations. |
| [DocuColor grid](./diagrams/xerox-docucolor-grid.svg) | Original synthetic grid and minute-decoding example based on EFF's format. |
| [Evidence workflow](./diagrams/xerox-docucolor-evidence-flow.svg) | Original conceptual preservation, observation, decoding, and corroboration workflow. |

## GCP Security Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [gcp security policy inheritance](./diagrams/gcp-security-policy-inheritance.svg) | [Guide](../Cloud/gcp.md) |
| [gcp security audit coverage](./diagrams/gcp-security-audit-coverage.svg) | [Guide](../Cloud/gcp.md) |
| [gcp security service account routes](./diagrams/gcp-security-service-account-routes.svg) | [Guide](../Cloud/gcp.md) |

## Argus Recon Toolkit Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [argus osint module scope](./diagrams/argus-osint-module-scope.svg) | [Guide](../OSINT/argus_osint.md) |
| [argus osint environment selection](./diagrams/argus-osint-environment-selection.svg) | [Guide](../OSINT/argus_osint.md) |

## Historical Case Study Diagrams

These twelve original static vector diagrams explain mechanisms and evidence limits
in the other case studies. They contain no measured traces or reproduced exploit
results. Each figure has an accessible title and description; source links and
provenance appear in its embedding caption.

| Diagram | Embedded Analysis |
|---|---|
| [onity maintenance trust boundary](./diagrams/onity-maintenance-trust-boundary.svg) | [onity-locks-2012](../CaseStudies/hardware/onity-locks-2012.md) |
| [unsaflok system trust chain](./diagrams/unsaflok-system-trust-chain.svg) | [unsaflok-3m-hotel-locks](../CaseStudies/hardware/unsaflok-3m-hotel-locks.md) |
| [tesla dst40 cloning vs relay](./diagrams/tesla-dst40-cloning-vs-relay.svg) | [tesla-model-s-key-fob-2018](../CaseStudies/hardware/tesla-model-s-key-fob-2018.md) |
| [eucleak intended output vs em leakage](./diagrams/eucleak-intended-output-vs-em-leakage.svg) | [eucleak-yubikey-2024](../CaseStudies/hardware/eucleak-yubikey-2024.md) |
| [directv dss authorization boundary](./diagrams/directv-dss-authorization-boundary.svg) | [directv-dss-smart-card-black-sunday](../CaseStudies/hardware/directv-dss-smart-card-black-sunday.md) |
| [Stuxnet Analysis](./diagrams/stuxnet-it-to-physical-process.svg) | [Enhanced Master Guide](../ENHANCED_MASTER_GUIDE.md#stuxnet-analysis) |
| [WannaCry Breakdown](./diagrams/wannacry-worm-and-ransomware.svg) | [Enhanced Master Guide](../ENHANCED_MASTER_GUIDE.md#wannacry-breakdown) |
| [EternalBlue Exploitation](./diagrams/eternalblue-vulnerability-exploit-payload.svg) | [Enhanced Master Guide](../ENHANCED_MASTER_GUIDE.md#eternalblue-exploitation) |
| [SolarWinds Attack](./diagrams/solarwinds-update-trust-and-follow-on.svg) | [Enhanced Master Guide](../ENHANCED_MASTER_GUIDE.md#solarwinds-attack) |
| [Carbanak APT Campaign](./diagrams/carbanak-intrusion-to-financial-fraud.svg) | [Enhanced Master Guide](../ENHANCED_MASTER_GUIDE.md#carbanak-apt-campaign) |
| [NotPetya Ransomware](./diagrams/notpetya-parallel-propagation-paths.svg) | [Enhanced Master Guide](../ENHANCED_MASTER_GUIDE.md#notpetya-ransomware) |
| [Edward Snowden Revelations](./diagrams/snowden-prism-vs-upstream.svg) | [Enhanced Master Guide](../ENHANCED_MASTER_GUIDE.md#edward-snowden-revelations) |

## Azure And Entra Security Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [azure security rbac scope](./diagrams/azure-security-rbac-scope.svg) | [Guide](../Cloud/azure.md) |
| [azure security logging coverage](./diagrams/azure-security-logging-coverage.svg) | [Guide](../Cloud/azure.md) |
| [azure security role planes](./diagrams/azure-security-role-planes.svg) | [Guide](../Cloud/azure.md) |

## RFID & NFC Guide Visuals

Original conceptual diagrams embedded in the [RFID & NFC guide](../SDR/rfid.md).
Captions link primary technical references; no device testing or measured RF
data is claimed.

| Diagram | What It Explains |
|---|---|
| [Passive HF coupling](./diagrams/nfc-passive-tag-coupling.svg) | Reader energy, commands, and tag load modulation. |
| [Identification, authentication, authorization](./diagrams/rfid-identification-authentication-authorization.svg) | Why an identifier is only one part of a credential system. |
| [Band and reader map](./diagrams/rfid-band-and-reader-map.svg) | LF, HF/NFC, and the separate UHF reader ecosystem. |
| [Read troubleshooting](./diagrams/rfid-read-troubleshooting-evidence.svg) | Compatibility checks, controlled observations, and defensible conclusions. |

## Container Security Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [container security image runtime host](./diagrams/container-security-image-runtime-host.svg) | [Guide](../ContainerSecurity/containers.md) |
| [container security isolation controls](./diagrams/container-security-isolation-controls.svg) | [Guide](../ContainerSecurity/containers.md) |
| [container security secrets lifecycle](./diagrams/container-security-secrets-lifecycle.svg) | [Guide](../ContainerSecurity/containers.md) |

## Sub-GHz RF Guide Visuals

Five original conceptual diagrams embedded in the [Sub-GHz RF guide](../SDR/subghz.md).
The waveform and packet examples are synthetic, not captured signals. Each caption
identifies its source context and evidence limits.

| Diagram | What It Explains |
|---|---|
| [OOK versus FSK](./diagrams/subghz-ook-vs-fsk.svg) | Amplitude-envelope versus frequency-state signaling. |
| [Fixed versus stateful validation](./diagrams/subghz-fixed-vs-stateful-validation.svg) | Why repeated or changing messages do not alone establish replay security. |
| [IQ to evidence](./diagrams/subghz-iq-to-evidence.svg) | Capture, metadata, working-copy processing, and interpretation. |
| [Capture quality](./diagrams/subghz-capture-quality.svg) | Schematic clipping and the limits of visual diagnosis. |
| [Frame inference](./diagrams/subghz-frame-inference.svg) | Distinguishing repeated/changing regions from verified field meanings. |

## Microsoft 365 Assessment Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [scuba configuration assessment](./diagrams/scuba-configuration-assessment.svg) | [Guide](../Cloud/m365-scuba-assessment.md) |
| [scuba findings to controlled change](./diagrams/scuba-findings-to-controlled-change.svg) | [Guide](../Cloud/m365-scuba-assessment.md) |

## Additional Asset Awaiting Placement

- [advnacedflows.jpg](./advnacedflows.jpg) — a large image with an ambiguous filename. **Not embedded automatically** because its intended subject has not been visually verified; avoid mismatched or misleading placement. Review the image and rename or document its subject before assigning it.

## rtl_433 Telemetry Lab Visuals

Two original conceptual figures embedded in the [receive-only telemetry lab](../SDR/rtl433-passive-telemetry-lab.md).

| Diagram | Purpose |
|---|---|
| [Decoder to collector](./diagrams/rtl433-decoder-to-collector.svg) | Separate native decoder output, normalization and collector validation. |
| [Alert evidence limits](./diagrams/rtl433-alert-evidence-limits.svg) | Investigate benign alternatives and corroborate anomalies. |

These illustrate a proposed lab; no live sensor data or deployed detection results are claimed.

## Image Guidelines

1. Use a **relative path from the embedding Markdown file**; for a root-level page use `./assets/image.png`, for a one-level-deep section use `../assets/image.png`, and for a two-level-deep section use `../../assets/image.svg`.
2. Provide meaningful Markdown alt text and a short caption, including whether the image is *conceptual* or based on verified deployment/test data.
3. Avoid claiming an illustration proves encryption security, exploitability, network isolation, or real-world device behavior.
4. Keep SVG assets static: no script, animation, external fonts or third-party image dependencies. Preserve the embedded `title` and `desc` for accessibility.
5. When an image is superseded, update all backlinks and run repository lint/link checks. Maintain this table.

---

[Master README](../README.md) | [Role Navigation](../START_HERE.md) | [Visual reference notes](./imageplacement.md)
