<a id="diagram-and-image-asset-index"></a>
# Diagram & Image Asset Index

_Visual placements updated 2026-11-24. Figures show conceptual examples unless their captions identify live evidence._

Return to [the main guide](../README.md) or [the visual reference notes](./imageplacement.md).

This folder stores diagrams as shared assets. Embed them in the **topic guide where they clarify a specific procedure** rather than repeating the same figure across multiple unrelated README pages. Captions should identify a diagram as conceptual when it does not describe a validated PNWC deployment.

## Algorithms & Cryptography Visual Guides

These six original SVG diagrams use descriptive alternative text, avoid external fonts/scripts, and distinguish conceptual examples from validated product implementations.

| Diagram | Embedded Guide & Teaching Goal |
|---|---|
| [Everyday Algorithms → Security](./diagrams/algorithm-families-cybersecurity-map.svg) | [Algorithm index](../Algorithms/README.md): taxonomy, applications and limits |
| [Dijkstra, A*, OSPF & BGP](./diagrams/algorithms-dijkstra-astar-ospf-bgp.svg) | [Routing algorithms](../Algorithms/graphs-and-routing.md): weighted paths and different routing models |
| [Compression, Hashing, Encryption & Signatures](./diagrams/algorithms-compression-hashing-encryption.svg) | [Compression & cryptography](../Algorithms/compression-hashing-and-crypto.md), [crypto parallels](../Algorithms/cryptography-parallels.md): distinct security properties |
| [TLS 1.3 Algorithm Pipeline](./diagrams/algorithms-tls13-cryptographic-pipeline.svg) | [Cryptography parallels](../Algorithms/cryptography-parallels.md), [applied cryptography](../Cryptography/applied-crypto.md): authentication, key agreement, HKDF and record AEAD |
| [Detection & Evaluation](./diagrams/algorithms-detection-evaluation-pipeline.svg) | [Detection algorithms](../Algorithms/detection-and-recommendations.md): sensor visibility, matching, scoring and verification |
| [Search, Indexing & Ranking](./diagrams/algorithms-search-index-ranking.svg) | [Search & indexing](../Algorithms/search-sorting-and-indexing.md): finding candidates versus ranking or validating truth |

## NanoVNA Cable Distance, SWR and Smith Chart Visuals

| Diagram | Embedded guide |
|---|---|
| [Time-domain reflection and one-way distance](./diagrams/nanovna-tdr-reflection-distance.svg) | [NanoVNA cable measurements](../SDR/nanovna/06-cables-filters-other-uses.md#61-tdr--time-domain-reflectometry) |
| [SWR at two reference impedances](./diagrams/nanovna-swr-reference-impedance.svg) | [NanoVNA special cases](../SDR/nanovna/10-antenna-types-and-special-cases.md#105--75-ohm-antennas-on-a-50-ohm-instrument) |
| [50 Ω Smith chart marker positions](./diagrams/nanovna-smith-chart-marker-positions.svg) | [NanoVNA RF fundamentals](../SDR/nanovna/02-rf-fundamentals.md#25-the-smith-chart) |

## Additional Guide Diagrams

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [AUR package review](./diagrams/aur-package-review-build-install.svg) | [Arch Linux cheat sheet](../Documentation/ArchLinux_CheatSheet.md) | Source and build review before installation |
| [Persistence validation safety](./diagrams/authorized-persistence-validation.svg) | [Domain persistence checklist](../Checklists/Domain-Persistence.md), [persistence checklist](../Checklists/Persistence.md) | Authorization, cleanup, and verifying restored state |
| [GreatFET I2C observation](./diagrams/greatfet-authorized-i2c-workflow.svg) | [GreatFET One](../HardwareHacking/GreatFETone.md) | Bus ownership, voltage, and observation gates |
| [Local LLM data paths](./diagrams/local-llm-data-paths.svg) | [Offline LLMs](../AI/offline-llm.md) | Local, remote, and optional network data paths |
| [Marauder firmware selection](./diagrams/marauder-firmware-selection.svg) | [Wi-Fi Marauder guide](../Documentation/WiFiMarauder_Guide.md) | Board compatibility and firmware verification |
| [OPNsense rules and SPAN visibility](./diagrams/opnsense-rules-and-span-visibility.svg) | [Homelab setup](../Homelab/HomeLab_Setup.md) | Distinguishes firewall enforcement from sensor visibility |
| [OSINT evidence publication](./diagrams/osint-evidence-publication-decision.svg) | [OSINT guide](../OSINT/OSINT_GUIDE.md) | Source corroboration and release review |
| [OSINT scope and collection](./diagrams/osint-opsec-scope-decision.svg) | [Linux cheat sheet](../Documentation/LinuxCheatSheet.md), [OSINT index](../OSINT/README.md) | Scope checks and permitted collection |
| [OWASP Top 10 category changes](./diagrams/owasp-top10-2021-to-2025-changes.svg) | [OWASP Top 10](../WebAppSecurity/owasp-top-10.md) | Category changes between editions |
| [PCI DSS scope and validation](./diagrams/pci-dss-scope-and-validation.svg) | [Compliance overview](../Compliance/README.md) | Scope, applicability, and validation evidence |
| [Raspberry Pi onboard Wi-Fi support](./diagrams/raspberry-pi-onboard-wifi-support.svg) | [Specialized Topics](../SPECIALIZED_TOPICS_GUIDE.md), [CM5 setup](../uConsole/CM5-SETUP.md) | Board, chipset, and driver compatibility checks |
| [Space RF testing authorization](./diagrams/space-rf-transmission-authorization-flow.svg) | [Space Security Part I](../SpaceSecurity/PartI.md) | Boundaries for receive-only observation and authorized transmission |
| [Suricata NFQUEUE failure modes](./diagrams/suricata-nfqueue-failure-modes.svg) | [Suricata and Zeek](../IncidentResponse/IDS&IPS/suricata+zeek.md) | Packet handling when the inspection path is unavailable |
| [T48 supported chip reading](./diagrams/t48-supported-chip-read-workflow.svg) | [T48 programmer](../HardwareHacking/T48_TL866-3G.md) | Part identification, voltage, and readback verification |
| [Unicode and IDN risk assessment](./diagrams/unicode-idn-risk-assessment.svg) | [Classical cryptography security](../Cryptography/Classical/security.md) | Interpretation of visual similarity in identifiers |
| [USB-to-UART safe observation](./diagrams/usb-uart-safe-observation.svg) | [BitPirate](../HardwareHacking/BitPirate.md) | Voltage checks and receive-only observation |
| [Passive and active wireless scope](./diagrams/wireless-passive-active-boundary.svg) | [Network audit playbook](../PlayBooks/NetworkAuditPlayBook.md) | Separates passive observations from actions requiring approval |
| [Wireless capture mode boundaries](./diagrams/wifi-capture-mode-boundaries.svg) | [Aircrack-ng commands](../Documentation/Aircrack-ng_Commands.md) | Separates receive-only observation, active radio interactions and offline analysis |
| [MITM path and TLS trust boundaries](./diagrams/mitm-path-and-tls-boundaries.svg) | [MITM detection playbook](../Documentation/mitm-detection-prevention.md#data-integrity--encryption-boundaries) | Shows what an on-path intermediary can observe and the trust failures that expose payloads |

## Evidence Collection and Release Verification

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [Bento evidence media boundaries](./diagrams/bento-live-response-media-boundaries.svg) | [Bento portable DFIR guide](../IncidentResponse/Digital-Forensics/tsurugi-bento-portable-dfir-guide.md) | Separates tools, the live source, and the protected evidence destination |
| [Pipeline CI trust and promotion](./diagrams/data-pipeline-ci-trust-and-promotion.svg) | [Pipeline testing and CI/CD](../Data-Engineering/Phase3/pipeline_testing_cicd.md) | Connects test scope, trusted artifact identity and deployment approval |
| [Supply-chain attestation layers](./diagrams/supply-chain-attestation-layers.svg) | [Software supply-chain assessment](../ContainerSecurity/software-supply-chain-assessment.md#attestations-verification-and-policy-are-separate) | Separates artifact subject binding and signer verification from policy checks on provenance claims |
| [Unified visibility evidence sources](./diagrams/unified-visibility-evidence-sources.svg) | [Unified network visibility](../IncidentResponse/IDS%26IPS/unified-network-visibility-architecture.md#reference-topology) | Compares wireless observations, wired traffic and device inventory before correlation |

## Processing Cadence and Assessment Decisions

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [Processing cadence timeline](./diagrams/data-processing-cadence-timeline.svg) | [Data engineering fundamentals](../Data-Engineering/Phase1/data_engineering_fundamentals.md#5-batch-micro-batch-and-streaming) | Compares how the same arrivals are grouped and processed |
| [Assessment finding and retest decisions](./diagrams/assessment-finding-retest-disposition.svg) | [Assessment findings lifecycle](../PlayBooks/assessment-findings-lifecycle.md#end-to-end-case-process) | Separates retest evidence from acceptance of residual risk |

## Sampling, Memory and Evidence Handling

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [NanoVNA segmented sweep sampling](./diagrams/nanovna-segmented-sweep-sampling.svg) | [NanoVNA-Saver guide](../SDR/nanovna/08-pc-software-and-firmware.md#the-segmented-sweep--the-killer-feature) | Shows the effect of denser frequency sampling on a narrow dip |
| [Python processing and memory bounds](./diagrams/python-processing-memory-bounds.svg) | [Python data processing](../Data-Engineering/Phase1/python_data_processing.md#1-stream-do-not-load) | Shows where records accumulate and where incremental processing releases them |
| [Dionaea event and sample boundaries](./diagrams/dionaea-event-and-sample-boundaries.svg) | [Dionaea](../IncidentResponse/HoneyPot/dionaea.md) | Separates monitoring metadata from quarantined untrusted files |

## Wireless Observation and Rule Verification

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [BLE passive and active scanning](./diagrams/ble-passive-and-active-scan-evidence.svg) | [BLE scanning and privacy](../Documentation/bluetooth-passive-scanning-sniffing.md#ble-advertising-vs-scan-responses) | Shows when a scanner may transmit and receive additional advertising data |
| [Wazuh rule validation stages](./diagrams/wazuh-synthetic-rule-validation-stages.svg) | [Wazuh synthetic rule validation](../Documentation/WAZUH-SYNTHETIC-RULE-VALIDATION.md) | Connects the offline, manager and end-to-end tests to the evidence each provides |

## Setup and Capability Readback

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [Parrot CM5 plan and readback](./diagrams/uconsole-parrot-cm5-plan-and-readback.svg) | [Parrot CM5 setup](../uConsole/PARROT-CM5.md#run) | Separates installed-image checks, cached package simulation and physical validation |
| [OpenClaw gateway access checks](./diagrams/openclaw-gateway-access-checks.svg) | [OpenClaw setup](../AI/OpenClaw/README.md#local-access-before-https) | Shows effective exposure, authenticated access and pairing |
| [OpenClaw Gateway trust boundary](./diagrams/openclaw-gateway-trust-boundary.svg) | [OpenClaw setup](../AI/OpenClaw/README.md#gateway-trust-boundary) | Distinguishes mutually trusting shared use from adversarial-user isolation |
| [Cyberdeck qualification evidence gate](./diagrams/cyberdeck-qualification-evidence-gate.svg) | [Cyberdeck acceptance tests](../Cyberdeck/docs/ACCEPTANCE_TESTS.md#completion-definitions) | Connects pass criteria and evidence to capability claims |

## Computing Setup and Shell Verification

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [Preserving a working CM4 image](./diagrams/uconsole-cm4-preserve-working-image.svg) | [CM4 first-boot audit](../uConsole/CM4-SETUP.md) | Distinguishes whole-device recovery, read-only preflight and optional configuration archives |
| [Bash pipeline exit status](./diagrams/bash-pipeline-exit-status.svg) | [CLI field reference](../Documentation/devhints-cli-field-reference.md#1-shell-and-bash-safety-checks) | Shows where a successful final stage can mask an earlier failure |

## Secure Data Pipeline Operations

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [Kafka consumer commit and replay](./diagrams/secure-pipeline-kafka-offset-commit.svg) | [Kafka delivery](../Data-Engineering/data_pipelines.md#8-stream-and-centralize-events-with-kafka) | Shows the replay window between a durable output and committing the next offset |
| [Ansible deployment and verification](./diagrams/secure-pipeline-ansible-canary.svg) | [Ansible deployment](../Data-Engineering/data_pipelines.md#9-automate-deployments-with-ansible) | Shows target selection, limited preview, application, and independent verification |
| [Trace an event through the pipeline](./diagrams/secure-pipeline-event-readback.svg) | [Integrated pipeline](../Data-Engineering/data_pipelines.md#10-build-the-integrated-pipeline) | Shows how to reconcile a synthetic event across processing and sink persistence |

## Container Operations

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [Compose change review](./diagrams/docker-compose-change-review.svg) | [Docker CLI Operations](../ContainerSecurity/docker-cli-operations-reference.md#docker-compose) | Connects target selection, model validation, dry run and post-change health checks |

## Honeypot, Streaming, Recovery & Authorization Illustrations

These are editable SVG reference diagrams embedded within the relevant chapter. They distinguish source-supported architecture from unverified production operation.

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [OpenCanary alert validation](./diagrams/opencanary-alert-validation.svg) | [OpenCanary](../IncidentResponse/HoneyPot/opencanary.md#validate-from-a-separate-machine) | Confirms a synthetic event at the local log and the alert destination |
| [Wazuh Honeypot Telemetry Evidence Path](./diagrams/honeypot-wazuh-telemetry-evidence-path.svg) | [Wazuh Honeypot Integration](../IncidentResponse/HoneyPot/wazuh-honeypot-integration.md) | Separate logs, agent collection, manager rules, index and analyst review |
| [CDC Snapshot/Offset Replay Boundary](./diagrams/cdc-snapshot-offset-replay-boundary.svg) | [Streaming & Change Data Capture](../Data-Engineering/Phase2/streaming_cdc.md) | Explain coordinated snapshot handoff, source positions, tombstones and idempotent replay |
| [RPO/RTO & Recovery Timeline](./diagrams/recovery-point-rpo-rto-replay-timeline.svg) | [Backup, Replay & Disaster Recovery](../Data-Engineering/Phase3/data_recovery_replay.md) | Distinguish trusted backup point, retained changes, restore time and verified cutover |
| [Web Application Authorization Matrix](./diagrams/webapp-object-authorization-role-matrix.svg) | [Web Application Testing Methodology](../WebAppSecurity/methodology.md) | Horizontal ownership checks, vertical privileges and server-side subject-object-action decisions |

## Proxmox Honeynet, Endpoint Telemetry & Lineage Diagrams

| Diagram | Embedded Guide | Why It Helps |
|---|---|---|
| [Proxmox Honeynet Trust Zones](./diagrams/proxmox-honeynet-vm-trust-boundaries.svg) | [Proxmox VM Honeynet](../IncidentResponse/HoneyPot/proxmox-vm-honeynet.md) | Shows restricted decoy ingress, agent telemetry path and protected management plane |
| [osquery Interactive vs Scheduled Results](./diagrams/osquery-interactive-scheduled-siem-flow.svg) | [Linux osquery Deployment](../IncidentResponse/Endpoint-Visibility/Linux/osquery.md) | Differentiates interactive snapshots, scheduled differential results, logger and SIEM visibility |
| [Dataset / Job / Run Lineage & Access](./diagrams/data-lineage-job-run-access-boundaries.svg) | [Data Governance & Lineage](../Data-Engineering/Phase3/data_governance_lineage.md) | Multi-input transformations, run provenance, restricted outputs and controls outside graph |

## RAG, Agent Reliability & Pipeline Observability Diagrams

| Diagram | Embedded Guide | Reference Concept |
|---|---|---|
| [RAG Ingestion & Retrieval Permission Boundaries](./diagrams/rag-ingestion-retrieval-permission-boundaries.svg) | [RAG & Knowledge Engineering](../AI/rag-and-knowledge-engineering.md) | Authorized ingestion, access-aware indexes, untrusted retrieved text, citation and approval |
| [Structured AI Action Gates](./diagrams/ai-structured-output-authorized-action-gates.svg) | [Structured Outputs & Data Contracts](../AI/structured-outputs-and-data-contracts.md) | Separate JSON syntax/schema from factual checks, ACL, external writes and readback |
| [Agent Ambiguous-Write Reconciliation](./diagrams/ai-agent-ambiguous-write-reconciliation.svg) | [AI Reliability & Failure Recovery](../AI/agent-reliability-and-recovery.md) | Durable state, verified outcome, uncertainty and safe retry with idempotency key |
| [Pipeline Observability & Reconciliation](./diagrams/pipeline-observability-reconciliation-slo.svg) | [Pipeline Observability & Reliability](../Data-Engineering/Phase3/pipeline_observability.md) | Production/processing/consumer telemetry, reconciliation, actionable alerts and service objectives |

## RF Measurement, Honeypot Deployment & OSINT Workstation Diagrams

| Image | Embedded Guide | Source-Checked Boundary |
|---|---|---|
| [NanoVNA S11: Resonance & Match](./diagrams/nanovna-s11-resonance-vs-match.svg) | [NanoVNA Antenna Tuning & Matching](../SDR/nanovna/05-antenna-tuning.md) | Calibrated reference plane, complex impedance and distinction between VSWR and radiation efficiency |
| [T-Pot Hive, Sensor & Administration](./diagrams/tpot-hive-sensor-management-boundaries.svg) | [T-Pot Deployment](../IncidentResponse/HoneyPot/tpot.md) | Decoy ingress and local sensor logs, optional Hive aggregation, isolated management and community sharing |
| [Tsurugi OSINT Image & Evidence Flow](./diagrams/tsurugi-osint-image-provenance-case-flow.svg) | [Tsurugi Linux OSINT Workstation](../OSINT/TSURUGI_LINUX_OSINT_GUIDE.md) | Official image, verified signed digest, isolated workstation, case-original evidence and reporting |

## Spacecraft Architecture Visual

| Diagram | Embedded guide |
|---|---|
| [Spacecraft bus and payload comparison](./diagrams/spacecraft-bus-payload-architecture.svg) | [Space Security appendices](../SpaceSecurity/Appendices.md#representative-spacecraft-architectures) |


| Diagram | Embedded Guide | Verified Visual Subject |
|---|---|---|
| [Splunk Universal Forwarder → Indexer → Search](./diagrams/splunk-forwarder-indexer-search-head-data-flow.svg) | [Splunk SIEM Deployment](../IncidentResponse/SIEM/splunk.md) | Universal Forwarder cannot index or search; storage/search/alerting are independently checked |
| [Ground-Space Command & Telemetry](./diagrams/space-ground-command-telemetry-trust-boundaries.svg) | [Space Security: Ground Segment](../SpaceSecurity/PartII.md) | Mission authorization, telecommands, telemetry, and mission-dependent CCSDS SDLS controls |
| [NanoVNA feedline loss and return loss](./diagrams/nanovna-feedline-return-loss.svg) | [NanoVNA Calibration & Reference Planes](../SDR/nanovna/03-calibration.md) | Quantifies how round-trip cable loss changes the displayed return loss and SWR |
| [NanoVNA S11/S21 Calibration Planes](./diagrams/nanovna-s11-s21-calibration-plane.svg) | [NanoVNA Calibration & Reference Planes](../SDR/nanovna/03-calibration.md) | OPEN/SHORT/LOAD on S11 plane and separate instrument-specific S21 calibration |
| [DIY HTTP Decoy JSONL → Wazuh](./diagrams/diy-http-honeypot-jsonl-wazuh-safe-path.svg) | [Minimal HTTP Honeypot Lab](../IncidentResponse/HoneyPot/diy-sensor-lab.md) | Lab-only request metadata capture, 404 response, JSONL localfile and optional Wazuh forwarding |

## Elastic, Flight Software, Mobile Linux & ETL/ELT Diagrams

| Image | Embedded Guide | Verified Learning Objective |
|---|---|---|
| [Elastic Ingest, Index & Kibana](./diagrams/elastic-stack-log-ingest-index-search.svg) | [Elastic Stack SIEM](../IncidentResponse/SIEM/elk_stack.md) | Shows optional Logstash versus direct shipping, Elasticsearch processing, Kibana investigation and evidence validation |
| [Space Flight Software Layers](./diagrams/spaceflight-fsw-cfs-security-layers.svg) | [Space Security: Flight Software](../SpaceSecurity/PartIII.md) | NASA cFS-like mission app, executive, OS abstraction, BSP/driver and onboard hardware boundary |
| [UserLAnd independent file export](./diagrams/userland-independent-file-export.svg) | [UserLAnd files and backups](../Mobile/UserLAnd/readme.md#-files-reports-and-backups) | Shows why a visible export folder can still be app-scoped |
| [UserLAnd Android Permission Boundary](./diagrams/userland-android-proot-capability-boundaries.svg) | [UserLAnd Linux on Android](../Mobile/UserLAnd/readme.md) | Distinguishes no-root Linux userspace tools from unavailable host kernel/raw-radio privileges |
| [ETL Versus ELT Data Paths](./diagrams/etl-vs-elt-transform-privacy-and-replay.svg) | [ETL & ELT Pipeline Design](../Data-Engineering/Phase1/etl_elt_pipeline_design.md) | Preload vs in-destination transforms, and why raw retention and security are independent choices |

## Promptfoo Red-Team Evaluation Data Paths

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [Promptfoo red-team provider data paths](./diagrams/promptfoo-redteam-provider-data-paths.svg) | [LLM and Agent Security Evaluations with Promptfoo](../AI/llm-security-evaluation-promptfoo.md#practical-evaluation-sequence) | Separates attack generation, target, grader, telemetry, and artifact paths before approved evaluations |

## Nmap AgentFlow Evidence Gates

| Diagram | Embedded guide |
|---|---|
| [Nmap analysis evidence gates](./diagrams/nmap-agentflow-evidence-gates.svg) | [AnythingLLM Nmap Analyzer](../AI/AnythingLLM/flow-nmap_analyzer.md#flow-information) |

## Breach Exposure Metadata Privacy

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [HIBP metadata privacy workflow](./diagrams/hibp-breach-metadata-privacy-workflow.svg) | [Breach Exposure Check AgentFlow](../AI/AnythingLLM/flow-breacher_check.md#suggested-flow); [Email Account Exposure Review](../AI/AnythingLLM/flow-email_osint.md#authorized-use-and-privacy) | Shows consent, metadata minimization, interpretation limits, and owner-directed next steps for related HIBP account checks |

## Company OSINT Source Confidence & Scope

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [Company OSINT source confidence and scope](./diagrams/company-osint-source-confidence-scope.svg) | [CompanyOSINT AgentFlow](../AI/AnythingLLM/flow-company_osint.md#scope-and-safeguards) | Separates permitted sources, provenance, organization-only analysis, independent verification, and human scope review |

## GitHub Secrets Redaction and Owner Response

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [GitHub secret alert redaction workflow](./diagrams/github-secrets-redaction-owner-response.svg) | [GitHubSecrets AgentFlow](../AI/AnythingLLM/flow-github_secrets.md#scope-and-safety) | Keeps credential values in restricted scanner systems, separates the metadata-only AgentFlow, and leaves verification and response with the authorized owner |

## Vulnerability Report Evidence Review

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [Vulnerability report evidence review](./diagrams/vulnerability-report-evidence-review.svg) | [VulnReportGenerator AgentFlow](../AI/AnythingLLM/flow-vulnreport_gen.md#purpose) | Separates evidence status, scoring sources, impact bounds, remediation review, and human approval |

## Domain Reconnaissance Scope and Evidence

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [Domain reconnaissance scope and evidence flow](./diagrams/domain-recon-scope-evidence-flow.svg) | [DomainRecon AgentFlow](../AI/AnythingLLM/flow-domain_recon.md#purpose) | Separates third-party public-source queries, unverified leads, an optional active HTTP check, and human scope confirmation |

## Offensive AI Engagement Scope and Stop Gates

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [Authorized AI red-team engagement gates](./diagrams/offensive-ai-authorized-engagement-gates.svg) | [Offensive AI](../AI/offensive_ai.md#chapter-2-the-engagement---an-ai-red-teamers-methodology) | Connects written scope, bounded synthetic tests, stop conditions, safe validation, and reporting |

## OpenClaw Use-Case Safety Workflow

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [OpenClaw use-case safety workflow](./diagrams/openclaw-use-case-safety-workflow.svg) | [OpenClaw Use Cases](../AI/OpenClaw/use_cases.md#before-using-a-prompt) | Connects data minimization, channel/scope checks, least-privilege tools, verification, and human approval |

## Context Authority, Evidence & Freshness

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [Context authority, evidence, and freshness](./diagrams/ai-context-authority-evidence-freshness.svg) | [Context Engineering & Memory Management](../AI/context-engineering-and-memory.md#1-understand-the-context-layers) | Separates trusted host policy, untrusted retrieved material, live state, model output, and verified handoff |

## AI Project Workspace Trust and Evidence Boundaries

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [AI project workspace trust boundaries](./diagrams/ai-project-workspace-trust-boundaries.svg) | [AI Projects, Notebooks, GPTs, Plugins and Reusable Assistants](../AI/ai-workspaces-notebooks-and-assistants.md#step-1--establish-the-trust-boundary) | Separates project context from host permissions, connected tools, provider data paths, human verification, and evidence handoff |

## AI Flow Readiness & Audit Retention

| Diagram | Embedded guide | What it explains |
|---|---|---|
| [AnythingLLM flow readiness](./diagrams/anythingllm-flow-readiness.svg) | [AnythingLLM Agentflow documentation](../AI/AnythingLLM/README.md#how-to-use-this-documentation) | Pre-save destination review, synthetic testing, and approval before real data |
| [AI telemetry and audit retention](./diagrams/ai-telemetry-audit-retention-paths.svg) | [AI Agent Observability](../AI/ai-observability-and-auditing.md#reference-architecture) | Diagnostic sampling, audit continuity, and minimized security events |

## Five-Layer Prompt to Evidence Handoff

| Diagram | Embedded guide | Why it belongs |
|---|---|---|
| [Five-layer prompt to evidence handoff](./diagrams/ai-five-layer-prompt-to-evidence-handoff.svg) | [Practical AI Usage and Interaction Guide](../AI/ai-usage-interaction-guide.md#the-five-instruction-layers) | Shows how mission, context, boundaries, execution, and evidence connect to verification, approval, and handoff |

## AI Agent Lanes, Durable Handoffs & Data Execution Gates

| Visual | Embedded Guide | Source-Aligned Concepts |
|---|---|---|
| [Multi-Agent Delegation & Review](./diagrams/ai-multi-agent-fanout-review-integration.svg) | [Multi-Agent Orchestration](../AI/multi-agent-orchestration.md) | Scoped ownership, independent verification, final integrated test and human approval |
| [Project Status, Evidence & Handoff](./diagrams/ai-project-status-evidence-handoff-flow.svg) | [AI Project & Agent Workflows](../AI/agent-project-workflows.md) | Charter rules, current decisions, reproducible evidence and explicit context reload |
| [Orchestrator Logical Interval & Publish Gate](./diagrams/data-orchestrator-interval-dependency-publish-gates.svg) | [Data Workflow Orchestration](../Data-Engineering/Phase2/workflow_orchestration.md) | DAG dependencies, source versions, ready/blocked states and consumer acceptance |
| [API Ingestion Cursor, Retry & Reconciliation](./diagrams/api-file-ingest-cursor-retry-reconciliation.svg) | [API & File Ingestion](../Data-Engineering/Phase2/api_file_ingestion.md) | Authenticated source contract, cursor semantics, rate-limit handling and exact batch evidence |

## Wireless Frames, BLE Sniffing, AD, Android, Social OSINT & CM5 Recovery

| Image | Embedded Guide | Source-Checked Content |
|---|---|---|
| [802.11 Deauth, Disassoc & PMF](./diagrams/wifi-deauth-disassoc-pmf-corroboration.svg) | [Wi-Fi Deauthentication Defensive Analysis](../Documentation/wifi-deauthentication-detection.md) | Authentication state versus association, negotiated protected management frames, channel visibility and AP/client corroboration |
| [BLE Sniffle Modes & Capture](./diagrams/ble-sniffle-advertising-connection-path.svg) | [Sniffle BLE Capture](../Documentation/ble-capture-sniffle.md) | Compatible TI device, advertisement capture versus connection following, encrypted-content and missed-packet limitations |
| [Active Directory Ticket Trust & Recovery](./diagrams/ad-kerberos-ticket-trust-recovery.svg) | [Active Directory Checklist](../Checklists/ActiveDirectory.md) | KDC/KRBTGT trust, detection evidence and coordinated compromise recovery |
| [Android Static, Dynamic & Backend Tests](./diagrams/android-app-static-runtime-backend-test-lanes.svg) | [Android Application Checklist](../Checklists/Android-Applications-Checklist.md) | Distinguishes static artifact inspection, runtime testing and API authorization checks |
| [Social Account Source Provenance](./diagrams/social-osint-account-provenance-verification.svg) | [Social Media OSINT](../OSINT/OSINT_socialmedia.md) | Matching handles and profile images are leads until independently corroborated |
| [uConsole CM5 Display Recovery](./diagrams/uconsole-cm5-display-diagnostic-recovery.svg) | [CM5 Display Recovery](../uConsole/CM5-DISPLAY-RECOVERY.md) | Exact image, session versus rotation diagnosis, package side effects and hardware validation |

## Network Monitoring, Locksport, WPA Evidence, C5 Wardriving & Hardware Test Bench

These original accessible diagrams are embedded in their canonical chapters and include explicit limitations on capture modes, physical measurements, protocol scope or test evidence.

| Image | Embedded Guide | Visual Purpose |
|---|---|---|
| [Network Sensor Placement & Evidence](./diagrams/network-detection-sensor-coverage-and-evidence.svg) | [Network Detection & Packet Analysis](../Tradecraft/network-detection.md) | WAN/DMZ/east-west vantage points, packet acquisition, Zeek/Suricata processing, SIEM validation |
| [Pin-Tumbler Shear Line Cutaway](./diagrams/locksport-pin-tumbler-shear-line.svg) | [Locksport Mechanical Fundamentals](../Documentation/Locksport.md) | Side-by-side locked/appropriately keyed pin-stack alignment |
| [WPA-PBKDF2 PMKID/EAPOL Audit Boundaries](./diagrams/wpa-pmkid-eapol-hc22000-protocol-boundaries.svg) | [HCXTools & Hashcat Reference](../Documentation/hcxtoolshashcat.md) | RF active/passive mode gates, original PCAPNG, offline conversion and Hashcat 22000 applicability |
| [ESP32-C5 Normal, Node & Core](./diagrams/esp32-c5-wardriver-normal-node-core.svg) | [ESP32-C5 Wardriver](../Wardriving/esp32-c5-wardriver.md) | Device roles, GNSS/SD logging, Node observations and Core aggregation |
| [Hardware Bench Diagnostic & Write Safety](./diagrams/hardware-bench-inventory-stress-storage-safety.svg) | [Manjaro Intel Hardware Test Bench](../HardwareTesting/Manjaro_Intel_TestBench.md); [Python test scripts](../HardwareTesting/py/README.md) | Baseline, telemetry, bounded stress, write-test permission and reproducible results |
| [Thermal soak evidence timeline](./diagrams/hardware-thermal-soak-evidence.svg) | [Thermal monitoring](../HardwareTesting/Manjaro_Intel_TestBench.md#3-thermal-monitoring-and-power-management) | Aligns workload phases, package temperature, busy frequency, and supporting evidence |
| [File-backed storage benchmark evidence](./diagrams/hardware-storage-benchmark-target-evidence.svg) | [Storage benchmarking with fio](../HardwareTesting/Manjaro_Intel_TestBench.md#10-storage-benchmarking-with-fio) | Verifies the mounted target and records the workload before comparing results |

## VoIP Call Paths, Linux Privilege Risk, Arduino IDE & Threat Intelligence

| New Diagram | Embedded Guide | Fact-Checked Scope |
|---|---|---|
| [SIP Signaling vs RTP Media](./diagrams/voip-sip-signaling-vs-rtp-media-security.svg) | [VoIP Assessment Checklist](../Checklists/voip-checklist.md) | Asterisk TLS-protected signaling versus separately negotiated SRTP media and PBX/SBC routing |
| [Linux Privilege & Vendor Patch Triage](./diagrams/linux-privilege-risk-and-vendor-patch-triage.svg) | [Linux Privilege Escalation Checklist](../Checklists/Linux-Privilege-Escalation.md) | Versioned vendor CVEs, distro backports, effective sudo/SUID/cron checks and safe remediation |
| [Arduino Board, Port & Bootloader Diagnostics](./diagrams/arduino-ide-board-port-bootloader-diagnostics.svg) | [Arduino IDE Multi-Platform Setup](../Documentation/arduinoIDE.md) | Installed board core, physical USB interface and upload protocol must be diagnosed separately |
| [OSINT/CTI Source Quality to Detection](./diagrams/osint-cti-source-quality-to-detection.svg) | [OSINT & Threat Intelligence Deep Dive](../Tradecraft/osint-threat-intel.md) | Source provenance, corroboration, time-sensitive IOCs, behavior mapping and detected-outcome evidence |

## Reverse Engineering, Wireless Survey, Account Response & Cyberdeck Diagrams

Original, editable SVG figures are placed in the relevant guides. Captions distinguish conceptual design from live evidence and link to official sources where available.

| Diagram | Embedded Guide | What the Diagram Clarifies |
|---|---|---|
| [Ghidra Analysis and Validation](./diagrams/ghidra-analysis-hypothesis-validation.svg) | [Ghidra Master Guide](../ReverseEngineering/ghidra-guide-index.md) | Inferred control flow and decompilation are hypotheses requiring independent analyst checks |
| [REMnux Isolation Boundaries](./diagrams/remnux-malware-analysis-network-isolation.svg) | [REMnux Malware Analysis](../ReverseEngineering/remnux-malware-analysis-guide.md), [vx-underground](../ReverseEngineering/vx-underground.md) | Evidence intake, static-analysis guest, optional isolated execution VM and safe export |
| [Kismet GPS and Log Retention](./diagrams/kismet-wardrive-gps-log-retention-flow.svg) | [Kismet Wireless Survey](../Wardriving/kismet.md) | Wireless observations, location-fix gate, additive log types and sharing approval |
| [Identity Alert Investigation](./diagrams/identity-alert-investigation-evidence-containment.svg) | [Unauthorized Access Playbook](../PlayBooks/unauth_access.md) | Corroborate access events and contextual identity risk before containment |
| [Cyberdeck Trust Boundaries](./diagrams/cyberdeck-zone-policy-logical-architecture.svg) | [Cyberdeck Public Reference](../Cyberdeck/README.md) | Logical GL.iNet/MikroTik path, intended zones and hardware validation caveat |

## Incident Response Revision 3, AI Auditing, Cryptanalysis, Bash & Firmware

These editable original SVGs are embedded in their explanatory chapters and paired with appropriate source references and caveats.

| Diagram | Embedded Guide | Verified Scope |
|---|---|---|
| [NIST 800-61 Rev. 3 & CSF 2.0 Incident Response](./diagrams/incident-response-nist-800-61r3-csf2-operations.svg) | [Enhanced Incident Response Playbook](../PlayBooks/BlueTeam_IncResp_Enhanced.md) | Current NIST framework, locally defined operating steps and explicit non-certification |
| [Independent AI Evidence Audit](./diagrams/ai-audit-claims-tools-and-outcomes.svg) | [Verification & AI Audits](../AI/verification-and-ai-audits.md) | Distinguish source claims, actual tool receipts and confirmed end state |
| [Historical Cipher Analysis](./diagrams/classical-cipher-frequency-vigenere-ic-analysis.svg) | [Classical Cryptanalysis](../Cryptography/Classical/cryptanalysis.md) | Substitution versus repeating-key tests, misleading peaks and ambiguity |
| [Safe Bash Execution Gates](./diagrams/bash-script-input-validation-and-dry-run-gates.svg) | [Bash Scripting Cheat Sheet](../Scripts/Bash/bash_scripting_cheat-sheet.md) | Validate optional args, quoting, syntax checks, side-effect boundaries |
| [Safe HID Marker Validation](./diagrams/ducky-safe-validation-flow.svg) | [USB Rubber Ducky guide](../Scripts/Ducky/README.md#safe-build-compile--approval-workflow) | Model-specific fixed-text testing, isolated validation, stop conditions and evidence |
| [Bash Bunny Device-Policy Validation](./diagrams/bashbunny-defensive-policy-validation.svg) | [Bash Bunny guide](../Scripts/Bash/BashBunny/README.md#authorized-field-assessment-labs--deployment-examples) | Scope and baseline, device/firmware review, minimal checks, telemetry and cleanup |
| [Safe PDF Reference Use](./diagrams/pdf-safe-reference-use-flow.svg) | [PDF Reference Library](../PDF/README.md#-how-to-use-these-resources) | Provenance, integrity, safe inspection, primary-source checks and qualified citations |
| [ESP32 Firmware Acceptance Gates](./diagrams/esp32-firmware-board-build-flash-acceptance.svg) | [ESP32 Security Firmware Catalog](../Documentation/esp32-security-firmware-catalog.md) | Chip/board-specific builds, flash layouts, recovery and post-boot qualification |

## Python Reference Safety, Classical Ciphers, Pentoo & Incident Casebook

Original, editable diagrams embedded directly into the related technical chapters. Their captions distinguish educational models from any untested device/runtime scenario.

| Diagram | Embedded Guide | Core Limit |
|---|---|---|
| [Python Security Example Qualification](./diagrams/python-security-snippet-platform-scope-test-gates.svg) | [Python Security Cheat Sheet](../Documentation/python.md) | Windows native prototypes, legacy API versions, safe local probes and observed outcomes |
| [Classical Cipher Family Comparison](./diagrams/classical-cipher-swap-position-and-one-time-pad.svg) | [Classical Ciphers](../Cryptography/Classical/ciphers.md) | Distinguishes codes, substitution, transposition, periodic shifts and OTP requirements |
| [Pentoo Deployment & Portage Gates](./diagrams/pentoo-gentoo-deployment-profile-safety.svg) | [Pentoo Linux Field Guide](../Tradecraft/pentoo-linux-guide.md) | Distinguishes live image, installed system, Gentoo overlay and hardware validation |
| [Incident Casebook Evidence and Approval](./diagrams/incident-casebook-scope-evidence-action-approval.svg) | [Operational Playbook Library](../PlayBooks/cybersecurity_playbooks.md) | Correlate event evidence and authority before containment, recovery and notification |

## Repository-Wide Audit & Evidence Diagram

| Diagram | Embedded Guide | Scope |
|---|---|---|
| [Whole-repository evidence gates](./diagrams/repository-evidence-gates.svg) | [Repository Verification & Content Completeness Protocol](../Documentation/REPOSITORY-VERIFICATION-PROTOCOL.md) | All-file inventory, static checks, fact/source review, lab verification and independently reviewed corrections |

This diagram illustrates the **verification method**, not a certification that any individual claim or system was tested. Coverage reports are generated by the [visual audit tool](../tools/audit_visual_coverage.py).

## Newly Embedded Field & Agent Workflow Diagrams

These figures illustrate the actual decision points in their respective guides; they are not claims of tested hardware, live provider integrations, or completed assessments.

| Diagram | Embedded Guide | Visual Purpose |
|---|---|---|
| [OSINT Case Evidence & Review](./diagrams/osint-case-evidence-provenance.svg) | [OSINT Investigator Playbook](../OSINT/Playbook/README.md) | Authorized indicators, scoped collection, raw evidence, source verification, incomplete-result handling |
| [Wardrive Go Platform Collection Boundaries](./diagrams/wardrive-go-platform-collection-boundaries.svg) | [Wardrive Go Mobile Surveys](../Wardriving/wardrive-go.md) | Android and iOS radio paths, optional external receiver, GPS session review, privacy before upload |
| [Cyberdeck Assessment Gates](./diagrams/cyberdeck-seven-stage-assessment-gates.svg) | [Cyberdeck Assessment Workflow](../Cyberdeck/docs/ASSESSMENT_WORKFLOW.md) | Four visual groups summarizing the seven manual assessment stages |
| [MCP Trust & Approval Gates](./diagrams/mcp-trust-and-approval-boundaries.svg) | [MCP Tooling & Secure Permissions](../AI/mcp-tooling-and-permissions.md) | Separate untrusted input, host policy, server-side permissions, and human approval of effects |
| [MCP Protocol Lifecycle Eras](./diagrams/mcp-protocol-lifecycle-eras.svg) | [MCP Tooling & Secure Permissions](../AI/mcp-tooling-and-permissions.md) | Distinguishes initialization/session revisions from the 2026-07-28 stateless protocol |
| [Wireless Survey Data & Privacy Gates](./diagrams/wardriving-survey-data-privacy-gates.svg) | [Wardriving Data Handling](../Wardriving/data-handling.md) | Authorized survey records, protected originals, minimized derivatives and upload review |
| [Cyberdeck public release review](../Cyberdeck/docs/images/cyberdeck-safe-publication.svg) | [Cyberdeck release checklist](../Cyberdeck/docs/PUBLISHING_AND_RELEASE.md#pre-publication-checklist) | Separates private history from a reviewed standalone publication tree |
| [Cyberdeck Evidence & Redaction Lifecycle](./diagrams/cyberdeck-evidence-and-redaction-lifecycle.svg) | [Cyberdeck Evidence & Privacy](../Cyberdeck/docs/EVIDENCE_AND_PRIVACY.md) | Offline case, SHA-256 integrity inventory, redacted derivative and controlled retention |
| [AI Evaluation Evidence Matrix](./diagrams/ai-evaluation-evidence-matrix.svg) | [AI Evaluation & Regression Testing](../AI/ai-evaluation-and-regression-testing.md) | Separate deterministic tests, live agent behavior and independent end-state validation |
| [uConsole Hardware & OS Preflight](./diagrams/uconsole-hardware-os-preflight-paths.svg) | [uConsole Setup](../uConsole/README.md) | CM4/CM5 distinction, native OS image, optional peripherals and physical readback |
| [Cryptography Primitive Decision Map](./diagrams/cryptography-primitive-decision-map.svg) | [Cryptography Overview](../Cryptography/README.md) | Four distinct security goals: AEAD, password KDF, signatures/HMAC and key establishment |
| [Vigenère candidate periods](./diagrams/vigenere-candidate-periods.svg) | [Classical cryptanalysis](../Cryptography/Classical/cryptanalysis.md#the-index-of-coincidence-ic) | Mean column IC values for a reproducible synthetic repeating-key example |
| [Encrypted DNS and DNSSEC boundaries](./diagrams/dns-encryption-and-validation-boundaries.svg) | [DNS resolver defense](../Documentation/dns-hijacking-secure-dns.md) | Shows the separate confidentiality and authenticity controls |
| [DNS resolution trust path](./diagrams/dns-resolution-trust-path.svg) | [DNS resolver defense](../Documentation/dns-hijacking-secure-dns.md#dns-trust-boundaries--common-threats) | Maps endpoint, local-network, recursive-resolver, and authoritative-zone controls and evidence |
| [TAP monitor capacity](./diagrams/tap-full-duplex-monitor-capacity.svg) | [Network TAPs](../Documentation/network-taps-and-packet-visibility.md#breakout-vs-aggregation-example) | Explains aggregate output oversubscription during full-duplex traffic |
| [Network observation method selection](./diagrams/tap-observation-method-selection.svg) | [Network TAPs](../Documentation/network-taps-and-packet-visibility.md#passive-vs-active-what-to-buy-or-build-for-each-task) | Chooses SPAN, a physical TAP, or virtual switch mirroring by observation point |
| [VLAN forwarding and enforcement](./diagrams/vlan-forwarding-policy-boundaries.svg) | [Network segmentation](../Documentation/network-segmentation-dmz-acl-vlan.md#acl-strategy--secure-defaults) | Locates policy enforcement along the actual traffic path |
| [Passive IDS Network Visibility](./diagrams/homelab-passive-ids-visibility-mirror-tap.svg) | [Homelab Networking & Isolation](../Homelab/README.md) | Unmanaged switch visibility limitation vs configured managed SPAN; inline TAP is a separate physical option |

## Firmware, Cyberdeck Devices & Virtualization Visuals

New original technical reference diagrams appear **inside their canonical guides**, with explicit boundaries between source-verified principles, device-specific configuration and untested physical behavior.

| Diagram | Embedded Guide | Visual Focus |
|---|---|---|
| [Firmware Flashing Verification Gates](./diagrams/firmware-flashing-verification-gates.svg) | [Firmware Web Flashers & Installers](../Documentation/firmware-web-flashers.md) | Verify exact MCU/revision, approved release, installer route and post-boot feature checks |
| [Device-First Firmware Compatibility](./diagrams/device-firmware-compatibility-selection.svg) | [Device-First Firmware List](../Documentation/device-firmware-list.md) | Target matrix, board image versus controller/FAP artifact, flash layout, stop on mismatch |
| [Portable Cyberdeck Device Roles & Artifacts](./diagrams/cyberdeck-portable-device-roles-and-artifacts.svg) | [Cyberdeck Portable Wireless Field Devices](../Cyberdeck/docs/PORTABLE_WIRELESS_FIELD_DEVICES.md) | Flipper external Marauder, standalone boards, alternate Plus2 firmware and separate Pineapple interface |
| [Virtual Lab Network Isolation Paths](./diagrams/homelab-virtual-network-isolation-paths.svg) | [Complete Homelab Setup](../Homelab/HomeLab_Setup.md) | Virtual internal versus host-only and routed networks; host access, egress and production-risk boundaries |

## AI Project Operations, OSINT Investigations & Wireless Survey Quality

These original SVGs are embedded in the corresponding procedural chapter and distinguish planned actions from completed, observed or independently accepted outcomes.

| Diagram | Embedded Guide | Technical Boundary |
|---|---|---|
| [AI Notes, Hooks & Evidence](./diagrams/ai-notes-hooks-evidence-boundaries.svg) | [Notes, Memory, Hooks & Automation](../AI/notes-hooks-and-automation.md) | Reference context cannot execute; host events require permissions and independent result checks |
| [AI Milestone Independent Acceptance](./diagrams/ai-milestone-independent-acceptance-gate.svg) | [Milestones & Acceptance Criteria](../AI/milestones-and-acceptance-criteria.md) | Tasks and commits are not accepted outcomes without real test evidence and review |
| [OSINT Fraud Case Source Confidence](./diagrams/osint-fraud-investigation-source-confidence.svg) | [OSINT Investigation Procedures](../OSINT/Playbook/investigation_guide.md) | Registration is not geolocation; search output is not identity; reposts require provenance |
| [Wardriving Field Quality & Acceptance](./diagrams/wardriving-field-quality-acceptance.svg) | [Wardriving Field Procedure](../Wardriving/field-workflow.md) | Calibration, passive behavior, GPS evidence, explicit STOP and per-case acceptance |

## Live Forensics & SIEM Data-Flow Visuals

| Diagram | Embedded Guide | Source-Checked Scope |
|---|---|---|
| [Graylog Ingest, Search & Metadata Roles](./diagrams/graylog-data-node-ingest-architecture.svg) | [Graylog SIEM Guide](../IncidentResponse/SIEM/graylog.md) | Graylog inputs/processing, recommended Data Node or compatible self-managed backend and MongoDB metadata |
| [Live Response Volatility & Evidence Gates](./diagrams/live-response-volatility-evidence-gates.svg) | [Live Response Collection](../IncidentResponse/Digital-Forensics/LiveData/live_data_collection.md) | Case-dependent volatility, operational safety, original preservation and independent analysis |

## New Workflow & Evidence Visuals

Original, accessible SVGs for workflow comprehension. They are **conceptual only**: none certify a specific deployment, vendor rule, collection interface, or completed lab exercise.

| Diagram | Embedded Guide | Scope |
|---|---|---|
| [Purple Team emulation & detection loop](./diagrams/purple-team-emulation-detection-loop.svg) | [Detection validation playbook](../PlayBooks/purple-team-detection-validation.md) and [detailed playbook](../PlayBooks/PurpleTeam_Detailed.md) | Scope, approval, safe canary, telemetry, alert, tune/retest |
| [Detection evidence verification gates](./diagrams/detection-evidence-verification-gates.svg) | [SIEM detection content](../IncidentResponse/SIEM/detection-content-validation.md) and [offline canary validator](../Documentation/CANARY-DETECTION-VALIDATOR.md) | Fixture vs imported vs verified lab evidence |
| [Cyberdeck policy zones](./diagrams/cyberdeck-policy-zones.svg) | [Public Cyberdeck architecture](../Cyberdeck/docs/ARCHITECTURE.md) | Conceptual router/zone boundaries, field RF, evidence storage |
| [Wireshark two-point TCP reply check](./diagrams/wireshark-tcp-reply-two-capture-points.svg) | [Wireshark master filter list](../Documentation/wireshark-master-filters.md#slow-networks-broken-connections-and-intermittent-problems) | Corroborates missing-handshake evidence across capture points |
| [Wireshark capture & display boundaries](./diagrams/wireshark-capture-display-boundaries.svg) | [Advanced Wireshark reference](../Documentation/wireshark.md) | Vantage point, optional BPF, PCAP, display filter, analyst validation |
| [AI-SOC trust & approval boundaries](./diagrams/ai-soc-trust-and-approval-boundaries.svg) | [AI-augmented security operations](../AI/ai-security-operations-workflows.md) | Authenticated intake, schema/evidence boundary, read-only AI, independent review and privileged-action approval |
| [CTI-to-approved-emulation gates](./diagrams/cti-to-approved-emulation-gates.svg) | [Detailed Purple Team playbook](../PlayBooks/PurpleTeam_Detailed.md) | Independently verify CTI, map ATT&CK, prepare benign controls, obtain human authorization, assess observed evidence |

## PCI DSS Scoping Visual

Original conceptual scope-classification workflow; this diagram does **not** certify any real CDE or confirm that a service is outside scope.

| Diagram | Embedded guide |
|---|---|
| [PCI DSS scope & evidence gates](./diagrams/pci-dss-scoping-boundaries.svg) | [PCI DSS scoping field guide](../Compliance/pci-dss-scoping.md) |

## Security Key And Recovery Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [security key recovery paths](./diagrams/security-key-recovery-paths.svg) | [Guide](../Cryptography/security-keys-passkeys.md) |
| [security key protocol boundaries](./diagrams/security-key-protocol-boundaries.svg) | [Guide](../Cryptography/security-keys-passkeys.md) |

## Encrypted Storage Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [encrypted storage status questions](./diagrams/encrypted-storage-status-questions.svg) | [Guide](../Cryptography/encrypted-storage.md) |
| [encrypted storage recovery components](./diagrams/encrypted-storage-recovery-components.svg) | [Guide](../Cryptography/encrypted-storage.md) |

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
## Fail2Ban Event Response Visuals

Original conceptual flow; actual coverage depends on the configured source, filter, jail thresholds, and action.

| Diagram | Embedded guide |
|---|---|
| [Fail2Ban event-to-action flow](./diagrams/fail2ban-log-to-action-flow.svg) | [Fail2Ban guide](../IncidentResponse/IDS&IPS/fail2ban.md) |

## Snort Guide Visuals

Original conceptual map separating Snort 2 and Snort 3 configuration, then passive and inline traffic modes.

| Diagram | Embedded guide |
|---|---|
| [Snort generation and traffic modes](./diagrams/snort-generation-and-traffic-modes.svg) | [Snort guide](../IncidentResponse/IDS&IPS/snort.md) |

## Security Onion Data Flow Visuals

Original conceptual topology separating sniffing, sensor processing, event transport, search, packet capture, and analyst access.

| Diagram | Embedded guide |
|---|---|
| [Security Onion sensor-to-search data flow](./diagrams/security-onion-sensor-to-search-flow.svg) | [Security Onion guide](../IncidentResponse/IDS&IPS/security-onion.md) |

## Kismet And Wazuh Wireless Lab Visuals

Original conceptual figure separating passive live alerting from optional offline PCAP analysis and case correlation.

| Diagram | Embedded guide |
|---|---|
| [Kismet and Wazuh live and offline flows](./diagrams/kismet-wazuh-live-and-offline-flow.svg) | [Wireless intrusion detection lab](../IncidentResponse/IDS&IPS/kismet-wazuh-wireless-lab.md) |

## nzyme And Wazuh Integration Visuals

Original conceptual diagram separating one-shot nzyme actions, local durable collection, Wazuh rule mapping, and optional contextual Kismet comparison.

| Diagram | Embedded guide |
|---|---|
| [nzyme event ingestion into Wazuh](./diagrams/nzyme-wazuh-event-ingestion.svg) | [nzyme + Wazuh integration](../IncidentResponse/IDS&IPS/nzyme-wazuh-integration.md) |

## nzyme Wireless Tap Architecture Visuals

Original conceptual topology for two band-split WiFi taps sending summarized data to a node and PostgreSQL; channel hopping and regional channel limits remain.

| Diagram | Embedded guide |
|---|---|
| [nzyme band-split tap architecture](./diagrams/nzyme-band-split-tap-architecture.svg) | [DIY WiFi intrusion detection with nzyme](../IncidentResponse/IDS&IPS/nzyme_wids.md) |

## Oscilloscope Measurement Visuals

Original conceptual comparison of analog bandwidth, sample rate, record length, and probe limits. It does not recommend a specific scope model or describe a tested setup.

| Diagram | Embedded guide |
|---|---|
| [Oscilloscope bandwidth, sampling, and record length](./diagrams/oscilloscope-bandwidth-sampling-record-length.svg) | [Electrical Fundamentals — Oscilloscope Selection](../HardwareHacking/Chapter2.md#oscilloscope-selection-for-hardware-hacking) |

## Electrical Measurement Visuals

Original conceptual shunt-measurement figure; the resistor value depends on target current, allowable voltage drop, power dissipation, and instrument limits.

| Diagram | Embedded guide |
|---|---|
| [Shunt current measurement](./diagrams/shunt-current-measurement.svg) | [Electrical Fundamentals — Shunt Resistors](../HardwareHacking/Chapter2.md#shunt-resistors-for-power-measurement) |

## Hardware Security Assessment Visuals

Original conceptual workflow; the exact test method and safe limits depend on the authorized target and its documentation.

| Diagram | Embedded guide |
|---|---|
| [Hardware security bench workflow](./diagrams/hardware-security-bench-workflow.svg) | [Hardware Hacking overview](../HardwareHacking/README.md#-overview) |

## Integrated Png & Svg Diagrams

| Image | Used in | Explanation |
|---|---|---|
| [Tradecraft scope-to-detection loop](./diagrams/tradecraft-scope-to-detection-loop.svg) | [Tradecraft index](../Tradecraft/README.md) | Conceptual flow from written authorization to controlled testing, observable telemetry, defensive validation, and reporting |
| [AD attack paths](./ad_attack_paths.png) | [AD attacks and defenses](../Tradecraft/active-directory.md#kerberos-attacks) | Kerberos and AD risk-path illustration |
| [AI agent architecture](./ai_agent_arch.png) | [AI section](../AI/README.md) | Conceptual file-system-first agent/tool boundaries |
| [Hardware diagnostics](./hardware_diagnostics.png) | [Hardware Testing](../HardwareTesting/README.md) | Reference board-level diagnostic workflow |
| [Network architecture](./network_security_arch.png) | [Homelab](../Homelab/README.md) | Example segmented design, not a verified live topology |
| [Charging diagnostics & power reference](./charging-diagnostics-power-reference.jpg) | [Hardware Testing](../HardwareTesting/README.md#charging--power-diagnostics) | Typical USB/laptop charging ranges and meter-reading fault isolation; match the device's own rating |
| [Mac startup & reset cheat sheet](./mac-startup-reset-cheatsheet.png) | [Hardware Testing](../HardwareTesting/README.md#mac-startup--reset) | Apple-sourced startup keys, NVRAM/SMC resets by chip type and firmware revive/restore |
| [PC & Mac maintenance guide](./pc-mac-maintenance-guide.jpg) | [Hardware Testing](../HardwareTesting/README.md#pc--mac-everyday-maintenance) | Client hand-out for updates, cleaning, storage, startup items, security and 3-2-1 backups |
| [CC1101 reference sheet](./cc1101-reference-cheatsheet.jpg) | [SBC & radio add-on compatibility](../Documentation/sbc-radio-addon-compatibility.md#add-on-modules--hats-abilities--integration) | Datasheet chip pins, key registers and module examples; wire colors are vendor-specific |
| [RAM versus storage](./ram_vs_storage.png) | [Manjaro test bench](../HardwareTesting/Manjaro_Intel_TestBench.md#5-memory-and-storage-diagnostics) | Introductory CPU/RAM/storage mental model |
| [VM compartmentalization](./vm_compartmentalization.png) | [OPSEC guide](../OPSEC/README.md#principles) | Boundary illustration with important host/guest limitations |
| [Wireless auditing](./wireless_auditing.png) | [Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md#section-2-wireless-specific-testing-procedures) | Wireless engagement workflow |
| [Penetration-test lifecycle](./pentest_lifecycle.png) | [Playbooks](../PlayBooks/README.md) | Assessment lifecycle overview |
| [JWrapper abuse case study](./jwrapper_attack.png) | [Incident Response](../IncidentResponse/README.md) | Illustrative remote-access-software abuse path, not proof of infection |
| [FIDO2 / passkey authentication](./fido2-passkey-authentication-flow.svg) | [Hardware keys and passkeys](../Cryptography/security-keys-passkeys.md#what-is-a-security-key) | **New accessible vector figure**, showing registration and sign-in |
| [Encrypted storage boundaries](./encrypted-storage-protection-boundaries.svg) | [Encrypted storage](../Cryptography/encrypted-storage.md#choose-the-right-design) | **New accessible vector figure**, locked versus unlocked data and backup limitations |
| [Journalist source-data lifecycle](./journalist-source-data-lifecycle.svg) | [Press freedom / source protection](../OPSEC/press-freedom/README.md#mission) | **New accessible vector figure**, preservation holds and approved disposition |

## OPSEC Workstation Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [opsec vm network choices](./diagrams/opsec-vm-network-choices.svg) | [Guide](../OPSEC/OPSEC_guide.md) |
| [opsec malware lab boundaries](./diagrams/opsec-malware-lab-boundaries.svg) | [Guide](../OPSEC/OPSEC_guide.md) |

## Docker Operations Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [docker operations data lifetimes](./diagrams/docker-operations-data-lifetimes.svg) | [Guide](../ContainerSecurity/docker-cli-operations-reference.md) |
| [docker operations image review](./diagrams/docker-operations-image-review.svg) | [Guide](../ContainerSecurity/docker-cli-operations-reference.md) |
| [docker operations context control](./diagrams/docker-operations-context-control.svg) | [Guide](../ContainerSecurity/docker-cli-operations-reference.md) |

## Memory Forensics Visual

| Diagram | Embedded guide |
|---|---|
| [Volatility evidence triage](./diagrams/volatility-evidence-triage.svg) | [Volatility 3 memory forensics](../IncidentResponse/Digital-Forensics/Memory/volatility_cheatsheet.md#validation-before-triage) |

## Applied Cryptography Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [applied crypto tls boundaries](./diagrams/applied-crypto-tls-boundaries.svg) | [Guide](../Cryptography/applied-crypto.md) |
| [applied crypto envelope rotation](./diagrams/applied-crypto-envelope-rotation.svg) | [Guide](../Cryptography/applied-crypto.md) |
| [applied crypto presence verification](./diagrams/applied-crypto-presence-verification.svg) | [Guide](../Cryptography/applied-crypto.md) |
| [applied crypto authentication records](./diagrams/applied-crypto-authentication-records.svg) | [Guide](../Cryptography/applied-crypto.md) |

## HackRF Guide Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [hackrf guide iq representations](./diagrams/hackrf-guide-iq-representations.svg) | [Guide](../SDR/hackrf.md) |
| [hackrf guide passband vs span](./diagrams/hackrf-guide-passband-vs-span.svg) | [Guide](../SDR/hackrf.md) |
| [hackrf guide sweep coverage](./diagrams/hackrf-guide-sweep-coverage.svg) | [Guide](../SDR/hackrf.md) |
| [hackrf guide evidence ladder](./diagrams/hackrf-guide-evidence-ladder.svg) | [Guide](../SDR/hackrf.md) |
| [hackrf guide bench observation](./diagrams/hackrf-guide-bench-observation.svg) | [Guide](../SDR/hackrf.md) |

## Endpoint Collection and PF Rule Evaluation

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [Endpoint telemetry and query paths](./diagrams/endpoint-telemetry-query-paths.svg) | [Endpoint Visibility index](../IncidentResponse/Endpoint-Visibility/README.md) | Distinguishes event streams, scheduled query logging, and interactive results |
| [OpenBSD PF state and rule flow](./diagrams/openbsd-pf-state-and-rule-flow.svg) | [OpenBSD PF guide](../IncidentResponse/Firewalls/openbsd_pf.md) | Shows when PF uses existing state and when ordered filter rules decide the action |

## Sysmon Telemetry Visuals

Original conceptual flow of configured events through Windows Event Log to a collector; actual coverage depends on configuration and retention.

| Diagram | Embedded guide |
|---|---|
| [Sysmon telemetry coverage flow](./diagrams/sysmon-telemetry-coverage-flow.svg) | [Windows Sysmon Deployment Guide](../IncidentResponse/Endpoint-Visibility/Windows/sysmon.md) |

## Linux Auditd And Syslog Visuals

Original conceptual flow from audit rules through local collection and configured forwarding; verify every hop and document losses.

| Diagram | Embedded guide |
|---|---|
| [Linux audit event flow](./diagrams/linux-audit-event-flow.svg) | [Linux Auditd & Syslog Hardening Guide](../IncidentResponse/Endpoint-Visibility/Linux/auditd_syslog.md) |

## Log Aggregation Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [log aggregation transport controls](./diagrams/log-aggregation-transport-controls.svg) | [Guide](../IncidentResponse/log_agg.md) |
| [log aggregation pipeline contracts](./diagrams/log-aggregation-pipeline-contracts.svg) | [Guide](../IncidentResponse/log_agg.md) |
| [log aggregation time provenance](./diagrams/log-aggregation-time-provenance.svg) | [Guide](../IncidentResponse/log_agg.md) |
| [log aggregation end to end validation](./diagrams/log-aggregation-end-to-end-validation.svg) | [Guide](../IncidentResponse/log_agg.md) |

## Expanded Topical Svg Diagrams (November 2026)

These 19 newly authored diagrams provide short conceptual overviews beside the relevant guide sections. Each SVG contains a built-in title and description, uses local fonts and shapes only, and deliberately avoids asserting that a particular device, network or lab was tested.

| Diagram | Embedded guide | Purpose |
|---|---|---|
| [SIEM telemetry correlation](./diagrams/siem-telemetry-correlation.svg) | [IncidentResponse/SIEM/README.md](../IncidentResponse/SIEM/README.md) | Collect, normalize, correlate and validate events |
| [Honeypot sensor isolation](./diagrams/honeypot-segmented-logging.svg) | [IncidentResponse/HoneyPot/readme.md](../IncidentResponse/HoneyPot/readme.md) | Decoy isolation, log ingestion and safe triage |
| [Cloud shared responsibility](./diagrams/cloud-shared-responsibility.svg) | [Cloud/README.md](../Cloud/README.md) | Provider/customer security responsibilities |
| [Container trust boundaries](./diagrams/container-security-boundaries.svg) | [ContainerSecurity/README.md](../ContainerSecurity/README.md) | Supply chain and shared-kernel risks |
| [DFIR evidence lifecycle](./diagrams/dfir-evidence-custody.svg) | [IncidentResponse/Digital-Forensics/README.md](../IncidentResponse/Digital-Forensics/README.md) | Authorize, collect, verify, analyze and preserve |
| [Autopsy and KAPE evidence workflows](./diagrams/dfir-autopsy-kape-workflows.svg) | [Autopsy + KAPE guide](../IncidentResponse/Digital-Forensics/Disks/autopsy_kape.md) | Separate disk imaging from selective artifact triage |
| [OSINT verification](./diagrams/osint-verification-workflow.svg) | [OSINT/README.md](../OSINT/README.md) | Scope, corroborate, protect sources and report |
| [Wireless IDS correlation](./diagrams/wireless-ids-correlation.svg) | [IncidentResponse/IDS&IPS/readme.md](../IncidentResponse/IDS&IPS/readme.md) | Kismet/nzyme event correlation and evidence checks |
| [Web application testing](./diagrams/webapp-assessment-cycle.svg) | [WebAppSecurity/README.md](../WebAppSecurity/README.md) | Scope through retest with safe validation |
| [GRC control evidence](./diagrams/grc-controls-evidence.svg) | [Compliance/README.md](../Compliance/README.md) | Risk, mapping, control implementation and testing |
| [Reverse engineering](./diagrams/reverse-engineering-workflow.svg) | [ReverseEngineering/README.md](../ReverseEngineering/README.md) | Sample intake to defensible findings |
| [Space system segments](./diagrams/space-security-segments.svg) | [SpaceSecurity/README.md](../SpaceSecurity/README.md) | Ground, comms, spacecraft and user trust boundaries |
| [GNSS authentication and integrity boundaries](./diagrams/gnss-authentication-and-integrity-boundaries.svg) | [SpaceSecurity GNSS chapter](../SpaceSecurity/PartIV.md) | Distinguish message authentication, integrity checks, and interference indicators |
| [Wardriving data handling](./diagrams/wardriving-collection-lifecycle.svg) | [Wardriving/README.md](../Wardriving/README.md) | Passive survey quality, privacy and disclosure |
| [Data pipeline reliability](./diagrams/data-pipeline-reliability.svg) | [Data-Engineering/Phase2/README.md](../Data-Engineering/Phase2/README.md) | Contract, transformations, security and replay |
| [NanoVNA calibration](./diagrams/nanovna-calibration-plane.svg) | [SDR/nanovna/README.md](../SDR/nanovna/README.md) | Measurement reference plane and uncertainty |
| [Mobile security layers](./diagrams/mobile-security-boundaries.svg) | [Mobile/README.md](../Mobile/README.md) | Device, account, app, network and backups |
| [Incident response stages](./diagrams/incident-response-cycle.svg) | [IncidentResponse/README.md](../IncidentResponse/README.md) | Preparation through recovery and improvement |
| [Assessment checklist lifecycle](./diagrams/checklist-assessment-quality.svg) | [Checklists](../Checklists/README.md) | Authorization, coverage, evidence, QA and closure |
| [Safe script execution](./diagrams/safe-script-execution.svg) | [Scripts](../Scripts/README.md) | Code review, scope approval, rollback and results |
| [CM5 AIO v2 and NVMe validation](./diagrams/uconsole-cm5-aio-nvme-validation.svg) | [CM5 Setup](../uConsole/CM5-SETUP.md) | Boot-file settings, live peripheral checks, and optional NVMe startup validation |
| [uConsole cautious setup](./diagrams/uconsole-six-phase-setup.svg) | [uConsole](../uConsole/README.md) | Model-aware, opt-in six-phase CM5 workflow |

## Web Application Assessment Visuals

Original conceptual flow mapping authorization to versioned requirements, scoped tests, evidence and retesting.

| Diagram | Embedded guide |
|---|---|
| [Web assessment requirement-to-evidence flow](./diagrams/webapp-requirement-to-evidence-flow.svg) | [OWASP standards and Nuclei review](../WebAppSecurity/owasp-assessment-and-nuclei.md) |
| [Web assessment authorization and scope gates](./diagrams/webapp-authorization-scope-gates.svg) | [Web testing methodology](../WebAppSecurity/methodology.md) |

## Assessment Service Integration Visuals

Original conceptual gates for approval, phase selection, evidence validation and closure.

| Diagram | Embedded guide |
|---|---|
| [Assessment integration evidence gates](./diagrams/assessment-integration-evidence-gates.svg) | [Staged security assessment integration map](../PlayBooks/assessment-service-integration-map.md) |

## Control Framework Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [frameworks evidence reuse](./diagrams/frameworks-evidence-reuse.svg) | [Guide](../Compliance/frameworks.md) |
| [privacy breach notification decision paths](./diagrams/privacy-breach-notification-decision-path.svg) | [Guide](../Compliance/regulations.md) |

Distinct GDPR, HIPAA, and state-law triggers.

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

## General OSINT Investigation Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [osint investigation evidence handling](./diagrams/osint-investigation-evidence-handling.svg) | [Guide](../OSINT/OSINT_GUIDE.md) |
| [osint investigation cycle](./diagrams/osint-investigation-cycle.svg) | [Guide](../OSINT/OSINT_GUIDE.md) |
| [osint investigation request scope](./diagrams/osint-investigation-request-scope.svg) | [Guide](../OSINT/OSINT_GUIDE.md) |
| [osint investigation identity evidence](./diagrams/osint-investigation-identity-evidence.svg) | [Guide](../OSINT/OSINT_GUIDE.md) |

## Raster Illustrations in the Hardware Chapters

| Asset | Chapter |
|---|---|
| [UART](./UART.jpg), [SPI](./SPI.jpg), [I²C](./i2c.jpg), [JTAG](./JTAG.jpg) | [Hardware Hacking — Chapter 2](../HardwareHacking/Chapter2.md) |
| [Clock/voltage glitch](./ClockvsVoltage.jpg), [EMFI](./ElectromagneticFaultInjection.jpg), [Laser FI](./LaserFaultInjection.jpg) | [Hardware Hacking — Chapter 3](../HardwareHacking/Chapter3.md) |
| [SPA on RSA](./SPAonRSA.jpg) | [Hardware Hacking — Chapter 4](../HardwareHacking/Chapter4.md) |
| [Master guide banner](./cybersecurityguide.png) | [Master README](../README.md) and [START HERE](../START_HERE.md) |

## Historical Hardware Illustrations

| Historical asset | Current guide illustration |
|---|---|
| [Trust boundary](./CollapsingtheTrustBoundary.jpg) | [Hardware threat-model figure](../HardwareHacking/Chapter1.md) |
| [Shunt setup](./ShuntSetup.jpg) | [Shunt-current figure](../HardwareHacking/Chapter2.md) |
| [CPA correlation](./CPACorrelationProcess.jpg) | [Power measurement and evidence flow](../HardwareHacking/Chapter5.md) |

## Phishing Response Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [phishing response triage](./diagrams/phishing-response-triage.svg) | [Guide](../PlayBooks/sop_phishing_analysis.md) |
| [phishing response control boundaries](./diagrams/phishing-response-control-boundaries.svg) | [Guide](../PlayBooks/sop_phishing_analysis.md) |

## Cryptographic Algorithm Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [crypto algorithms aead contract](./diagrams/crypto-algorithms-aead-contract.svg) | [Guide](../Cryptography/algorithms.md) |
| [crypto algorithms primitive roles](./diagrams/crypto-algorithms-primitive-roles.svg) | [Guide](../Cryptography/algorithms.md) |
| [crypto algorithms pqc roles](./diagrams/crypto-algorithms-pqc-roles.svg) | [Guide](../Cryptography/algorithms.md) |

## AI Agent Security Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [agent security evaluation evidence](./diagrams/agent-security-evaluation-evidence.svg) | [Guide](../AI/agent-threat-modeling-and-security.md) |
| [agent threat-modeling evaluation loop](./diagrams/agent-threat-modeling-evaluation-loop.svg) | [Guide](../AI/agent-threat-modeling-and-security.md) |
| [agent security trust boundaries](./diagrams/agent-security-trust-boundaries.svg) | [Guide](../AI/agent-threat-modeling-and-security.md) |
| [agent security action gate](./diagrams/agent-security-action-gate.svg) | [Guide](../AI/agent-threat-modeling-and-security.md) |

Scope, map, test, review and re-scope.

## AWS Security Guide Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [aws request policy evaluation](./diagrams/aws-request-policy-evaluation.svg) | [Guide](../Cloud/aws.md) |
| [aws s3 independent controls](./diagrams/aws-s3-independent-controls.svg) | [Guide](../Cloud/aws.md) |
| [AWS CloudTrail event coverage](./diagrams/aws-cloudtrail-event-coverage.svg) | [AWS Hardening & Detection](../Cloud/aws.md#hardening--detection) |
| [aws imdsv2 token boundary](./diagrams/aws-imdsv2-token-boundary.svg) | [Guide](../Cloud/aws.md) |

## YARA-X Rule Lab Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [yara rule lifecycle](./diagrams/yara-rule-lifecycle.svg) | [Guide](../ReverseEngineering/yara-x-rule-lab.md) |
| [yara rule detection interpretation](./diagrams/yara-rule-detection-interpretation.svg) | [Guide](../ReverseEngineering/yara-x-rule-lab.md) |

## Xerox DocuColor Case Study Visuals

Embedded in the [Xerox DocuColor case study](../CaseStudies/hardware/xerox-docucolor-machine-identification-code.md).

| Asset | Purpose and provenance |
|---|---|
| [Printer dots](./printerdots.jpg) | Owner-supplied illustrative introduction; not authenticated as a physical capture. |
| [MIC overview](./printerdotsbasic%20breakdown.jpg) | Owner-supplied conceptual breakdown; caption explains layout and lighting limitations. |
| [DocuColor grid](./diagrams/xerox-docucolor-grid.svg) | Original synthetic grid and minute-decoding example based on EFF's format. |
| [Evidence workflow](./diagrams/xerox-docucolor-evidence-flow.svg) | Original conceptual preservation, observation, decoding, and corroboration workflow. |

## OSINT Source Verification Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [source verification preservation vs claim](./diagrams/source-verification-preservation-vs-claim.svg) | [Guide](../OSINT/bellingcat-source-verification.md) |
| [source verification provenance independence](./diagrams/source-verification-provenance-independence.svg) | [Guide](../OSINT/bellingcat-source-verification.md) |

## Data Quality And Schema Contract Visuals

Original conceptual flow separating per-record validation, batch handling and schema evolution compatibility checks.

| Diagram | Embedded guide |
|---|---|
| [Data contract validation and schema evolution](./diagrams/data-contract-validation-and-evolution.svg) | [Data Quality & Schema Contracts](../Data-Engineering/Phase1/data_quality_schema_contracts.md) |

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

## Suricata And Zeek Deployment Visuals

Original conceptual diagram distinguishing mirrored sensor copies, alert/protocol logs and inline enforcement.

| Diagram | Embedded guide |
|---|---|
| [Suricata and Zeek visibility and blocking](./diagrams/suricata-zeek-visibility-and-blocking.svg) | [Suricata & Zeek deployment guide](../IncidentResponse/IDS&IPS/suricata+zeek.md) |

## Network Intrusion Response Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [network intrusion evidence correlation](./diagrams/network-intrusion-evidence-correlation.svg) | [Guide](../IncidentResponse/network_intrusion.md) |
| [network intrusion containment recovery](./diagrams/network-intrusion-containment-recovery.svg) | [Guide](../IncidentResponse/network_intrusion.md) |
| [network intrusion filter vs aggregation](./diagrams/network-intrusion-filter-vs-aggregation.svg) | [Guide](../IncidentResponse/network_intrusion.md) |

## Azure And Entra Security Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [azure security rbac scope](./diagrams/azure-security-rbac-scope.svg) | [Guide](../Cloud/azure.md) |
| [azure security logging coverage](./diagrams/azure-security-logging-coverage.svg) | [Guide](../Cloud/azure.md) |
| [azure security role planes](./diagrams/azure-security-role-planes.svg) | [Guide](../Cloud/azure.md) |

## Mobile Penetration Testing SOP Visuals

Original conceptual diagrams that summarize authorization gates and evidence handling.

| Diagram | Embedded guide |
|---|---|
| [Mobile test scope gates](./diagrams/mobile-pentest-scope-gates.svg) | [Mobile penetration testing SOP](../Mobile/mobile_pentest_sop.md) |
| [Mobile test evidence chain](./diagrams/mobile-pentest-evidence-chain.svg) | [Mobile penetration testing SOP](../Mobile/mobile_pentest_sop.md) |

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

## Software Supply-Chain Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [supply chain complementary evidence](./diagrams/supply-chain-complementary-evidence.svg) | [Guide](../ContainerSecurity/software-supply-chain-assessment.md) |
| [supply chain subject binding](./diagrams/supply-chain-subject-binding.svg) | [Guide](../ContainerSecurity/software-supply-chain-assessment.md) |

## Proxmox Sensor Visibility Visuals

Original conceptual capture-path diagram; validate the expected test flow against packets received at the sensor.

| Diagram | Embedded guide |
|---|---|
| [Proxmox sensor visibility paths](./diagrams/proxmox-sensor-visibility.svg) | [Proxmox IDS / Security Onion checklist](../Homelab/proxmox-security-monitoring-visibility.md) |

## Container Security Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [container security image runtime host](./diagrams/container-security-image-runtime-host.svg) | [Guide](../ContainerSecurity/containers.md) |
| [container escape evidence paths](./diagrams/container-escape-evidence-paths.svg) | [Guide](../ContainerSecurity/containers.md) |
| [container security isolation controls](./diagrams/container-security-isolation-controls.svg) | [Guide](../ContainerSecurity/containers.md) |
| [container security secrets lifecycle](./diagrams/container-security-secrets-lifecycle.svg) | [Guide](../ContainerSecurity/containers.md) |

Distinguish direct authority exposure from software escape paths.

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

## Windows Build Review Visuals

Original conceptual workflow; the checklist separates baseline selection, effective evidence and scoped follow-up.

| Diagram | Embedded guide |
|---|---|
| [Windows build review evidence flow](./diagrams/windows-build-review-evidence.svg) | [Windows Build Review checklist](../Checklists/Windows-Build-Review-Checklist.md) |

## Microsoft 365 Assessment Visuals

Original conceptual figures; source links and evidence limits appear in the guide captions.

| Diagram | Embedded guide |
|---|---|
| [scuba configuration assessment](./diagrams/scuba-configuration-assessment.svg) | [Guide](../Cloud/m365-scuba-assessment.md) |
| [scuba findings to controlled change](./diagrams/scuba-findings-to-controlled-change.svg) | [Guide](../Cloud/m365-scuba-assessment.md) |

## Historical Asset With Cropped Labels

- [advnacedflows.jpg](./advnacedflows.jpg) is a simplified CPU, RAM and storage illustration. The right edge cuts through the storage node and its labels. The [Manjaro test bench guide](../HardwareTesting/Manjaro_Intel_TestBench.md#5-memory-and-storage-diagnostics) already embeds a complete CPU, RAM and storage comparison.

## rtl_433 Telemetry Lab Visuals

Two original conceptual figures embedded in the [receive-only telemetry lab](../SDR/rtl433-passive-telemetry-lab.md).

| Diagram | Purpose |
|---|---|
| [Decoder to collector](./diagrams/rtl433-decoder-to-collector.svg) | Separate native decoder output, normalization and collector validation. |
| [Alert evidence limits](./diagrams/rtl433-alert-evidence-limits.svg) | Investigate benign alternatives and corroborate anomalies. |

These illustrate a proposed lab; no live sensor data or deployed detection results are claimed.

## Velociraptor Endpoint Triage Visuals

Original conceptual flow showing collection authorization, artifact selection and Flow ID/status review.

| Diagram | Embedded guide |
|---|---|
| [Velociraptor endpoint triage flow](./diagrams/velociraptor-triage-flow.svg) | [Velociraptor and ForensicArtifacts triage](../IncidentResponse/Digital-Forensics/velociraptor-artifact-triage.md) |

## MVT Forensic Visuals

Original conceptual diagrams; MVT release behavior and evidence limits are documented in the guide.

| Diagram | Embedded guide |
|---|---|
| [MVT artifact coverage](./diagrams/mvt-triage-artifact-coverage.svg) | [MVT forensic triage](../Mobile/mvt-forensic-triage.md) |
| [MVT consent and custody](./diagrams/mvt-triage-consent-custody.svg) | [MVT forensic triage](../Mobile/mvt-forensic-triage.md) |

## VPN Trust Boundary Visuals

Original conceptual diagram separating what the local network, VPN operator, and destination may observe. HTTPS remains an independent end-to-end protection.

| Diagram | Embedded guide |
|---|---|
| [VPN trust boundaries](./diagrams/vpn-trust-boundaries.svg) | [VPN Security Guide](../Documentation/VPN.md) |

## Tor Circuit and Visibility Visuals

Original conceptual diagram separating Tor Browser or explicitly configured client traffic from other device traffic, with relay roles and the independent role of HTTPS.

| Diagram | Embedded guide |
|---|---|
| [Tor circuit and relay visibility](./diagrams/tor-circuit-visibility.svg) | [Tor Browser and Tor Network Guide](../Documentation/TOR.md) |
| [Tor Browser download verification](./diagrams/tor-browser-download-verification.svg) | [Install and update Tor Browser](../Documentation/TOR.md#2-install-and-update-tor-browser) |

## Virtual Machine And Lab Boundary Visuals

Original conceptual diagrams illustrating common VM network exposure and the Black Hat Bash container network roles. Actual reachability depends on the hypervisor, Docker Compose configuration, daemon, host routes, firewall, and published ports.

| Diagram | Embedded guide |
|---|---|
| [VM network isolation modes](./diagrams/vm-network-isolation-modes.svg) | [VM and lab environments](../Documentation/virtualmachines.md) |
| [Black Hat Bash lab boundaries](./diagrams/black-hat-bash-lab-boundaries.svg) | [VM and lab environments](../Documentation/virtualmachines.md) |

## Tails USB Session Boundary Visual

Original conceptual diagram separating the Tails system area, volatile live session, optional encrypted Persistent Storage, Tor Browser traffic, and the Unsafe Browser's direct-network exception.

| Diagram | Embedded guide |
|---|---|
| [Tails Persistent Storage backup](./diagrams/tails-persistent-storage-backup.svg) | [Tails USB setup guide](../OPSEC/tails-usb-setup-guide.md) |
| [Tails storage and network boundaries](./diagrams/tails-storage-and-network-boundaries.svg) | [Tails USB setup guide](../OPSEC/tails-usb-setup-guide.md) |

## Journalist Device, Account And Network Boundaries Visual

Original conceptual data-flow map emphasizing that device, account, copy/sync, and network protections address different boundaries.

| Diagram | Embedded guide |
|---|---|
| [Journalist device, account, and network boundaries](./diagrams/journalist-device-account-network-boundaries.svg) | [Journalist device and network protection](../OPSEC/press-freedom/device-network-protection.md) |

## Press Freedom Source Data Lifecycle Visual

Original conceptual workflow for data minimization, protection, retention review, legal holds, and authorized disposal. It does not specify a legal retention period or sanitize media automatically.

| Diagram | Embedded guide |
|---|---|
| [Journalist source-data lifecycle](./journalist-source-data-lifecycle.svg) | [Data retention, minimization and lawful disposal](../OPSEC/press-freedom/data-retention-removal.md) |

## Journalist Device Seizure And Duress Response Visual

Original conceptual response sequence separating pre-incident preparation, immediate safety and counsel priorities, and post-incident preservation and account containment. It is not legal advice or a universal response procedure.

| Diagram | Embedded guide |
|---|---|
| [Journalist device seizure and duress response](./journalist-seizure-response.svg) | [Duress, device seizure and emergency response](../OPSEC/press-freedom/duress-seizure-response.md) |

## Proxy Route And Observer Visibility Visual

Original conceptual comparison of proxy, VPN, SSH, and Tor paths. It distinguishes routing metadata visible to intermediaries from page contents protected by valid destination TLS.

| Diagram | Embedded guide |
|---|---|
| [Proxy routes and observer visibility](./diagrams/proxy-route-observer-visibility.svg) | [Proxy types, DNS leaks and Froxy](../OPSEC/proxy-reference-froxy.md) |

## OPSEC Anonymity Layering Decision Visual

Original conceptual decision map separating task intent, network-path choices, observer tradeoffs, and the limits of proxying and browser compartments.

| Diagram | Embedded guide |
|---|---|
| [Anonymity layering decision map](./diagrams/opsec-anonymity-layering-decisions.svg) | [Anonymity layering for OSINT and authorized engagements](../OPSEC/anonymity-layering.md) |
| [VPS tunnel health checks](./diagrams/opsec-vps-tunnel-health-checks.svg) | [Anonymity layering for OSINT and authorized engagements](../OPSEC/anonymity-layering.md) |

Separate listener, SSH, destination, and bypass checks.

## Whonix And Kicksecure USB Boundaries Visual

Original conceptual topology of an encrypted Kicksecure host, Whonix Gateway/Workstation routing, and persistent versus live session storage.

| Diagram | Embedded guide |
|---|---|
| [Whonix and Kicksecure USB boundaries](./diagrams/whonix-kicksecure-usb-boundaries.svg) | [Whonix + Kicksecure USB setup](../OPSEC/whonix-kicksecure-usb-guide.md) |

## Image Guidelines

1. Use a **relative path from the embedding Markdown file**; for a root-level page use `./assets/image.png`, for a one-level-deep section use `../assets/image.png`, and for a two-level-deep section use `../../assets/image.svg`.
2. Provide meaningful Markdown alt text and a short caption, including whether the image is *conceptual* or based on verified deployment/test data.
3. Avoid claiming an illustration proves encryption security, exploitability, network isolation, or real-world device behavior.
4. Keep SVG assets static: no script, animation, external fonts or third-party image dependencies. Preserve the embedded `title` and `desc` for accessibility.
5. When an image is superseded, update all backlinks and run repository lint/link checks. Maintain this table.

---

[Master README](../README.md) | [Role Navigation](../START_HERE.md) | [Visual reference notes](./imageplacement.md)


## Fault Injection Evaluation Visual

Original conceptual evidence flow for authorized, controlled assessments. It does not show circuit connections or claim a tested attack result.

| Diagram | Embedded guide |
|---|---|
| [Fault-injection evaluation evidence flow](./diagrams/fault-injection-evaluation-flow.svg) | [Fault Injection Attacks](../HardwareHacking/Chapter3.md#concept) |


## Side-Channel Evidence Visual

Original conceptual analysis flow separating physical observation, leakage modeling, statistical analysis, and independent validation. It does not represent a measured trace or proven key recovery.

| Diagram | Embedded guide |
|---|---|
| [Side-channel evidence analysis](./diagrams/side-channel-evidence-analysis.svg) | [Timing and Power Analysis](../HardwareHacking/Chapter4.md#introduction-to-side-channel-analysis) |


## Power Analysis Measurement Visual

Original conceptual workflow for authorized leakage assessment. It does not represent a measured trace or tested key recovery.

| Diagram | Embedded guide |
|---|---|
| [Power-analysis measurement and evidence flow](./diagrams/power-analysis-measurement-evidence-flow.svg) | [Power Analysis Practicals](../HardwareHacking/Chapter5.md#measurement-setup) |


## Hardware Threat Modeling Visual

Original conceptual flow from attacker capability and reachable interfaces to assessed controls, residual risk, and evidence. Physical possession does not guarantee interface access or secret extraction.

| Diagram | Embedded guide |
|---|---|
| [Hardware threat-model capability flow](./diagrams/hardware-threat-model-capability-flow.svg) | [Hardware Threat Modeling](../HardwareHacking/Chapter1.md#why-hardware-threat-modeling-differs) |

## Bus Pirate SPI Visual

Original conceptual wiring map. Pin labels depend on hardware revision and adapters; the optional VOUT path is separate and requires checking the target rail before connection.

| Diagram | Embedded guide |
|---|---|
| [Bus Pirate SPI signal mapping](./diagrams/buspirate-spi-signal-mapping.svg) | [Bus Pirate guide](../HardwareHacking/BusPirate.md#conceptual-spi-wiring) |

## JTAGulator Discovery Visual

Original conceptual process map. It separates target power from VADJ level translation and treats scan output as a candidate requiring validation.

| Diagram | Embedded guide |
|---|---|
| [JTAGulator discovery and validation flow](./diagrams/jtagulator-discovery-validation-flow.svg) | [JTAGulator guide](../HardwareHacking/JTAGulator.md#discovery-and-validation-flow) |

## Digital Logic Capture Visual

Original conceptual workflow. Device specifications, input limits, supported drivers, capture rates, and thresholds vary by hardware; decoded protocol annotations depend on configuration.

| Diagram | Embedded guide |
|---|---|
| [Digital logic capture boundaries](./diagrams/digital-logic-capture-boundaries.svg) | [HiLetgo logic-analyzer guide](../HardwareHacking/HiLetgo.md#capture-and-interpretation-boundaries) |

## LA1010 Sampling Visual

Manufacturer-published sampling limits by active-channel count. Use the detailed model specifications and current manual; the diagram is not a measured capture.

| Diagram | Embedded guide |
|---|---|
| [LA1010 active-channel sample-rate tradeoff](./diagrams/la1010-active-channel-sample-rate.svg) | [LA1010 guide](../HardwareHacking/LA1010.md#active-channel-tradeoff) |

## Profiles and Provider Evidence

| Diagram | Where embedded | Why it belongs |
|---|---|---|
| [CSF 2.0 Profiles and action plan](./diagrams/csf-profiles-gap-and-action-plan.svg) | [Security Control Frameworks](../Compliance/frameworks.md#nist-cybersecurity-framework-csf-20) | Compares observed and target outcomes within the same scope to prioritize gaps |
| [PCI DSS provider evidence decision](./diagrams/pci-dss-provider-evidence-decision.svg) | [PCI DSS Scoping & Segmentation](../Compliance/pci-dss-scoping.md#service-providers-remote-it--shared-responsibility) | Checks the provider's evidence against the service used and assigned responsibilities |

## PCI DSS Scope Worksheet Visual

| Diagram | Embedded guide |
|---|---|
| [PCI DSS scoping evidence trail](./diagrams/pci-scope-evidence-trail.svg) | [PCI DSS scope review worksheet](../Compliance/pci-scope-review-template.md#how-to-use-the-worksheet) |

## Mobile TLS Proxy Trust Visual

Original conceptual comparison of Android and iOS trust gates for a controlled HTTPS proxy test. CA installation, platform trust, app-specific trust, and pinning are separate checks.

| Diagram | Embedded guide |
|---|---|
| [Mobile TLS proxy trust path](./diagrams/mobile-tls-proxy-trust-path.svg) | [Mobile guide](../Mobile/README.md#-mobile-https-proxy-trust-flow) |

## ETL Reconciliation Visual

Original conceptual flow separating extraction and transactional checkpoints from post-commit validation. The diagram distinguishes key-coverage checks from optional row-content comparison and shows the bounded-lateness limitation of a fixed overlap window.

| Diagram | Embedded guide |
|---|---|
| [ETL key-coverage reconciliation flow](./diagrams/etl-key-coverage-reconciliation-flow.svg) | [Incremental ETL/ELT pipeline design](../Data-Engineering/Phase1/etl_elt_pipeline_design.md#8-reconciliation) |

## AI Routing and OpenSCAD Export Visuals

| Diagram | Embedded guide |
|---|---|
| [AI model routing and fallback](./diagrams/ai-model-routing-policy.svg) | [Model routing and cost management](../AI/model-routing-and-cost-management.md#3-routing-policy--safe-fallback) |
| [Analyst-gated AgentFlow handoffs](./diagrams/anythingllm-analyst-gated-handoffs.svg) | [AnythingLLM workflow examples](../AI/AnythingLLM/anything_llm_agentflows.md#analyst-gated-workflow-map) | Shows scope, provider disclosure, untrusted outputs, analyst review and stop conditions |
| [Threat intelligence evidence review](./diagrams/threat-intelligence-evidence-review.svg) | [ThreatIntelCheck](../AI/AnythingLLM/flow-threat_intel.md#analyst-review) | Separates provider observations, unknown results, local corroboration, and human action |
| [OpenSCAD slicer and fit checks](./diagrams/openscad-slicer-fit-verification.svg) | [OpenSCAD design for printing](../CAD/OpenSCAD/05-design-for-printing.md#after-importing-into-the-slicer) |
| [OpenSCAD preset to print file](./diagrams/openscad-preset-to-export.svg) | [OpenSCAD project structure](../CAD/OpenSCAD/02-project-structure.md#command-line-export--automation) |
| [CAD design to verified fit loop](./diagrams/cad-design-to-fit-verification-loop.svg) | [CAD & 3D Printing](../CAD/README.md#cad-design-to-fit-loop) |
| [OpenSCAD shortcuts cheat sheet](../CAD/OpenSCAD/images/openscad-shortcuts-cheatsheet.svg) | [OpenSCAD keyboard shortcuts](../CAD/OpenSCAD/06-keyboard-shortcuts.md#-purpose) |

## Data Modeling & Version Publication

| Diagram | Embedded guide |
|---|---|
| [Asset and checkin join grain](./diagrams/sql-asset-checkin-join-grain.svg) | [SQL joins](../Data-Engineering/Phase1/sql_data_modeling.md#4-joins) |
| [Complete dataset version publication](./diagrams/dataset-version-publication.svg) | [Publish complete versions](../Data-Engineering/Phase2/data_storage_file_formats.md#publication) |


## Script Pinning Visual

Original conceptual flow for strict manifest parsing and supply-chain checks. Malformed requested pins stop the install; downloads require an exact SHA-256 match before use.

| Diagram | Embedded guide |
|---|---|
| [Script pin validation and verified installation](./diagrams/script-pin-validation-flow.svg) | [Tool pinning policy](../Scripts/PINNING.md#behaviour) |


## Repository Search Visual

Conceptual guide to choosing the local helper, GitHub code search, Wiki search, or the complete documentation index based on where the reader is browsing.

| Diagram | Embedded guide |
|---|---|
| [Repository search paths](./diagrams/repository-search-paths.svg) | [Main README](../README.md) |
